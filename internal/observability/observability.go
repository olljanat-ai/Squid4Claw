package observability

import (
	"crypto/rand"
	"fmt"
	"log"
	"strings"
	"time"

	proxylog "github.com/olljanat-ai/firewall4ai/internal/logging"
)

// Observer receives proxy log entries and forwards LLM-related ones
// to the configured observability backend (Langfuse).
type Observer struct {
	endpoints []LLMEndpoint
	langfuse  *LangfuseClient
}

// Config holds the observability configuration.
type Config struct {
	Enabled          bool          `json:"enabled"`
	LangfuseHost     string        `json:"langfuse_host"`
	LangfusePublicKey string       `json:"langfuse_public_key"`
	LangfuseSecretKey string       `json:"langfuse_secret_key"`
	LLMEndpoints     []LLMEndpoint `json:"llm_endpoints"`
}

// New creates a new Observer from configuration. Returns nil if observability is disabled.
func New(cfg Config) *Observer {
	if !cfg.Enabled {
		return nil
	}
	if cfg.LangfuseHost == "" || cfg.LangfusePublicKey == "" || cfg.LangfuseSecretKey == "" {
		log.Printf("[observability] Disabled: missing Langfuse configuration")
		return nil
	}

	endpoints := cfg.LLMEndpoints
	if len(endpoints) == 0 {
		endpoints = DefaultEndpoints()
	}

	log.Printf("[observability] Enabled: sending to Langfuse at %s with %d LLM endpoints", cfg.LangfuseHost, len(endpoints))
	return &Observer{
		endpoints: endpoints,
		langfuse:  NewLangfuseClient(cfg.LangfuseHost, cfg.LangfusePublicKey, cfg.LangfuseSecretKey),
	}
}

// Close shuts down the observer and flushes pending events.
func (o *Observer) Close() {
	if o != nil && o.langfuse != nil {
		o.langfuse.Close()
	}
}

// ProcessEntry checks if a log entry is an LLM API call and forwards it to Langfuse.
// This should be called asynchronously (go o.ProcessEntry(...)) to avoid blocking the proxy.
func (o *Observer) ProcessEntry(entry proxylog.Entry, sourceIP string) {
	if o == nil || entry.FullDetail == nil {
		return
	}

	// Only process successful requests with full logging data.
	if entry.Status != "allowed" || entry.FullDetail.RequestBody == "" {
		return
	}

	// Check if this is a known LLM endpoint.
	ep, ok := DetectLLMEndpoint(entry.Host, entry.Path, o.endpoints)
	if !ok {
		return
	}

	// Parse the LLM request.
	model, inputMsgs := ParseLLMRequest(ep.Provider, entry.FullDetail.RequestBody)
	if model == "" && len(inputMsgs) == 0 {
		return // Not a parseable LLM request
	}

	// Parse the LLM response.
	output, inputTokens, outputTokens, totalTokens, finishReason := ParseLLMResponse(ep.Provider, entry.FullDetail.ResponseBody)

	// For Gemini, model is in the URL path (e.g., /v1beta/models/gemini-pro:generateContent).
	if model == "" && ep.Provider == ProviderGemini {
		model = extractGeminiModel(entry.Path)
	}

	// Generate IDs for trace and generation.
	traceID := generateID()
	genID := generateID()

	startTime := entry.Timestamp.Add(-time.Duration(entry.Duration) * time.Millisecond)
	endTime := entry.Timestamp

	// Use skill ID as session ID for grouping agent LLM calls.
	sessionID := entry.SkillID

	// Send trace event.
	o.langfuse.SendTrace(
		traceID,
		fmt.Sprintf("%s %s%s", entry.Method, entry.Host, entry.Path),
		sessionID,
		sourceIP,
		startTime,
		map[string]any{
			"provider": string(ep.Provider),
			"host":     entry.Host,
			"path":     entry.Path,
		},
	)

	// Send generation event.
	o.langfuse.SendGeneration(GenerationEvent{
		ID:           genID,
		TraceID:      traceID,
		Name:         fmt.Sprintf("%s/%s", ep.Provider, model),
		Model:        model,
		StartTime:    startTime,
		EndTime:      endTime,
		Input:        inputMsgs,
		Output:       output,
		InputTokens:  inputTokens,
		OutputTokens: outputTokens,
		TotalTokens:  totalTokens,
		StatusCode:   entry.FullDetail.ResponseStatus,
		Metadata: map[string]any{
			"provider":      string(ep.Provider),
			"finish_reason": finishReason,
			"source_ip":     sourceIP,
			"skill_id":      entry.SkillID,
			"duration_ms":   entry.Duration,
		},
	})

	log.Printf("[observability] Forwarded LLM call: provider=%s model=%s tokens=%d/%d source=%s",
		ep.Provider, model, inputTokens, outputTokens, sourceIP)
}

// extractGeminiModel extracts the model name from a Gemini API path.
// Example: /v1beta/models/gemini-pro:generateContent -> gemini-pro
func extractGeminiModel(path string) string {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if p == "models" && i+1 < len(parts) {
			model := parts[i+1]
			// Strip the method suffix (e.g., ":generateContent")
			if idx := strings.Index(model, ":"); idx >= 0 {
				model = model[:idx]
			}
			return model
		}
	}
	return ""
}

// generateID returns a random hex ID suitable for Langfuse trace/generation IDs.
func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
