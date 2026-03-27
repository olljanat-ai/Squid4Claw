// Package observability provides LLM request/response detection, parsing,
// and forwarding to observability backends (e.g., Langfuse) for auditing
// AI agent interactions with LLM APIs.
package observability

import (
	"encoding/json"
	"strings"
)

// Provider identifies an LLM API provider.
type Provider string

const (
	ProviderOpenAI    Provider = "openai"
	ProviderAnthropic Provider = "anthropic"
	ProviderGemini    Provider = "gemini"
	ProviderMistral   Provider = "mistral"
	ProviderUnknown   Provider = "unknown"
)

// LLMEndpoint defines a known LLM API endpoint pattern.
type LLMEndpoint struct {
	Host       string   `json:"host"`
	PathPrefix string   `json:"path_prefix"`
	Provider   Provider `json:"provider"`
}

// DefaultEndpoints returns the built-in LLM API endpoint patterns.
func DefaultEndpoints() []LLMEndpoint {
	return []LLMEndpoint{
		{Host: "api.openai.com", PathPrefix: "/v1/", Provider: ProviderOpenAI},
		{Host: "api.anthropic.com", PathPrefix: "/v1/", Provider: ProviderAnthropic},
		{Host: "generativelanguage.googleapis.com", PathPrefix: "/", Provider: ProviderGemini},
		{Host: "api.mistral.ai", PathPrefix: "/v1/", Provider: ProviderMistral},
	}
}

// DetectLLMEndpoint checks if a host+path matches a known LLM API endpoint.
// Returns the matching endpoint and true if found, zero value and false otherwise.
func DetectLLMEndpoint(host, path string, endpoints []LLMEndpoint) (LLMEndpoint, bool) {
	for _, ep := range endpoints {
		if ep.Host == host && strings.HasPrefix(path, ep.PathPrefix) {
			return ep, true
		}
	}
	return LLMEndpoint{}, false
}

// LLMGeneration holds parsed LLM generation data extracted from request/response.
type LLMGeneration struct {
	Provider         Provider
	Model            string
	InputMessages    []Message
	OutputMessage    string
	InputTokens      int
	OutputTokens     int
	TotalTokens      int
	FinishReason     string
	RequestBodyRaw   string // original request body for reference
	ResponseBodyRaw  string // original response body for reference
}

// Message represents a chat message (role + content).
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ParseLLMRequest parses a request body to extract model and input messages.
func ParseLLMRequest(provider Provider, body string) (model string, messages []Message) {
	switch provider {
	case ProviderOpenAI, ProviderMistral:
		return parseOpenAIRequest(body)
	case ProviderAnthropic:
		return parseAnthropicRequest(body)
	case ProviderGemini:
		return parseGeminiRequest(body)
	default:
		return "", nil
	}
}

// ParseLLMResponse parses a response body to extract completion, token usage, and finish reason.
func ParseLLMResponse(provider Provider, body string) (output string, inputTokens, outputTokens, totalTokens int, finishReason string) {
	switch provider {
	case ProviderOpenAI, ProviderMistral:
		return parseOpenAIResponse(body)
	case ProviderAnthropic:
		return parseAnthropicResponse(body)
	case ProviderGemini:
		return parseGeminiResponse(body)
	default:
		return "", 0, 0, 0, ""
	}
}

// --- OpenAI / Mistral format ---

func parseOpenAIRequest(body string) (string, []Message) {
	var req struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string `json:"role"`
			Content any    `json:"content"` // string or array
		} `json:"messages"`
	}
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		return "", nil
	}
	msgs := make([]Message, 0, len(req.Messages))
	for _, m := range req.Messages {
		msgs = append(msgs, Message{
			Role:    m.Role,
			Content: contentToString(m.Content),
		})
	}
	return req.Model, msgs
}

func parseOpenAIResponse(body string) (string, int, int, int, string) {
	var resp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			TotalTokens      int `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return "", 0, 0, 0, ""
	}
	output := ""
	finishReason := ""
	if len(resp.Choices) > 0 {
		output = resp.Choices[0].Message.Content
		finishReason = resp.Choices[0].FinishReason
	}
	return output, resp.Usage.PromptTokens, resp.Usage.CompletionTokens, resp.Usage.TotalTokens, finishReason
}

// --- Anthropic format ---

func parseAnthropicRequest(body string) (string, []Message) {
	var req struct {
		Model    string `json:"model"`
		System   any    `json:"system"` // string or array
		Messages []struct {
			Role    string `json:"role"`
			Content any    `json:"content"` // string or array of content blocks
		} `json:"messages"`
	}
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		return "", nil
	}
	msgs := make([]Message, 0, len(req.Messages)+1)
	// Include system prompt if present.
	if sysStr := contentToString(req.System); sysStr != "" {
		msgs = append(msgs, Message{Role: "system", Content: sysStr})
	}
	for _, m := range req.Messages {
		msgs = append(msgs, Message{
			Role:    m.Role,
			Content: contentToString(m.Content),
		})
	}
	return req.Model, msgs
}

func parseAnthropicResponse(body string) (string, int, int, int, string) {
	var resp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
		Usage      struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return "", 0, 0, 0, ""
	}
	var parts []string
	for _, c := range resp.Content {
		if c.Type == "text" && c.Text != "" {
			parts = append(parts, c.Text)
		}
	}
	total := resp.Usage.InputTokens + resp.Usage.OutputTokens
	return strings.Join(parts, ""), resp.Usage.InputTokens, resp.Usage.OutputTokens, total, resp.StopReason
}

// --- Google Gemini format ---

func parseGeminiRequest(body string) (string, []Message) {
	var req struct {
		Contents []struct {
			Role  string `json:"role"`
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"contents"`
	}
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		return "", nil
	}
	// Gemini model name is in the URL path, not the body. Return empty model.
	msgs := make([]Message, 0, len(req.Contents))
	for _, c := range req.Contents {
		var parts []string
		for _, p := range c.Parts {
			if p.Text != "" {
				parts = append(parts, p.Text)
			}
		}
		msgs = append(msgs, Message{
			Role:    c.Role,
			Content: strings.Join(parts, "\n"),
		})
	}
	return "", msgs
}

func parseGeminiResponse(body string) (string, int, int, int, string) {
	var resp struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
			FinishReason string `json:"finishReason"`
		} `json:"candidates"`
		UsageMetadata struct {
			PromptTokenCount     int `json:"promptTokenCount"`
			CandidatesTokenCount int `json:"candidatesTokenCount"`
			TotalTokenCount      int `json:"totalTokenCount"`
		} `json:"usageMetadata"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return "", 0, 0, 0, ""
	}
	output := ""
	finishReason := ""
	if len(resp.Candidates) > 0 {
		var parts []string
		for _, p := range resp.Candidates[0].Content.Parts {
			if p.Text != "" {
				parts = append(parts, p.Text)
			}
		}
		output = strings.Join(parts, "")
		finishReason = resp.Candidates[0].FinishReason
	}
	return output,
		resp.UsageMetadata.PromptTokenCount,
		resp.UsageMetadata.CandidatesTokenCount,
		resp.UsageMetadata.TotalTokenCount,
		finishReason
}

// contentToString converts various LLM content formats to a plain string.
// Handles: string, []{"type":"text","text":"..."}, and other JSON structures.
func contentToString(v any) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case []any:
		var parts []string
		for _, item := range val {
			if m, ok := item.(map[string]any); ok {
				if t, ok := m["text"].(string); ok {
					parts = append(parts, t)
				}
			}
		}
		return strings.Join(parts, "")
	default:
		// Fallback: marshal back to JSON string.
		b, _ := json.Marshal(v)
		return string(b)
	}
}
