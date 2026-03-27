package observability

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

const (
	// langfuseBatchSize is the max events per batch request.
	langfuseBatchSize = 10
	// langfuseFlushInterval is how often to flush pending events.
	langfuseFlushInterval = 5 * time.Second
	// langfuseChannelSize is the buffer size for the event channel.
	langfuseChannelSize = 1000
	// langfuseTimeout is the HTTP timeout for Langfuse API calls.
	langfuseTimeout = 10 * time.Second
)

// LangfuseClient sends generation events to a Langfuse instance via its REST API.
type LangfuseClient struct {
	host      string
	publicKey string
	secretKey string
	client    *http.Client
	events    chan langfuseEvent
	wg        sync.WaitGroup
	done      chan struct{}
}

// langfuseEvent is a single event to send to Langfuse.
type langfuseEvent struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Body any    `json:"body"`
}

// langfuseBatch is the request body for POST /api/public/ingestion.
type langfuseBatch struct {
	Batch    []langfuseEvent `json:"batch"`
	Metadata *batchMetadata  `json:"metadata,omitempty"`
}

type batchMetadata struct {
	SDKName    string `json:"sdk_name"`
	SDKVersion string `json:"sdk_version"`
}

// NewLangfuseClient creates a new Langfuse client that sends events asynchronously.
func NewLangfuseClient(host, publicKey, secretKey string) *LangfuseClient {
	c := &LangfuseClient{
		host:      host,
		publicKey: publicKey,
		secretKey: secretKey,
		client:    &http.Client{Timeout: langfuseTimeout},
		events:    make(chan langfuseEvent, langfuseChannelSize),
		done:      make(chan struct{}),
	}
	c.wg.Add(1)
	go c.flushLoop()
	return c
}

// Close stops the background flush loop and waits for pending events to be sent.
func (c *LangfuseClient) Close() {
	close(c.done)
	c.wg.Wait()
}

// SendTrace sends a trace-create event to Langfuse.
func (c *LangfuseClient) SendTrace(id, name, sessionID, userID string, timestamp time.Time, metadata map[string]any) {
	body := map[string]any{
		"id":        id,
		"name":      name,
		"timestamp": timestamp.UTC().Format(time.RFC3339Nano),
	}
	if sessionID != "" {
		body["sessionId"] = sessionID
	}
	if userID != "" {
		body["userId"] = userID
	}
	if metadata != nil {
		body["metadata"] = metadata
	}
	c.enqueue(langfuseEvent{
		ID:   id,
		Type: "trace-create",
		Body: body,
	})
}

// SendGeneration sends a generation-create event to Langfuse.
func (c *LangfuseClient) SendGeneration(gen GenerationEvent) {
	body := map[string]any{
		"id":             gen.ID,
		"traceId":        gen.TraceID,
		"name":           gen.Name,
		"model":          gen.Model,
		"startTime":      gen.StartTime.UTC().Format(time.RFC3339Nano),
		"completionStartTime": gen.StartTime.UTC().Format(time.RFC3339Nano),
		"endTime":        gen.EndTime.UTC().Format(time.RFC3339Nano),
	}
	if gen.Input != nil {
		body["input"] = gen.Input
	}
	if gen.Output != "" {
		body["output"] = gen.Output
	}
	if gen.InputTokens > 0 || gen.OutputTokens > 0 {
		usage := map[string]int{}
		if gen.InputTokens > 0 {
			usage["input"] = gen.InputTokens
		}
		if gen.OutputTokens > 0 {
			usage["output"] = gen.OutputTokens
		}
		if gen.TotalTokens > 0 {
			usage["total"] = gen.TotalTokens
		}
		body["usage"] = usage
	}
	if gen.Metadata != nil {
		body["metadata"] = gen.Metadata
	}
	if gen.StatusCode != 0 {
		body["statusMessage"] = fmt.Sprintf("HTTP %d", gen.StatusCode)
	}
	c.enqueue(langfuseEvent{
		ID:   gen.ID,
		Type: "generation-create",
		Body: body,
	})
}

// GenerationEvent holds the data for a Langfuse generation event.
type GenerationEvent struct {
	ID           string
	TraceID      string
	Name         string
	Model        string
	StartTime    time.Time
	EndTime      time.Time
	Input        any
	Output       string
	InputTokens  int
	OutputTokens int
	TotalTokens  int
	StatusCode   int
	Metadata     map[string]any
}

func (c *LangfuseClient) enqueue(e langfuseEvent) {
	select {
	case c.events <- e:
	default:
		log.Printf("[observability] Langfuse event channel full, dropping event %s", e.ID)
	}
}

func (c *LangfuseClient) flushLoop() {
	defer c.wg.Done()
	ticker := time.NewTicker(langfuseFlushInterval)
	defer ticker.Stop()

	var batch []langfuseEvent

	for {
		select {
		case e := <-c.events:
			batch = append(batch, e)
			if len(batch) >= langfuseBatchSize {
				c.sendBatch(batch)
				batch = nil
			}
		case <-ticker.C:
			if len(batch) > 0 {
				c.sendBatch(batch)
				batch = nil
			}
		case <-c.done:
			// Drain remaining events.
			for {
				select {
				case e := <-c.events:
					batch = append(batch, e)
				default:
					if len(batch) > 0 {
						c.sendBatch(batch)
					}
					return
				}
			}
		}
	}
}

func (c *LangfuseClient) sendBatch(events []langfuseEvent) {
	payload := langfuseBatch{
		Batch: events,
		Metadata: &batchMetadata{
			SDKName:    "firewall4ai",
			SDKVersion: "1.0.0",
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[observability] Failed to marshal Langfuse batch: %v", err)
		return
	}

	url := c.host + "/api/public/ingestion"
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		log.Printf("[observability] Failed to create Langfuse request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.publicKey, c.secretKey)

	resp, err := c.client.Do(req)
	if err != nil {
		log.Printf("[observability] Failed to send to Langfuse: %v", err)
		return
	}
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("[observability] Langfuse returned HTTP %d for batch of %d events", resp.StatusCode, len(events))
	}
}
