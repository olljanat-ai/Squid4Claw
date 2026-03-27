# AI Agent LLM Observability - Evaluation & Design

## Problem Statement

Firewall4AI already intercepts all HTTP/HTTPS traffic from AI agent VMs via transparent proxy with TLS MITM. It has full-level logging that captures request/response headers and bodies. However, the raw logs lack LLM-specific context: there's no extraction of model names, token usage, cost estimates, prompt/completion content in a structured way, or trace visualization.

We need tooling that makes it easy to **understand and audit AI agent queries to LLMs** — what models are being called, how many tokens are consumed, what prompts are sent, what completions are returned, and how agent sessions flow.

## Evaluated Solutions

### 1. Langfuse (Recommended)

- **Repository**: github.com/langfuse/langfuse (21k+ GitHub stars)
- **License**: MIT (core), enterprise features separate
- **Self-hosted**: Yes — Docker Compose, Kubernetes (Helm). Uses ClickHouse + S3 + Redis.
- **API**: REST `/api/public/ingestion` (batch events) + OTLP endpoint `/api/public/otel/v1/traces`
- **Go SDK**: No official SDK, but REST API is straightforward to call from Go
- **Auth**: Basic Auth with public key + secret key
- **UI**: Full-featured web UI with trace viewer, generation details, token/cost dashboards, prompt management, session tracking, evaluation tools
- **LLM-specific**: First-class support for generations (model, input/output, tokens, cost, latency), traces (multi-step agent flows), and sessions
- **Maturity**: Very mature, YC W23, acquired by ClickHouse, battle-tested at scale

**Fit for Firewall4AI**: Excellent. The proxy already captures request/response bodies — we parse LLM API payloads and send structured generation events to Langfuse via its REST API. Self-hostable for air-gapped environments. The Langfuse UI provides exactly the visualization needed for auditing agent-to-LLM interactions.

### 2. OpenLIT

- **Repository**: github.com/openlit/openlit
- **License**: Apache 2.0
- **Self-hosted**: Yes — uses ClickHouse backend
- **API**: OpenTelemetry native (OTLP/HTTP, OTLP/gRPC)
- **Go SDK**: Yes (vendor-neutral OTel SDK)
- **UI**: Custom dashboards, cost tracking, evaluations
- **LLM-specific**: Auto-instrumentation for 50+ LLM providers, GPU monitoring, guardrails
- **Maturity**: Active development, smaller community than Langfuse

**Fit for Firewall4AI**: Good for teams with existing OTel stacks. However, OpenLIT's value is primarily in client-side auto-instrumentation (wrapping SDK calls), not proxy-side interception. We'd be sending custom OTel spans anyway, so Langfuse's richer LLM-focused UI wins.

### 3. OpenTelemetry GenAI Semantic Conventions (Direct OTel)

- **Standard**: OpenTelemetry GenAI SIG semantic conventions
- **Backend**: Any OTel-compatible backend (Jaeger, Grafana Tempo, etc.)
- **Go SDK**: Official Go OTel SDK available
- **UI**: Depends on backend (Jaeger UI, Grafana, etc.)
- **LLM-specific**: Defines standard attributes (`gen_ai.system`, `gen_ai.request.model`, `gen_ai.usage.*`) but visualization depends on backend

**Fit for Firewall4AI**: Too generic. Standard tracing backends don't have LLM-specific dashboards (token costs, prompt/completion viewing). Would require building custom dashboards. Better as a future export format alongside Langfuse.

### 4. Lunary

- **License**: Apache 2.0 (core)
- **Self-hosted**: Yes — Docker
- **Focus**: RAG pipelines and chatbots
- **Maturity**: Smaller community, limited features vs Langfuse

**Fit for Firewall4AI**: Adequate but less feature-rich than Langfuse for our use case.

## Decision: Langfuse

**Langfuse is the best fit** because:
1. **Self-hostable** with Docker — critical for isolated VM environments
2. **REST API** for ingestion — no Go SDK needed, just HTTP calls
3. **Rich LLM-focused UI** — trace viewer, generation details, token/cost dashboards
4. **Generation data model** matches what we can extract from proxied LLM requests
5. **Session/trace hierarchy** maps well to agent skill sessions
6. **MIT licensed** — compatible with any deployment
7. **Most mature and widely adopted** open-source LLM observability platform

## Integration Architecture

### How It Works

```
Agent VM                    Firewall4AI Proxy                    LLM API
   |                              |                                |
   |--- POST /v1/chat/completions |                                |
   |      (via transparent proxy) |                                |
   |                              |--- Forward request ----------->|
   |                              |<-- Response (with tokens) -----|
   |<---- Response ---------------|                                |
   |                              |                                |
   |                              |--- Parse LLM req/resp -------->|
   |                              |--- POST /api/public/ingestion  |
   |                              |     to Langfuse (async)        |
   |                              |                                |
                                  Langfuse (self-hosted)
                                  - Trace viewer
                                  - Token/cost dashboards
                                  - Prompt audit logs
```

### Key Design Points

1. **LLM API Detection**: Detect requests to known LLM API endpoints by host+path pattern:
   - `api.openai.com/v1/chat/completions` (OpenAI)
   - `api.openai.com/v1/responses` (OpenAI Responses API)
   - `api.anthropic.com/v1/messages` (Anthropic)
   - `generativelanguage.googleapis.com` (Google Gemini)
   - `api.mistral.ai/v1/chat/completions` (Mistral)
   - Extensible via configuration

2. **Request/Response Parsing**: When full logging is enabled and the request matches an LLM endpoint, parse the JSON to extract:
   - Model name (from request body)
   - Input messages/prompt (from request body)
   - Output completion (from response body)
   - Token usage (from response body)
   - Latency (already captured)

3. **Async Forwarding**: Send generation events to Langfuse asynchronously (goroutine + buffered channel) so proxy latency is not affected.

4. **Session Mapping**: Use the agent's skill ID as the Langfuse session ID, creating natural grouping of an agent's LLM calls.

5. **Source IP as User**: Map the source VM IP to the Langfuse user ID for per-VM filtering.

6. **Configuration**: New `observability` section in config.json:
   ```json
   {
     "observability": {
       "enabled": false,
       "langfuse_host": "http://localhost:3000",
       "langfuse_public_key": "",
       "langfuse_secret_key": "",
       "llm_endpoints": [
         {"host": "api.openai.com", "path_prefix": "/v1/", "provider": "openai"},
         {"host": "api.anthropic.com", "path_prefix": "/v1/", "provider": "anthropic"}
       ]
     }
   }
   ```

7. **No extra dependencies**: Uses Go stdlib `net/http` + `encoding/json` to call Langfuse REST API.

### New Packages

- `internal/observability/` — Core observability module:
  - `llmdetect.go` — Detect LLM API requests and parse provider-specific formats
  - `langfuse.go` — Langfuse REST API client with async batching
  - `observability.go` — Main orchestrator wired into proxy

### Supported LLM Providers (Initial)

| Provider | Request Format | Token Fields |
|----------|---------------|--------------|
| OpenAI | `model`, `messages[]` | `usage.prompt_tokens`, `usage.completion_tokens` |
| Anthropic | `model`, `messages[]` | `usage.input_tokens`, `usage.output_tokens` |
| Google Gemini | `model` in URL | `usageMetadata.promptTokenCount`, `usageMetadata.candidatesTokenCount` |
| Mistral | Same as OpenAI | Same as OpenAI |
| Azure OpenAI | Same as OpenAI | Same as OpenAI |
