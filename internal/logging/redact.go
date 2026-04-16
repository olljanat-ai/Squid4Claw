package logging

import (
	"encoding/json"
	"net/url"
	"strings"
)

// RedactedPlaceholder is the string substituted for any header value, body
// field, or credential value that logging must not expose.
const RedactedPlaceholder = "***REDACTED***"

// sensitiveHeaders lists HTTP header names (lowercased) whose values are
// always redacted in stored log entries. Includes credentials Firewall4AI
// itself injects via credentials.InjectForRequest so that they do not leak
// through the log viewer or persisted JSONL on disk.
var sensitiveHeaders = map[string]struct{}{
	"authorization":       {},
	"proxy-authorization": {},
	"cookie":              {},
	"set-cookie":          {},
	"x-api-key":           {},
	"x-auth-token":        {},
	"x-access-token":      {},
	"api-key":             {},
}

// sensitiveBodyFields lists JSON object keys and form field names
// (lowercased) whose values are redacted in captured request/response bodies.
var sensitiveBodyFields = map[string]struct{}{
	"password":      {},
	"passwd":        {},
	"token":         {},
	"secret":        {},
	"api_key":       {},
	"apikey":        {},
	"access_token":  {},
	"refresh_token": {},
	"id_token":      {},
	"authorization": {},
	"client_secret": {},
	"private_key":   {},
}

// IsSensitiveHeader reports whether the named header's value should never be
// stored in plaintext in log entries.
func IsSensitiveHeader(name string) bool {
	_, ok := sensitiveHeaders[strings.ToLower(name)]
	return ok
}

// RedactHeaders returns a copy of h with values of sensitive headers
// replaced by RedactedPlaceholder. Non-sensitive headers are copied
// unchanged. Returns nil for a nil input.
func RedactHeaders(h map[string][]string) map[string][]string {
	if h == nil {
		return nil
	}
	out := make(map[string][]string, len(h))
	for k, vals := range h {
		if IsSensitiveHeader(k) {
			red := make([]string, len(vals))
			for i := range red {
				red[i] = RedactedPlaceholder
			}
			out[k] = red
			continue
		}
		out[k] = append([]string(nil), vals...)
	}
	return out
}

// RedactBody best-effort redacts known secret fields from a captured body.
// It understands JSON (objects, arrays, nested) and application/x-www-form-
// urlencoded payloads. For any other content type the body is returned
// unchanged (we prefer false-negatives over corrupting unknown payloads).
func RedactBody(contentType, body string) string {
	if body == "" {
		return body
	}
	ct := strings.ToLower(contentType)
	switch {
	case strings.Contains(ct, "application/json"), strings.Contains(ct, "+json"):
		return redactJSONBody(body)
	case strings.Contains(ct, "application/x-www-form-urlencoded"):
		return redactFormBody(body)
	default:
		return body
	}
}

func redactJSONBody(body string) string {
	// Strip truncation marker so the decoder doesn't fail on it; reattach later.
	const marker = "... (truncated)"
	trimmed := body
	truncated := false
	if strings.HasSuffix(trimmed, marker) {
		trimmed = strings.TrimSuffix(trimmed, marker)
		truncated = true
	}
	var v any
	if err := json.Unmarshal([]byte(trimmed), &v); err != nil {
		return body
	}
	redactJSONValue(v)
	out, err := json.Marshal(v)
	if err != nil {
		return body
	}
	if truncated {
		return string(out) + marker
	}
	return string(out)
}

func redactJSONValue(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if _, bad := sensitiveBodyFields[strings.ToLower(k)]; bad {
				t[k] = RedactedPlaceholder
				continue
			}
			redactJSONValue(child)
		}
	case []any:
		for i := range t {
			redactJSONValue(t[i])
		}
	}
}

func redactFormBody(body string) string {
	values, err := url.ParseQuery(body)
	if err != nil {
		return body
	}
	changed := false
	for k, vals := range values {
		if _, bad := sensitiveBodyFields[strings.ToLower(k)]; bad {
			for i := range vals {
				vals[i] = RedactedPlaceholder
			}
			values[k] = vals
			changed = true
		}
	}
	if !changed {
		return body
	}
	return values.Encode()
}

// RedactFullDetail redacts sensitive headers and known secret body fields
// in place. Safe to call with a nil pointer. Callers should invoke this
// before the FullDetail is committed to storage or returned to clients.
func RedactFullDetail(fd *FullDetail) {
	if fd == nil {
		return
	}
	reqCT := headerValue(fd.RequestHeaders, "Content-Type")
	respCT := headerValue(fd.ResponseHeaders, "Content-Type")

	fd.RequestHeaders = RedactHeaders(fd.RequestHeaders)
	fd.InjectedHeaders = RedactHeaders(fd.InjectedHeaders)
	fd.ResponseHeaders = RedactHeaders(fd.ResponseHeaders)
	fd.RequestBody = RedactBody(reqCT, fd.RequestBody)
	fd.ResponseBody = RedactBody(respCT, fd.ResponseBody)
}

func headerValue(h map[string][]string, name string) string {
	lower := strings.ToLower(name)
	for k, v := range h {
		if strings.ToLower(k) == lower && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}
