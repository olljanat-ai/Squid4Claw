package logging

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRedactHeaders_RedactsSensitive(t *testing.T) {
	in := map[string][]string{
		"Authorization":       {"Bearer super-secret-token-xyz"},
		"Proxy-Authorization": {"Basic dXNlcjpwYXNz"},
		"Cookie":              {"session=abc123; other=ok"},
		"X-Api-Key":           {"live_sk_XYZ"},
		"Content-Type":        {"application/json"},
		"User-Agent":          {"curl/8.0"},
	}
	out := RedactHeaders(in)

	for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie", "X-Api-Key"} {
		if got := out[name][0]; got != RedactedPlaceholder {
			t.Errorf("%s not redacted: %q", name, got)
		}
	}
	if got := out["Content-Type"][0]; got != "application/json" {
		t.Errorf("Content-Type unexpectedly altered: %q", got)
	}
	if got := out["User-Agent"][0]; got != "curl/8.0" {
		t.Errorf("User-Agent unexpectedly altered: %q", got)
	}
}

func TestRedactHeaders_CaseInsensitive(t *testing.T) {
	in := map[string][]string{"authorization": {"Bearer xyz"}}
	out := RedactHeaders(in)
	if out["authorization"][0] != RedactedPlaceholder {
		t.Errorf("lowercase header not redacted")
	}
}

func TestRedactHeaders_CopiesNonSensitive(t *testing.T) {
	in := map[string][]string{"X-Trace-Id": {"abc"}}
	out := RedactHeaders(in)
	out["X-Trace-Id"][0] = "mutated"
	if in["X-Trace-Id"][0] != "abc" {
		t.Errorf("input mutated through shared backing array")
	}
}

func TestRedactHeaders_Nil(t *testing.T) {
	if got := RedactHeaders(nil); got != nil {
		t.Errorf("nil in should produce nil out, got %v", got)
	}
}

func TestRedactBody_JSONObject(t *testing.T) {
	body := `{"user":"alice","password":"hunter2","token":"abc","nested":{"api_key":"k1","ok":"v"}}`
	out := RedactBody("application/json", body)

	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("redacted body is not valid JSON: %v", err)
	}
	if m["password"] != RedactedPlaceholder {
		t.Errorf("password not redacted: %v", m["password"])
	}
	if m["token"] != RedactedPlaceholder {
		t.Errorf("token not redacted: %v", m["token"])
	}
	nested := m["nested"].(map[string]any)
	if nested["api_key"] != RedactedPlaceholder {
		t.Errorf("nested api_key not redacted: %v", nested["api_key"])
	}
	if nested["ok"] != "v" {
		t.Errorf("non-sensitive nested field altered: %v", nested["ok"])
	}
	if m["user"] != "alice" {
		t.Errorf("non-sensitive field altered: %v", m["user"])
	}
}

func TestRedactBody_JSONArrayOfObjects(t *testing.T) {
	body := `[{"password":"p1"},{"password":"p2"}]`
	out := RedactBody("application/json", body)
	if strings.Contains(out, "p1") || strings.Contains(out, "p2") {
		t.Errorf("plaintext password leaked through array redaction: %s", out)
	}
}

func TestRedactBody_JSONInvalidPassThrough(t *testing.T) {
	body := `not json { password: "p" `
	out := RedactBody("application/json", body)
	if out != body {
		t.Errorf("invalid JSON should pass through unchanged, got %q", out)
	}
}

func TestRedactBody_Form(t *testing.T) {
	body := "user=alice&password=hunter2&token=xyz&keep=ok"
	out := RedactBody("application/x-www-form-urlencoded", body)
	if strings.Contains(out, "hunter2") {
		t.Errorf("password leaked: %s", out)
	}
	if strings.Contains(out, "xyz") {
		t.Errorf("token leaked: %s", out)
	}
	if !strings.Contains(out, "user=alice") {
		t.Errorf("non-sensitive user field missing: %s", out)
	}
	if !strings.Contains(out, "keep=ok") {
		t.Errorf("non-sensitive keep field missing: %s", out)
	}
}

func TestRedactBody_UnknownContentType(t *testing.T) {
	body := `password=hunter2`
	out := RedactBody("application/octet-stream", body)
	if out != body {
		t.Errorf("unknown content-type should pass through, got %q", out)
	}
}

func TestRedactFullDetail_InPlace(t *testing.T) {
	fd := &FullDetail{
		RequestHeaders: map[string][]string{
			"Authorization": {"Bearer live_token_123"},
			"Content-Type":  {"application/json"},
		},
		InjectedHeaders: map[string][]string{
			"Authorization": {"Bearer injected_credential"},
		},
		RequestBody: `{"password":"hunter2","keep":"ok"}`,
		ResponseHeaders: map[string][]string{
			"Set-Cookie":   {"session=abc123; Path=/"},
			"Content-Type": {"application/json"},
		},
		ResponseBody: `{"access_token":"leaked","user":"alice"}`,
	}
	RedactFullDetail(fd)

	blob, _ := json.Marshal(fd)
	s := string(blob)
	for _, secret := range []string{
		"live_token_123",
		"injected_credential",
		"hunter2",
		"abc123",
		"leaked",
	} {
		if strings.Contains(s, secret) {
			t.Errorf("secret %q leaked into FullDetail: %s", secret, s)
		}
	}
	if !strings.Contains(s, "alice") {
		t.Errorf("non-sensitive user field missing from redacted output")
	}
}

func TestLogger_AddRedactsFullDetail(t *testing.T) {
	l := NewLogger(10)
	e := l.Add(Entry{
		Method: "POST",
		Host:   "example.com",
		Status: "allowed",
		FullDetail: &FullDetail{
			RequestHeaders: map[string][]string{"Authorization": {"Bearer xyz"}},
			RequestBody:    "",
		},
	})
	if got := e.FullDetail.RequestHeaders["Authorization"][0]; got != RedactedPlaceholder {
		t.Errorf("Authorization not redacted in stored entry: %q", got)
	}
	stored, ok := l.GetByID(e.ID)
	if !ok {
		t.Fatal("stored entry not found")
	}
	if got := stored.FullDetail.RequestHeaders["Authorization"][0]; got != RedactedPlaceholder {
		t.Errorf("Authorization not redacted when fetched back: %q", got)
	}
}

func TestRedactFullDetail_NilSafe(t *testing.T) {
	RedactFullDetail(nil) // must not panic
}
