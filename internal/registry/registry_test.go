package registry

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/olljanat-ai/firewall4ai/internal/approval"
	"github.com/olljanat-ai/firewall4ai/internal/auth"
	"github.com/olljanat-ai/firewall4ai/internal/config"
	proxylog "github.com/olljanat-ai/firewall4ai/internal/logging"
)

func setupProxy(t *testing.T, upstream *httptest.Server) (*Proxy, *approval.Manager) {
	t.Helper()
	mgr := approval.NewManager()
	skills := auth.NewSkillStore()
	logger := proxylog.NewLogger(100)
	p := New(config.RegistryConfig{
		Name:     "docker.io",
		Upstream: upstream.URL,
		Port:     5000,
	}, mgr, skills, logger)
	p.ApprovalTimeout = 50 * time.Millisecond
	return p, mgr
}

func TestVersionCheck(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	p, _ := setupProxy(t, upstream)

	req := httptest.NewRequest("GET", "/v2/", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Docker-Distribution-API-Version"), "registry/2.0") {
		t.Error("missing Docker-Distribution-API-Version header")
	}
	var body map[string]string
	json.NewDecoder(w.Body).Decode(&body)
	if body["name"] != "Firewall4AI Registry Mirror" {
		t.Errorf("unexpected body: %v", body)
	}
}

func TestManifest_Denied(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	p, _ := setupProxy(t, upstream)

	req := httptest.NewRequest("GET", "/v2/library/ubuntu/manifests/latest", nil)
	req.RemoteAddr = "10.255.255.10:12345"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestManifest_PreApproved(t *testing.T) {
	manifestBody := `{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json"}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
		w.Header().Set("Docker-Content-Digest", "sha256:abc123")
		w.Write([]byte(manifestBody))
	}))
	defer upstream.Close()
	p, mgr := setupProxy(t, upstream)

	// Pre-approve the image.
	mgr.Decide("docker.io/library/ubuntu:latest", "", "", approval.StatusApproved, "test")

	req := httptest.NewRequest("GET", "/v2/library/ubuntu/manifests/latest", nil)
	req.RemoteAddr = "10.255.255.10:12345"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != manifestBody {
		t.Errorf("unexpected body: %s", w.Body.String())
	}
}

func TestManifest_WildcardApproval(t *testing.T) {
	manifestBody := `{"schemaVersion":2}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(manifestBody))
	}))
	defer upstream.Close()
	p, mgr := setupProxy(t, upstream)

	// Approve wildcard pattern.
	mgr.Decide("docker.io/library/*", "", "", approval.StatusApproved, "all official images")

	req := httptest.NewRequest("GET", "/v2/library/ubuntu/manifests/latest", nil)
	req.RemoteAddr = "10.255.255.10:12345"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestManifest_TagWildcard(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	}))
	defer upstream.Close()
	p, mgr := setupProxy(t, upstream)

	mgr.Decide("docker.io/library/ubuntu:*", "", "", approval.StatusApproved, "any tag")

	req := httptest.NewRequest("GET", "/v2/library/ubuntu/manifests/22.04", nil)
	req.RemoteAddr = "10.255.255.10:12345"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestManifest_VMSpecific(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	}))
	defer upstream.Close()
	p, mgr := setupProxy(t, upstream)

	// Approve only for specific VM.
	mgr.Decide("docker.io/library/ubuntu:latest", "", "10.255.255.10", approval.StatusApproved, "")

	// Allowed VM.
	req := httptest.NewRequest("GET", "/v2/library/ubuntu/manifests/latest", nil)
	req.RemoteAddr = "10.255.255.10:12345"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for approved VM, got %d", w.Code)
	}

	// Different VM - should be denied (timeout).
	req2 := httptest.NewRequest("GET", "/v2/library/ubuntu/manifests/latest", nil)
	req2.RemoteAddr = "10.255.255.20:12345"
	w2 := httptest.NewRecorder()
	p.ServeHTTP(w2, req2)
	if w2.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for other VM, got %d", w2.Code)
	}
}

func TestBlob_RepoApproved(t *testing.T) {
	blobData := "fake-layer-data"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write([]byte(blobData))
	}))
	defer upstream.Close()
	p, mgr := setupProxy(t, upstream)

	// Approve an image in the repo.
	mgr.Decide("docker.io/library/ubuntu:latest", "", "", approval.StatusApproved, "")

	req := httptest.NewRequest("GET", "/v2/library/ubuntu/blobs/sha256:abc123def456", nil)
	req.RemoteAddr = "10.255.255.10:12345"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != blobData {
		t.Errorf("unexpected body: %s", w.Body.String())
	}
}

func TestBlob_RepoNotApproved(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	p, _ := setupProxy(t, upstream)

	req := httptest.NewRequest("GET", "/v2/library/ubuntu/blobs/sha256:abc123", nil)
	req.RemoteAddr = "10.255.255.10:12345"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestUpstreamAuth_BearerToken(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token":      "test-token-123",
			"expires_in": 300,
		})
	}))
	defer authServer.Close()

	callCount := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.Header.Get("Authorization") == "Bearer test-token-123" {
			w.Write([]byte(`{"schemaVersion":2}`))
			return
		}
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="`+authServer.URL+`/token",service="test-registry",scope="repository:library/ubuntu:pull"`)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"errors":[{"code":"UNAUTHORIZED"}]}`))
	}))
	defer upstream.Close()

	p, mgr := setupProxy(t, upstream)
	mgr.Decide("docker.io/library/ubuntu:latest", "", "", approval.StatusApproved, "")

	req := httptest.NewRequest("GET", "/v2/library/ubuntu/manifests/latest", nil)
	req.RemoteAddr = "10.255.255.10:12345"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	if callCount != 2 {
		t.Errorf("expected 2 upstream calls (401 then retry), got %d", callCount)
	}
}

func TestUpstreamRedirect(t *testing.T) {
	cdnData := "redirected-blob-data"
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(cdnData))
	}))
	defer cdn.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/blobs/") {
			http.Redirect(w, r, cdn.URL+"/blob-data", http.StatusTemporaryRedirect)
			return
		}
		w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	p, mgr := setupProxy(t, upstream)
	mgr.Decide("docker.io/library/nginx:latest", "", "", approval.StatusApproved, "")

	req := httptest.NewRequest("GET", "/v2/library/nginx/blobs/sha256:redirect123", nil)
	req.RemoteAddr = "10.255.255.10:12345"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body, _ := io.ReadAll(w.Result().Body)
	if string(body) != cdnData {
		t.Errorf("expected CDN data, got: %s", string(body))
	}
}

func TestParsePath(t *testing.T) {
	tests := []struct {
		path     string
		name     string
		ref      string
		pathType string
		ok       bool
	}{
		{"/v2/library/ubuntu/manifests/latest", "library/ubuntu", "latest", "manifests", true},
		{"/v2/library/ubuntu/manifests/sha256:abc123", "library/ubuntu", "sha256:abc123", "manifests", true},
		{"/v2/library/ubuntu/blobs/sha256:abc123", "library/ubuntu", "sha256:abc123", "blobs", true},
		{"/v2/myorg/myrepo/manifests/v1.0", "myorg/myrepo", "v1.0", "manifests", true},
		{"/v2/a/b/c/manifests/latest", "a/b/c", "latest", "manifests", true},
		{"/v2/", "", "", "", false},
		{"/v2/library/ubuntu", "", "", "", false},
		{"/v1/library/ubuntu/manifests/latest", "", "", "", false},
		{"/v2//manifests/latest", "", "", "", false},
		{"/v2/library/ubuntu/manifests/", "", "", "", false},
	}
	for _, tt := range tests {
		name, ref, pathType, ok := parsePath(tt.path)
		if ok != tt.ok || name != tt.name || ref != tt.ref || pathType != tt.pathType {
			t.Errorf("parsePath(%q) = (%q, %q, %q, %v), want (%q, %q, %q, %v)",
				tt.path, name, ref, pathType, ok, tt.name, tt.ref, tt.pathType, tt.ok)
		}
	}
}

func TestMatchImageRef(t *testing.T) {
	tests := []struct {
		pattern  string
		imageRef string
		want     bool
	}{
		// Exact match.
		{"docker.io/library/ubuntu:latest", "docker.io/library/ubuntu:latest", true},
		{"docker.io/library/ubuntu:latest", "docker.io/library/ubuntu:22.04", false},

		// Suffix wildcard.
		{"docker.io/library/*", "docker.io/library/ubuntu:latest", true},
		{"docker.io/library/*", "docker.io/library/nginx:1.25", true},
		{"docker.io/library/*", "docker.io/myorg/myrepo:latest", false},
		{"docker.io/*", "docker.io/library/ubuntu:latest", true},
		{"ghcr.io/org/*", "ghcr.io/org/repo:v1", true},
		{"ghcr.io/org/*", "ghcr.io/other/repo:v1", false},

		// Tag wildcard.
		{"docker.io/library/ubuntu:*", "docker.io/library/ubuntu:latest", true},
		{"docker.io/library/ubuntu:*", "docker.io/library/ubuntu:22.04", true},
		{"docker.io/library/ubuntu:*", "docker.io/library/nginx:latest", false},

		// Digest wildcard.
		{"docker.io/library/ubuntu@*", "docker.io/library/ubuntu@sha256:abc123", true},

		// No match.
		{"docker.io/library/ubuntu:latest", "ghcr.io/library/ubuntu:latest", false},
	}
	for _, tt := range tests {
		got := MatchImageRef(tt.pattern, tt.imageRef)
		if got != tt.want {
			t.Errorf("MatchImageRef(%q, %q) = %v, want %v", tt.pattern, tt.imageRef, got, tt.want)
		}
	}
}

func TestParseImageRef(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()

	// Docker Hub proxy.
	p, _ := setupProxy(t, upstream)

	tests := []struct {
		name      string
		reference string
		want      string
	}{
		{"library/ubuntu", "latest", "docker.io/library/ubuntu:latest"},
		{"ubuntu", "latest", "docker.io/library/ubuntu:latest"}, // auto library/ prefix
		{"myorg/myrepo", "v1.0", "docker.io/myorg/myrepo:v1.0"},
		{"library/ubuntu", "sha256:abc123", "docker.io/library/ubuntu@sha256:abc123"},
	}
	for _, tt := range tests {
		got := p.parseImageRef(tt.name, tt.reference)
		if got != tt.want {
			t.Errorf("parseImageRef(%q, %q) = %q, want %q", tt.name, tt.reference, got, tt.want)
		}
	}

	// Non-Docker Hub proxy.
	p2 := New(config.RegistryConfig{
		Name:     "ghcr.io",
		Upstream: upstream.URL,
		Port:     5001,
	}, approval.NewManager(), auth.NewSkillStore(), nil)

	got := p2.parseImageRef("myorg/myrepo", "v1.0")
	if got != "ghcr.io/myorg/myrepo:v1.0" {
		t.Errorf("ghcr.io parseImageRef = %q", got)
	}
}

func TestParseBearerParams(t *testing.T) {
	header := `Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/ubuntu:pull"`
	params := parseBearerParams(header)

	if params["realm"] != "https://auth.docker.io/token" {
		t.Errorf("realm = %q", params["realm"])
	}
	if params["service"] != "registry.docker.io" {
		t.Errorf("service = %q", params["service"])
	}
	if params["scope"] != "repository:library/ubuntu:pull" {
		t.Errorf("scope = %q", params["scope"])
	}
}

func TestDockerHubLibraryNormalization(t *testing.T) {
	// When pulling "ubuntu" (no org prefix), Docker Hub uses "library/ubuntu".
	manifestBody := `{"schemaVersion":2}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(manifestBody))
	}))
	defer upstream.Close()
	p, mgr := setupProxy(t, upstream)

	// Approve with the normalized name.
	mgr.Decide("docker.io/library/ubuntu:latest", "", "", approval.StatusApproved, "")

	// Request comes with just "ubuntu" (no library/ prefix) - but the URL path
	// from Docker client would actually be /v2/library/ubuntu/manifests/latest
	// since Docker normalizes this before sending to the mirror.
	req := httptest.NewRequest("GET", "/v2/library/ubuntu/manifests/latest", nil)
	req.RemoteAddr = "10.255.255.10:12345"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestNotFound(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	p, _ := setupProxy(t, upstream)

	paths := []string{"/v2/foo", "/v1/library/ubuntu/manifests/latest", "/other"}
	for _, path := range paths {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("path %s: expected 404, got %d", path, w.Code)
		}
	}
}
