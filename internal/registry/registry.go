// Package registry implements a Docker Registry V2 API pull-through proxy
// with image-level approval gates. Each configured upstream registry gets
// its own HTTPS listener. Manifest requests trigger approval checks while
// blob requests are allowed at the repository level.
package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/olljanat-ai/firewall4ai/internal/approval"
	"github.com/olljanat-ai/firewall4ai/internal/auth"
	"github.com/olljanat-ai/firewall4ai/internal/config"
	proxylog "github.com/olljanat-ai/firewall4ai/internal/logging"
)

const approvalTimeout = 5 * time.Minute

// Proxy handles Docker Registry V2 API requests for one upstream registry.
type Proxy struct {
	Config          config.RegistryConfig
	Approvals       *approval.Manager
	Skills          *auth.SkillStore
	Logger          *proxylog.Logger
	Transport       http.RoundTripper
	ApprovalTimeout time.Duration

	mu         sync.RWMutex
	tokenCache map[string]*cachedToken
}

// cachedToken holds a Bearer token for an upstream scope with expiry.
type cachedToken struct {
	Token     string
	ExpiresAt time.Time
}

// New creates a new registry Proxy for the given upstream.
func New(cfg config.RegistryConfig, approvals *approval.Manager, skills *auth.SkillStore, logger *proxylog.Logger) *Proxy {
	return &Proxy{
		Config:          cfg,
		Approvals:       approvals,
		Skills:          skills,
		Logger:          logger,
		ApprovalTimeout: approvalTimeout,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConns:          50,
			IdleConnTimeout:       90 * time.Second,
		},
		tokenCache: make(map[string]*cachedToken),
	}
}

// ServeHTTP routes Docker Registry V2 API requests.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// /v2/ version check
	if path == "/v2/" || path == "/v2" {
		p.handleVersionCheck(w, r)
		return
	}

	// Parse registry V2 path: /v2/{name...}/manifests/{ref} or /v2/{name...}/blobs/{digest}
	name, ref, pathType, ok := parsePath(path)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	switch pathType {
	case "manifests":
		p.handleManifest(w, r, name, ref)
	case "blobs":
		p.handleBlob(w, r, name, ref)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// handleVersionCheck responds to /v2/ API version check.
func (p *Proxy) handleVersionCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"name": "Firewall4AI Registry Mirror"})
}

// handleManifest checks image approval and proxies manifest requests.
func (p *Proxy) handleManifest(w http.ResponseWriter, r *http.Request, name, reference string) {
	imageRef := p.parseImageRef(name, reference)
	sourceIP := extractSourceIP(r.RemoteAddr)
	skill := p.authenticateOptional(r)
	skillID := ""
	if skill != nil {
		skillID = skill.ID
	}

	start := time.Now()
	status := p.checkImageApproval(imageRef, skillID, sourceIP)

	if status == approval.StatusDenied {
		p.logRequest(skillID, r.Method, p.Config.Name, "/v2/"+name+"/manifests/"+reference, "denied", "image not approved: "+imageRef, time.Since(start))
		http.Error(w, fmt.Sprintf(`{"errors":[{"code":"DENIED","message":"image not approved: %s"}]}`, imageRef), http.StatusForbidden)
		return
	}

	p.logRequest(skillID, r.Method, p.Config.Name, "/v2/"+name+"/manifests/"+reference, "allowed", imageRef, time.Since(start))

	// Proxy to upstream.
	upstreamPath := "/v2/" + name + "/manifests/" + reference
	if err := p.proxyUpstream(w, r.Method, upstreamPath, r.Header); err != nil {
		http.Error(w, `{"errors":[{"code":"UPSTREAM_ERROR","message":"upstream error"}]}`, http.StatusBadGateway)
	}
}

// handleBlob checks repo-level approval and proxies blob requests.
func (p *Proxy) handleBlob(w http.ResponseWriter, r *http.Request, name, digest string) {
	sourceIP := extractSourceIP(r.RemoteAddr)
	repo := p.Config.Name + "/" + name

	if !p.checkRepoApproval(repo, sourceIP) {
		http.Error(w, `{"errors":[{"code":"DENIED","message":"repository not approved"}]}`, http.StatusForbidden)
		return
	}

	upstreamPath := "/v2/" + name + "/blobs/" + digest
	if err := p.proxyUpstream(w, r.Method, upstreamPath, r.Header); err != nil {
		http.Error(w, `{"errors":[{"code":"UPSTREAM_ERROR","message":"upstream error"}]}`, http.StatusBadGateway)
	}
}

// checkImageApproval performs the three-level approval check for an image reference.
// Checks broadest-first: global -> VM-specific -> skill-specific.
func (p *Proxy) checkImageApproval(imageRef, skillID, sourceIP string) approval.Status {
	// 1. Check global approvals (skillID="", sourceIP="") with wildcards.
	if status, ok := p.Approvals.CheckExistingWithMatcher(imageRef, "", "", MatchImageRef); ok {
		if status == approval.StatusApproved {
			return approval.StatusApproved
		}
		if status == approval.StatusDenied {
			return approval.StatusDenied
		}
	}

	// 2. Check VM-specific approvals (skillID="", sourceIP set).
	if sourceIP != "" {
		if status, ok := p.Approvals.CheckExistingWithMatcher(imageRef, "", sourceIP, MatchImageRef); ok {
			if status == approval.StatusApproved {
				return approval.StatusApproved
			}
			if status == approval.StatusDenied {
				return approval.StatusDenied
			}
		}
	}

	// 3. Check skill-specific approvals.
	if skillID != "" {
		if status, ok := p.Approvals.CheckExistingWithMatcher(imageRef, skillID, "", MatchImageRef); ok {
			if status == approval.StatusApproved {
				return approval.StatusApproved
			}
			if status == approval.StatusDenied {
				return approval.StatusDenied
			}
		}
	}

	// No existing approval; register pending and wait for admin decision.
	p.Approvals.Check(imageRef, skillID, sourceIP)
	return p.Approvals.WaitForDecision(imageRef, skillID, sourceIP, p.ApprovalTimeout)
}

// checkRepoApproval returns true if any image in the repository has been approved.
func (p *Proxy) checkRepoApproval(repo, sourceIP string) bool {
	repoPrefix := repo + ":"
	repoWild := repo + "/*"
	for _, a := range p.Approvals.ListAll() {
		if a.Status != approval.StatusApproved {
			continue
		}
		// Match: exact repo (without tag), repo prefix "repo:", or repo wildcard.
		if strings.HasPrefix(a.Host, repoPrefix) || a.Host == repo || MatchImageRef(a.Host, repoWild) {
			return true
		}
	}
	return false
}

// proxyUpstream makes a request to the upstream registry, handling Bearer
// token auth and CDN redirects, streaming the response body to the client.
func (p *Proxy) proxyUpstream(w http.ResponseWriter, method, path string, clientHeaders http.Header) error {
	upstreamURL := strings.TrimRight(p.Config.Upstream, "/") + path

	req, err := http.NewRequest(method, upstreamURL, nil)
	if err != nil {
		return err
	}

	// Copy Accept headers (important for manifest media types).
	for _, v := range clientHeaders.Values("Accept") {
		req.Header.Add("Accept", v)
	}

	// Use client that does not follow redirects automatically.
	client := &http.Client{
		Transport: p.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Handle 401 -> fetch Bearer token -> retry.
	if resp.StatusCode == http.StatusUnauthorized {
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		if strings.HasPrefix(wwwAuth, "Bearer ") {
			// Drain the 401 response body.
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			token, err := p.fetchBearerToken(wwwAuth)
			if err != nil {
				return fmt.Errorf("fetch bearer token: %w", err)
			}

			req2, err := http.NewRequest(method, upstreamURL, nil)
			if err != nil {
				return err
			}
			for _, v := range clientHeaders.Values("Accept") {
				req2.Header.Add("Accept", v)
			}
			req2.Header.Set("Authorization", "Bearer "+token)

			resp2, err := client.Do(req2)
			if err != nil {
				return err
			}
			defer resp2.Body.Close()

			return p.streamResponse(w, resp2)
		}
	}

	// Handle redirects (follow ourselves since agent VMs can't reach CDNs).
	if resp.StatusCode == http.StatusTemporaryRedirect ||
		resp.StatusCode == http.StatusFound ||
		resp.StatusCode == http.StatusMovedPermanently ||
		resp.StatusCode == http.StatusSeeOther {
		location := resp.Header.Get("Location")
		if location != "" {
			// Drain the redirect response body.
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			redirectReq, err := http.NewRequest(method, location, nil)
			if err != nil {
				return err
			}
			redirectResp, err := p.Transport.RoundTrip(redirectReq)
			if err != nil {
				return err
			}
			defer redirectResp.Body.Close()
			return p.streamResponse(w, redirectResp)
		}
	}

	return p.streamResponse(w, resp)
}

// streamResponse copies the upstream response headers and body to the client.
func (p *Proxy) streamResponse(w http.ResponseWriter, resp *http.Response) error {
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Use Flusher for streaming large blobs.
	if flusher, ok := w.(http.Flusher); ok {
		buf := make([]byte, 32*1024)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
				flusher.Flush()
			}
			if err != nil {
				if err == io.EOF {
					break
				}
				return err
			}
		}
		return nil
	}

	_, err := io.Copy(w, resp.Body)
	return err
}

// fetchBearerToken handles the Docker registry auth flow:
// Parse WWW-Authenticate -> request token -> cache it.
func (p *Proxy) fetchBearerToken(wwwAuth string) (string, error) {
	params := parseBearerParams(wwwAuth)
	realm := params["realm"]
	service := params["service"]
	scope := params["scope"]

	if realm == "" {
		return "", fmt.Errorf("no realm in WWW-Authenticate header")
	}

	// Check cache.
	cacheKey := service + "|" + scope
	p.mu.RLock()
	if ct, ok := p.tokenCache[cacheKey]; ok && time.Now().Before(ct.ExpiresAt) {
		p.mu.RUnlock()
		return ct.Token, nil
	}
	p.mu.RUnlock()

	// Build token request URL.
	tokenURL := realm + "?service=" + service
	if scope != "" {
		tokenURL += "&scope=" + scope
	}

	resp, err := http.Get(tokenURL)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request returned %d", resp.StatusCode)
	}

	var tokenResp struct {
		Token     string `json:"token"`
		ExpiresIn int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}

	if tokenResp.Token == "" {
		return "", fmt.Errorf("empty token in response")
	}

	// Cache the token.
	expiresIn := time.Duration(tokenResp.ExpiresIn) * time.Second
	if expiresIn <= 0 {
		expiresIn = 60 * time.Second
	}
	p.mu.Lock()
	p.tokenCache[cacheKey] = &cachedToken{
		Token:     tokenResp.Token,
		ExpiresAt: time.Now().Add(expiresIn - 10*time.Second), // subtract buffer
	}
	p.mu.Unlock()

	return tokenResp.Token, nil
}

// parseImageRef constructs a full image reference from URL path components.
// For Docker Hub, names without a slash get "library/" prefix.
func (p *Proxy) parseImageRef(name, reference string) string {
	// Normalize Docker Hub library images.
	if p.Config.Name == "docker.io" && !strings.Contains(name, "/") {
		name = "library/" + name
	}
	if strings.HasPrefix(reference, "sha256:") {
		return p.Config.Name + "/" + name + "@" + reference
	}
	return p.Config.Name + "/" + name + ":" + reference
}

// authenticateOptional validates X-Firewall4AI-Token header if present.
func (p *Proxy) authenticateOptional(r *http.Request) *auth.Skill {
	token := r.Header.Get("X-Firewall4AI-Token")
	if token == "" {
		return nil
	}
	skill, _ := p.Skills.Authenticate(token)
	return skill
}

func (p *Proxy) logRequest(skillID, method, host, path, status, detail string, duration time.Duration) {
	if p.Logger == nil {
		return
	}
	p.Logger.Add(proxylog.Entry{
		Timestamp: time.Now(),
		SkillID:   skillID,
		Method:    method,
		Host:      host,
		Path:      path,
		Status:    status,
		Detail:    detail,
		Duration:  duration.Milliseconds(),
	})
}

// --- Path parsing ---

// parsePath extracts the name and reference from a Registry V2 URL path.
// Returns (name, reference, pathType, ok) where pathType is "manifests" or "blobs".
func parsePath(urlPath string) (name, ref, pathType string, ok bool) {
	// Must start with /v2/
	if !strings.HasPrefix(urlPath, "/v2/") {
		return "", "", "", false
	}
	rest := urlPath[4:] // strip /v2/

	// Find /manifests/ or /blobs/ separator.
	for _, pt := range []string{"/manifests/", "/blobs/"} {
		idx := strings.LastIndex(rest, pt)
		if idx < 0 {
			continue
		}
		name = rest[:idx]
		ref = rest[idx+len(pt):]
		if name == "" || ref == "" {
			continue
		}
		pathType = pt[1 : len(pt)-1] // strip leading/trailing slashes
		return name, ref, pathType, true
	}
	return "", "", "", false
}

// --- Pattern matching ---

// MatchImageRef checks if an image reference matches a pattern.
// Supports:
//   - Exact match: "docker.io/library/ubuntu:latest"
//   - Suffix wildcard: "docker.io/library/*" (matches any image in library/)
//   - Tag wildcard: "docker.io/library/ubuntu:*" (matches any tag)
//   - Digest wildcard: "docker.io/library/ubuntu@*" (matches any digest)
func MatchImageRef(pattern, imageRef string) bool {
	if pattern == imageRef {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := pattern[:len(pattern)-1] // "docker.io/library/"
		return strings.HasPrefix(imageRef, prefix)
	}
	if strings.HasSuffix(pattern, ":*") {
		prefix := pattern[:len(pattern)-1] // "docker.io/library/ubuntu:"
		return strings.HasPrefix(imageRef, prefix)
	}
	if strings.HasSuffix(pattern, "@*") {
		prefix := pattern[:len(pattern)-1] // "docker.io/library/ubuntu@"
		return strings.HasPrefix(imageRef, prefix)
	}
	return false
}

// --- WWW-Authenticate parsing ---

// parseBearerParams parses key=value pairs from a WWW-Authenticate Bearer header.
// Example: Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/ubuntu:pull"
func parseBearerParams(header string) map[string]string {
	params := make(map[string]string)
	// Strip "Bearer " prefix.
	header = strings.TrimPrefix(header, "Bearer ")

	for header != "" {
		header = strings.TrimSpace(header)
		eqIdx := strings.Index(header, "=")
		if eqIdx < 0 {
			break
		}
		key := header[:eqIdx]
		header = header[eqIdx+1:]

		var value string
		if strings.HasPrefix(header, `"`) {
			// Quoted value.
			header = header[1:]
			endQuote := strings.Index(header, `"`)
			if endQuote < 0 {
				value = header
				header = ""
			} else {
				value = header[:endQuote]
				header = header[endQuote+1:]
			}
		} else {
			// Unquoted value.
			commaIdx := strings.Index(header, ",")
			if commaIdx < 0 {
				value = header
				header = ""
			} else {
				value = header[:commaIdx]
				header = header[commaIdx:]
			}
		}

		params[key] = value

		// Skip comma separator.
		header = strings.TrimLeft(header, ", ")
	}

	return params
}

// extractSourceIP returns the IP address (without port) from a remote address string.
func extractSourceIP(remoteAddr string) string {
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return h
	}
	return remoteAddr
}
