// proxy_registry.go handles Docker Registry V2 traffic: detecting manifest
// and blob requests, applying per-image approval using wildcard matching,
// and auto-approving registry infrastructure endpoints (auth, CDN, pings).
// When CA injection is enabled, manifest responses are mutated on-the-fly
// to include the Firewall4AI root CA certificate, and injected blobs
// (the CA layer and rewritten config) are served directly from cache.

package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/olljanat-ai/firewall4ai/internal/approval"
	"github.com/olljanat-ai/firewall4ai/internal/config"
	proxylog "github.com/olljanat-ai/firewall4ai/internal/logging"
	"github.com/olljanat-ai/firewall4ai/internal/registry"
)

// handleRegistryRequest handles a request to a known container registry host.
// Manifest requests trigger image-level approval; blob requests use repo-level
// approval; all other registry traffic (auth, /v2/ pings) is auto-approved.
// Returns the response to send to the client.
func (p *Proxy) handleRegistryRequest(req *http.Request, rc *requestContext, reg *config.RegistryConfig) *http.Response {
	sid := getSkillID(rc.skill)
	urlPath := req.URL.Path
	host := rc.host

	name, ref, pathType, isV2 := registry.ParsePath(urlPath)

	if isV2 && (pathType == "manifests" || pathType == "blobs") {
		// Manifest and blob requests use repo-level approval.
		repo := registry.ParseImageRepo(reg.Name, name)
		if p.GetLearningMode() || !registry.CheckRepoApproval(p.ImageApprovals, repo) {
			if pathType == "blobs" && !p.GetLearningMode() {
				// Blobs don't create pending entries; they are only
				// allowed if the repo was already approved via a manifest.
				p.Logger.Add(proxylog.Entry{
					SkillID: sid,
					Method:  req.Method,
					Host:    host,
					Path:    urlPath,
					Status:  "denied",
					Detail:  "repository not approved: " + repo,
				})
				rc.logged = true
				return errorResponse(req, statusToHTTPCode(approval.StatusDenied),
					denialMessage(approval.StatusDenied, "container image "+repo))
			}
			// Manifest (or blob in learning mode): register pending and wait.
			status := p.checkRefApproval(p.ImageApprovals, repo, rc.skill, rc.sourceIP, registry.MatchImageRef)
			if status != approval.StatusApproved {
				p.Logger.Add(proxylog.Entry{
					SkillID: sid,
					Method:  req.Method,
					Host:    host,
					Path:    urlPath,
					Status:  string(status),
					Detail:  "image not approved: " + repo,
				})
				rc.logged = true
				return errorResponse(req, statusToHTTPCode(status),
					denialMessage(status, "container image "+repo))
			}
		}

		// CA injection: intercept blob requests for injected digests.
		if pathType == "blobs" && p.CAInjector != nil && isDigestRef(ref) {
			if blobData, ct, found := p.CAInjector.HandleBlobRequest(ref); found {
				p.Logger.Add(proxylog.Entry{
					SkillID: sid,
					Method:  req.Method,
					Host:    host,
					Path:    urlPath,
					Status:  "allowed",
					Detail:  "CA injection: serving injected blob " + ref,
				})
				rc.logged = true
				return syntheticBlobResponse(req, blobData, ct, ref)
			}
		}

		resp := p.forwardRegistryAndLog(req, rc, repo)

		// CA injection: mutate manifest responses.
		if pathType == "manifests" && p.CAInjector != nil && resp != nil && resp.StatusCode == http.StatusOK {
			mutated, err := p.CAInjector.HandleManifestResponse(resp)
			if err != nil {
				p.Logger.Add(proxylog.Entry{
					SkillID: sid,
					Method:  req.Method,
					Host:    host,
					Path:    urlPath,
					Status:  "error",
					Detail:  "CA injection manifest mutation failed: " + err.Error(),
				})
			} else {
				resp = mutated
			}
		}

		return resp
	}

	// Other registry traffic (auth, /v2/ ping, etc.): auto-approve.
	return p.forwardRegistryAndLog(req, rc, "registry infra")
}

// isDigestRef returns true if the reference looks like a digest (sha256:...).
func isDigestRef(ref string) bool {
	return len(ref) > 7 && ref[:7] == "sha256:"
}

// syntheticBlobResponse creates an HTTP 200 response serving blob data directly
// (used for CA-injected layers and configs that don't exist upstream).
func syntheticBlobResponse(req *http.Request, data []byte, contentType, digest string) *http.Response {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(data)),
		Request:    req,
	}
	resp.ContentLength = int64(len(data))
	resp.Header.Set("Content-Type", contentType)
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(data)))
	resp.Header.Set("Docker-Content-Digest", digest)
	return resp
}
