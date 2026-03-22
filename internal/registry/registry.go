// Package registry provides utility functions for detecting and handling
// Docker Registry V2 API requests within the transparent proxy. It handles
// image reference parsing, pattern matching, and registry host lookup for
// container image pull approval.
package registry

import (
	"strings"

	"github.com/olljanat-ai/firewall4ai/internal/approval"
	"github.com/olljanat-ai/firewall4ai/internal/config"
)

// RegistryForHost returns the registry config if the host belongs to a
// configured registry, or nil if it's not a known registry host.
func RegistryForHost(host string, registries []config.RegistryConfig) *config.RegistryConfig {
	for i := range registries {
		for _, h := range registries[i].Hosts {
			if h == host {
				return &registries[i]
			}
		}
	}
	return nil
}

// CheckRepoApproval returns true if the repository (or a broader wildcard
// pattern covering it) has been approved. Approvals are stored as repo refs
// without tags (e.g., "docker.io/library/ubuntu").
func CheckRepoApproval(mgr *approval.Manager, repo string) bool {
	// Exact match.
	if status, ok := mgr.CheckExisting(repo, "", "", ""); ok && status == approval.StatusApproved {
		return true
	}
	// Wildcard match (e.g., "docker.io/library/*" covers "docker.io/library/ubuntu").
	if status, ok := mgr.CheckExistingWithMatcher(repo, "", "", MatchImageRef); ok && status == approval.StatusApproved {
		return true
	}
	return false
}

// ParseImageRepo constructs a repository reference (without tag) from URL
// path components. For Docker Hub, names without a slash get "library/" prefix.
// Example: ("docker.io", "library/ubuntu") -> "docker.io/library/ubuntu"
func ParseImageRepo(registryName, name string) string {
	if registryName == "docker.io" && !strings.Contains(name, "/") {
		name = "library/" + name
	}
	return registryName + "/" + name
}

// ParsePath extracts the name and reference from a Registry V2 URL path.
// Returns (name, reference, pathType, ok) where pathType is "manifests" or "blobs".
func ParsePath(urlPath string) (name, ref, pathType string, ok bool) {
	if !strings.HasPrefix(urlPath, "/v2/") {
		return "", "", "", false
	}
	rest := urlPath[4:] // strip /v2/

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
		pathType = pt[1 : len(pt)-1]
		return name, ref, pathType, true
	}
	return "", "", "", false
}

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
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(imageRef, prefix)
	}
	if strings.HasSuffix(pattern, ":*") {
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(imageRef, prefix)
	}
	if strings.HasSuffix(pattern, "@*") {
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(imageRef, prefix)
	}
	return false
}
