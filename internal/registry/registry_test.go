package registry

import (
	"testing"

	"github.com/olljanat-ai/firewall4ai/internal/approval"
	"github.com/olljanat-ai/firewall4ai/internal/config"
)

func TestRegistryForHost(t *testing.T) {
	registries := []config.RegistryConfig{
		{Name: "docker.io", Hosts: []string{"registry-1.docker.io", "auth.docker.io", "production.cloudflare.docker.com"}},
		{Name: "ghcr.io", Hosts: []string{"ghcr.io"}},
	}

	tests := []struct {
		host string
		want string
	}{
		{"registry-1.docker.io", "docker.io"},
		{"auth.docker.io", "docker.io"},
		{"production.cloudflare.docker.com", "docker.io"},
		{"ghcr.io", "ghcr.io"},
		{"example.com", ""},
		{"docker.io", ""},
	}
	for _, tt := range tests {
		reg := RegistryForHost(tt.host, registries)
		if tt.want == "" {
			if reg != nil {
				t.Errorf("RegistryForHost(%q) = %q, want nil", tt.host, reg.Name)
			}
		} else {
			if reg == nil {
				t.Errorf("RegistryForHost(%q) = nil, want %q", tt.host, tt.want)
			} else if reg.Name != tt.want {
				t.Errorf("RegistryForHost(%q) = %q, want %q", tt.host, reg.Name, tt.want)
			}
		}
	}
}

func TestCheckRepoApproval(t *testing.T) {
	mgr := approval.NewManager()

	// No approvals yet.
	if CheckRepoApproval(mgr, "docker.io/library/ubuntu") {
		t.Error("expected false with no approvals")
	}

	// Approve the repo.
	mgr.Decide("docker.io/library/ubuntu", "", "", "", approval.StatusApproved, "")
	if !CheckRepoApproval(mgr, "docker.io/library/ubuntu") {
		t.Error("expected true after approving repo")
	}

	// Different repo should not match.
	if CheckRepoApproval(mgr, "docker.io/library/nginx") {
		t.Error("expected false for different repo")
	}

	// Wildcard approval.
	mgr.Decide("docker.io/library/*", "", "", "", approval.StatusApproved, "")
	if !CheckRepoApproval(mgr, "docker.io/library/nginx") {
		t.Error("expected true after wildcard approval")
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
		name, ref, pathType, ok := ParsePath(tt.path)
		if ok != tt.ok || name != tt.name || ref != tt.ref || pathType != tt.pathType {
			t.Errorf("ParsePath(%q) = (%q, %q, %q, %v), want (%q, %q, %q, %v)",
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
		{"docker.io/library/ubuntu", "docker.io/library/ubuntu", true},
		{"docker.io/library/ubuntu", "docker.io/library/nginx", false},
		{"docker.io/library/*", "docker.io/library/ubuntu", true},
		{"docker.io/library/*", "docker.io/library/nginx", true},
		{"docker.io/library/*", "docker.io/myorg/myrepo", false},
		{"docker.io/*", "docker.io/library/ubuntu", true},
		{"ghcr.io/org/*", "ghcr.io/org/repo", true},
		{"ghcr.io/org/*", "ghcr.io/other/repo", false},
		// Legacy tag/digest patterns still work.
		{"docker.io/library/ubuntu:*", "docker.io/library/ubuntu:latest", true},
		{"docker.io/library/ubuntu@*", "docker.io/library/ubuntu@sha256:abc123", true},
	}
	for _, tt := range tests {
		got := MatchImageRef(tt.pattern, tt.imageRef)
		if got != tt.want {
			t.Errorf("MatchImageRef(%q, %q) = %v, want %v", tt.pattern, tt.imageRef, got, tt.want)
		}
	}
}

func TestParseImageRepo(t *testing.T) {
	tests := []struct {
		registry string
		name     string
		want     string
	}{
		{"docker.io", "library/ubuntu", "docker.io/library/ubuntu"},
		{"docker.io", "ubuntu", "docker.io/library/ubuntu"},
		{"docker.io", "myorg/myrepo", "docker.io/myorg/myrepo"},
		{"ghcr.io", "myorg/myrepo", "ghcr.io/myorg/myrepo"},
	}
	for _, tt := range tests {
		got := ParseImageRepo(tt.registry, tt.name)
		if got != tt.want {
			t.Errorf("ParseImageRepo(%q, %q) = %q, want %q", tt.registry, tt.name, got, tt.want)
		}
	}
}
