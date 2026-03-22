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
		want string // expected registry name, or "" for nil
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

	// Approve a specific tag.
	mgr.Decide("docker.io/library/ubuntu:latest", "", "", approval.StatusApproved, "")
	if !CheckRepoApproval(mgr, "docker.io/library/ubuntu") {
		t.Error("expected true after approving a tag")
	}

	// Different repo should not match.
	if CheckRepoApproval(mgr, "docker.io/library/nginx") {
		t.Error("expected false for different repo")
	}

	// Wildcard approval.
	mgr.Decide("docker.io/library/*", "", "", approval.StatusApproved, "")
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
		{"docker.io/library/ubuntu:latest", "docker.io/library/ubuntu:latest", true},
		{"docker.io/library/ubuntu:latest", "docker.io/library/ubuntu:22.04", false},
		{"docker.io/library/*", "docker.io/library/ubuntu:latest", true},
		{"docker.io/library/*", "docker.io/library/nginx:1.25", true},
		{"docker.io/library/*", "docker.io/myorg/myrepo:latest", false},
		{"docker.io/*", "docker.io/library/ubuntu:latest", true},
		{"ghcr.io/org/*", "ghcr.io/org/repo:v1", true},
		{"ghcr.io/org/*", "ghcr.io/other/repo:v1", false},
		{"docker.io/library/ubuntu:*", "docker.io/library/ubuntu:latest", true},
		{"docker.io/library/ubuntu:*", "docker.io/library/ubuntu:22.04", true},
		{"docker.io/library/ubuntu:*", "docker.io/library/nginx:latest", false},
		{"docker.io/library/ubuntu@*", "docker.io/library/ubuntu@sha256:abc123", true},
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
	tests := []struct {
		registry  string
		name      string
		reference string
		want      string
	}{
		{"docker.io", "library/ubuntu", "latest", "docker.io/library/ubuntu:latest"},
		{"docker.io", "ubuntu", "latest", "docker.io/library/ubuntu:latest"},
		{"docker.io", "myorg/myrepo", "v1.0", "docker.io/myorg/myrepo:v1.0"},
		{"docker.io", "library/ubuntu", "sha256:abc123", "docker.io/library/ubuntu@sha256:abc123"},
		{"ghcr.io", "myorg/myrepo", "v1.0", "ghcr.io/myorg/myrepo:v1.0"},
		{"ghcr.io", "myorg/myrepo", "sha256:abc", "ghcr.io/myorg/myrepo@sha256:abc"},
	}
	for _, tt := range tests {
		got := ParseImageRef(tt.registry, tt.name, tt.reference)
		if got != tt.want {
			t.Errorf("ParseImageRef(%q, %q, %q) = %q, want %q", tt.registry, tt.name, tt.reference, got, tt.want)
		}
	}
}
