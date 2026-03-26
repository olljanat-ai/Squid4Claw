package netboot

import (
	"strings"
	"testing"
)

func TestGenerateDeployIPXEScript(t *testing.T) {
	m := NewManager("/tmp/test", "10.255.255.1")

	script := m.GenerateDeployIPXEScript("agent-123")
	if !strings.HasPrefix(script, "#!ipxe") {
		t.Fatal("missing iPXE shebang")
	}
	if !strings.Contains(script, "kernel") {
		t.Fatal("missing kernel line")
	}
	if !strings.Contains(script, "initrd") {
		t.Fatal("missing initrd line")
	}
	if !strings.Contains(script, "alpine_repo") {
		t.Fatal("missing alpine_repo parameter")
	}
	if !strings.Contains(script, "fw4ai_agent=agent-123") {
		t.Fatal("missing agent ID parameter")
	}
	if !strings.Contains(script, "fw4ai_server=10.255.255.1") {
		t.Fatal("missing server IP parameter")
	}
	if !strings.Contains(script, "boot") {
		t.Fatal("missing boot command")
	}
	if !strings.Contains(script, "/boot/deploy/kernel") {
		t.Fatal("missing deploy kernel URL")
	}
	if !strings.Contains(script, "/boot/deploy/initrd") {
		t.Fatal("missing deploy initrd URL")
	}
}

func TestGenerateDeployApkovl(t *testing.T) {
	m := NewManager("/tmp/test", "10.255.255.1")

	data := m.GenerateDeployApkovl()
	if len(data) == 0 {
		t.Fatal("empty apkovl")
	}

	// Should be a valid gzip (starts with 0x1f 0x8b).
	if data[0] != 0x1f || data[1] != 0x8b {
		t.Fatal("not a valid gzip")
	}
}

func TestDeployDir(t *testing.T) {
	m := NewManager("/var/lib/firewall4ai", "10.255.255.1")

	expected := "/var/lib/firewall4ai/netboot/deploy"
	if d := m.DeployDir(); d != expected {
		t.Fatalf("expected %s, got %s", expected, d)
	}
}

func TestTFTPDir(t *testing.T) {
	m := NewManager("/var/lib/firewall4ai", "10.255.255.1")

	expected := "/var/lib/firewall4ai/netboot/tftp"
	if d := m.TFTPDir(); d != expected {
		t.Fatalf("expected %s, got %s", expected, d)
	}
}
