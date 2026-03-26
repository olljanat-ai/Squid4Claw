package image

import (
	"testing"

	"github.com/olljanat-ai/firewall4ai/internal/agent"
)

func TestAddAndGet(t *testing.T) {
	m := NewManager(t.TempDir())
	err := m.Add(DiskImage{
		ID:        "img1",
		Name:      "Alpine Dev",
		OS:        agent.OSAlpine,
		OSVersion: "3.23",
		Packages:  []string{"curl", "vim"},
	})
	if err != nil {
		t.Fatal(err)
	}

	img, ok := m.Get("img1")
	if !ok {
		t.Fatal("image not found")
	}
	if img.Name != "Alpine Dev" {
		t.Fatalf("unexpected name: %s", img.Name)
	}
	if img.OS != agent.OSAlpine {
		t.Fatalf("unexpected OS: %s", img.OS)
	}
	if len(img.Packages) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(img.Packages))
	}
}

func TestDuplicateID(t *testing.T) {
	m := NewManager(t.TempDir())
	m.Add(DiskImage{ID: "img1", Name: "Test", OS: agent.OSAlpine})

	err := m.Add(DiskImage{ID: "img1", Name: "Test2", OS: agent.OSDebian})
	if err == nil {
		t.Fatal("expected error for duplicate ID")
	}
}

func TestUpdate(t *testing.T) {
	m := NewManager(t.TempDir())
	m.Add(DiskImage{ID: "img1", Name: "Test", OS: agent.OSAlpine, OSVersion: "3.23"})

	err := m.Update(DiskImage{
		ID:        "img1",
		Name:      "Updated",
		OS:        agent.OSDebian,
		OSVersion: "13",
	})
	if err != nil {
		t.Fatal(err)
	}

	img, _ := m.Get("img1")
	if img.Name != "Updated" {
		t.Fatalf("name not updated: %s", img.Name)
	}
	if img.OS != agent.OSDebian {
		t.Fatalf("OS not updated: %s", img.OS)
	}
}

func TestDelete(t *testing.T) {
	m := NewManager(t.TempDir())
	m.Add(DiskImage{ID: "img1", Name: "Test", OS: agent.OSAlpine})

	err := m.Delete("img1")
	if err != nil {
		t.Fatal(err)
	}

	_, ok := m.Get("img1")
	if ok {
		t.Fatal("image should be deleted")
	}
}

func TestList(t *testing.T) {
	m := NewManager(t.TempDir())
	m.Add(DiskImage{ID: "img1", Name: "Alpine", OS: agent.OSAlpine})
	m.Add(DiskImage{ID: "img2", Name: "Debian", OS: agent.OSDebian})

	list := m.List()
	if len(list) != 2 {
		t.Fatalf("expected 2, got %d", len(list))
	}
}

func TestExportLoad(t *testing.T) {
	m := NewManager(t.TempDir())
	m.Add(DiskImage{ID: "img1", Name: "Alpine", OS: agent.OSAlpine})
	m.Add(DiskImage{ID: "img2", Name: "Debian", OS: agent.OSDebian})

	exported := m.ExportImages()
	if len(exported) != 2 {
		t.Fatalf("expected 2 exported, got %d", len(exported))
	}

	m2 := NewManager(t.TempDir())
	m2.LoadImages(exported)
	if m2.Count() != 2 {
		t.Fatalf("expected 2 loaded, got %d", m2.Count())
	}
}

func TestVersioning(t *testing.T) {
	m := NewManager(t.TempDir())
	m.Add(DiskImage{ID: "img1", Name: "Test", OS: agent.OSAlpine})

	img, _ := m.Get("img1")
	if v := img.NextVersion(); v != 1 {
		t.Fatalf("expected next version 1, got %d", v)
	}

	// Add version 1.
	err := m.AddVersion("img1", ImageVersion{Version: 1, Status: BuildStatusPending})
	if err != nil {
		t.Fatal(err)
	}

	img, _ = m.Get("img1")
	if len(img.Versions) != 1 {
		t.Fatalf("expected 1 version, got %d", len(img.Versions))
	}
	if v := img.NextVersion(); v != 2 {
		t.Fatalf("expected next version 2, got %d", v)
	}

	// LatestReadyVersion should be 0 (no ready versions).
	if v := img.LatestReadyVersion(); v != 0 {
		t.Fatalf("expected 0 ready version, got %d", v)
	}

	// Set version 1 to ready.
	m.SetVersionStatus("img1", 1, BuildStatusReady, "")
	img, _ = m.Get("img1")
	if v := img.LatestReadyVersion(); v != 1 {
		t.Fatalf("expected latest ready version 1, got %d", v)
	}

	// Add version 2 as ready.
	m.AddVersion("img1", ImageVersion{Version: 2, Status: BuildStatusReady})
	img, _ = m.Get("img1")
	if v := img.LatestReadyVersion(); v != 2 {
		t.Fatalf("expected latest ready version 2, got %d", v)
	}

	// Delete version 1.
	err = m.DeleteVersion("img1", 1)
	if err != nil {
		t.Fatal(err)
	}
	img, _ = m.Get("img1")
	if len(img.Versions) != 1 {
		t.Fatalf("expected 1 version after delete, got %d", len(img.Versions))
	}
}

func TestImagePaths(t *testing.T) {
	m := NewManager("/var/lib/firewall4ai")

	if d := m.ImagesDir(); d != "/var/lib/firewall4ai/images" {
		t.Fatalf("unexpected images dir: %s", d)
	}
	if d := m.VersionDir("img1", 1); d != "/var/lib/firewall4ai/images/img1/1" {
		t.Fatalf("unexpected version dir: %s", d)
	}
	if p := m.RootfsPath("img1", 1); p != "/var/lib/firewall4ai/images/img1/1/rootfs.tar.gz" {
		t.Fatalf("unexpected rootfs path: %s", p)
	}
}
