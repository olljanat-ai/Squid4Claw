package cainjector

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"testing"
)

var testCACert = []byte(`-----BEGIN CERTIFICATE-----
MIIBdTCCARugAwIBAgIRALbKOsMI8JEWr1DOlST/tCIwCgYIKoZIzj0EAwIwHDEa
MBgGA1UEAxMRRmlyZXdhbGw0QUkgQ0EwHhcNMjQwMTAxMDAwMDAwWhcNMzQwMTAx
MDAwMDAwWjAcMRowGAYDVQQDExFGaXJld2FsbDRBSSBDQTBZMBMGByqGSM49AgEG
CCqGSM49AwEHA0IABKfake+test+data+here/not/a/real/certReallyFake
-----END CERTIFICATE-----
`)

func TestBuildCALayer(t *testing.T) {
	inj := New(testCACert)
	layer, err := inj.buildCALayer()
	if err != nil {
		t.Fatalf("buildCALayer() error: %v", err)
	}

	if layer.size <= 0 {
		t.Error("expected positive layer size")
	}
	if layer.digest.Algorithm != "sha256" || layer.digest.Hex == "" {
		t.Error("expected valid digest")
	}
	if layer.diffID.Algorithm != "sha256" || layer.diffID.Hex == "" {
		t.Error("expected valid diffID")
	}

	// Decompress and verify tar contents.
	gr, err := gzip.NewReader(bytes.NewReader(layer.compressed))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	foundDebian := false
	foundRHEL := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		if hdr.Name == "usr/local/share/ca-certificates/firewall4ai-root-ca.crt" {
			foundDebian = true
			data, _ := io.ReadAll(tr)
			if !bytes.Equal(data, testCACert) {
				t.Error("Debian cert content mismatch")
			}
		}
		if hdr.Name == "etc/pki/ca-trust/source/anchors/firewall4ai-root-ca.crt" {
			foundRHEL = true
			data, _ := io.ReadAll(tr)
			if !bytes.Equal(data, testCACert) {
				t.Error("RHEL cert content mismatch")
			}
		}
	}
	if !foundDebian {
		t.Error("missing Debian/Ubuntu/Alpine cert path")
	}
	if !foundRHEL {
		t.Error("missing RHEL/Fedora cert path")
	}
}

func TestIsImageManifest(t *testing.T) {
	tests := []struct {
		ct   string
		want bool
	}{
		{"application/vnd.docker.distribution.manifest.v2+json", true},
		{"application/vnd.oci.image.manifest.v1+json", true},
		{"application/vnd.docker.distribution.manifest.list.v2+json", false},
		{"application/json", false},
		{"application/vnd.docker.distribution.manifest.v2+json; charset=utf-8", true},
	}
	for _, tt := range tests {
		got := isImageManifest(tt.ct)
		if got != tt.want {
			t.Errorf("isImageManifest(%q) = %v, want %v", tt.ct, got, tt.want)
		}
	}
}

func TestHandleBlobRequest_InjectedLayer(t *testing.T) {
	inj := New(testCACert)
	layer, err := inj.buildCALayer()
	if err != nil {
		t.Fatalf("buildCALayer: %v", err)
	}

	// Manually add a cache entry.
	mi := &mutatedImage{
		layerBlob:   layer.compressed,
		layerDigest: layer.digest.String(),
		configBlob:  []byte(`{"config":"test"}`),
		configDigest: "sha256:abcd1234",
		originalDigests: map[string]bool{"sha256:orig1": true},
	}
	inj.mu.Lock()
	inj.cache["sha256:test"] = mi
	inj.mu.Unlock()

	// Should find the layer.
	data, ct, found := inj.HandleBlobRequest(layer.digest.String())
	if !found {
		t.Fatal("expected to find injected layer blob")
	}
	if ct != "application/octet-stream" {
		t.Errorf("unexpected content type: %s", ct)
	}
	if !bytes.Equal(data, layer.compressed) {
		t.Error("blob data mismatch")
	}

	// Should find the config.
	data, ct, found = inj.HandleBlobRequest("sha256:abcd1234")
	if !found {
		t.Fatal("expected to find injected config blob")
	}
	if ct != "application/vnd.docker.container.image.v1+json" {
		t.Errorf("unexpected config content type: %s", ct)
	}

	// Original digests should not be found.
	_, _, found = inj.HandleBlobRequest("sha256:orig1")
	if found {
		t.Error("original digest should not be served by injector")
	}

	// Unknown digest should not be found.
	_, _, found = inj.HandleBlobRequest("sha256:unknown")
	if found {
		t.Error("unknown digest should not be found")
	}
}
