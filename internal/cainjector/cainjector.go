// Package cainjector provides on-the-fly injection of the Firewall4AI root CA
// certificate into OCI/Docker images pulled through the transparent proxy.
// It intercepts registry manifest and blob responses, adds a new layer with
// the CA certificate placed in the appropriate trust store directory, and
// rewrites the manifest/config so the Docker client receives an image that
// already trusts the proxy's CA.
package cainjector

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// Injector mutates OCI images on-the-fly to include the Firewall4AI root CA.
type Injector struct {
	caCertPEM []byte // raw PEM bytes of the CA certificate

	mu    sync.RWMutex
	cache map[string]*mutatedImage // keyed by original manifest digest
}

// mutatedImage holds the cached result of mutating an image.
type mutatedImage struct {
	// The rewritten manifest bytes and their digest/mediaType.
	manifest      []byte
	manifestDigest string
	mediaType     string

	// The rewritten config blob and its digest.
	configBlob   []byte
	configDigest string

	// The injected CA layer blob (gzipped tar) and its digests.
	layerBlob       []byte
	layerDigest     string // compressed digest (sha256)
	layerDiffID     string // uncompressed digest (sha256)
	layerSize       int64

	// Map from original blob digest → true, so we know to pass-through.
	originalDigests map[string]bool

	createdAt time.Time
}

// New creates an Injector with the given CA certificate PEM bytes.
func New(caCertPEM []byte) *Injector {
	return &Injector{
		caCertPEM: caCertPEM,
		cache:     make(map[string]*mutatedImage),
	}
}

// caLayer implements v1.Layer for our injected CA certificate layer.
type caLayer struct {
	compressed   []byte
	diffID       v1.Hash
	digest       v1.Hash
	size         int64
	uncompressed []byte
}

func (l *caLayer) Digest() (v1.Hash, error)                          { return l.digest, nil }
func (l *caLayer) DiffID() (v1.Hash, error)                          { return l.diffID, nil }
func (l *caLayer) Compressed() (io.ReadCloser, error)                { return io.NopCloser(bytes.NewReader(l.compressed)), nil }
func (l *caLayer) Uncompressed() (io.ReadCloser, error)              { return io.NopCloser(bytes.NewReader(l.uncompressed)), nil }
func (l *caLayer) Size() (int64, error)                              { return l.size, nil }
func (l *caLayer) MediaType() (types.MediaType, error)               { return types.DockerLayer, nil }
func (l *caLayer) Exists() (bool, error)                             { return true, nil }

// buildCALayer creates a gzipped tar layer containing the CA cert in standard
// trust store locations for Debian/Ubuntu, Alpine, and RHEL/Fedora.
func (inj *Injector) buildCALayer() (*caLayer, error) {
	certPaths := []string{
		"usr/local/share/ca-certificates/firewall4ai-root-ca.crt", // Debian/Ubuntu/Alpine
		"etc/pki/ca-trust/source/anchors/firewall4ai-root-ca.crt", // RHEL/Fedora
	}

	// Build uncompressed tar.
	var uncompBuf bytes.Buffer
	tw := tar.NewWriter(&uncompBuf)

	// Create parent directories.
	dirs := map[string]bool{}
	for _, p := range certPaths {
		parts := strings.Split(p, "/")
		for i := 1; i < len(parts); i++ {
			dir := strings.Join(parts[:i], "/") + "/"
			if !dirs[dir] {
				dirs[dir] = true
				tw.WriteHeader(&tar.Header{
					Typeflag: tar.TypeDir,
					Name:     dir,
					Mode:     0755,
					ModTime:  time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
				})
			}
		}
	}

	for _, p := range certPaths {
		if err := tw.WriteHeader(&tar.Header{
			Name:    p,
			Size:    int64(len(inj.caCertPEM)),
			Mode:    0644,
			ModTime: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		}); err != nil {
			return nil, fmt.Errorf("write tar header for %s: %w", p, err)
		}
		if _, err := tw.Write(inj.caCertPEM); err != nil {
			return nil, fmt.Errorf("write tar body for %s: %w", p, err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("close tar writer: %w", err)
	}

	uncompBytes := uncompBuf.Bytes()
	diffIDHash := sha256.Sum256(uncompBytes)
	diffID := v1.Hash{Algorithm: "sha256", Hex: hex.EncodeToString(diffIDHash[:])}

	// Gzip compress.
	var compBuf bytes.Buffer
	gw, _ := gzip.NewWriterLevel(&compBuf, gzip.BestCompression)
	if _, err := gw.Write(uncompBytes); err != nil {
		return nil, fmt.Errorf("gzip write: %w", err)
	}
	if err := gw.Close(); err != nil {
		return nil, fmt.Errorf("gzip close: %w", err)
	}

	compBytes := compBuf.Bytes()
	digestHash := sha256.Sum256(compBytes)
	digest := v1.Hash{Algorithm: "sha256", Hex: hex.EncodeToString(digestHash[:])}

	return &caLayer{
		compressed:   compBytes,
		uncompressed: uncompBytes,
		diffID:       diffID,
		digest:       digest,
		size:         int64(len(compBytes)),
	}, nil
}

// MutateManifest takes an original manifest response body from upstream,
// parses the image, appends the CA layer, and returns the mutated manifest.
// The result is cached by the original manifest's content digest.
func (inj *Injector) MutateManifest(originalManifest []byte, originalMediaType string) (*mutatedImage, error) {
	// Compute original digest for cache key.
	origHash := sha256.Sum256(originalManifest)
	origDigest := "sha256:" + hex.EncodeToString(origHash[:])

	inj.mu.RLock()
	if cached, ok := inj.cache[origDigest]; ok {
		inj.mu.RUnlock()
		return cached, nil
	}
	inj.mu.RUnlock()

	// Parse as an OCI/Docker manifest.
	img, err := parseManifestToImage(originalManifest, originalMediaType)
	if err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}

	// Build the CA layer.
	layer, err := inj.buildCALayer()
	if err != nil {
		return nil, fmt.Errorf("build CA layer: %w", err)
	}

	// Collect original blob digests (layers + config) before mutation.
	origManifest, err := img.Manifest()
	if err != nil {
		return nil, fmt.Errorf("get original manifest: %w", err)
	}
	originalDigests := make(map[string]bool)
	originalDigests[origManifest.Config.Digest.String()] = true
	for _, l := range origManifest.Layers {
		originalDigests[l.Digest.String()] = true
	}

	// Mutate: append our CA layer.
	mutImg, err := mutate.AppendLayers(img, layer)
	if err != nil {
		return nil, fmt.Errorf("append CA layer: %w", err)
	}

	// Add history entry.
	cfg, err := mutImg.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("get config: %w", err)
	}
	cfgCopy := cfg.DeepCopy()
	cfgCopy.History = append(cfgCopy.History, v1.History{
		CreatedBy: "Firewall4AI: inject root CA certificate",
		Comment:   "Added Firewall4AI CA to /usr/local/share/ca-certificates/ and /etc/pki/ca-trust/source/anchors/",
		EmptyLayer: false,
	})
	mutImg, err = mutate.ConfigFile(mutImg, cfgCopy)
	if err != nil {
		return nil, fmt.Errorf("update config history: %w", err)
	}

	// Serialize the mutated manifest.
	newManifestBytes, err := json.Marshal(mustManifest(mutImg))
	if err != nil {
		return nil, fmt.Errorf("marshal mutated manifest: %w", err)
	}

	newManifestHash := sha256.Sum256(newManifestBytes)
	newManifestDigest := "sha256:" + hex.EncodeToString(newManifestHash[:])

	// Serialize the new config.
	newConfigBytes, err := json.Marshal(cfgCopy)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	newConfigHash := sha256.Sum256(newConfigBytes)
	newConfigDigest := "sha256:" + hex.EncodeToString(newConfigHash[:])

	result := &mutatedImage{
		manifest:        newManifestBytes,
		manifestDigest:  newManifestDigest,
		mediaType:       originalMediaType,
		configBlob:      newConfigBytes,
		configDigest:    newConfigDigest,
		layerBlob:       layer.compressed,
		layerDigest:     layer.digest.String(),
		layerDiffID:     layer.diffID.String(),
		layerSize:       layer.size,
		originalDigests: originalDigests,
		createdAt:       time.Now(),
	}

	inj.mu.Lock()
	// Evict old entries if cache grows too large.
	if len(inj.cache) > 500 {
		for k := range inj.cache {
			delete(inj.cache, k)
			break // just remove one
		}
	}
	inj.cache[origDigest] = result
	inj.mu.Unlock()

	log.Printf("CA injection: mutated image — original digest: %s, new digest: %s, new layer: %s",
		origDigest, newManifestDigest, layer.digest.String())

	return result, nil
}

// HandleManifestResponse intercepts an upstream manifest response, mutates it
// to include the CA cert, and returns a new response to serve to the client.
// If the response is not a 200 or not a recognized manifest type, it is
// returned unchanged.
func (inj *Injector) HandleManifestResponse(resp *http.Response) (*http.Response, error) {
	if resp.StatusCode != http.StatusOK {
		return resp, nil
	}

	ct := resp.Header.Get("Content-Type")
	if !isImageManifest(ct) {
		return resp, nil
	}

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("read manifest body: %w", err)
	}

	mutated, err := inj.MutateManifest(body, ct)
	if err != nil {
		// On error, return original manifest unchanged.
		log.Printf("CA injection: mutation failed, serving original: %v", err)
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		return resp, nil
	}

	// Replace response body with mutated manifest.
	resp.Body = io.NopCloser(bytes.NewReader(mutated.manifest))
	resp.ContentLength = int64(len(mutated.manifest))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(mutated.manifest)))
	resp.Header.Set("Docker-Content-Digest", mutated.manifestDigest)

	return resp, nil
}

// HandleBlobRequest checks if the requested blob digest matches an injected
// layer or config. If so, it returns the blob bytes directly. If the digest
// belongs to the original image, returns nil (caller should proxy upstream).
// The origManifestDigest is the digest from the manifest the client pulled.
func (inj *Injector) HandleBlobRequest(blobDigest string) ([]byte, string, bool) {
	inj.mu.RLock()
	defer inj.mu.RUnlock()

	for _, mi := range inj.cache {
		if blobDigest == mi.layerDigest {
			return mi.layerBlob, "application/octet-stream", true
		}
		if blobDigest == mi.configDigest {
			return mi.configBlob, "application/vnd.docker.container.image.v1+json", true
		}
	}
	return nil, "", false
}

// --- Helpers ---

func isImageManifest(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	// Strip parameters (e.g. ";charset=utf-8")
	if idx := strings.Index(ct, ";"); idx >= 0 {
		ct = strings.TrimSpace(ct[:idx])
	}
	switch ct {
	case "application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.oci.image.manifest.v1+json":
		return true
	}
	return false
}

func mustManifest(img v1.Image) *v1.Manifest {
	m, err := img.Manifest()
	if err != nil {
		panic(err)
	}
	return m
}

// parseManifestToImage creates a v1.Image from raw manifest bytes.
// This uses partial.CompressedToImage with a manifestImage adapter.
func parseManifestToImage(manifestBytes []byte, mediaType string) (v1.Image, error) {
	var m v1.Manifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return nil, fmt.Errorf("unmarshal manifest: %w", err)
	}

	mi := &manifestImage{
		manifest:  &m,
		mediaType: types.MediaType(mediaType),
		rawManifest: manifestBytes,
	}
	return partial.CompressedToImage(mi)
}

// manifestImage implements partial.CompressedImageCore from raw manifest bytes.
// This is a minimal implementation that only needs to provide the manifest;
// layers and config will be fetched lazily by go-containerregistry.
type manifestImage struct {
	manifest    *v1.Manifest
	mediaType   types.MediaType
	rawManifest []byte
}

func (mi *manifestImage) RawManifest() ([]byte, error) {
	return mi.rawManifest, nil
}

func (mi *manifestImage) MediaType() (types.MediaType, error) {
	return mi.mediaType, nil
}

func (mi *manifestImage) LayerByDigest(h v1.Hash) (partial.CompressedLayer, error) {
	return nil, fmt.Errorf("layer %s not available locally (proxy passthrough)", h.String())
}

func (mi *manifestImage) RawConfigFile() ([]byte, error) {
	// Return an empty config; it will be populated during mutation.
	return []byte("{}"), nil
}
