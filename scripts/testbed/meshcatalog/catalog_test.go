// Package meshcatalog is the stand's stand-in for the signed extension catalog
// (Spark) that the disposable Mesh installs extensions from. It serves one
// extension, the manifest file given with -manifest, signed with an ed25519 key
// that is made at start: the public half goes to -pubkey-out (it is public),
// the private half never leaves this process.
//
// The routes are the ones internal/extensions/catalog of evc-mesh reads:
//
//	GET /api/v1/mesh-extensions/catalog.json                  signed, with ETag
//	GET /api/v1/mesh-extensions/<id>                          detail, release installable
//	GET /api/v1/mesh-extensions/<id>/releases/<v>/artifact    tar.gz holding mesh-extension.json
//
// It is a test file on purpose, like ../humaninput: signing is confined by the
// linter to job and intake descriptors and to tests, and this signs a test
// catalog only. The stand runs it as a compiled test binary:
//
//	meshcatalog -test.run TestServe -manifest ... -commit ... -pubkey-out ... -digest-out ... -listen ...
package meshcatalog

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var (
	manifestPath = flag.String("manifest", "", "mesh-extension manifest to publish")
	commit       = flag.String("commit", "", "commit the manifest comes from (catalog commit_sha)")
	pubOut       = flag.String("pubkey-out", "", "file that receives the base64 public key")
	digestOut    = flag.String("digest-out", "", "file that receives the artifact sha256 (hex)")
	listen       = flag.String("listen", ":8090", "listen address")
)

func TestServe(t *testing.T) {
	if *manifestPath == "" {
		t.Skip("a helper of the rotation testbed; run by the meshaux container")
	}
	if err := run(); err != nil {
		t.Fatalf("meshcatalog: %v", err)
	}
}

func run() error {
	raw, err := os.ReadFile(filepath.Clean(*manifestPath))
	if err != nil {
		return err
	}
	var m struct {
		ID        string          `json:"id"`
		Name      string          `json:"name"`
		Version   string          `json:"version"`
		Kind      string          `json:"kind"`
		Runtime   string          `json:"runtime"`
		Category  string          `json:"category"`
		Publisher string          `json:"publisher"`
		Caps      json.RawMessage `json:"capabilities"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("manifest: %w", err)
	}
	art, err := artifact(raw)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(art)
	digest := hex.EncodeToString(sum[:])
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if *pubOut != "" {
		if err := os.WriteFile(*pubOut, []byte(base64.StdEncoding.EncodeToString(pub)), 0o644); err != nil { //nolint:gosec // G306: a public key
			return err
		}
	}
	if *digestOut != "" {
		if err := os.WriteFile(*digestOut, []byte(digest), 0o644); err != nil { //nolint:gosec // G306: a digest
			return err
		}
	}
	rel := map[string]any{"version": m.Version, "mesh_api": ">=1 <2", "commit_sha": *commit, "artifact_sha256": digest, "capabilities": json.RawMessage(m.Caps)}
	body, err := json.Marshal(map[string]any{
		"schema": 1, "generated_at": time.Now().UTC().Format(time.RFC3339),
		"extensions": []any{map[string]any{
			"id": m.ID, "name": m.Name, "kind": m.Kind, "runtime": m.Runtime, "category": m.Category,
			"trust": "community", "publisher": m.Publisher, "latest": rel, "releases": []any{rel}, "page_url": "",
		}},
		"blocklist": []any{},
	})
	if err != nil {
		return err
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, body))
	etag := sha256.Sum256(body)
	detail, err := json.Marshal(map[string]any{
		"id": m.ID, "name": m.Name,
		"releases": []any{map[string]any{"version": m.Version, "manifest": json.RawMessage(raw), "installable": true, "status": "published", "yanked": false}},
	})
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	base := "/api/v1/mesh-extensions/"
	mux.HandleFunc("GET "+base+"catalog.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Catalog-Signature", sig)
		w.Header().Set("ETag", `"`+hex.EncodeToString(etag[:])+`"`)
		_, _ = w.Write(body)
	})
	mux.HandleFunc("GET "+base+m.ID, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(detail)
	})
	mux.HandleFunc("GET "+base+m.ID+"/releases/"+m.Version+"/artifact", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(art)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	return srv.ListenAndServe()
}

// artifact is the release tarball: the manifest under the name the installer reads.
func artifact(manifest []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	if err := tw.WriteHeader(&tar.Header{Name: "mesh-extension.json", Mode: 0o644, Size: int64(len(manifest)), Typeflag: tar.TypeReg}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(manifest); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
