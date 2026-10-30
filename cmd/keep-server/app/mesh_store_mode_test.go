package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/entire-vc/evc-keep/internal/config"
	"github.com/entire-vc/evc-keep/internal/meshext"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
)

// storeFetcher counts the hierarchy fetches Keep starts, per workspace.
type storeFetcher struct {
	mu   sync.Mutex
	seen map[uuid.UUID]int
}

func (s *storeFetcher) FetchHierarchy(_ context.Context, _, ws uuid.UUID, _, _ string) (meshext.Fetched, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen[ws]++
	return meshext.Fetched{}, errors.New("unauthorized")
}

func (f *meshFixture) installStore(ws uuid.UUID, token string) *httptest.ResponseRecorder {
	f.t.Helper()
	b, _ := json.Marshal(map[string]string{
		"mesh_url": "https://mesh.example.test", "workspace_id": ws.String(),
		"extension_token": token, "events_endpoint_secret": meshTestEventsSecret, "mode": "store",
	})
	rec := f.post("/mesh/install", f.admin, b, nil)
	installedKeepSecret(f.t, rec)
	return rec
}

// A workspace installed as a secret store only keeps working for the calls
// its Mesh makes into Keep: a secret it puts is resolved back through the
// same signed Mesh path. Keep makes no call of its own to that Mesh: no
// hierarchy fetch and no gate token, while an extension installation of the
// same organisation is still fetched. Neither the token handed over at a store
// install nor a secret value reaches a log, the journal, a metadata table, the
// sealed storage in clear, or the install answer.
func TestMeshStoreInstallServesSecretsAndIsNeverCalled(t *testing.T) {
	f := newMeshFixture(t, true)
	c := canary.New()
	st := uuid.New()
	install := f.installStore(st, c.Value(1))
	var mode string
	if err := f.pool.QueryRow(context.Background(), `SELECT mode FROM mesh_installations WHERE workspace_id=$1`, st).Scan(&mode); err != nil || mode != "store" {
		t.Fatalf("admin install with mode store recorded %q (%v)", mode, err)
	}

	val := c.Value(2)
	if rec := f.putSecret(st, "store-ref", val); rec.Code != http.StatusOK {
		t.Fatalf("PUT through the Mesh path of a store installation: %d", rec.Code)
	}
	rec := f.resolveSecret(st, "store-ref")
	var out map[string]string
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil || out["value"] != val {
		t.Fatalf("resolve through the Mesh path of a store installation: %d", rec.Code)
	}
	if !c.In(rec.Body.String()) {
		t.Fatal("the canary detector misses the value in the resolve body; the leak check proves nothing")
	}

	ext := f.installedWorkspace()
	fetch := &storeFetcher{seen: map[uuid.UUID]int{}}
	f.repo.ReconcileAll(context.Background(), fetch, f.logger)
	if fetch.seen[st] != 0 {
		t.Fatalf("store installation fetched %d times, want 0", fetch.seen[st])
	}
	if fetch.seen[ext] != 1 {
		t.Fatalf("extension installation fetched %d times, want 1 (positive control)", fetch.seen[ext])
	}

	// The gate's token source exactly as the server wires it.
	gateFor := func(ws uuid.UUID) (string, error) {
		src, err := gateTokens(config.MeshGate{WorkspaceID: ws.String(), URL: "https://mesh.example.test"}, f.pool, f.local.MeshVault())
		if err != nil || src == nil {
			t.Fatalf("gate token source: %v", err)
		}
		return src.Token(context.Background())
	}
	if _, err := gateFor(st); !errors.Is(err, ErrGateToken) {
		t.Fatalf("gate token of a store installation: %v, want ErrGateToken", err)
	}
	if tok, err := gateFor(ext); err != nil || tok == "" {
		t.Fatalf("gate token of the extension installation: %v (positive control)", err)
	}

	if f.logbuf.Len() == 0 {
		t.Fatal("logger captured nothing; the log check proves nothing")
	}
	for i, s := range append(f.surfaces(), install.Body.String(), headersText(install)) {
		if c.In(s) {
			t.Fatalf("surface %d carries the store install token or a secret value", i)
		}
	}
}

// Mesh's install handshake is the extension install: the workspace it binds is
// recorded as an extension and is reconciled.
func TestMeshHandshakeInstallsAnExtension(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := uuid.New()
	f.handshakeBound(ws, "mode-signing-"+strings.Repeat("m", 40))
	var mode string
	if err := f.pool.QueryRow(context.Background(), `SELECT mode FROM mesh_installations WHERE workspace_id=$1`, ws).Scan(&mode); err != nil || mode != "extension" {
		t.Fatalf("handshake install recorded mode %q (%v), want extension", mode, err)
	}
	fetch := &storeFetcher{seen: map[uuid.UUID]int{}}
	f.repo.ReconcileAll(context.Background(), fetch, f.logger)
	if fetch.seen[ws] != 1 {
		t.Fatalf("handshake installation fetched %d times, want 1", fetch.seen[ws])
	}
}
