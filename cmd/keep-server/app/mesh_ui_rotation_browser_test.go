//go:build mesh_ui_browser

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/api"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/carriers"
	"github.com/entire-vc/evc-keep/internal/config"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/meshgate"
	"github.com/entire-vc/evc-keep/internal/rotation"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

// browserRotation is the provider side of a real rotation engine for the
// browser run: four carriers, the last two hold their layout until release.
type browserRotation struct {
	ids     [4]uuid.UUID
	once    sync.Once
	release chan struct{}
}

func (b *browserRotation) Prepare(context.Context, rotation.Ref, uuid.UUID) (rotation.Version, error) {
	return rotation.Version{Old: "11", New: "12", Fingerprint: "kfp1:k1:abcdefghijklmnop", Length: 32}, nil
}
func (b *browserRotation) List(context.Context, rotation.Ref) ([]rotation.Carrier, error) {
	out := make([]rotation.Carrier, len(b.ids))
	for i, id := range b.ids {
		out[i] = rotation.Carrier{ID: id.String()}
	}
	return out, nil
}
func (b *browserRotation) Deploy(ctx context.Context, _ rotation.Ref, _ uuid.UUID, c rotation.Carrier, _ string) error {
	if c.ID == b.ids[2].String() || c.ID == b.ids[3].String() {
		select {
		case <-b.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}
func (b *browserRotation) Verify(context.Context, rotation.Ref, rotation.Carrier, string) (rotation.Report, error) {
	return rotation.Report{Fingerprint: "kfp1:k1:abcdefghijklmnop", Healthy: true}, nil
}
func (b *browserRotation) Revoke(context.Context, rotation.Ref, uuid.UUID, string) error { return nil }
func (b *browserRotation) Open(context.Context, rotation.IncidentRecord) error           { return nil }
func (b *browserRotation) Resolve(context.Context, rotation.IncidentRecord) error        { return nil }
func (b *browserRotation) end()                                                          { b.once.Do(func() { close(b.release) }) }
func (b *browserRotation) Register(context.Context, uuid.UUID, uuid.UUID, string, carriers.Metadata) (carriers.Carrier, error) {
	return carriers.Carrier{}, nil
}

// List names the carriers for the page, as the carrier registry does.
func (b *browserRotation) listCarriers() []carriers.Carrier {
	hosts := []string{"web-01", "web-02", "worker-01", "a-very-long-host-name-of-the-batch-cluster.internal.example"}
	out := make([]carriers.Carrier, len(b.ids))
	for i, id := range b.ids {
		out[i] = carriers.Carrier{ID: id, Metadata: carriers.Metadata{Host: hosts[i], TargetKind: runnerproto.TargetFile, TargetPath: "/etc/app/" + hosts[i] + "/db.env"}}
	}
	return out
}

type browserCarriers struct{ b *browserRotation }

func (c browserCarriers) Register(ctx context.Context, org, secret uuid.UUID, v string, md carriers.Metadata) (carriers.Carrier, error) {
	return c.b.Register(ctx, org, secret, v, md)
}
func (c browserCarriers) List(context.Context, uuid.UUID, uuid.UUID) ([]carriers.Carrier, error) {
	return c.b.listCarriers(), nil
}

// The run page in a real browser: an active rotation run is marked live and
// refreshes itself in place every 3 s; when the server ends the run the page
// turns into the finished run without a reload and stops asking; the run
// list opens it. Screenshots of both states at 1440 and 393 go to
// KEEP_MESH_UI_SHOTS. What the browser rendered must not carry the value.
func TestMeshUIBrowserRotationRun(t *testing.T) {
	f := newUIFixture(t)
	cn := canary.New()
	f.seedSecret("db-password", cn.Value(1))
	cookie := f.login("boss", "boss@example.test")
	f.grant("boss", identity.RoleAdmin)
	var secretID uuid.UUID
	if err := f.pool.QueryRow(context.Background(), `SELECT id FROM secrets WHERE org_id=$1 AND name='db-password'`, f.org.ID).Scan(&secretID); err != nil {
		t.Fatal(err)
	}

	eng := &browserRotation{release: make(chan struct{})}
	for i := range eng.ids {
		eng.ids[i] = uuid.New()
	}
	t.Cleanup(eng.end)
	journal := audit.NewJournal(f.pool)
	svc := rotation.NewService(rotation.New(f.pool, rotation.Deps{Versions: eng, Carriers: eng, Deployer: eng, Verifier: eng, Revoker: eng, Incident: eng})).WithJournal(journal)
	t.Cleanup(svc.Wait)
	mesh := meshDeps(config.Config{MeshExtension: true}, f.pool, f.local, f.outcomes, meshgate.New(meshgate.NewPG(f.pool), nil, nil, f.logger), journal, f.logger)
	router := api.NewRouter(f.logger, f.pool, api.Deps{Mesh: mesh, Rotations: svc, Carriers: browserCarriers{eng}})

	ctx := context.Background()
	started, err := svc.Start(ctx, rotation.Ref{OrgID: f.org.ID, SecretID: secretID}, rotation.Origin{Actor: audit.Actor{Type: audit.ActorUser, ID: uuid.NewString(), Via: audit.ViaAPI}, Scope: "org:" + f.org.ID.String(), Name: "db-password", Class: "api_token"})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	keep := httptest.NewTLSServer(router)
	t.Cleanup(keep.Close)
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			eng.end()
		}
	}))
	t.Cleanup(control.Close)

	list := keep.URL + "/mesh/ui/secrets/" + secretID.String() + "/rotations"
	domDump := filepath.Join(t.TempDir(), "dom.txt")
	in, _ := json.Marshal(map[string]any{"keep": keep.URL, "cookieName": uiCookie, "cookie": cookie, "list": list, "active": list + "/" + started.RunID.String(),
		"release": control.URL, "shots": os.Getenv("KEEP_MESH_UI_SHOTS"), "domDump": domDump})
	runCtx, cancel := context.WithTimeout(ctx, 150*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "node", "../../../scripts/check-mesh-ui-rotation-browser.mjs")
	cmd.Stdin = bytes.NewReader(in)
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	err = cmd.Run()
	for name, s := range map[string]string{"stdout": out.String(), "stderr": stderr.String()} {
		if cn.In(s) {
			t.Fatalf("canary in the browser script %s", name)
		}
	}
	if err != nil {
		t.Fatalf("browser rotation run failed: %v\n%s", err, strings.TrimSpace(stderr.String()))
	}
	t.Logf("browser rotation run: %s", strings.TrimSpace(out.String()))
	dom, err := os.ReadFile(domDump) //nolint:gosec // G304: a file in t.TempDir()
	if err != nil || !strings.Contains(string(dom), "Rotation in progress") || !strings.Contains(string(dom), "Rotation done") || !strings.Contains(string(dom), "worker-01") {
		t.Fatal("the DOM dump is missing or does not hold the screens it must scan")
	}
	if cn.In(string(dom)) {
		t.Fatal("canary in the browser DOM")
	}
	if cn.In(f.logbuf.String()) {
		t.Fatal("canary in the server log")
	}
}
