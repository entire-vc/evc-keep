//go:build mesh_ui_browser

package app

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/api"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/enrolltoken"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/registry"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

// Real sessions, policy and database decisions; the browser submits the
// production console forms, including their CSRF and frozen binding fields.
func TestMeshUIBrowserYAMLAdoption(t *testing.T) {
	ctx := context.Background()
	f := newMeshFixtureOn(t, scratchPool(t, ctx), false)
	cat := catalog.New(f.pool)
	scope := tenancy.Org(f.org.ID)
	st, err := cat.CreateStore(ctx, f.org.ID, "builtin", "yaml-browser", scope)
	must(t, err)
	ref, err := cat.CreateRef(ctx, catalog.CreateRefInput{Org: f.org.ID, Scope: scope, StoreID: st.ID, Name: "yaml-browser", Class: "prod", Type: "generic", ProviderRef: "builtin://default/yaml-browser"})
	must(t, err)
	version, err := cat.AddVersion(ctx, f.org.ID, ref.ID, "1", "kfp1:k1:abcdefghijklmnop", 32)
	must(t, err)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	must(t, err)
	runner := uuid.New()
	shared := false
	must(t, registry.NewRepo(f.pool).CreateEnrolled(ctx, f.org.ID, runner, "yaml-browser.example.test", "1", time.Now().Add(time.Hour), registry.Enrollment{HPKEPublicKey: key.PublicKey().Bytes(), HostAttrs: &enrolltoken.HostAttrs{UIDShared: &shared}}))
	var requester uuid.UUID
	must(t, f.pool.QueryRow(ctx, `SELECT id FROM users WHERE org_id=$1 AND email='admin@example.test'`, f.org.ID).Scan(&requester))
	approver := f.bearer(tenancy.New(f.pool), "yaml-approver", true)
	session, _, err := identity.NewRepo(f.pool).OpenSession(ctx, identity.NewToken(approver))
	must(t, err)
	repo := deployment.NewRepo(f.pool, audit.NewJournal(f.pool))
	path := "/srv/" + strings.Repeat("long-directory/", 12) + "config.yaml"
	field := "service." + strings.Repeat("long_", 24) + "token"
	ids := make([]string, 0, 2)
	for _, id := range []string{"yaml-browser-approve", "yaml-browser-reject"} {
		out, err := repo.SubmitAdopt(ctx, deployment.AdoptRequest{OrgID: f.org.ID, Scope: scope, SecretID: ref.ID, RunnerID: runner, RequestID: id,
			Target: runnerproto.Target{Kind: runnerproto.TargetYAMLScalar, Path: path, Field: field, Mode: 0o600}, Actor: audit.Actor{Type: audit.ActorUser, ID: requester.String(), Via: audit.ViaAPI}})
		must(t, err)
		if out.Status != deployment.NeedsApproval || out.ApprovalID == uuid.Nil {
			t.Fatal("production adoption did not require approval")
		}
		ids = append(ids, out.ApprovalID.String())
	}
	keep := httptest.NewTLSServer(api.NewRouter(f.logger, f.pool, api.Deps{Deployments: repo, PublicURL: "https://keep.example.test"}))
	t.Cleanup(keep.Close)
	dump := filepath.Join(t.TempDir(), "dom.txt")
	in, err := json.Marshal(map[string]any{"keep": keep.URL, "cookie": session, "ids": ids, "version": version.ID.String(), "runner": runner.String(), "path": path, "field": field, "shots": os.Getenv("KEEP_MESH_UI_SHOTS"), "domDump": dump})
	must(t, err)
	runCtx, cancel := context.WithTimeout(ctx, 150*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "node", "../../../scripts/check-yaml-adoption-browser.mjs")
	cmd.Stdin = bytes.NewReader(in)
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err = cmd.Run(); err != nil {
		t.Fatalf("adoption browser failed: %v\n%s", err, strings.TrimSpace(stderr.String()))
	}
	for i, want := range []string{"approved", "rejected"} {
		a, err := repo.GetApproval(ctx, f.org.ID, uuid.MustParse(ids[i]))
		must(t, err)
		if a.Status != want || a.VersionID != version.ID {
			t.Fatal("browser decision lost its bound version")
		}
	}
	var jobs, writes int
	must(t, f.pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE action='deploy') FROM deployment_jobs WHERE org_id=$1`, f.org.ID).Scan(&jobs, &writes))
	if jobs != 1 || writes != 0 {
		t.Fatal("browser approval created a writer or rejection created a job")
	}
	dom, err := os.ReadFile(dump) //nolint:gosec // G304: file in the test-owned temporary directory
	must(t, err)
	if !strings.Contains(string(dom), "Read-only YAML adoption") || !strings.Contains(string(dom), field) {
		t.Fatal("browser DOM did not contain the adoption destination")
	}
	t.Logf("adoption browser: %s", strings.TrimSpace(out.String()))
}
