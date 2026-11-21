package api

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/carriers"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/enrolltoken"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/registry"
	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type adoptAPIFixture struct {
	*routeFixture
	repo         *deployment.Repo
	secret       tenancy.SecretRef
	runner       uuid.UUID
	bearer, path string
}

// All admission, identity, registry, approval and catalog boundaries are real.
// Each test owns a throwaway database; no internal service is mocked.
func newAdoptAPIFixture(t *testing.T) adoptAPIFixture {
	t.Helper()
	ctx := context.Background()
	dsn := pgscratch.New(t, nil)
	db, err := store.OpenMigrationDB(ctx, dsn)
	if err != nil {
		t.Fatal("open adoption API database")
	}
	p, err := store.NewProvider(db)
	if err != nil {
		t.Fatal("open adoption API migrations")
	}
	if _, err = p.Up(ctx); err != nil {
		t.Fatal("migrate adoption API database")
	}
	if err = db.Close(); err != nil {
		t.Fatal("close migration connection")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("open adoption API pool")
	}
	t.Cleanup(pool.Close)
	rf := newRouteFixtureOn(t, pool)
	r := deployment.NewRepo(pool, audit.NewJournal(pool))
	f := adoptAPIFixture{routeFixture: rf, repo: r, runner: uuid.New()}
	admin := f.mustAdmin("adoption-admin")
	f.bearer = f.mustToken(identity.KindUser, admin.ID, "org:"+f.org.ID.String())
	st := f.mustStore("adoption-test", tenancy.Org(f.org.ID))
	f.secret, err = f.cat.CreateRef(f.ctx, catalog.CreateRefInput{Org: f.org.ID, Scope: tenancy.Org(f.org.ID), Name: "yaml-test", Class: "dev", Type: "generic", ProviderRef: "disposable-reference", StoreID: st.ID})
	if err != nil {
		t.Fatal("create disposable adoption reference")
	}
	if _, err = f.cat.AddVersion(f.ctx, f.org.ID, f.secret.ID, "1", carrierVersionFP, 12); err != nil {
		t.Fatal("create disposable current version")
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate disposable runner key")
	}
	shared := false
	if err = registry.NewRepo(pool).CreateEnrolled(f.ctx, f.org.ID, f.runner, "disposable-yaml-host", "1", time.Now().Add(time.Hour), registry.Enrollment{HPKEPublicKey: key.PublicKey().Bytes(), HostAttrs: &enrolltoken.HostAttrs{UIDShared: &shared}}); err != nil {
		t.Fatal("enroll disposable runner")
	}
	if _, err = r.SetPolicy(f.ctx, deployment.PolicyChange{OrgID: f.org.ID, ExpectRevision: -1, Actor: audit.Actor{Type: audit.ActorUser, ID: admin.ID.String(), Via: audit.ViaAPI}, Policy: deployment.Policy{AdoptionRules: []deployment.AdoptionRule{{SecretID: f.secret.ID, RunnerID: f.runner, Kind: runnerproto.TargetYAMLScalar, Path: "/srv/app/config.yaml", Field: "service.token"}}}}); err != nil {
		t.Fatal("set exact adoption policy")
	}
	f.path = fmt.Sprintf("/orgs/%s/secrets/%s/carriers/adopt", f.org.ID, f.secret.ID)
	f.router = NewRouter(obs.New(f.logbuf), pool, Deps{Catalog: unlimitedCatalog, Deployments: r, Carriers: carriers.NewService(pool)})
	return f
}

func (f adoptAPIFixture) body(id string) map[string]any {
	return map[string]any{"request_id": id, "runner_id": f.runner.String(), "target": map[string]any{"kind": "yaml-scalar", "path": "/srv/app/config.yaml", "field": "service.token"}}
}

func (f adoptAPIFixture) count(t *testing.T, sql string) int {
	t.Helper()
	var n int
	if f.pool.QueryRow(f.ctx, sql).Scan(&n) != nil {
		t.Fatal("count adoption metadata")
	}
	return n
}

func TestAdoptAPIQueuesAndRetriesOnlyTheCurrentRead(t *testing.T) {
	f := newAdoptAPIFixture(t)
	var first CarrierAdoptionResult
	for i := 0; i < 2; i++ {
		rec := f.do(http.MethodPost, f.path, f.bearer, f.body("adopt-api-1"))
		if rec.Code != http.StatusAccepted || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("adopt status=%d", rec.Code)
		}
		var row CarrierAdoptionResult
		decodeClosed(t, rec.Body.Bytes(), &row)
		if row.OK || row.Status != "pending" || row.RequestID != "adopt-api-1" || row.VersionID == "" || row.JobID == "" || row.Approval != nil {
			t.Fatal("adoption did not return closed pending references")
		}
		if i == 0 {
			first = row
		} else if row != first {
			t.Fatal("retry changed the bound job")
		}
	}
	rec := f.do(http.MethodGet, f.path+"/adopt-api-1", f.bearer, nil)
	if rec.Code != http.StatusAccepted {
		t.Fatal("bound adoption status unavailable")
	}
	if f.count(t, `SELECT count(*) FROM deployment_jobs WHERE action='adopt'`) != 1 || f.count(t, `SELECT count(*) FROM carriers`) != 0 || f.count(t, `SELECT count(*) FROM deployment_jobs WHERE action='deploy'`) != 0 {
		t.Fatal("API request fabricated delivery evidence")
	}
	if rec = f.do(http.MethodGet, "/v1/deployments/adopt-api-1", f.bearer, nil); rec.Code != http.StatusNotFound {
		t.Fatal("adoption appeared on the deployment surface")
	}
	wrong := f.body("adopt-api-1")
	wrong["target"].(map[string]any)["field"] = "other.token"
	if f.do(http.MethodPost, f.path, f.bearer, wrong).Code != http.StatusConflict {
		t.Fatal("request id accepted a changed destination")
	}
}

func TestAdoptAPIRefusesInjectedEvidenceWithoutLeakingIt(t *testing.T) {
	f := newAdoptAPIFixture(t)
	c := canary.New()
	if !c.In(c.Value(1)) {
		t.Fatal("blind canary detector")
	}
	for _, key := range []string{"fingerprint", "value", "version", "version_id", "host", "provenance", "healthcheck", "consumer", "org_id", "attestation_job_id"} {
		for _, nested := range []bool{false, true} {
			body := f.body("injected-evidence")
			if nested {
				body["target"].(map[string]any)[key] = c.Value(1)
			} else {
				body[key] = c.Value(1)
			}
			rec := f.do(http.MethodPost, f.path, f.bearer, body)
			if rec.Code != http.StatusBadRequest || c.In(rec.Body.String()) || c.In(f.logbuf.String()) {
				t.Fatal("injected evidence was accepted or exposed")
			}
		}
	}
	for _, field := range []string{"service.*", "service..token", "service[0].token", "service."} {
		body := f.body("invalid-field")
		body["target"].(map[string]any)["field"] = field
		if f.do(http.MethodPost, f.path, f.bearer, body).Code != http.StatusBadRequest {
			t.Fatal("ambiguous YAML selector accepted")
		}
	}
	if f.count(t, `SELECT count(*) FROM deployment_requests`) != 0 {
		t.Fatal("rejected input reached admission")
	}
	if f.do(http.MethodPost, f.path, f.bearer, f.body("positive-control")).Code != http.StatusAccepted {
		t.Fatal("positive API control failed")
	}
}

func TestAdoptAPIRequiresSeparatePermissionAndExactPolicy(t *testing.T) {
	f := newAdoptAPIFixture(t)
	dev := f.mustUser("developer")
	if _, err := f.tr.CreateMembership(f.ctx, f.org.ID, dev.ID, tenancy.Org(f.org.ID), string(identity.RoleMember)); err != nil {
		t.Fatal("grant deployment role")
	}
	devToken := f.mustToken(identity.KindUser, dev.ID, "org:"+f.org.ID.String())
	for _, bearer := range []string{devToken, f.mustToken(identity.KindUser, f.mustUser("stranger").ID, "org:"+f.org.ID.String())} {
		if f.do(http.MethodPost, f.path, bearer, f.body("forbidden-role")).Code != http.StatusNotFound {
			t.Fatal("a deployment right granted adoption")
		}
	}
	foreign := strings.Replace(f.path, f.org.ID.String(), uuid.NewString(), 1)
	if f.do(http.MethodPost, foreign, f.bearer, f.body("foreign-org")).Code != http.StatusNotFound {
		t.Fatal("foreign org route was reachable")
	}
	body := f.body("neighbor-field")
	body["target"].(map[string]any)["field"] = "other.token"
	rec := f.do(http.MethodPost, f.path, f.bearer, body)
	var out CarrierAdoptionResult
	decodeClosed(t, rec.Body.Bytes(), &out)
	if rec.Code != http.StatusAccepted || out.Status != "approval_required" || out.Approval == nil || out.JobID != "" || f.count(t, `SELECT count(*) FROM deployment_jobs`) != 0 {
		t.Fatal("an unlisted destination ran without bound human approval")
	}
	a, err := f.repo.GetApproval(f.ctx, f.org.ID, uuid.MustParse(out.Approval.ID))
	if err != nil || !a.Adopt || a.Target.Field != "other.token" || a.VersionID.String() != out.VersionID {
		t.Fatal("approval did not identify the exact read-only operation")
	}
	view := toCard(a, "test-csrf")
	view.CanDecide = true
	var rendered strings.Builder
	if err := consoleTemplates.ExecuteTemplate(&rendered, "card", view); err != nil {
		t.Fatal("render bound adoption approval")
	}
	card := rendered.String()
	for _, want := range []string{"Read-only YAML adoption", "Approve adoption", out.VersionID, a.Target.Path, a.Target.Field, a.RunnerID.String(), a.BindingHash} {
		if !strings.Contains(card, want) {
			t.Fatal("approval card omitted a bound adoption reference")
		}
	}
	if hasDeploymentTargetRows(card) || !strings.Contains(listTarget(a), "Read-only adoption") || !strings.Contains(listTarget(a), a.Target.Field) {
		t.Fatal("adoption was presented as permission to write")
	}
	if f.do(http.MethodPost, f.path, f.bearer, f.body("allowed-control")).Code != http.StatusAccepted {
		t.Fatal("authorized exact policy control failed")
	}
}
