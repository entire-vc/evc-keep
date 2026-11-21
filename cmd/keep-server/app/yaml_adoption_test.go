package app

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/api"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/builtin/orgpki"
	"github.com/entire-vc/evc-keep/internal/carriers"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/dispatch"
	"github.com/entire-vc/evc-keep/internal/enrolltoken"
	"github.com/entire-vc/evc-keep/internal/mtls"
	"github.com/entire-vc/evc-keep/internal/registry"
	"github.com/entire-vc/evc-keep/internal/targets"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/google/uuid"
)

// This integration starts at dispatch's authenticated mTLS-principal boundary.
// It uses real catalog, policy, sealing, PKI, HPKE, YAML parsing, result
// transactions and API reads. Transport authentication and protected file reads
// have their own tests; no internal service here is replaced by a stand-in.
func TestAdoptDispatchRealCryptoAndCarrierAPI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool := scratchPool(t, ctx)
	f := newMeshFixtureOn(t, pool, false)
	c := canary.New()
	if !c.In(c.Value(1)) {
		t.Fatal("canary detector positive control failed")
	}
	cat := catalog.New(pool)
	scope := tenancy.Org(f.org.ID)
	st, err := cat.CreateStore(ctx, f.org.ID, "builtin", "yaml-adoption", scope)
	must(t, err)
	ref, err := cat.CreateRef(ctx, catalog.CreateRefInput{Org: f.org.ID, Scope: scope, Name: "yaml-adoption", Class: "dev", Type: "generic", ProviderRef: "builtin://default/yaml-adoption", StoreID: st.ID})
	must(t, err)
	prov := f.local.Provider(f.org.ID.String(), "", "", "")
	value := secret.New([]byte(c.Value(1)))
	defer value.Wipe()
	meta, err := prov.Write(ctx, provider.Ref{Path: ref.ProviderRef}, value)
	must(t, err)
	key, err := prov.FingerprintKey(ctx)
	must(t, err)
	fp, err := fingerprint.Compute(key, value)
	key.Wipe()
	must(t, err)
	_, err = cat.AddVersion(ctx, f.org.ID, ref.ID, meta.Version, fp, value.Len())
	must(t, err)

	delivery, err := ecdh.X25519().GenerateKey(rand.Reader)
	must(t, err)
	runnerID := uuid.New()
	shared := false
	reg := registry.NewRepo(pool)
	must(t, reg.CreateEnrolled(ctx, f.org.ID, runnerID, "yaml-adoption.example.test", "1", time.Now().Add(time.Hour), registry.Enrollment{HPKEPublicKey: delivery.PublicKey().Bytes(), HostAttrs: &enrolltoken.HostAttrs{UIDShared: &shared}}))
	pki := orgpki.NewRepoFromLocal(pool, f.local)
	bundle, err := pki.Ensure(ctx, f.org.ID)
	must(t, err)
	journal := audit.NewJournal(pool).WithLogger(f.logger)
	repo := deployment.NewRepo(pool, journal)
	var adminID uuid.UUID
	must(t, pool.QueryRow(ctx, `SELECT id FROM users WHERE org_id=$1 AND email='admin@example.test'`, f.org.ID).Scan(&adminID))
	target := runnerproto.Target{Kind: runnerproto.TargetYAMLScalar, Path: "/srv/yaml-adoption/config.yaml", Field: "service.token", Mode: 0o600}
	_, err = repo.SetPolicy(ctx, deployment.PolicyChange{OrgID: f.org.ID, ExpectRevision: -1, Actor: audit.Actor{Type: audit.ActorUser, ID: adminID.String(), Via: audit.ViaAPI}, Policy: deployment.Policy{AdoptionRules: []deployment.AdoptionRule{{SecretID: ref.ID, RunnerID: runnerID, Kind: target.Kind, Path: target.Path, Field: target.Field}}}})
	must(t, err)
	dis := dispatch.New(pool, journal, pki, f.local)
	f.router = api.NewRouter(f.logger, pool, api.Deps{Deployments: repo, Carriers: carriers.NewService(pool), Catalog: api.CatalogLimit{PerMinute: 10000, Burst: 10000}})
	principal := mtls.Principal{OrgID: f.org.ID, RunnerID: runnerID, Serial: "1"}
	base := fmt.Sprintf("/orgs/%s/secrets/%s/carriers", f.org.ID, ref.ID)

	request := func(method, path string, body any) *httptest.ResponseRecorder {
		t.Helper()
		var payload []byte
		if body != nil {
			payload, err = json.Marshal(body)
			must(t, err)
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(payload))
		r.Header.Set("Authorization", "Bearer "+f.admin)
		r.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		f.router.ServeHTTP(rec, r)
		if c.In(rec.Body.String()) || c.In(f.logbuf.String()) {
			t.Fatal("adoption API or log exposed the canary")
		}
		return rec
	}
	decode := func(raw []byte, into any) {
		t.Helper()
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(into) != nil {
			t.Fatal("unexpected adoption API schema")
		}
	}
	submit := func(id string) api.CarrierAdoptionResult {
		t.Helper()
		rec := request(http.MethodPost, base+"/adopt", map[string]any{"request_id": id, "runner_id": runnerID, "target": map[string]string{"kind": string(target.Kind), "path": target.Path, "field": target.Field}})
		if rec.Code != http.StatusAccepted && rec.Code != http.StatusOK {
			t.Fatalf("adopt submit status=%d", rec.Code)
		}
		var out api.CarrierAdoptionResult
		decode(rec.Body.Bytes(), &out)
		if (out.Status != "pending" && out.Status != "registered") || out.JobID == "" || out.VersionID == "" {
			t.Fatal("adopt did not freeze its job and version")
		}
		return out
	}
	keys := runnerproto.TrustedKeys{bundle.SignKeyID: bundle.SignPubKey}
	me := runnerproto.Identity{OrgID: f.org.ID.String(), RunnerID: runnerID.String()}
	claim := func(out api.CarrierAdoptionResult) runnerproto.Job {
		t.Helper()
		signed, ok, err := dis.Poll(ctx, principal)
		if err != nil || !ok {
			t.Fatal("real dispatch did not issue adoption")
		}
		seen := runnerproto.NewMemJournal()
		job, err := runnerproto.VerifyJob(signed, keys, me, time.Now(), seen)
		if err != nil || job.JobID != out.JobID || job.Action != runnerproto.ActionAdopt || job.Target != target {
			t.Fatal("adoption signature or frozen target failed")
		}
		if _, err = runnerproto.VerifyJob(signed, keys, me, time.Now(), seen); !errors.Is(err, runnerproto.ErrReplay) {
			t.Fatal("runner accepted a replayed signed adoption")
		}
		return job
	}
	observe := func(job runnerproto.Job, scalar string) string {
		t.Helper()
		env, err := dis.Material(ctx, principal, job.JobID)
		if err != nil || len(env.Sealed) != 0 || len(env.SealedFingerprintKey) == 0 {
			t.Fatal("real adoption delivery was not key-only")
		}
		if _, err = dis.Material(ctx, principal, job.JobID); !errors.Is(err, dispatch.ErrNotFound) {
			t.Fatal("adoption key issuance was reusable")
		}
		opened, err := builtin.OpenRunnerKey(job, delivery, env)
		must(t, err)
		defer opened.Wipe()
		findings, err := targets.FingerprintYAML([]byte("service:\n  token: '"+scalar+"'\n"), []string{target.Field}, opened)
		if err != nil || len(findings) != 1 {
			t.Fatal("read-only YAML fingerprint failed")
		}
		return findings[0].Fingerprint
	}
	count := func(sql string) int {
		t.Helper()
		var n int
		must(t, pool.QueryRow(ctx, sql).Scan(&n))
		return n
	}

	bad := claim(submit("adopt-wrong-scalar"))
	wrong := observe(bad, c.Value(2))
	if wrong == fp {
		t.Fatal("wrong-scalar negative control matched")
	}
	must(t, dis.Result(ctx, principal, bad.JobID, runnerproto.Result{ErrorClass: runnerproto.ErrClassFingerprintMismatch, Fingerprint: wrong, Version: bad.ExpectedVersion}))
	if count(`SELECT count(*) FROM carriers`) != 0 || count(`SELECT count(*) FROM carrier_adoption_receipts`) != 0 {
		t.Fatal("wrong YAML scalar registered a carrier")
	}

	out := submit("adopt-genuine")
	job := claim(out)
	result := runnerproto.Result{OK: true, Fingerprint: fp, Version: job.ExpectedVersion}
	if !errors.Is(dis.Result(ctx, principal, job.JobID, result), dispatch.ErrNotFound) {
		t.Fatal("unissued material was accepted as evidence")
	}
	if got := observe(job, c.Value(1)); got != fp {
		t.Fatal("real tenant key did not match the catalog")
	}
	foreign := principal
	foreign.RunnerID = uuid.New()
	if !errors.Is(dis.Result(ctx, foreign, job.JobID, result), dispatch.ErrNotFound) {
		t.Fatal("foreign runner submitted adoption evidence")
	}
	for i := 0; i < 2; i++ {
		must(t, dis.Result(ctx, principal, job.JobID, result))
	}
	if count(`SELECT count(*) FROM carrier_adoption_receipts`) != 1 || count(`SELECT count(*) FROM carriers`) != 1 || count(`SELECT count(*) FROM deployment_jobs WHERE action='deploy'`) != 0 {
		t.Fatal("adoption receipt was not unique or fabricated deployment")
	}
	var got []api.Carrier
	rec := request(http.MethodGet, base, nil)
	decode(rec.Body.Bytes(), &got)
	if rec.Code != http.StatusOK || len(got) != 1 {
		t.Fatal("registered carrier GET failed")
	}
	carrier := got[0]
	if carrier.OrgID != f.org.ID.String() || carrier.SecretID != ref.ID.String() || carrier.Version != meta.Version || carrier.RunnerID != runnerID.String() || carrier.Host != "yaml-adoption.example.test" || carrier.Provenance != "adoption" || carrier.AttestationJobID != job.JobID || carrier.Target != (api.CarrierTarget{Kind: string(target.Kind), Path: target.Path, Field: target.Field}) || carrier.Status != "registered" || !carrier.FingerprintMatch {
		t.Fatal("carrier GET lost an attested reference")
	}
	var completed api.CarrierAdoptionResult
	rec = request(http.MethodGet, base+"/adopt/adopt-genuine", nil)
	decode(rec.Body.Bytes(), &completed)
	if rec.Code != http.StatusOK || !completed.OK || completed.Status != "registered" || completed.JobID != job.JobID || completed.VersionID != out.VersionID {
		t.Fatal("completed adoption GET lost its receipt")
	}
	if again := submit("adopt-genuine"); again.JobID != job.JobID {
		t.Fatal("idempotent adoption made another job")
	}
	if rec := request(http.MethodGet, "/v1/deployments/adopt-genuine", nil); rec.Code != http.StatusNotFound {
		t.Fatal("adoption appeared as a completed deployment")
	}
	// Continue through the public verification and discovery surfaces. Each
	// observation uses a fresh signed job and its real, action-bound HPKE key.
	for i, scalar := range []string{c.Value(1), c.Value(2), c.Value(1)} {
		id := fmt.Sprintf("adopt-verify-%d", i)
		if request(http.MethodPost, base+"/verify", map[string]string{"request_id": id}).Code != http.StatusAccepted {
			t.Fatal("adopted YAML verification was not queued")
		}
		signed, ok, err := dis.Poll(ctx, principal)
		must(t, err)
		if !ok {
			t.Fatal("verification job unavailable")
		}
		vjob, err := runnerproto.VerifyJob(signed, keys, me, time.Now(), runnerproto.NewMemJournal())
		must(t, err)
		if vjob.Action != runnerproto.ActionVerify || vjob.Target != target {
			t.Fatal("verification lost the exact YAML field")
		}
		observed := observe(vjob, scalar)
		match := observed == fp
		res := runnerproto.Result{OK: match, Fingerprint: observed}
		want := "mismatch"
		if match {
			res.Version, want = vjob.ExpectedVersion, "match"
		} else {
			res.ErrorClass = runnerproto.ErrClassFingerprintMismatch
		}
		must(t, dis.Result(ctx, principal, vjob.JobID, res))
		var report api.CarrierVerifyResult
		rec := request(http.MethodGet, base+"/verify/"+id, nil)
		decode(rec.Body.Bytes(), &report)
		if rec.Code != http.StatusOK || report.OK != match || len(report.Carriers) != 1 || report.Carriers[0].Status != want || report.Carriers[0].Target.Field != target.Field || report.Carriers[0].FingerprintMatch == nil || *report.Carriers[0].FingerprintMatch != match {
			t.Fatal("YAML verify report lost its match or field")
		}
	}
	discoveryPath := fmt.Sprintf("/orgs/%s/carriers/discover", f.org.ID)
	if request(http.MethodPost, discoveryPath, map[string]string{"request_id": "adopt-discover", "runner_id": runnerID.String(), "store_id": st.ID.String()}).Code != http.StatusAccepted {
		t.Fatal("adopted YAML discovery was not queued")
	}
	signed, ok, err := dis.Poll(ctx, principal)
	must(t, err)
	if !ok {
		t.Fatal("discovery job unavailable")
	}
	djob, err := runnerproto.VerifyJob(signed, keys, me, time.Now(), runnerproto.NewMemJournal())
	must(t, err)
	if djob.Action != runnerproto.ActionDiscover {
		t.Fatal("discovery received another action")
	}
	envelope, err := dis.Material(ctx, principal, djob.JobID)
	must(t, err)
	dkey, err := builtin.OpenDiscoverKey(djob, delivery, envelope)
	must(t, err)
	findings, err := targets.FingerprintYAML([]byte("service:\n  token: '"+c.Value(1)+"'\n"), []string{target.Field}, dkey)
	dkey.Wipe()
	must(t, err)
	if len(findings) != 1 {
		t.Fatal("discovery did not select the YAML scalar")
	}
	dbody, err := json.Marshal(runnerproto.DiscoverResult{OK: true, Findings: []runnerproto.DiscoverFinding{{Path: target.Path, Name: target.Field, Fingerprint: findings[0].Fingerprint, Len: value.Len()}}})
	must(t, err)
	must(t, dis.ResultBody(ctx, principal, djob.JobID, dbody))
	var discovery api.CarrierDiscoverResult
	rec = request(http.MethodGet, discoveryPath+"/adopt-discover", nil)
	decode(rec.Body.Bytes(), &discovery)
	if rec.Code != http.StatusOK || !discovery.OK || discovery.State != "completed" || discovery.Total != 1 || len(discovery.Findings) != 1 || discovery.Findings[0].Name != target.Field || discovery.Findings[0].Verdict != "match" || discovery.Findings[0].CarrierID != carrier.ID || discovery.Findings[0].Incident {
		t.Fatal("adopted YAML was lost or reported unknown by discovery")
	}

	// Even a new catalog version with identical bytes invalidates an old job.
	stale := claim(submit("adopt-stale-current"))
	staleFP := observe(stale, c.Value(1))
	newMeta, err := prov.Write(ctx, provider.Ref{Path: ref.ProviderRef}, value)
	must(t, err)
	_, err = cat.AddVersion(ctx, f.org.ID, ref.ID, newMeta.Version, fp, value.Len())
	must(t, err)
	if !errors.Is(dis.Result(ctx, principal, stale.JobID, runnerproto.Result{OK: true, Fingerprint: staleFP, Version: stale.ExpectedVersion}), dispatch.ErrNotFound) || count(`SELECT count(*) FROM carrier_adoption_receipts`) != 1 {
		t.Fatal("changed current version accepted stale adoption")
	}
	if _, err := pool.Exec(ctx, `UPDATE runners SET revoked_at=clock_timestamp() WHERE org_id=$1 AND id=$2`, f.org.ID, runnerID); err != nil {
		t.Fatal("revoke disposable trust")
	}
	if !errors.Is(dis.Result(ctx, principal, job.JobID, result), dispatch.ErrNotFound) {
		t.Fatal("revoked runner replay was acknowledged")
	}
}
