package deployment

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

const (
	currentFP   = "kfp1:k1:abcdefghijklmnop" // the fixture's version v1
	unrelatedFP = "kfp1:k1:zzzzzzzzzzzzzzzz"
	foreignFP   = "kfp1:k9:abcdefghijklmnop" // a key id this store never used
)

func (f fixture) discoverRequest(t *testing.T) DiscoverRequest {
	t.Helper()
	return DiscoverRequest{OrgID: f.org, RunnerID: f.runner, StoreID: f.store, RequestID: mustID(t).String(),
		Actor: audit.Actor{Type: audit.ActorUser, ID: f.user.String(), Via: audit.ViaAPI}}
}

func (f fixture) fileCarrier(t *testing.T, path, field string) uuid.UUID {
	t.Helper()
	id := mustID(t)
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO carriers(id,org_id,secret_id,version,host,target_kind,target_path,target_field,last_fp,state)
	 VALUES($1,$2,$3,'v1','test-host','env-file',$4,$5,$6,'registered')`, id, f.org, f.secret, path, field, currentFP); err != nil {
		t.Fatal("insert carrier")
	}
	return id
}

// discoverJob loads the job SubmitDiscover queued, as the runner would get it.
func (f fixture) discoverJob(t *testing.T, requestID string) runnerproto.Job {
	t.Helper()
	var payload []byte
	if err := f.pool.QueryRow(f.ctx, `SELECT job_payload FROM discovery_jobs WHERE org_id=$1 AND request_id=$2`, f.org, requestID).Scan(&payload); err != nil {
		t.Fatal("no discover job")
	}
	job, err := runnerproto.DecodeJob(payload)
	if err != nil {
		t.Fatal("queued discover job does not decode")
	}
	return job
}

func (f fixture) applyDiscover(t *testing.T, job runnerproto.Job, res runnerproto.DiscoverResult) (DiscoverSummary, error) {
	t.Helper()
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal("begin")
	}
	defer func() { _ = tx.Rollback(f.ctx) }()
	sum, err := ApplyDiscoverResultTx(f.ctx, tx, f.org, job, res)
	if err == nil {
		if err = tx.Commit(f.ctx); err != nil {
			t.Fatal("commit")
		}
	}
	return sum, err
}

func finding(path, name, fp string) runnerproto.DiscoverFinding {
	return runnerproto.DiscoverFinding{Path: path, Name: name, Fingerprint: fp, Len: 12}
}

func okReport(findings ...runnerproto.DiscoverFinding) runnerproto.DiscoverResult {
	if findings == nil {
		findings = []runnerproto.DiscoverFinding{}
	}
	return runnerproto.DiscoverResult{OK: true, Findings: findings}
}

func TestSubmitDiscoverIdempotentBusyAndScoped(t *testing.T) {
	f := newFixture(t)
	in := f.discoverRequest(t)
	first, err := f.repo.SubmitDiscover(f.ctx, in)
	if err != nil || !first.Created || first.State != DiscoverPending || first.Host != "test-host" {
		t.Fatalf("submit: %+v %v", first, err)
	}
	again, err := f.repo.SubmitDiscover(f.ctx, in)
	if err != nil || again.Created || again.RequestID != first.RequestID {
		t.Fatalf("same request id must return the first request: %+v %v", again, err)
	}
	if _, err = f.repo.SubmitDiscover(f.ctx, f.discoverRequest(t)); !errors.Is(err, ErrDiscoverBusy) {
		t.Fatalf("second discover on a busy runner = %v", err)
	}
	other := in
	other.StoreID = mustID(t)
	if _, err = f.repo.SubmitDiscover(f.ctx, other); !errors.Is(err, ErrConflict) {
		t.Fatalf("same request id for another store = %v", err)
	}
	foreign := f.discoverRequest(t)
	foreign.OrgID = mustID(t)
	if _, err = f.repo.SubmitDiscover(f.ctx, foreign); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign org = %v", err)
	}
	if _, err = f.repo.DiscoverReport(f.ctx, mustID(t), in.RequestID, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another org must not read the report: %v", err)
	}
	job := f.discoverJob(t, in.RequestID)
	if job.Action != runnerproto.ActionDiscover || job.Secret.StoreID != f.store.String() || job.Secret.Name != "" {
		t.Fatalf("job carries more than the store: %+v", job.Secret)
	}
}

func TestSubmitDiscoverInvalidAndUnknownRunner(t *testing.T) {
	f := newFixture(t)
	bad := f.discoverRequest(t)
	bad.RequestID = "not a request id!"
	if _, err := f.repo.SubmitDiscover(f.ctx, bad); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("bad request id = %v", err)
	}
	unknown := f.discoverRequest(t)
	unknown.RunnerID = mustID(t)
	if _, err := f.repo.SubmitDiscover(f.ctx, unknown); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown runner = %v", err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE stores SET status='disabled' WHERE id=$1`, f.store); err != nil {
		t.Fatal("disable store")
	}
	if _, err := f.repo.SubmitDiscover(f.ctx, f.discoverRequest(t)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a disabled store = %v", err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE stores SET status='active' WHERE id=$1`, f.store); err != nil {
		t.Fatal("enable store")
	}
	// A store owned below the organization is not the caller's to scan with.
	userStore := mustID(t)
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO stores(id,org_id,provider,name,owner_scope_level,owner_scope_id) VALUES($1,$2,'builtin','mine','user',$3)`, userStore, f.org, f.user); err != nil {
		t.Fatal("insert user store")
	}
	scoped := f.discoverRequest(t)
	scoped.StoreID = userStore
	if _, err := f.repo.SubmitDiscover(f.ctx, scoped); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a user-owned store = %v", err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE runners SET revoked_at=now() WHERE id=$1`, f.runner); err != nil {
		t.Fatal("revoke runner")
	}
	if _, err := f.repo.SubmitDiscover(f.ctx, f.discoverRequest(t)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a revoked runner = %v", err)
	}
}

func TestSubmitDiscoverRateLimit(t *testing.T) {
	f := newFixture(t)
	for i := 0; i < MaxDiscoversPerHour; i++ {
		rep, err := f.repo.SubmitDiscover(f.ctx, f.discoverRequest(t))
		if err != nil {
			t.Fatalf("submit %d: %v", i, err)
		}
		if _, err = f.pool.Exec(f.ctx, `UPDATE discovery_jobs SET status='failed',issued_at=now(),result='{"ok":false,"error_class":"discovery_failed"}' WHERE org_id=$1 AND request_id=$2`, f.org, rep.RequestID); err != nil {
			t.Fatal("finish job")
		}
	}
	if _, err := f.repo.SubmitDiscover(f.ctx, f.discoverRequest(t)); !errors.Is(err, ErrDiscoverRateLimited) {
		t.Fatalf("over the hourly cap = %v", err)
	}
}

func TestDiscoverReportExpiresUnansweredJob(t *testing.T) {
	f := newFixture(t)
	in := f.discoverRequest(t)
	if _, err := f.repo.SubmitDiscover(f.ctx, in); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, `ALTER TABLE discovery_jobs DISABLE TRIGGER discovery_jobs_frozen`); err != nil {
		t.Fatal("disable trigger")
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE discovery_jobs SET created_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 second' WHERE org_id=$1`, f.org); err != nil {
		t.Fatal("age job")
	}
	rep, err := f.repo.DiscoverReport(f.ctx, f.org, in.RequestID, 0)
	if err != nil || rep.State != DiscoverExpired {
		t.Fatalf("unanswered past deadline = %+v %v", rep, err)
	}
	if _, err = f.repo.SubmitDiscover(f.ctx, f.discoverRequest(t)); err != nil {
		t.Fatalf("an expired job must free the runner: %v", err)
	}
}

func TestApplyDiscoverComparesAndNeverQueuesWork(t *testing.T) {
	f := newFixture(t)
	a := f.fileCarrier(t, "/srv/a.env", "DB_PASSWORD")
	b := f.fileCarrier(t, "/srv/b.env", "DB_PASSWORD")
	stale := f.fileCarrier(t, "/srv/s.env", "DB_PASSWORD")
	// Carriers a scan of this runner and this store must not speak about.
	f.fileCarrier(t, "/srv/nofield.env", "") // cannot be matched by name
	f.otherCarrier(t, "other-store", "test-host", "active")
	f.otherCarrier(t, "other-host", "elsewhere", "active")
	f.otherCarrier(t, "gone", "test-host", "disabled")
	in := f.discoverRequest(t)
	if _, err := f.repo.SubmitDiscover(f.ctx, in); err != nil {
		t.Fatal(err)
	}
	job := f.discoverJob(t, in.RequestID)
	sum, err := f.applyDiscover(t, job, okReport(
		finding("/srv/a.env", "DB_PASSWORD", currentFP),       // registered, current value
		finding("/srv/s.env", "DB_PASSWORD", unrelatedFP),     // registered, other value
		finding("/srv/copy.env", "DB_PASSWORD", currentFP),    // unregistered file holding a known value
		finding("/srv/other.env", "DB_PASSWORD", unrelatedFP), // unregistered, unrelated value
	))
	if err != nil {
		t.Fatal(err)
	}
	if sum.Match != 1 || sum.Stale != 1 || sum.Sprawl != 2 || sum.UnknownFind != 1 || sum.Findings != 4 || len(sum.Incidents) != 2 {
		t.Fatalf("summary: %+v", sum)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE discovery_jobs SET status='completed',issued_at=now(),result='{"ok":true}' WHERE org_id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	rep, err := f.repo.DiscoverReport(f.ctx, f.org, in.RequestID, 0)
	if err != nil || rep.State != DiscoverCompleted {
		t.Fatalf("report: %+v %v", rep, err)
	}
	got := map[string]DiscoverItem{}
	for _, it := range rep.Items {
		got[it.Path] = it
	}
	want := map[string]struct {
		verdict  DiscoverVerdict
		carrier  uuid.UUID
		incident bool
	}{
		"/srv/a.env":     {VerdictMatch, a, false},
		"/srv/s.env":     {VerdictStale, stale, false},
		"/srv/copy.env":  {VerdictSprawl, uuid.Nil, true},
		"/srv/other.env": {VerdictSprawl, uuid.Nil, false},
		"/srv/b.env":     {VerdictUnknownFind, b, true},
	}
	if len(got) != len(want) {
		t.Fatalf("lines: %d", len(got))
	}
	for path, w := range want {
		g := got[path]
		if g.Verdict != w.verdict || g.CarrierID != w.carrier || g.Incident != w.incident {
			t.Errorf("%s: %+v want %+v", path, g, w)
		}
	}
	for _, path := range []string{"/srv/nofield.env", "/srv/other-store.env", "/srv/other-host.env", "/srv/gone.env"} {
		if _, found := got[path]; found {
			t.Errorf("%s is outside this scan's registry but was reported", path)
		}
	}
	if u := got["/srv/b.env"]; u.Fingerprint != "" || u.Len != 0 {
		t.Errorf("an absent carrier has no observed fingerprint: %+v", u)
	}
	// An unknown carrier is a find for a person: nothing is queued, rotated or deployed.
	var n int
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM deployment_jobs`).Scan(&n); err != nil || n != 0 {
		t.Errorf("deployment_jobs has %d rows after discover (%v)", n, err)
	}
	// A carrier's own state is left to verify: discover only reads it.
	var state string
	if err = f.pool.QueryRow(f.ctx, `SELECT state FROM carriers WHERE id=$1`, b).Scan(&state); err != nil || state != "registered" {
		t.Errorf("carrier state changed by discover: %q %v", state, err)
	}
}

func TestApplyDiscoverIsIdempotent(t *testing.T) {
	f := newFixture(t)
	f.fileCarrier(t, "/srv/a.env", "DB_PASSWORD")
	in := f.discoverRequest(t)
	if _, err := f.repo.SubmitDiscover(f.ctx, in); err != nil {
		t.Fatal(err)
	}
	job := f.discoverJob(t, in.RequestID)
	res := okReport(finding("/srv/a.env", "DB_PASSWORD", currentFP))
	if _, err := f.applyDiscover(t, job, res); err != nil {
		t.Fatal(err)
	}
	sum, err := f.applyDiscover(t, job, res)
	if err != nil || sum.Findings != 0 {
		t.Fatalf("retry stored again: %+v %v", sum, err)
	}
	var n int
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM discovery_observations WHERE org_id=$1`, f.org).Scan(&n); err != nil || n != 1 {
		t.Fatalf("lines after retry: %d %v", n, err)
	}
}

func TestFailedScanProvesNothingAboutAbsence(t *testing.T) {
	f := newFixture(t)
	f.fileCarrier(t, "/srv/a.env", "DB_PASSWORD")
	in := f.discoverRequest(t)
	if _, err := f.repo.SubmitDiscover(f.ctx, in); err != nil {
		t.Fatal(err)
	}
	job := f.discoverJob(t, in.RequestID)
	sum, err := f.applyDiscover(t, job, runnerproto.DiscoverResult{ErrorClass: runnerproto.ErrClassDiscoveryFailed, Findings: []runnerproto.DiscoverFinding{}})
	if err != nil || sum.UnknownFind != 0 || len(sum.Incidents) != 0 {
		t.Fatalf("failed scan: %+v %v", sum, err)
	}
	var n int
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM discovery_observations`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("a failed scan stored %d lines (%v)", n, err)
	}
}

func TestApplyDiscoverRejectsForeignKeyAndStoresNothing(t *testing.T) {
	f := newFixture(t)
	f.fileCarrier(t, "/srv/a.env", "DB_PASSWORD")
	in := f.discoverRequest(t)
	if _, err := f.repo.SubmitDiscover(f.ctx, in); err != nil {
		t.Fatal(err)
	}
	job := f.discoverJob(t, in.RequestID)
	_, err := f.applyDiscover(t, job, okReport(finding("/srv/a.env", "DB_PASSWORD", currentFP), finding("/srv/x.env", "DB_PASSWORD", foreignFP)))
	if !errors.Is(err, ErrDiscoverRejected) {
		t.Fatalf("a fingerprint under an unused key = %v", err)
	}
	var n int
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM discovery_observations`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("a rejected report stored %d lines (%v)", n, err)
	}
	// A store whose versions carry no parsable fingerprint has no key to
	// bind to: any key id would pass, so every report is refused.
	if _, err = f.pool.Exec(f.ctx, `UPDATE secret_versions SET fingerprint=''`); err != nil {
		t.Fatal("blank fingerprints")
	}
	if _, err = f.applyDiscover(t, job, okReport(finding("/srv/a.env", "DB_PASSWORD", foreignFP))); !errors.Is(err, ErrDiscoverRejected) {
		t.Fatalf("a report for a store without any key id = %v", err)
	}
	other := job
	other.Action = runnerproto.ActionVerify
	if _, err = f.applyDiscover(t, other, okReport()); !errors.Is(err, ErrDiscoverRejected) {
		t.Fatalf("a non-discover job = %v", err)
	}
}

func TestDiscoverJournalCarriesNoPathOrFingerprint(t *testing.T) {
	f := newFixture(t)
	f.fileCarrier(t, "/srv/canary-path.env", "CANARY_NAME")
	in := f.discoverRequest(t)
	if _, err := f.repo.SubmitDiscover(f.ctx, in); err != nil {
		t.Fatal(err)
	}
	job := f.discoverJob(t, in.RequestID)
	if _, err := f.applyDiscover(t, job, okReport(finding("/srv/canary-path.env", "CANARY_NAME", unrelatedFP))); err != nil {
		t.Fatal(err)
	}
	var dump string
	if err := f.pool.QueryRow(f.ctx, `SELECT COALESCE(string_agg(row_to_json(a)::text,' '),'') FROM audit_records a WHERE action='carrier.discover'`).Scan(&dump); err != nil || dump == "" {
		t.Fatalf("no discover journal record: %v", err)
	}
	for _, leak := range []string{"canary-path", "CANARY_NAME", unrelatedFP, currentFP} {
		if strings.Contains(dump, leak) {
			t.Errorf("journal holds %q", leak)
		}
	}
}

func TestDiscoveryTablesRefuseWhatContractForbids(t *testing.T) {
	f := newFixture(t)
	c := f.fileCarrier(t, "/srv/a.env", "DB_PASSWORD")
	in := f.discoverRequest(t)
	if _, err := f.repo.SubmitDiscover(f.ctx, in); err != nil {
		t.Fatal(err)
	}
	var job uuid.UUID
	if err := f.pool.QueryRow(f.ctx, `SELECT id FROM discovery_jobs WHERE org_id=$1`, f.org).Scan(&job); err != nil {
		t.Fatal(err)
	}
	insert := func(verdict string, carrier any, fp string, length int, incident any) error {
		_, err := f.pool.Exec(f.ctx, `INSERT INTO discovery_observations(id,org_id,job_id,runner_id,verdict,carrier_id,path,name,fingerprint,length,incident_state,created_at)
		 VALUES($1,$2,$3,$4,$5,$6,'/p',$7,$8,$9,$10,now())`, mustID(t), f.org, job, f.runner, verdict, carrier, "N"+strings.ReplaceAll(mustID(t).String(), "-", ""), fp, length, incident)
		return err
	}
	for name, err := range map[string]error{
		"incident on a match":       insert("match", c, currentFP, 12, "open"),
		"unknown find with a value": insert("unknown_find", c, currentFP, 12, "open"),
		"match without carrier":     insert("match", nil, currentFP, 12, nil),
		"unknown verdict":           insert("fine", c, currentFP, 12, nil),
		"bad fingerprint":           insert("match", c, "sha256:abc", 12, nil),
	} {
		if err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if err := insert("sprawl", nil, unrelatedFP, 12, "open"); err != nil {
		t.Errorf("a sprawl incident must be accepted: %v", err)
	}
	// Path and name are bounded as registration bounds them, in characters.
	at := func(path, name string) error {
		_, err := f.pool.Exec(f.ctx, `INSERT INTO discovery_observations(id,org_id,job_id,runner_id,verdict,carrier_id,path,name,fingerprint,length,incident_state,created_at)
		 VALUES($1,$2,$3,$4,'unknown_find',$5,$6,$7,'',0,'open',now())`, mustID(t), f.org, job, f.runner, c, path, name)
		return err
	}
	longest, field := "/"+strings.Repeat("é", 4095), strings.Repeat("é", 256)
	if err := at(longest, field); err != nil {
		t.Errorf("a registration-length path and field must be accepted: %v", err)
	}
	for name, err := range map[string]error{
		"path past 4096 characters": at(longest+"q", "DB_PASSWORD"),
		"name past 256 characters":  at("/srv/n.env", field+"q"),
		"empty path":                at("", "DB_PASSWORD"),
		"empty name":                at("/srv/e.env", ""),
		"control character in path": at("/srv/\x1b[2J.env", "DB_PASSWORD"),
		"control character in name": at("/srv/c.env", "DB\nPASSWORD"),
	} {
		if err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO discovery_jobs(id,org_id,runner_id,request_id,request_hash,store_id,job_payload,nonce,expires_at,created_at)
	 SELECT $2,org_id,runner_id,$3,request_hash,store_id,job_payload,$4,expires_at,created_at FROM discovery_jobs WHERE id=$1`, job, mustID(t), strings.ReplaceAll(mustID(t).String(), "-", ""), []byte("0123456789abcdef")); err == nil {
		t.Error("a second active discover on one runner was accepted")
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE discovery_jobs SET job_payload='\x7b7d'::bytea WHERE id=$1`, job); err == nil {
		t.Error("a queued job's frozen payload was rewritten")
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE discovery_jobs SET status='completed',issued_at=now(),result='{"ok":true}' WHERE id=$1`, job); err != nil {
		t.Errorf("the lifecycle column must stay writable: %v", err)
	}
}

// otherCarrier registers a carrier the scan of f.store on test-host must
// ignore: of another store, on another host, or of a disabled secret.
func (f fixture) otherCarrier(t *testing.T, kind, host, secretStatus string) {
	t.Helper()
	store, secret := f.store, mustID(t)
	if kind == "other-store" {
		store = mustID(t)
		if _, err := f.pool.Exec(f.ctx, `INSERT INTO stores(id,org_id,provider,name,owner_scope_level,owner_scope_id) VALUES($1,$2,'vault','other','org',$2)`, store, f.org); err != nil {
			t.Fatal("insert store")
		}
	}
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO secrets(id,org_id,scope_level,scope_id,name,class,type,store_id,provider_ref,status) VALUES($1,$2,'org',$2,$3,'dev','generic',$4,$5,$6)`,
		secret, f.org, "SECRET_"+kind, store, "builtin://"+kind, secretStatus); err != nil {
		t.Fatal("insert secret")
	}
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length) VALUES($1,$2,$3,'v1',$4,12)`, mustID(t), f.org, secret, currentFP); err != nil {
		t.Fatal("insert version")
	}
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO carriers(id,org_id,secret_id,version,host,target_kind,target_path,target_field,last_fp,state)
	 VALUES($1,$2,$3,'v1',$4,'env-file',$5,'DB_PASSWORD',$6,'registered')`, mustID(t), f.org, secret, host, "/srv/"+kind+".env", currentFP); err != nil {
		t.Fatal("insert carrier")
	}
}

func TestApplyDiscoverComparesWithTheNewestEnabledVersion(t *testing.T) {
	f := newFixture(t)
	f.fileCarrier(t, "/srv/a.env", "DB_PASSWORD")
	const newest, disabled = "kfp1:k1:bbbbbbbbbbbbbbbb", "kfp1:k1:cccccccccccccccc"
	for _, v := range []struct {
		version, fp string
		off         bool
	}{{"v2", newest, false}, {"v3", disabled, true}} {
		if _, err := f.pool.Exec(f.ctx, `INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length,disabled) VALUES($1,$2,$3,$4,$5,12,$6)`, mustID(t), f.org, f.secret, v.version, v.fp, v.off); err != nil {
			t.Fatal("insert version")
		}
	}
	for fp, want := range map[string]DiscoverVerdict{newest: VerdictMatch, currentFP: VerdictStale, disabled: VerdictStale} {
		in := f.discoverRequest(t)
		if _, err := f.repo.SubmitDiscover(f.ctx, in); err != nil {
			t.Fatal(err)
		}
		sum, err := f.applyDiscover(t, f.discoverJob(t, in.RequestID), okReport(finding("/srv/a.env", "DB_PASSWORD", fp)))
		if err != nil {
			t.Fatal(err)
		}
		got := map[DiscoverVerdict]int{VerdictMatch: sum.Match, VerdictStale: sum.Stale}
		if got[want] != 1 {
			t.Errorf("fingerprint %s: %+v, want a %s line", fp, sum, want)
		}
		if _, err = f.pool.Exec(f.ctx, `UPDATE discovery_jobs SET status='failed',issued_at=now(),result='{"ok":false,"error_class":"discovery_failed"}' WHERE org_id=$1`, f.org); err != nil {
			t.Fatal("finish job")
		}
	}
}

// manyCarriers registers n discoverable carriers of the fixture's secret on
// the runner's host in one statement.
func (f fixture) manyCarriers(t *testing.T, from, n int) {
	t.Helper()
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO carriers(id,org_id,secret_id,version,host,target_kind,target_path,target_field,last_fp,state)
	 SELECT gen_random_uuid(),$1,$2,'v1','test-host','env-file','/srv/many/'||g||'.env','DB_PASSWORD',$3,'registered'
	 FROM generate_series($4::int,$5::int) g`, f.org, f.secret, currentFP, from, from+n-1); err != nil {
		t.Fatal("insert carriers")
	}
}

// Each registered carrier a scan does not see becomes an unknown_find line,
// so the registry one discover compares with is bounded: past the bound the
// request is refused (positive control: exactly the bound is queued) and a
// registry that grew past it after the request gets its report rejected,
// storing nothing. The answer stays within what the CLI reads whole.
func TestDiscoverBoundsTheRegistryItCompares(t *testing.T) {
	f := newFixture(t)
	f.manyCarriers(t, 1, MaxDiscoverCarriers)
	in := f.discoverRequest(t)
	if _, err := f.repo.SubmitDiscover(f.ctx, in); err != nil {
		t.Fatalf("a registry of exactly the bound was refused: %v", err)
	}
	job := f.discoverJob(t, in.RequestID)
	f.manyCarriers(t, MaxDiscoverCarriers+1, 1)
	if _, err := f.applyDiscover(t, job, okReport()); !errors.Is(err, ErrDiscoverRejected) {
		t.Fatalf("a report against a registry past the bound = %v", err)
	}
	var n int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM discovery_observations`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("a rejected report stored %d lines (%v)", n, err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE discovery_jobs SET status='failed',issued_at=now(),result='{"ok":false,"error_class":"discovery_failed"}' WHERE org_id=$1`, f.org); err != nil {
		t.Fatal("finish job")
	}
	if _, err := f.repo.SubmitDiscover(f.ctx, f.discoverRequest(t)); !errors.Is(err, ErrDiscoverTooManyCarriers) {
		t.Fatalf("a registry past the bound = %v", err)
	}
}

// A registered carrier whose path or field is longer than a finding's may be
// would make its unknown_find line larger than the CLI's bound assumes: the
// report is rejected (positive control: the longest allowed path is applied).
// Lines the runner and registration allow are stored, never a failed
// discover: a name of the secret-name pattern (not an env field), and two
// registered carriers of different secrets at one place, which are one
// unknown_find line.
func TestApplyDiscoverStoresEveryLineTheContractAllows(t *testing.T) {
	f := newFixture(t)
	f.otherCarrier(t, "shared", "test-host", "active") // /srv/shared.env DB_PASSWORD
	f.fileCarrier(t, "/srv/shared.env", "DB_PASSWORD")
	in := f.discoverRequest(t)
	if _, err := f.repo.SubmitDiscover(f.ctx, in); err != nil {
		t.Fatal(err)
	}
	sum, err := f.applyDiscover(t, f.discoverJob(t, in.RequestID), okReport(finding("/srv/copy.env", "app/key.v2", currentFP)))
	if err != nil || sum.Sprawl != 1 || sum.UnknownFind != 1 || sum.Findings != 1 || len(sum.Incidents) != 2 {
		t.Fatalf("summary: %+v %v", sum, err)
	}
	var n int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM discovery_observations WHERE org_id=$1`, f.org).Scan(&n); err != nil || n != 2 {
		t.Fatalf("stored %d lines, want 2 (%v)", n, err)
	}
}

func TestApplyDiscoverRejectsAnOversizedRegisteredCarrier(t *testing.T) {
	// Registration allows a target_path of 4096 and a target_field of 256
	// characters; such a carrier is compared, never a reason to fail the
	// host's discovery. Two-byte characters prove the count is in runes.
	f := newFixture(t)
	ok := "/" + strings.Repeat("é", 4095)
	f.fileCarrier(t, ok, strings.Repeat("é", 256))
	in := f.discoverRequest(t)
	if _, err := f.repo.SubmitDiscover(f.ctx, in); err != nil {
		t.Fatal(err)
	}
	job := f.discoverJob(t, in.RequestID)
	if sum, err := f.applyDiscover(t, job, okReport()); err != nil || sum.UnknownFind != 1 {
		t.Fatalf("the longest registrable path and field: %+v %v", sum, err)
	}
	// A row past those limits never came through registration; the bound on
	// the answer still holds.
	for _, c := range []struct{ path, name string }{{ok + "q", "DB_PASSWORD"}, {"/srv/n.env", strings.Repeat("N", 257)}} {
		g := newFixture(t)
		g.fileCarrier(t, c.path, c.name)
		gin := g.discoverRequest(t)
		if _, err := g.repo.SubmitDiscover(g.ctx, gin); err != nil {
			t.Fatal(err)
		}
		if _, err := g.applyDiscover(t, g.discoverJob(t, gin.RequestID), okReport()); !errors.Is(err, ErrDiscoverRejected) {
			t.Fatalf("path %d runes, name %d runes = %v", utf8.RuneCountInString(c.path), utf8.RuneCountInString(c.name), err)
		}
	}
}

// completedReport queues a discover and stores lines straight into the
// report table, past what one apply allows (MaxDiscoverCarriers), so paging
// is proven for any registry size: findings worst-length match lines of the
// carrier at, then one unknown_find line per carrier under /srv/many/.
func (f fixture) completedReport(t *testing.T, findings, unknown int) string {
	t.Helper()
	at := f.fileCarrier(t, "/a.env", "DB_PASSWORD")
	in := f.discoverRequest(t)
	if _, err := f.repo.SubmitDiscover(f.ctx, in); err != nil {
		t.Fatal(err)
	}
	if unknown > 0 {
		f.manyCarriers(t, 1, unknown)
	}
	// A runner's finding: a path of 1023 bytes, most of them '&' (six bytes
	// each on the wire), and a 128-character name.
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO discovery_observations(id,org_id,job_id,runner_id,verdict,carrier_id,path,name,fingerprint,length,incident_state,created_at)
	 SELECT gen_random_uuid(),j.org_id,j.id,j.runner_id,'match',$3,'/a/'||lpad(g::text,5,'0')||'/'||repeat('&',1014),'N'||lpad(g::text,5,'0')||repeat('A',122),$4,1048576,NULL,clock_timestamp()
	 FROM discovery_jobs j, generate_series(1,$5::int) g WHERE j.org_id=$1 AND j.request_id=$2`, f.org, in.RequestID, at, currentFP, findings); err != nil {
		t.Fatalf("insert findings: %v", err)
	}
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO discovery_observations(id,org_id,job_id,runner_id,verdict,carrier_id,path,name,fingerprint,length,incident_state,created_at)
	 SELECT gen_random_uuid(),j.org_id,j.id,j.runner_id,'unknown_find',c.id,c.target_path,c.target_field,'',0,'open',clock_timestamp()
	 FROM discovery_jobs j JOIN carriers c ON c.org_id=j.org_id AND c.target_path LIKE '/srv/many/%' WHERE j.org_id=$1 AND j.request_id=$2`, f.org, in.RequestID); err != nil {
		t.Fatalf("insert unknown_find: %v", err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE discovery_jobs SET status='completed',issued_at=now(),result='{"ok":true}' WHERE org_id=$1 AND request_id=$2`, f.org, in.RequestID); err != nil {
		t.Fatal("complete job")
	}
	return in.RequestID
}

// cliReadLimit is cmd/keep's maxDiscoverResponseBytes: every page must fit
// one read of the CLI.
const cliReadLimit = 64 << 20

// A report larger than one page is read in pages of at most DiscoverPageSize
// lines that cover the whole report once, in order; ok is the whole
// report's, so a first page of matches already says the report is not clean;
// an offset past the report is refused.
func TestDiscoverReportReadsWorstReportInPages(t *testing.T) {
	f := newFixture(t)
	const findings, unknown = runnerproto.MaxDiscoverFindings, runnerproto.MaxDiscoverFindings + 1
	requestID := f.completedReport(t, findings, unknown)
	seen := map[string]bool{}
	pages, offset := 0, 0
	for {
		rep, err := f.repo.DiscoverReport(f.ctx, f.org, requestID, offset)
		if err != nil {
			t.Fatalf("page at %d: %v", offset, err)
		}
		if rep.Total != findings+unknown || rep.Offset != offset || rep.State != DiscoverCompleted {
			t.Fatalf("page at %d: total %d offset %d state %s", offset, rep.Total, rep.Offset, rep.State)
		}
		if rep.AllMatch {
			t.Fatalf("page %d says the report is clean; it holds %d unknown_find lines", pages, unknown)
		}
		if len(rep.Items) > DiscoverPageSize {
			t.Fatalf("page at %d has %d lines, more than %d", offset, len(rep.Items), DiscoverPageSize)
		}
		if pages == 0 {
			for _, it := range rep.Items {
				if it.Verdict != VerdictMatch {
					t.Fatal("fixture: the first page must hold only matches, or ok per page is not tested")
				}
			}
		}
		if b, err := json.Marshal(rep); err != nil || len(b) > cliReadLimit {
			t.Fatalf("page at %d is %d bytes, past the CLI's read (%v)", offset, len(b), err)
		}
		if offset == rep.Total {
			if len(rep.Items) != 0 {
				t.Fatalf("the page at total has %d lines", len(rep.Items))
			}
			break
		}
		if len(rep.Items) == 0 {
			t.Fatalf("empty page at %d of %d", offset, rep.Total)
		}
		for _, it := range rep.Items {
			key := it.Path + "\x00" + it.Name
			if seen[key] {
				t.Fatalf("line %q is on two pages", it.Path)
			}
			seen[key] = true
		}
		offset += len(rep.Items)
		pages++
	}
	if len(seen) != findings+unknown || pages != 3 {
		t.Fatalf("pages covered %d of %d lines in %d pages, want 3", len(seen), findings+unknown, pages)
	}
	for _, bad := range []int{-1, findings + unknown + 1} {
		if _, err := f.repo.DiscoverReport(f.ctx, f.org, requestID, bad); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("offset %d = %v, want invalid argument", bad, err)
		}
	}
	// Positive control: a report of matches only is clean on its one page.
	g := newFixture(t)
	clean := g.completedReport(t, 2, 0)
	if rep, err := g.repo.DiscoverReport(g.ctx, g.org, clean, 0); err != nil || !rep.AllMatch || rep.Total != 2 || len(rep.Items) != 2 {
		t.Fatalf("clean report: %+v %v", rep.Total, err)
	}
	// A report that is not completed has no lines to page through.
	h := newFixture(t)
	in := h.discoverRequest(t)
	if _, err := h.repo.SubmitDiscover(h.ctx, in); err != nil {
		t.Fatal(err)
	}
	if rep, err := h.repo.DiscoverReport(h.ctx, h.org, in.RequestID, 0); err != nil || rep.AllMatch || rep.Total != 0 {
		t.Fatalf("pending report: %+v %v", rep, err)
	}
	if _, err := h.repo.DiscoverReport(h.ctx, h.org, in.RequestID, 1); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("offset 1 of a pending report = %v", err)
	}
}

// Lines may repeat a path and a name (one name seen twice in one file), so
// the page order needs a tie-break: the pages of a report whose every line
// has the same path and name still list each line exactly once, in the order
// of the report as a whole.
func TestDiscoverReportPagesAreStableWhenPathAndNameRepeat(t *testing.T) {
	f := newFixture(t)
	in := f.discoverRequest(t)
	if _, err := f.repo.SubmitDiscover(f.ctx, in); err != nil {
		t.Fatal(err)
	}
	const lines = DiscoverPageSize + 1
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO discovery_observations(id,org_id,job_id,runner_id,verdict,carrier_id,path,name,fingerprint,length,incident_state,created_at)
	 SELECT gen_random_uuid(),j.org_id,j.id,j.runner_id,'sprawl',NULL,'/same.env','SAME','kfp1:k1:'||translate(lpad(g::text,16,'0'),'0123456789','abcdefghij'),0,'open',clock_timestamp()
	 FROM discovery_jobs j, generate_series(1,$3::int) g WHERE j.org_id=$1 AND j.request_id=$2`, f.org, in.RequestID, lines); err != nil {
		t.Fatalf("insert lines: %v", err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE discovery_jobs SET status='completed',issued_at=now(),result='{"ok":true}' WHERE org_id=$1 AND request_id=$2`, f.org, in.RequestID); err != nil {
		t.Fatal("complete job")
	}
	var want []string
	rows, err := f.pool.Query(f.ctx, `SELECT o.fingerprint FROM discovery_observations o JOIN discovery_jobs j ON j.org_id=o.org_id AND j.id=o.job_id
	 WHERE j.org_id=$1 AND j.request_id=$2 ORDER BY o.id`, f.org, in.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			t.Fatal(err)
		}
		want = append(want, fp)
	}
	rows.Close()
	var got []string
	for offset := 0; offset < lines; {
		rep, err := f.repo.DiscoverReport(f.ctx, f.org, in.RequestID, offset)
		if err != nil || len(rep.Items) == 0 {
			t.Fatalf("page at %d: %d lines, %v", offset, len(rep.Items), err)
		}
		for _, it := range rep.Items {
			got = append(got, it.Fingerprint)
		}
		offset += len(rep.Items)
	}
	if len(want) != lines || len(got) != lines {
		t.Fatalf("got %d lines, want %d of %d", len(got), len(want), lines)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("line %d of the paged report is not line %d of the report: the pages repeat or skip lines with the same path and name", i, i)
		}
	}
}

// mcpCarrier registers an mcp-config carrier the way deploy writes one: its
// field is the JSON path mcpServers.<server>.env.<VAR>.
func (f fixture) mcpCarrier(t *testing.T, path, field string) uuid.UUID {
	t.Helper()
	id := mustID(t)
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO carriers(id,org_id,secret_id,version,host,target_kind,target_path,target_field,last_fp,state)
	 VALUES($1,$2,$3,'v1','test-host','mcp-config',$4,$5,$6,'registered')`, id, f.org, f.secret, path, field, currentFP); err != nil {
		t.Fatal("insert carrier")
	}
	return id
}

// A scan names an MCP variable by its env key, the registry by its JSON path:
// the same carrier must still be one match, not an unknown_find plus a sprawl.
func TestApplyDiscoverMatchesAnMCPConfigCarrierByItsVariable(t *testing.T) {
	f := newFixture(t)
	held := f.mcpCarrier(t, "/srv/mcp.json", "mcpServers.gateway.env.GATEWAY_TOKEN")
	changed := f.mcpCarrier(t, "/srv/other-mcp.json", "mcpServers.tools.env.TOOLS_TOKEN")
	gone := f.mcpCarrier(t, "/srv/gone-mcp.json", "mcpServers.gateway.env.GATEWAY_TOKEN")
	// An env file with the same variable name is a different carrier kind: the
	// MCP path rule must not reach it.
	envFile := f.fileCarrier(t, "/srv/gw.env", "mcpServers.gateway.env.GATEWAY_TOKEN")
	in := f.discoverRequest(t)
	if _, err := f.repo.SubmitDiscover(f.ctx, in); err != nil {
		t.Fatal(err)
	}
	sum, err := f.applyDiscover(t, f.discoverJob(t, in.RequestID), okReport(
		finding("/srv/mcp.json", "GATEWAY_TOKEN", currentFP),
		finding("/srv/other-mcp.json", "TOOLS_TOKEN", unrelatedFP),
		finding("/srv/gw.env", "GATEWAY_TOKEN", currentFP),
	))
	if err != nil {
		t.Fatal(err)
	}
	if sum.Match != 1 || sum.Stale != 1 || sum.Sprawl != 1 || sum.UnknownFind != 2 {
		t.Fatalf("summary: %+v", sum)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE discovery_jobs SET status='completed',issued_at=now(),result='{"ok":true}' WHERE org_id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	rep, err := f.repo.DiscoverReport(f.ctx, f.org, in.RequestID, 0)
	if err != nil || rep.State != DiscoverCompleted {
		t.Fatalf("report: %+v %v", rep, err)
	}
	got := map[uuid.UUID]DiscoverVerdict{}
	for _, it := range rep.Items {
		if it.CarrierID != uuid.Nil {
			got[it.CarrierID] = it.Verdict
		}
	}
	for id, want := range map[uuid.UUID]DiscoverVerdict{held: VerdictMatch, changed: VerdictStale, gone: VerdictUnknownFind, envFile: VerdictUnknownFind} {
		if got[id] != want {
			t.Errorf("carrier %s: %q, want %q", id, got[id], want)
		}
	}
}

// A malformed MCP field that reads like a variable is still no scanned name:
// the scan's finding there is an unregistered sprawl and the carrier stays an
// unknown_find, never a match or stale through the collision.
func TestApplyDiscoverMalformedMCPFieldMatchesNothing(t *testing.T) {
	f := newFixture(t)
	bare := f.mcpCarrier(t, "/srv/mcp.json", "GATEWAY_TOKEN")
	dotted := f.mcpCarrier(t, "/srv/mcp.json", "mcpServers.a.b.env.X")
	in := f.discoverRequest(t)
	if _, err := f.repo.SubmitDiscover(f.ctx, in); err != nil {
		t.Fatal(err)
	}
	sum, err := f.applyDiscover(t, f.discoverJob(t, in.RequestID), okReport(
		finding("/srv/mcp.json", "GATEWAY_TOKEN", currentFP),
		finding("/srv/mcp.json", "mcpServers.a.b.env.X", unrelatedFP),
	))
	if err != nil {
		t.Fatal(err)
	}
	if sum.Match != 0 || sum.Stale != 0 || sum.Sprawl != 2 || sum.UnknownFind != 2 {
		t.Fatalf("summary: %+v", sum)
	}
	got := map[uuid.UUID]int{}
	for _, it := range sum.Incidents {
		got[it.CarrierID]++
	}
	if got[bare] != 1 || got[dotted] != 1 {
		t.Fatalf("incidents per carrier: %v", got)
	}
}

// Only a well-formed MCP path maps to its variable; anything else maps to no
// name at all (a finding's name is never empty), so it cannot collide.
func TestDiscoverNameOfARegisteredField(t *testing.T) {
	for _, c := range []struct{ kind, field, want string }{
		{"mcp-config", "mcpServers.gateway.env.GATEWAY_TOKEN", "GATEWAY_TOKEN"},
		{"mcp-config", "mcpServers.a-b_1.env.X", "X"},
		{"mcp-config", "mcpServers.a.b.env.X", ""},
		{"mcp-config", "mcpServers.a/b.env.X", ""},
		{"mcp-config", "mcpServers.gateway.args.GATEWAY_TOKEN", ""},
		{"mcp-config", "mcpServers..env.GATEWAY_TOKEN", ""},
		{"mcp-config", "x.mcpServers.gateway.env.GATEWAY_TOKEN", ""},
		{"mcp-config", "mcpServers.gateway.env.GATEWAY_TOKEN.x", ""},
		{"mcp-config", "GATEWAY_TOKEN", ""},
		{"env-file", "mcpServers.gateway.env.GATEWAY_TOKEN", "mcpServers.gateway.env.GATEWAY_TOKEN"},
		{"env-file", "API_TOKEN", "API_TOKEN"},
	} {
		if got := scanNameOf(c.kind, c.field); got != c.want {
			t.Errorf("scanNameOf(%q, %q) = %q, want %q", c.kind, c.field, got, c.want)
		}
	}
}

// Two MCP servers of one file with one variable are one scanned place: one
// finding there accounts for both, and its absence is an unknown_find of both.
func TestApplyDiscoverTwoMCPServersWithOneVariable(t *testing.T) {
	f := newFixture(t)
	f.mcpCarrier(t, "/srv/mcp.json", "mcpServers.one.env.GATEWAY_TOKEN")
	f.mcpCarrier(t, "/srv/mcp.json", "mcpServers.two.env.GATEWAY_TOKEN")
	f.mcpCarrier(t, "/srv/gone.json", "mcpServers.one.env.GATEWAY_TOKEN")
	f.mcpCarrier(t, "/srv/gone.json", "mcpServers.two.env.GATEWAY_TOKEN")
	in := f.discoverRequest(t)
	if _, err := f.repo.SubmitDiscover(f.ctx, in); err != nil {
		t.Fatal(err)
	}
	sum, err := f.applyDiscover(t, f.discoverJob(t, in.RequestID), okReport(finding("/srv/mcp.json", "GATEWAY_TOKEN", currentFP)))
	if err != nil {
		t.Fatal(err)
	}
	if sum.Match != 1 || sum.Sprawl != 0 || sum.UnknownFind != 2 || len(sum.Incidents) != 2 {
		t.Fatalf("summary: %+v", sum)
	}
	for _, it := range sum.Incidents {
		if it.Path != "/srv/gone.json" {
			t.Errorf("incident outside the missing file: %+v", it)
		}
	}
}
