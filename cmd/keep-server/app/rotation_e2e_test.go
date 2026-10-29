package app

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/entire-vc/evc-keep/internal/api"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/carriers"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/intake"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/rotation"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/google/uuid"
)

const rotProviderRef = "builtin://default/rot-e2e"

// rotFixture is keep-server's real wiring (newRotations) over a real database
// and the real sealing store. The only stand-in is the runner: a goroutine that
// answers queued deployment and verify jobs the way an enrolled runner does.
type rotFixture struct {
	t          *testing.T
	f          *meshFixture
	local      *builtin.Local
	svc        api.RotationService
	input      *intake.Service
	router     http.Handler
	logbuf     *syncBuf
	stopSweep  context.CancelFunc // stops the fixture's own pending-layout sweeper
	org        uuid.UUID
	secretID   uuid.UUID
	path       string
	oldValue   string
	carriers   []uuid.UUID
	failDeploy map[uuid.UUID]bool
	generated  string      // the value the generator will produce, known from its entropy
	typed      string      // set when a human entered the value
	paused     atomic.Bool // the stub runner leaves queued jobs alone
}

func newRotFixture(t *testing.T, nCarriers int) *rotFixture {
	t.Helper()
	ctx := context.Background()
	pool := testPool(t)
	mf := newMeshFixtureOn(t, pool, false)
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	var buf syncBuf
	logger := obs.New(&buf)
	local, err := builtin.NewLocal(pool, "rot-test-root", raw, logger, nopAudit)
	if err != nil {
		t.Fatalf("local: %v", err)
	}
	r := &rotFixture{t: t, f: mf, local: local, logbuf: &buf, org: mf.org.ID, failDeploy: map[uuid.UUID]bool{}}
	cat := catalog.New(pool)
	owner := tenancy.Org(r.org)
	st, err := cat.CreateStore(ctx, r.org, "builtin", "rot-store", owner)
	must(t, err)
	_, err = cat.CreateStoreBinding(ctx, r.org, owner, st.ID)
	must(t, err)
	ref, err := cat.CreateRef(ctx, catalog.CreateRefInput{Org: r.org, Scope: owner, Name: "rot-secret", Class: "credential", Type: "generic", ProviderRef: rotProviderRef, StoreID: st.ID})
	must(t, err)
	r.secretID, r.path = ref.ID, rotProviderRef

	c := canary.New()
	r.oldValue = c.Value(1)
	prov := local.Provider(r.org.String(), "", "", "")
	val := secret.New([]byte(r.oldValue))
	meta, err := prov.Write(ctx, provider.Ref{Path: r.path}, val)
	must(t, err)
	key, err := prov.FingerprintKey(ctx)
	must(t, err)
	fp, err := fingerprint.Compute(key, val)
	key.Wipe()
	must(t, err)
	_, err = cat.AddVersion(ctx, r.org, ref.ID, meta.Version, fp, val.Len())
	must(t, err)

	// One enrolled runner, a policy that admits the env files, and the earlier
	// delivery of version 1 to every carrier.
	rk, err := ecdh.X25519().GenerateKey(rand.Reader)
	must(t, err)
	runner := uuid.New()
	host := "rot-host.example.test"
	_, err = pool.Exec(ctx, `INSERT INTO runners(id,org_id,host,cert_serial,cert_not_after,hpke_public_key,uid_shared,host_labels,attrs_source) VALUES($1,$2,$3,'01',now()+interval '1 day',$4,false,'{}','enroll_token')`, runner, r.org, host, rk.PublicKey().Bytes())
	must(t, err)
	rules, _ := json.Marshal(map[string]any{"rules": []map[string]any{{"secret_id": ref.ID.String(), "runner_id": runner.String(), "kind": "env-file", "path_prefix": "/srv/rot"}}})
	_, err = pool.Exec(ctx, `INSERT INTO deployment_policies(org_id,rules) VALUES($1,$2)`, r.org, rules)
	must(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO users(id,org_id,email) VALUES($1,$2,'approver@example.test')`, uuid.New(), r.org)
	must(t, err)
	var versionID, storeID uuid.UUID
	must(t, pool.QueryRow(ctx, `SELECT v.id,s.store_id FROM secret_versions v JOIN secrets s ON s.org_id=v.org_id AND s.id=v.secret_id WHERE v.org_id=$1 AND v.secret_id=$2`, r.org, ref.ID).Scan(&versionID, &storeID))
	for i := 0; i < nCarriers; i++ {
		cid := uuid.New()
		r.carriers = append(r.carriers, cid)
		target := runnerproto.Target{Kind: runnerproto.TargetEnvFile, Path: fmt.Sprintf("/srv/rot/app%d.env", i), Field: "TOKEN", Mode: 0o600}
		tj, _ := json.Marshal(target)
		_, err = pool.Exec(ctx, `INSERT INTO carriers(org_id,id,secret_id,version,host,target_kind,target_path,target_field,consumer,healthcheck_ref,last_fp,state,last_verified_at)
		 VALUES($1,$2,$3,$4,$5,'env-file',$6,'TOKEN','','',$7,'registered',now())`, r.org, cid, ref.ID, meta.Version, host, target.Path, fp)
		must(t, err)
		reqRow, jobID := uuid.New(), uuid.New()
		reqID := strings.ReplaceAll(reqRow.String(), "-", "")[:30]
		hash := bytes.Repeat([]byte{byte(i + 1)}, 32)
		_, err = pool.Exec(ctx, `INSERT INTO deployment_requests(id,org_id,request_id,request_hash,target_key,secret_id,version_id,runner_id,secret_scope_level,secret_scope_id,target,decision)
		 VALUES($1,$2,$3,$4,$4,$5,$6,$7,'org',$2,$8,'queued')`, reqRow, r.org, reqID, hash, ref.ID, versionID, runner, tj)
		must(t, err)
		res, _ := json.Marshal(runnerproto.Result{OK: true, Fingerprint: fp, Version: meta.Version})
		nonce := make([]byte, 16)
		_, _ = rand.Read(nonce)
		_, err = pool.Exec(ctx, `INSERT INTO deployment_jobs(id,org_id,runner_id,deployment_request_id,request_id,secret_id,version_id,secret_scope_level,secret_scope_id,store_id,store_owner_scope_level,store_owner_scope_id,provider,provider_ref,provider_version,catalog_name,catalog_class,job_payload,nonce,expires_at,created_at,status,issued_at,result)
		 VALUES($1,$2,$3,$4,$5,$6,$7,'org',$2,$8,'org',$2,'builtin',$9,$10,'rot-secret','credential','\x00',$11,now()+interval '10 minutes',now(),'completed',now(),$12)`,
			jobID, r.org, runner, reqRow, reqID, ref.ID, versionID, storeID, r.path, meta.Version, nonce, res)
		must(t, err)
	}

	ent := make([]byte, 32)
	_, _ = rand.Read(ent)
	r.generated = base64.RawURLEncoding.EncodeToString(ent)
	r.svc = newRotationsWith(bytes.NewReader(ent), pool, local, deployment.NewRepo(pool, audit.NewJournal(pool).WithLogger(logger)), carriers.NewService(pool), logger)
	r.input, err = newInputService(pool, local, "http://127.0.0.1", logger)
	must(t, err)
	sweep := wireRotationInput(r.input, r.svc, pool, logger)
	r.router = api.NewRouter(logger, pool, api.Deps{Rotations: r.svc, Input: r.input, Catalog: api.CatalogLimit{PerMinute: 100000, Burst: 100000}})
	ctxRun, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	go r.runner(ctxRun)
	sweepCtx, stopSweep := context.WithCancel(ctxRun)
	r.stopSweep = stopSweep
	go runPendingLayouts(sweepCtx, sweep)
	t.Cleanup(func() {
		if w, ok := r.svc.(interface{ Wait() }); ok {
			w.Wait()
		}
	})
	return r
}

func (r *rotFixture) runner(ctx context.Context) {
	pool := r.f.pool
	for ctx.Err() == nil {
		time.Sleep(20 * time.Millisecond)
		if r.paused.Load() {
			continue
		}
		rows, err := pool.Query(ctx, `SELECT j.id, j.action, j.provider_version, v.fingerprint, j.deployment_request_id,
			(SELECT c.id FROM carriers c WHERE c.org_id=j.org_id AND c.secret_id=j.secret_id AND c.target_path=(dr.target->>'Path'))
			FROM deployment_jobs j JOIN secret_versions v ON v.id=j.version_id JOIN deployment_requests dr ON dr.id=j.deployment_request_id
			WHERE j.org_id=$1 AND j.status='queued'`, r.org)
		if err != nil {
			continue
		}
		type job struct {
			id              uuid.UUID
			action, ver, fp string
			req             uuid.UUID
			carrier         uuid.UUID
		}
		var jobs []job
		for rows.Next() {
			var j job
			if rows.Scan(&j.id, &j.action, &j.ver, &j.fp, &j.req, &j.carrier) == nil {
				jobs = append(jobs, j)
			}
		}
		rows.Close()
		for _, j := range jobs {
			res := runnerproto.Result{OK: true, Fingerprint: j.fp, Version: j.ver}
			state, class := "match", ""
			if j.action == "deploy" && r.failDeploy[j.carrier] {
				res = runnerproto.Result{ErrorClass: runnerproto.ErrClassPolicyDenied}
			}
			enc, _ := json.Marshal(res)
			status := "completed"
			if !res.OK {
				status = "failed"
			}
			_, _ = pool.Exec(ctx, `UPDATE deployment_jobs SET status=$2,issued_at=now(),result=$3 WHERE id=$1`, j.id, status, enc)
			if j.action == "verify" {
				_, _ = pool.Exec(ctx, `UPDATE carrier_verification_items SET state=$3,error_class=$4,completed_at=now() WHERE job_id=$1 AND org_id=$2`, j.id, r.org, state, class)
			}
		}
	}
}

func (r *rotFixture) do(method, path string, body any) *httptest.ResponseRecorder {
	r.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Authorization", "Bearer "+r.f.admin)
	rec := httptest.NewRecorder()
	r.router.ServeHTTP(rec, req)
	return rec
}

func (r *rotFixture) rotatePath() string {
	return fmt.Sprintf("/orgs/%s/secrets/%s/rotate", r.org, r.secretID)
}

// surfaces is everything a value could have reached: bodies and headers seen,
// the log, and every table the rotation writes.
// syncBuf is a log sink the background run goroutines write while the test reads.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.b.Bytes()...)
}

func (s *syncBuf) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Len()
}

func (r *rotFixture) surfaces(seen []string) string {
	r.t.Helper()
	var b strings.Builder
	for _, s := range seen {
		b.WriteString(s)
	}
	b.Write(r.logbuf.Bytes())
	for _, tbl := range []string{"rotation_runs", "rotation_keys", "rotation_intents", "audit_records", "deployment_requests", "deployment_jobs", "carriers", "secret_versions", "carrier_verification_items", "intake_links", "intake_rotation_links"} {
		rows, err := r.f.pool.Query(context.Background(), fmt.Sprintf(`SELECT row_to_json(t)::text FROM %s t`, tbl))
		if err != nil {
			r.t.Fatalf("dump %s: %v", tbl, err)
		}
		for rows.Next() {
			var s string
			_ = rows.Scan(&s)
			b.WriteString(s)
		}
		rows.Close()
	}
	return b.String()
}

func (r *rotFixture) record(rec *httptest.ResponseRecorder) string {
	var b strings.Builder
	b.WriteString(rec.Body.String())
	for k, v := range rec.Header() {
		b.WriteString(k + strings.Join(v, ","))
	}
	return b.String()
}

// newValue is the value the run laid out: what the human typed, else what the
// generator was fed. Outside the plaintext zone nothing reads it back.
func (r *rotFixture) newValue() string {
	if r.typed != "" {
		return r.typed
	}
	return r.generated
}

func (r *rotFixture) fingerprintOf(v string) string {
	r.t.Helper()
	fk, err := r.local.Provider(r.org.String(), "", "", "").FingerprintKey(context.Background())
	must(r.t, err)
	defer fk.Wipe()
	fp, err := fingerprint.Compute(fk, secret.New([]byte(v)))
	must(r.t, err)
	return fp
}

func (r *rotFixture) poll(id string, seen *[]string) api.RotateResult {
	r.t.Helper()
	for i := 0; i < 400; i++ {
		rec := r.do(http.MethodGet, r.rotatePath()+"/"+id, nil)
		*seen = append(*seen, r.record(rec))
		if rec.Code == http.StatusOK {
			var got api.RotateResult
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				r.t.Fatalf("status shape: %v", err)
			}
			return got
		}
		if rec.Code != http.StatusAccepted {
			r.t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		time.Sleep(25 * time.Millisecond)
	}
	var state, class string
	_ = r.f.pool.QueryRow(context.Background(), `SELECT state,error_class FROM rotation_runs WHERE id=$1`, id).Scan(&state, &class)
	r.t.Fatalf("run did not finish: state %q class %q", state, class)
	return api.RotateResult{}
}

func (r *rotFixture) start(seen *[]string) string {
	r.t.Helper()
	rec := r.do(http.MethodPost, r.rotatePath(), map[string]string{"mode": "generate"})
	*seen = append(*seen, r.record(rec))
	var got api.RotateResult
	if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.RequestID == "" {
		r.t.Fatalf("start: %d %s", rec.Code, rec.Body.String())
	}
	return got.RequestID
}

func (r *rotFixture) activeVersions() []string {
	rows, err := r.f.pool.Query(context.Background(), `SELECT version::text FROM keep_envelope WHERE secret_id=$1 AND status='active' ORDER BY version`, r.path)
	if err != nil {
		r.t.Fatalf("versions: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		_ = rows.Scan(&v)
		out = append(out, v)
	}
	return out
}

func TestRotateE2E_AllCarriersConfirmed(t *testing.T) {
	r := newRotFixture(t, 2)
	var seen []string
	res := r.poll(r.start(&seen), &seen)
	if !res.OK || res.Version != "2" || res.Fingerprint == "" || res.ErrorClass != "" || len(res.Carriers) != 2 {
		t.Fatalf("rotation not done: %+v", res)
	}
	if res.Fingerprint != r.fingerprintOf(r.generated) {
		t.Fatal("the laid-out version is not the value the generator produced")
	}
	if got := r.activeVersions(); len(got) != 1 || got[0] != "2" {
		t.Fatalf("after a clean run only version 2 is active, got %v", got)
	}
	var disabled []string
	rows, err := r.f.pool.Query(context.Background(), `SELECT provider_version FROM secret_versions WHERE secret_id=$1 AND disabled`, r.secretID)
	must(t, err)
	for rows.Next() {
		var v string
		_ = rows.Scan(&v)
		disabled = append(disabled, v)
	}
	rows.Close()
	if len(disabled) != 1 || disabled[0] != "1" {
		t.Fatalf("the catalog must show only version 1 revoked, got %v", disabled)
	}
	r.checkNoLeak(seen)
}

func (r *rotFixture) checkNoLeak(seen []string) {
	r.t.Helper()
	newV := r.newValue()
	dump := r.surfaces(seen)
	for _, v := range []string{r.oldValue, newV} {
		c := canary.Of(v)
		if !c.In("x" + v) {
			r.t.Fatal("canary detector is blind; the test proves nothing")
		}
		if c.In(dump) {
			r.t.Fatalf("a secret value reached a response, header, log, journal or table (%d bytes inspected)", len(dump))
		}
	}
	if r.logbuf.Len() == 0 {
		r.t.Fatal("log interception saw nothing; the test proves nothing")
	}
}

func TestRotateE2E_OneFailingCarrierActivatesNothing(t *testing.T) {
	r := newRotFixture(t, 3)
	r.failDeploy[r.carriers[1]] = true
	var seen []string
	res := r.poll(r.start(&seen), &seen)
	if res.OK || res.ErrorClass != "deploy_failed" || res.Version != "" || res.Fingerprint != "" {
		t.Fatalf("a failing carrier must activate nothing: %+v", res)
	}
	got := r.activeVersions()
	if len(got) != 2 || got[0] != "1" {
		t.Fatalf("the old version must stay active next to the unconfirmed new one, got %v", got)
	}
	var revoked int
	_ = r.f.pool.QueryRow(context.Background(), `SELECT count(*) FROM secret_versions WHERE secret_id=$1 AND disabled`, r.secretID).Scan(&revoked)
	if revoked != 0 {
		t.Fatalf("%d versions disabled after a failed run", revoked)
	}
	r.checkNoLeak(seen)
}

// A run whose old version could not be revoked is not over: a second rotation
// is refused with revoke_pending (409), through rotationAppError.
func TestRotateE2E_RevokePendingIs409(t *testing.T) {
	r := newRotFixture(t, 1)
	ctx := context.Background()
	_, err := r.f.pool.Exec(ctx, `CREATE FUNCTION rot_block() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'blocked'; END $$;
		CREATE TRIGGER rot_block BEFORE UPDATE ON keep_envelope FOR EACH ROW EXECUTE FUNCTION rot_block()`)
	must(t, err)
	var seen []string
	_ = r.start(&seen)
	deadline := time.Now().Add(15 * time.Second)
	for {
		var n int
		_ = r.f.pool.QueryRow(ctx, `SELECT count(*) FROM rotation_runs WHERE secret_id=$1 AND state='revoking_old' AND error_class='revoke_failed'`, r.secretID).Scan(&n)
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the run never reached revoke_pending")
		}
		time.Sleep(25 * time.Millisecond)
	}
	rec := r.do(http.MethodPost, r.rotatePath(), map[string]string{"mode": "generate"})
	seen = append(seen, r.record(rec))
	var body struct {
		ErrorClass string `json:"error_class"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != http.StatusConflict || body.ErrorClass != "revoke_pending" {
		t.Fatalf("want 409 revoke_pending, got %d %s", rec.Code, rec.Body.String())
	}
	_, _ = r.f.pool.Exec(ctx, `DROP TRIGGER rot_block ON keep_envelope`)
	r.checkNoLeak(seen)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
}

// enter is the human's side: open the one-time link, seal the typed value to
// its public key as the browser does and submit it.
func (r *rotFixture) enter(link intake.Issued, typed string) string {
	r.t.Helper()
	token := strings.SplitN(strings.SplitN(link.URL, "/input/", 2)[1], "#", 2)[0]
	view, err := r.input.Read(context.Background(), token)
	must(r.t, err)
	pk, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().UnmarshalBinaryPublicKey(view.PublicKey)
	must(r.t, err)
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)
	sender, err := suite.NewSender(pk, []byte("keep/intake/v1\x00"+view.RequestID))
	must(r.t, err)
	enc, sealer, err := sender.Setup(rand.Reader)
	must(r.t, err)
	ct, err := sealer.Seal([]byte(typed), nil)
	must(r.t, err)
	body, _ := json.Marshal(intake.Envelope{Enc: enc, Ciphertext: ct})
	rec := httptest.NewRecorder()
	r.router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/input/"+token, bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		r.t.Fatalf("complete: %d %s", rec.Code, rec.Body.String())
	}
	return r.record(rec)
}

// human_input: the value is typed by a human into the one-time link; finishing
// the input starts the layout, and the value reaches no surface on the way.
func TestRotateE2E_HumanInputStartsTheLayout(t *testing.T) {
	r := newRotFixture(t, 2)
	ctx := context.Background()
	var seen []string
	rec := r.do(http.MethodPost, r.rotatePath(), map[string]string{"mode": "human_input"})
	seen = append(seen, r.record(rec))
	var link intake.Issued
	if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &link) != nil || link.URL == "" {
		t.Fatalf("input link: %d %s", rec.Code, rec.Body.String())
	}
	typed := canary.New().Value(1)
	r.typed = typed
	seen = append(seen, r.enter(link, typed))

	var run string
	deadline := time.Now().Add(15 * time.Second)
	for run == "" {
		var id uuid.UUID
		if r.f.pool.QueryRow(ctx, `SELECT id FROM rotation_runs WHERE org_id=$1 AND secret_id=$2`, r.org, r.secretID).Scan(&id) == nil {
			run = id.String()
		} else if time.Now().After(deadline) {
			t.Fatal("finishing the input started no layout")
		} else {
			time.Sleep(25 * time.Millisecond)
		}
	}
	res := r.poll(run, &seen)
	if !res.OK || res.Version != "2" || res.Fingerprint == "" || len(res.Carriers) != 2 {
		t.Fatalf("layout of the typed value not done: %+v", res)
	}
	if got := r.activeVersions(); len(got) != 1 || got[0] != "2" {
		t.Fatalf("only the typed version stays active, got %v", got)
	}
	// The sealed version is the typed one: its fingerprint is the run's.
	if res.Fingerprint != r.fingerprintOf(typed) {
		t.Fatal("the laid-out version is not the value the human typed")
	}
	r.checkNoLeak(seen)
	if canary.Of(typed).In(r.surfaces(seen)) {
		t.Fatal("typed value on a surface")
	}
}

// A plain input link (request_secret_input) only stores the value: finishing
// it must not start a rotation.
func TestRotateE2E_PlainInputLinkStartsNothing(t *testing.T) {
	r := newRotFixture(t, 1)
	rec := r.do(http.MethodPost, "/v1/input-links", map[string]string{"secret": "rot-secret"})
	var link intake.Issued
	if rec.Code != http.StatusCreated || json.Unmarshal(rec.Body.Bytes(), &link) != nil || link.URL == "" {
		t.Fatalf("input link: %d %s", rec.Code, rec.Body.String())
	}
	r.enter(link, canary.New().Value(1))
	time.Sleep(500 * time.Millisecond)
	var n int
	_ = r.f.pool.QueryRow(context.Background(), `SELECT count(*) FROM rotation_runs WHERE secret_id=$1`, r.secretID).Scan(&n)
	if n != 0 {
		t.Fatalf("a plain input link started %d rotation runs", n)
	}
}

// The hook runs after the value is sealed and the link is used up: a hook that
// panics must not turn the completion into an error.
func TestRotateE2E_PanickingHookDoesNotFailTheInput(t *testing.T) {
	r := newRotFixture(t, 1)
	r.input.OnRotationInput(func(context.Context, intake.Completed) { panic("hook down") })
	rec := r.do(http.MethodPost, r.rotatePath(), map[string]string{"mode": "human_input"})
	var link intake.Issued
	if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &link) != nil {
		t.Fatalf("input link: %d", rec.Code)
	}
	r.enter(link, canary.New().Value(1)) // fails the test unless the answer is 200
}

// A human finishes entering a value while another run of the secret is still
// active: the sealed version is laid out once that run is over, not left
// without a layout while the input reports success.
func TestRotateE2E_HumanInputWaitsForTheActiveRun(t *testing.T) {
	every := rotationRetryEvery
	rotationRetryEvery = 50 * time.Millisecond
	t.Cleanup(func() { rotationRetryEvery = every })
	r := newRotFixture(t, 1)
	ctx := context.Background()
	var seen []string
	r.paused.Store(true)
	first := r.start(&seen) // holds the secret: its deploy job is not run
	// The run is in the background: the human must type after it has made its
	// own version, or the generated one lands newer than the typed one.
	for end := time.Now().Add(20 * time.Second); ; time.Sleep(25 * time.Millisecond) {
		var nv string
		_ = r.f.pool.QueryRow(context.Background(), `SELECT new_version FROM rotation_runs WHERE id=$1`, first).Scan(&nv)
		if nv != "" {
			break
		}
		if time.Now().After(end) {
			t.Fatal("the first run never made its version")
		}
	}
	rec := r.do(http.MethodPost, r.rotatePath(), map[string]string{"mode": "human_input"})
	seen = append(seen, r.record(rec))
	var link intake.Issued
	if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &link) != nil || link.URL == "" {
		t.Fatalf("input link: %d %s", rec.Code, rec.Body.String())
	}
	typed := canary.New().Value(1)
	r.typed = typed
	seen = append(seen, r.enter(link, typed))
	var n int
	_ = r.f.pool.QueryRow(ctx, `SELECT count(*) FROM rotation_runs WHERE org_id=$1 AND secret_id=$2`, r.org, r.secretID).Scan(&n)
	if n != 1 {
		t.Fatalf("a second run started while the first holds the secret: %d runs", n)
	}
	r.paused.Store(false)
	// The first run ends either way (the typed version became the newest one
	// under it, so its verify may fail); what matters is the second run.
	for end := time.Now().Add(20 * time.Second); ; time.Sleep(25 * time.Millisecond) {
		var st string
		_ = r.f.pool.QueryRow(ctx, `SELECT state FROM rotation_runs WHERE id=$1`, first).Scan(&st)
		if st == "done" || st == "failed" {
			break
		}
		if time.Now().After(end) {
			t.Fatalf("first run did not end: state %q", st)
		}
	}
	deadline := time.Now().Add(20 * time.Second)
	var second uuid.UUID
	for r.f.pool.QueryRow(ctx, `SELECT id FROM rotation_runs WHERE org_id=$1 AND secret_id=$2 AND id<>$3`, r.org, r.secretID, uuid.MustParse(first)).Scan(&second) != nil {
		if time.Now().After(deadline) {
			t.Fatal("the typed version never got its layout after the active run ended")
		}
		time.Sleep(25 * time.Millisecond)
	}
	res := r.poll(second.String(), &seen)
	if !res.OK || res.Fingerprint != r.fingerprintOf(typed) {
		t.Fatalf("typed value not laid out: %+v", res)
	}
	r.checkNoLeak(seen)
	if canary.Of(typed).In(r.surfaces(seen)) {
		t.Fatal("typed value on a surface")
	}
}

// The hook runs after the input is committed. When the layout cannot begin at
// that moment (here: the ledger refuses the adoption), the sealed value must
// still get its layout once the fault is gone, with no new input and no
// re-wiring: the pending state is in the database.
func TestRotateE2E_HumanInputSurvivesTransientAdoptFailure(t *testing.T) {
	every, back := rotationRetryEvery, rotationRetryBackoff
	rotationRetryEvery, rotationRetryBackoff = 50*time.Millisecond, 100*time.Millisecond
	t.Cleanup(func() { rotationRetryEvery, rotationRetryBackoff = every, back })
	r := newRotFixture(t, 1)
	ctx := context.Background()
	pool := r.f.pool
	_, err := pool.Exec(ctx, `CREATE OR REPLACE FUNCTION rot_refuse_adopt() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'transient'; END $$ LANGUAGE plpgsql`)
	must(t, err)
	_, err = pool.Exec(ctx, `CREATE TRIGGER rot_refuse_adopt BEFORE INSERT ON rotation_keys FOR EACH ROW EXECUTE FUNCTION rot_refuse_adopt()`)
	must(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DROP TRIGGER IF EXISTS rot_refuse_adopt ON rotation_keys`)
		_, _ = pool.Exec(ctx, `DROP FUNCTION IF EXISTS rot_refuse_adopt()`)
	})
	var seen []string
	rec := r.do(http.MethodPost, r.rotatePath(), map[string]string{"mode": "human_input"})
	seen = append(seen, r.record(rec))
	var link intake.Issued
	if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &link) != nil || link.URL == "" {
		t.Fatalf("input link: %d %s", rec.Code, rec.Body.String())
	}
	typed := canary.New().Value(1)
	r.typed = typed
	seen = append(seen, r.enter(link, typed))

	time.Sleep(600 * time.Millisecond) // several sweeps hit the fault
	var runs, pending int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM rotation_runs WHERE org_id=$1 AND secret_id=$2`, r.org, r.secretID).Scan(&runs)
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM intake_rotation_links WHERE org_id=$1 AND started_at IS NULL`, r.org).Scan(&pending)
	if runs != 0 || pending != 1 {
		t.Fatalf("under the fault: %d runs, %d pending layouts (want 0 and 1)", runs, pending)
	}
	_, err = pool.Exec(ctx, `DROP TRIGGER rot_refuse_adopt ON rotation_keys`)
	must(t, err)

	var run uuid.UUID
	for end := time.Now().Add(20 * time.Second); pool.QueryRow(ctx, `SELECT id FROM rotation_runs WHERE org_id=$1 AND secret_id=$2`, r.org, r.secretID).Scan(&run) != nil; time.Sleep(25 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal("the sealed value never got its layout after the fault ended")
		}
	}
	res := r.poll(run.String(), &seen)
	if !res.OK || res.Fingerprint != r.fingerprintOf(typed) {
		t.Fatalf("typed value not laid out: %+v", res)
	}
	var started bool
	for end := time.Now().Add(5 * time.Second); !started && time.Now().Before(end); time.Sleep(25 * time.Millisecond) {
		_ = pool.QueryRow(ctx, `SELECT started_at IS NOT NULL FROM intake_rotation_links WHERE org_id=$1`, r.org).Scan(&started)
	}
	if !started {
		t.Fatal("the pending layout stays pending after the run began")
	}
	r.checkNoLeak(seen)
}

// A restart: nobody calls the hook, the new process finds the pending layout.
func TestRotateE2E_PendingLayoutSurvivesRestart(t *testing.T) {
	every := rotationRetryEvery
	rotationRetryEvery = 50 * time.Millisecond
	t.Cleanup(func() { rotationRetryEvery = every })
	r := newRotFixture(t, 1)
	ctx := context.Background()
	r.stopSweep()                                                       // the old process is gone: nothing sweeps until the new one starts
	r.input.OnRotationInput(func(context.Context, intake.Completed) {}) // it died before its hook ran
	var seen []string
	rec := r.do(http.MethodPost, r.rotatePath(), map[string]string{"mode": "human_input"})
	var link intake.Issued
	if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &link) != nil {
		t.Fatalf("input link: %d", rec.Code)
	}
	typed := canary.New().Value(1)
	r.typed = typed
	seen = append(seen, r.enter(link, typed))
	var n int
	_ = r.f.pool.QueryRow(ctx, `SELECT count(*) FROM rotation_runs WHERE secret_id=$1`, r.secretID).Scan(&n)
	if n != 0 {
		t.Fatalf("no hook ran yet %d runs exist", n)
	}
	// The new process: fresh wiring, as keep-server does at start.
	sweep := wireRotationInput(r.input, r.svc, r.f.pool, obs.New(r.logbuf))
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go runPendingLayouts(sctx, sweep)
	var run uuid.UUID
	for end := time.Now().Add(20 * time.Second); r.f.pool.QueryRow(ctx, `SELECT id FROM rotation_runs WHERE secret_id=$1`, r.secretID).Scan(&run) != nil; time.Sleep(25 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal("a restart left the sealed value without a layout")
		}
	}
	res := r.poll(run.String(), &seen)
	if !res.OK || res.Fingerprint != r.fingerprintOf(typed) {
		t.Fatalf("typed value not laid out: %+v", res)
	}
	r.checkNoLeak(seen)
}

// enterRotationInput issues a human_input link and completes it with a typed
// value, with the fixture's own sweeper and hook silenced so the test drives
// the pending layout by hand.
func (r *rotFixture) enterRotationInput() {
	r.t.Helper()
	r.stopSweep()
	r.input.OnRotationInput(func(context.Context, intake.Completed) {})
	rec := r.do(http.MethodPost, r.rotatePath(), map[string]string{"mode": "human_input"})
	var link intake.Issued
	if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &link) != nil {
		r.t.Fatalf("input link: %d", rec.Code)
	}
	r.typed = canary.New().Value(1)
	r.enter(link, r.typed)
}

// A worker whose claim was taken over (it was slow, the claim expired, another
// worker claimed the row) must not start the layout it no longer owns.
func TestRotateE2E_ExpiredClaimDoesNotStartTheLayout(t *testing.T) {
	r := newRotFixture(t, 1)
	ctx := context.Background()
	r.enterRotationInput()
	ri := &rotationInputs{starter: r.svc.(*rotation.Service), pool: r.f.pool, logger: obs.New(r.logbuf)}
	batch := ri.claim(ctx, uuid.Nil, nil)
	if len(batch) != 1 {
		t.Fatalf("claimed %d rows, want 1", len(batch))
	}
	_, err := r.f.pool.Exec(ctx, `UPDATE intake_rotation_links SET claim_token=$1 WHERE org_id=$2`, uuid.New(), r.org)
	must(t, err)
	ri.layout(ctx, batch[0])
	var n int
	_ = r.f.pool.QueryRow(ctx, `SELECT count(*) FROM rotation_runs WHERE secret_id=$1`, r.secretID).Scan(&n)
	if n != 0 {
		t.Fatalf("a worker that lost its claim started %d runs", n)
	}
}

// A failure that never goes away is given up on after rotationMaxAttempts,
// not retried and logged forever.
func TestRotateE2E_PermanentFailureIsAbandoned(t *testing.T) {
	max, back := rotationMaxAttempts, rotationRetryBackoff
	rotationMaxAttempts, rotationRetryBackoff = 3, time.Millisecond
	t.Cleanup(func() { rotationMaxAttempts, rotationRetryBackoff = max, back })
	r := newRotFixture(t, 1)
	ctx := context.Background()
	pool := r.f.pool
	_, err := pool.Exec(ctx, `CREATE OR REPLACE FUNCTION rot_refuse_adopt() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'permanent'; END $$ LANGUAGE plpgsql`)
	must(t, err)
	_, err = pool.Exec(ctx, `CREATE TRIGGER rot_refuse_adopt BEFORE INSERT ON rotation_keys FOR EACH ROW EXECUTE FUNCTION rot_refuse_adopt()`)
	must(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DROP TRIGGER IF EXISTS rot_refuse_adopt ON rotation_keys`)
		_, _ = pool.Exec(ctx, `DROP FUNCTION IF EXISTS rot_refuse_adopt()`)
	})
	r.enterRotationInput()
	ri := &rotationInputs{starter: r.svc.(*rotation.Service), pool: pool, logger: obs.New(r.logbuf)}
	for i := 0; i < 10; i++ {
		ri.sweep(ctx)
		time.Sleep(5 * time.Millisecond)
	}
	var started bool
	_ = pool.QueryRow(ctx, `SELECT started_at IS NOT NULL FROM intake_rotation_links WHERE org_id=$1`, r.org).Scan(&started)
	if !started {
		t.Fatal("a permanent failure stays pending forever")
	}
	if !strings.Contains(string(r.logbuf.Bytes()), "rotation after input abandoned") {
		t.Fatal("abandoning is not logged")
	}
}

// Two sealed inputs wait for their layout while version 1 is the one deployed.
// A pending version is no predecessor: whichever input is handled, version 1 is
// revoked, the older input is retired without a layout and only the newest
// stays active.
func TestRotateE2E_PendingInputsRevokeTheDeployedVersion(t *testing.T) {
	every := rotationRetryEvery
	rotationRetryEvery = 20 * time.Millisecond
	t.Cleanup(func() { rotationRetryEvery = every })
	r := newRotFixture(t, 1)
	ctx := context.Background()
	r.enterRotationInput()
	r.enterRotationInput()
	ri := &rotationInputs{starter: r.svc.(*rotation.Service), pool: r.f.pool, logger: obs.New(r.logbuf)}
	// The newest input is handled first, as the hook does when it fires late for
	// the older one: its predecessor must still be the deployed version 1.
	var newest uuid.UUID
	must(t, r.f.pool.QueryRow(ctx, `SELECT request_id FROM intake_rotation_links WHERE org_id=$1 ORDER BY created_at DESC LIMIT 1`, r.org).Scan(&newest))
	ri.run(ctx, ri.claim(ctx, r.org, &newest))
	for end := time.Now().Add(20 * time.Second); ; time.Sleep(25 * time.Millisecond) {
		ri.sweep(ctx)
		var pending, open int
		_ = r.f.pool.QueryRow(ctx, `SELECT count(*) FROM intake_rotation_links WHERE org_id=$1 AND started_at IS NULL`, r.org).Scan(&pending)
		_ = r.f.pool.QueryRow(ctx, `SELECT count(*) FROM rotation_runs WHERE org_id=$1 AND secret_id=$2 AND state NOT IN ('done','failed')`, r.org, r.secretID).Scan(&open)
		if pending == 0 && open == 0 {
			break
		}
		if time.Now().After(end) {
			t.Fatalf("layouts not finished: pending=%d open runs=%d", pending, open)
		}
	}
	if got := r.activeVersions(); len(got) != 1 || got[0] != "3" {
		t.Fatalf("only the newest input stays active, got %v", got)
	}
	var runs int
	_ = r.f.pool.QueryRow(ctx, `SELECT count(*) FROM rotation_runs WHERE secret_id=$1`, r.secretID).Scan(&runs)
	if runs != 1 {
		t.Fatalf("the superseded input got a layout: %d runs", runs)
	}
	var oldV string
	_ = r.f.pool.QueryRow(ctx, `SELECT old_version FROM rotation_runs WHERE secret_id=$1`, r.secretID).Scan(&oldV)
	if oldV != "1" {
		t.Fatalf("the predecessor is the deployed version 1, got %q", oldV)
	}
}

// The inputs are completed in the reverse of the order their links were issued:
// the value sealed last is the newest version, whatever its link's age.
func TestRotateE2E_PendingInputsCompletedOutOfOrder(t *testing.T) {
	every := rotationRetryEvery
	rotationRetryEvery = 20 * time.Millisecond
	t.Cleanup(func() { rotationRetryEvery = every })
	r := newRotFixture(t, 1)
	ctx := context.Background()
	r.stopSweep()
	r.input.OnRotationInput(func(context.Context, intake.Completed) {})
	var links [2]intake.Issued
	for i := range links {
		rec := r.do(http.MethodPost, r.rotatePath(), map[string]string{"mode": "human_input"})
		if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &links[i]) != nil {
			t.Fatalf("input link %d: %d", i, rec.Code)
		}
	}
	r.typed = canary.New().Value(1)
	r.enter(links[1], r.typed)
	r.enter(links[0], canary.New().Value(2))
	ri := &rotationInputs{starter: r.svc.(*rotation.Service), pool: r.f.pool, logger: obs.New(r.logbuf)}
	for end := time.Now().Add(20 * time.Second); ; time.Sleep(25 * time.Millisecond) {
		ri.sweep(ctx)
		var pending, open int
		_ = r.f.pool.QueryRow(ctx, `SELECT count(*) FROM intake_rotation_links WHERE org_id=$1 AND started_at IS NULL`, r.org).Scan(&pending)
		_ = r.f.pool.QueryRow(ctx, `SELECT count(*) FROM rotation_runs WHERE org_id=$1 AND secret_id=$2 AND state NOT IN ('done','failed')`, r.org, r.secretID).Scan(&open)
		if pending == 0 && open == 0 {
			break
		}
		if time.Now().After(end) {
			t.Fatalf("layouts not finished: pending=%d open runs=%d", pending, open)
		}
	}
	var state string
	must(t, r.f.pool.QueryRow(ctx, `SELECT state FROM rotation_runs WHERE secret_id=$1`, r.secretID).Scan(&state))
	if got := r.activeVersions(); len(got) != 1 || got[0] != "3" || state != "done" {
		t.Fatalf("the input sealed last must be laid out: active %v, run %s", got, state)
	}
}

// After the rotations of a secret exactly one version is active, the newest,
// whatever order the sealed inputs were handled in, whether the pending mark
// (started_at) of a finished layout was lost before or after the next input,
// and whether the process restarted in between. The truth about "deployed" is
// the finished run, not the mark.
func TestRotateE2E_OnlyTheNewestVersionStaysActive(t *testing.T) {
	type step string
	const (
		newestFirst  step = "newest-first"
		oldestFirst  step = "oldest-first"
		lostBefore   step = "mark-lost-before-next-input"
		lostAfter    step = "mark-lost-after-all"
		restartInBtw step = "restart-between-steps"
	)
	for _, tc := range []step{newestFirst, oldestFirst, lostBefore, lostAfter, restartInBtw} {
		t.Run(string(tc), func(t *testing.T) {
			every := rotationRetryEvery
			rotationRetryEvery = 20 * time.Millisecond
			t.Cleanup(func() { rotationRetryEvery = every })
			r := newRotFixture(t, 1)
			ctx := context.Background()
			r.stopSweep()
			r.input.OnRotationInput(func(context.Context, intake.Completed) {})
			var links [2]intake.Issued
			for i := range links {
				rec := r.do(http.MethodPost, r.rotatePath(), map[string]string{"mode": "human_input"})
				if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &links[i]) != nil {
					t.Fatalf("input link %d: %d", i, rec.Code)
				}
			}
			newRI := func() *rotationInputs {
				return &rotationInputs{starter: r.svc.(*rotation.Service), pool: r.f.pool, logger: obs.New(r.logbuf)}
			}
			ids := func() (older, newer uuid.UUID) {
				rows, err := r.f.pool.Query(ctx, `SELECT l.request_id FROM intake_rotation_links l JOIN intake_links il ON il.org_id=l.org_id AND il.request_id=l.request_id JOIN secret_versions v ON v.org_id=il.org_id AND v.secret_id=il.secret_id AND v.provider_version=il.version WHERE l.org_id=$1 ORDER BY v.created_at, v.id`, r.org)
				must(t, err)
				defer rows.Close()
				var got []uuid.UUID
				for rows.Next() {
					var id uuid.UUID
					must(t, rows.Scan(&id))
					got = append(got, id)
				}
				if len(got) != 2 {
					t.Fatalf("want 2 sealed inputs, got %d", len(got))
				}
				return got[0], got[1]
			}
			idle := func() bool {
				var open int
				_ = r.f.pool.QueryRow(ctx, `SELECT count(*) FROM rotation_runs WHERE org_id=$1 AND secret_id=$2 AND state NOT IN ('done','failed')`, r.org, r.secretID).Scan(&open)
				return open == 0
			}
			waitIdle := func() {
				for end := time.Now().Add(40 * time.Second); !idle(); time.Sleep(25 * time.Millisecond) {
					if time.Now().After(end) {
						t.Fatal("run did not finish")
					}
				}
			}
			drain := func(ri *rotationInputs) {
				for end := time.Now().Add(40 * time.Second); ; time.Sleep(25 * time.Millisecond) {
					ri.sweep(ctx)
					var pending int
					_ = r.f.pool.QueryRow(ctx, `SELECT count(*) FROM intake_rotation_links WHERE org_id=$1 AND started_at IS NULL`, r.org).Scan(&pending)
					if pending == 0 && idle() {
						return
					}
					if time.Now().After(end) {
						t.Fatalf("layouts not finished: pending=%d", pending)
					}
				}
			}
			one := func(ri *rotationInputs, id uuid.UUID) {
				ri.run(ctx, ri.claim(ctx, r.org, &id))
				waitIdle()
			}
			lose := func() {
				_, err := r.f.pool.Exec(ctx, `UPDATE intake_rotation_links SET started_at=NULL, claimed_until=NULL, claim_token=NULL WHERE org_id=$1`, r.org)
				must(t, err)
			}
			switch tc {
			case lostBefore, restartInBtw:
				// The older input is sealed and laid out alone; then the next one arrives.
				r.typed = canary.New().Value(1)
				older, _ := ids2(t, r, ctx, links[0])
				r.enter(links[0], r.typed)
				ri := newRI()
				one(ri, older)
				if tc == lostBefore {
					lose()
				} else {
					ri = newRI()
				}
				r.enter(links[1], canary.New().Value(2))
				drain(ri)
				// The laid-out version is the predecessor, however its mark fares.
				var oldV, prev string
				must(t, r.f.pool.QueryRow(ctx, `SELECT old_version FROM rotation_runs WHERE secret_id=$1 ORDER BY created_at DESC LIMIT 1`, r.secretID).Scan(&oldV))
				must(t, r.f.pool.QueryRow(ctx, `SELECT new_version FROM rotation_runs WHERE secret_id=$1 ORDER BY created_at ASC LIMIT 1`, r.secretID).Scan(&prev))
				if oldV != prev {
					t.Fatalf("predecessor of the newest run is %q, want the laid-out version %q", oldV, prev)
				}
			default:
				r.typed = canary.New().Value(1)
				r.enter(links[1], r.typed)
				r.enter(links[0], canary.New().Value(2))
				ri := newRI()
				if tc == newestFirst {
					_, newer := ids()
					ri.run(ctx, ri.claim(ctx, r.org, &newer))
				}
				drain(ri)
				if tc == lostAfter {
					lose()
					drain(newRI())
				}
			}
			var last string
			must(t, r.f.pool.QueryRow(ctx, `SELECT provider_version FROM secret_versions WHERE secret_id=$1 ORDER BY created_at DESC, id DESC LIMIT 1`, r.secretID).Scan(&last))
			if got := r.activeVersions(); len(got) != 1 || got[0] != last {
				t.Fatalf("active versions %v, want only the newest %s", got, last)
			}
			var enabled int
			must(t, r.f.pool.QueryRow(ctx, `SELECT count(*) FROM secret_versions WHERE secret_id=$1 AND NOT disabled`, r.secretID).Scan(&enabled))
			if enabled != 1 {
				t.Fatalf("catalog has %d enabled versions, want 1", enabled)
			}
		})
	}
}

// ids2 is the request id of the input link of one issued link.
func ids2(t *testing.T, r *rotFixture, ctx context.Context, link intake.Issued) (uuid.UUID, uuid.UUID) {
	t.Helper()
	token := strings.SplitN(strings.SplitN(link.URL, "/input/", 2)[1], "#", 2)[0]
	view, err := r.input.Read(ctx, token)
	must(t, err)
	id, err := uuid.Parse(view.RequestID)
	must(t, err)
	return id, id
}

// A sealed input waits for its layout while a generated rotation of the same
// secret finishes; that run retires the input's version. The input's layout
// then finds nothing to lay out: a disabled version is never deployed.
func TestRotateE2E_InputRetiredByAGeneratedRotationIsNotLaidOut(t *testing.T) {
	r := newRotFixture(t, 1)
	ctx := context.Background()
	r.stopSweep()
	r.input.OnRotationInput(func(context.Context, intake.Completed) {})
	rec := r.do(http.MethodPost, r.rotatePath(), map[string]string{"mode": "human_input"})
	var link intake.Issued
	if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &link) != nil {
		t.Fatalf("input link: %d", rec.Code)
	}
	r.typed = canary.New().Value(1)
	r.enter(link, r.typed)
	var seen []string
	r.poll(r.start(&seen), &seen)
	ri := &rotationInputs{starter: r.svc.(*rotation.Service), pool: r.f.pool, logger: obs.New(r.logbuf)}
	for end := time.Now().Add(30 * time.Second); ; time.Sleep(25 * time.Millisecond) {
		ri.sweep(ctx)
		var pending int
		_ = r.f.pool.QueryRow(ctx, `SELECT count(*) FROM intake_rotation_links WHERE org_id=$1 AND started_at IS NULL`, r.org).Scan(&pending)
		if pending == 0 {
			break
		}
		if time.Now().After(end) {
			t.Fatal("pending input never settled")
		}
	}
	var runs int
	_ = r.f.pool.QueryRow(ctx, `SELECT count(*) FROM rotation_runs WHERE secret_id=$1`, r.secretID).Scan(&runs)
	if runs != 1 {
		t.Fatalf("the retired input got a layout: %d runs", runs)
	}
	if got := r.activeVersions(); len(got) != 1 {
		t.Fatalf("want one active version, got %v", got)
	}
}

// A run whose goroutine is gone (the hook failed after the commit, or the
// process died) is taken back by the resume sweep keep-server runs, and laid
// out like any other.
func TestRotateE2E_AbandonedRunIsResumed(t *testing.T) {
	every := rotationRetryEvery
	rotationRetryEvery = 50 * time.Millisecond
	t.Cleanup(func() { rotationRetryEvery = every })
	r := newRotFixture(t, 2)
	ctx := context.Background()
	run := uuid.New()
	_, err := r.f.pool.Exec(ctx, `INSERT INTO rotation_runs(id, org_id, secret_id, state, updated_at) VALUES ($1,$2,$3,'new_version', now() - interval '1 hour')`, run, r.org, r.secretID)
	must(t, err)
	var seen []string
	if rec := r.do(http.MethodGet, r.rotatePath()+"/"+run.String(), nil); rec.Code != http.StatusAccepted {
		t.Fatalf("setup: the abandoned run must be pending, got %d", rec.Code)
	}
	sweep := rotationResumeSweep(r.svc, obs.New(r.logbuf))
	if sweep == nil {
		t.Fatal("no resume sweep wired")
	}
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go runPendingLayouts(sctx, sweep)
	res := r.poll(run.String(), &seen)
	if !res.OK || res.Version != "2" || res.Fingerprint != r.fingerprintOf(r.generated) || len(res.Carriers) != 2 {
		t.Fatalf("abandoned run not laid out: %+v", res)
	}
	if got := r.activeVersions(); len(got) != 1 || got[0] != "2" {
		t.Fatalf("after the resumed run only version 2 is active, got %v", got)
	}
	r.checkNoLeak(seen)
}

// A service that is not the rotation service has nothing to resume.
func TestRotateE2E_ResumeSweepNeedsTheService(t *testing.T) {
	if rotationResumeSweep(nil, obs.New(&syncBuf{})) != nil {
		t.Fatal("a sweep was wired without a rotation service")
	}
}
