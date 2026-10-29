package security

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/api"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/carriers"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/dispatch"
	"github.com/entire-vc/evc-keep/internal/enrolltoken"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/mtls"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/registry"
	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// verifySigner signs with a real Ed25519 key, so the test can check the
// signature the runner would check.
type verifySigner struct{ s runnerproto.Signer }

func (v verifySigner) SignJob(_ context.Context, _ pgx.Tx, _ uuid.UUID, j runnerproto.Job) (runnerproto.SignedJob, error) {
	return v.s.Sign(j)
}

// keyOnly stands in for the sealer: a verify job is issued an envelope of the
// fingerprint key and never a value, so anything else fails the test.
type keyOnly struct{ t *testing.T }

func (n keyOnly) SealMaterial(_ context.Context, snap dispatch.Snapshot, _ []byte) (runnerproto.ValueEnvelope, error) {
	if !snap.Job.NeedsFingerprintKey() || snap.Job.NeedsValue() {
		n.t.Error("verify asked the server for the secret value")
		return runnerproto.ValueEnvelope{}, errors.New("no material")
	}
	return runnerproto.ValueEnvelope{JobID: snap.Job.JobID, SealedFingerprintKey: []byte("synthetic-sealed-key")}, nil
}

type allowAll struct{}

func (allowAll) Approved(context.Context, uuid.UUID, uuid.UUID, carriers.Metadata) (bool, error) {
	return true, nil
}

// verifyWorld is a migrated scratch database with one organization, one
// secret whose value is a canary, one carrier on one enrolled runner, and the
// real router, dispatcher and journal over them.
type verifyWorld struct {
	t       *testing.T
	pool    *pgxpool.Pool
	router  http.Handler
	logs    *bytes.Buffer
	bearer  string
	org     tenancy.Organization
	svc     *dispatch.Service
	peer    mtls.Principal
	pub     ed25519.PublicKey
	fp      string
	carrier carriers.Carrier
	canary  canary.Canary
	// meta is planted in the carrier fields verify must not pass on: the
	// consumer and the healthcheck reference.
	meta canary.Canary
}

func newVerifyWorld(t *testing.T) *verifyWorld {
	t.Helper()
	ctx := context.Background()
	dsn := pgscratch.New(t, nil)
	mdb, err := store.OpenMigrationDB(ctx, dsn)
	if err != nil {
		t.Fatal("open migration database")
	}
	defer func() { _ = mdb.Close() }()
	provider, err := store.NewProvider(mdb)
	if err != nil {
		t.Fatal("create migration provider")
	}
	if _, err = provider.Up(ctx); err != nil {
		t.Fatal("migrate scratch database")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("open scratch pool")
	}
	t.Cleanup(pool.Close)
	w := &verifyWorld{t: t, pool: pool, logs: &bytes.Buffer{}, canary: canary.New(), meta: canary.New()}

	tr, cat := tenancy.New(pool), catalog.New(pool)
	if w.org, err = tr.CreateOrganization(ctx, "verify-leak", ""); err != nil {
		t.Fatal("create organization")
	}
	admin, err := tr.CreateUser(ctx, w.org.ID, "admin@example.test")
	if err != nil {
		t.Fatal("create user")
	}
	if _, err = tr.CreateMembership(ctx, w.org.ID, admin.ID, tenancy.Org(w.org.ID), string(identity.RoleAdmin)); err != nil {
		t.Fatal("grant admin")
	}
	ir := identity.NewRepo(pool)
	issued, err := ir.Issue(ctx, identity.IssueParams{OrgID: w.org.ID, Kind: identity.KindUser, PrincipalID: admin.ID, Scope: "org:" + w.org.ID.String()})
	if err != nil {
		t.Fatal("issue token")
	}
	w.bearer = identity.Reveal(issued.Token)

	st, err := cat.CreateStore(ctx, w.org.ID, "builtin", "default", tenancy.Org(w.org.ID))
	if err != nil {
		t.Fatal("create store")
	}
	if _, err = cat.CreateStoreBinding(ctx, w.org.ID, tenancy.Org(w.org.ID), st.ID); err != nil {
		t.Fatal("bind store")
	}
	ref, err := cat.CreateRef(ctx, catalog.CreateRefInput{Org: w.org.ID, Scope: tenancy.Org(w.org.ID), Name: "db-password", Class: "credential", Type: "generic", ProviderRef: "builtin://default/db-password", StoreID: st.ID})
	if err != nil {
		t.Fatal("create secret")
	}
	key := mustKey(t, "verifyleak")
	t.Cleanup(key.Wipe)
	w.fp = carrierFP(t, key, w.canary.Value(1))
	if _, err = cat.AddVersion(ctx, w.org.ID, ref.ID, "7", w.fp, len(w.canary.Value(1))); err != nil {
		t.Fatal("add version")
	}

	meta := carriers.Metadata{Host: "runner.verify.test", TargetKind: runnerproto.TargetEnvFile, TargetPath: "/srv/app/.env", TargetField: "DB_PASSWORD", Consumer: w.meta.Value(1), HealthcheckRef: w.meta.Value(2)}
	if w.carrier, err = carriers.New(pool, allowAll{}).Register(ctx, w.org.ID, carriers.Registration{SecretID: ref.ID, Version: "7", LastFP: w.fp, Metadata: meta}); err != nil {
		t.Fatal("register carrier")
	}

	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate recipient")
	}
	runner, err := uuid.NewV7()
	if err != nil {
		t.Fatal("generate runner id")
	}
	shared := false
	if err = registry.NewRepo(pool).CreateEnrolled(ctx, w.org.ID, runner, meta.Host, "1", time.Now().Add(time.Hour), registry.Enrollment{HPKEPublicKey: recipient.PublicKey().Bytes(), HostAttrs: &enrolltoken.HostAttrs{UIDShared: &shared}}); err != nil {
		t.Fatal("enroll runner")
	}
	w.peer = mtls.Principal{OrgID: w.org.ID, RunnerID: runner, Serial: "1"}

	pubKey, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate signing key")
	}
	w.pub = pubKey
	journal := audit.NewJournal(pool)
	w.svc = dispatch.New(pool, journal, verifySigner{runnerproto.Signer{KeyID: "verifykey", Key: priv}}, keyOnly{t})
	w.router = api.NewRouter(obs.New(w.logs), pool, api.Deps{Deployments: deployment.NewRepo(pool, journal), Jobs: w.svc})
	return w
}

func (w *verifyWorld) do(method, path string, body any) (int, string, http.Header) {
	w.t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			w.t.Fatal("marshal body")
		}
		rd = bytes.NewReader(b)
	}
	r := httptest.NewRequest(method, path, rd)
	r.Header.Set("Authorization", "Bearer "+w.bearer)
	rec := httptest.NewRecorder()
	w.router.ServeHTTP(rec, r)
	return rec.Code, rec.Body.String(), rec.Header()
}

// dump renders every row of every table, so a value that reached storage in
// any form is found whatever the column.
func (w *verifyWorld) dump() map[string]string {
	w.t.Helper()
	ctx := context.Background()
	rows, err := w.pool.Query(ctx, `SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE'`)
	if err != nil {
		w.t.Fatal("list tables")
	}
	var tables []string
	for rows.Next() {
		var n string
		if rows.Scan(&n) != nil {
			w.t.Fatal("scan table name")
		}
		tables = append(tables, n)
	}
	rows.Close()
	out := map[string]string{}
	for _, n := range tables {
		if n == "goose_db_version" {
			continue
		}
		r, err := w.pool.Query(ctx, `SELECT row_to_json(t)::text FROM `+pgx.Identifier{n}.Sanitize()+` t`)
		if err != nil {
			w.t.Fatalf("dump table %s", n)
		}
		var b strings.Builder
		for r.Next() {
			var j string
			if r.Scan(&j) != nil {
				w.t.Fatal("scan row")
			}
			b.WriteString(j)
			b.WriteByte('\n')
		}
		r.Close()
		out["database "+n] = b.String()
	}
	return out
}

// leaked reports whether the canary is in s in any form, including base64 at
// the three alignments the detector is blind to.
func leaked(c canary.Canary, s string) bool {
	if c.In(s) {
		return true
	}
	for _, p := range []string{"", "x", "xx"} {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if strings.Contains(s, enc.EncodeToString([]byte(p+c.Value(1)))) {
				return true
			}
		}
	}
	return false
}

// TestW5_CarrierVerify_NoValueOnAnySurface runs the whole verify flow and
// looks for the secret's value on every surface that leaves the verify code:
// both HTTP answers and their headers, the log, the signed job, the runner's
// result path, every table of the database, and the journal.
func TestW5_CarrierVerify_NoValueOnAnySurface(t *testing.T) {
	w := newVerifyWorld(t)
	// Positive control: the detector sees the value in every form it checks.
	if !leaked(w.canary, "x "+w.canary.Value(1)) || !leaked(w.canary, base64.StdEncoding.EncodeToString([]byte("xx"+w.canary.Value(1)))) {
		t.Fatal("canary detector is blind; the test proves nothing")
	}
	surfaces := map[string]string{}
	add := func(name, s string, h http.Header) {
		surfaces[name] = s
		for k, v := range h {
			surfaces[name+" header "+k] = strings.Join(v, ",")
		}
	}

	code, body, h := w.do(http.MethodPost, "/v1/carriers/verify", map[string]any{"secret": "db-password", "request_id": "verify-leak-1"})
	if code != http.StatusAccepted {
		t.Fatalf("POST /v1/carriers/verify = %d, want 202", code)
	}
	add("POST", body, h)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	signed, ok, err := w.svc.Poll(ctx, w.peer)
	if err != nil || !ok {
		t.Fatal("verify job was not queued for the runner")
	}
	if !ed25519.Verify(w.pub, signed.Payload, signed.Sig) {
		t.Fatal("the verify job is not signed by the organization key")
	}
	job, err := runnerproto.DecodeJob(signed.Payload)
	if err != nil || job.Action != runnerproto.ActionVerify || job.Target.Consumer != "" || job.OrgID != w.org.ID.String() || job.RunnerID != w.peer.RunnerID.String() {
		t.Fatal("the signed job is not a consumer-less verify job for this runner")
	}
	enc, _ := json.Marshal(signed)
	add("signed job", string(enc), nil)

	if _, err = w.svc.Material(ctx, w.peer, "00000000-0000-7000-8000-000000000000"); err == nil {
		t.Fatal("material for an unknown job was issued")
	}
	jobID := job.JobID
	env, err := w.svc.Material(ctx, w.peer, jobID)
	if err != nil || len(env.Sealed) != 0 || len(env.SealedFingerprintKey) == 0 {
		t.Fatal("a verify job must be given the key envelope and no value")
	}
	envJSON, _ := json.Marshal(env)
	add("key envelope", string(envJSON), nil)
	if _, err = w.svc.Material(ctx, w.peer, jobID); err == nil {
		t.Fatal("the key of a verify job was issued twice")
	}

	result := runnerproto.Result{OK: true, Fingerprint: w.fp, Version: "7"}
	if err = w.svc.Result(ctx, w.peer, jobID, result); err != nil {
		t.Fatalf("runner result rejected: %v", err)
	}

	code, body, h = w.do(http.MethodGet, "/v1/carriers/verify/verify-leak-1", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /v1/carriers/verify/{request_id} = %d, want 200", code)
	}
	add("GET", body, h)
	add("log", w.logs.String(), nil)
	for name, rows := range w.dump() {
		add(name, rows, nil)
	}

	if w.logs.Len() == 0 {
		t.Fatal("logger is not connected; an empty log proves nothing")
	}
	for name, s := range surfaces {
		if leaked(w.canary, s) {
			t.Errorf("secret value leaked on surface %q", name)
		}
		// The carrier row legitimately stores its own metadata; nothing else
		// may carry the consumer or the healthcheck reference.
		if name != "database carriers" && leaked(w.meta, s) {
			t.Errorf("carrier consumer or healthcheck reference leaked on surface %q", name)
		}
	}
}
