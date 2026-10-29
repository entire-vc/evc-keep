package carriers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ctx = context.Background()

type approved struct {
	org, secret uuid.UUID
	meta        Metadata
}

func (a approved) Approved(_ context.Context, org, id uuid.UUID, m Metadata) (bool, error) {
	return a.org == org && a.secret == id && a.meta == m, nil
}

type failedPolicy struct{ err error }

func (p failedPolicy) Approved(context.Context, uuid.UUID, uuid.UUID, Metadata) (bool, error) {
	return false, p.err
}

type fixture struct {
	pool           *pgxpool.Pool
	repo           *Repository
	org, other, id uuid.UUID
	in             Registration
	fp             string
}

func setup(t *testing.T) fixture {
	t.Helper()
	dsn := os.Getenv("KEEP_DATABASE_URL")
	if dsn == "" {
		t.Fatal("KEEP_DATABASE_URL required: carrier tests must run against PostgreSQL")
	}
	db, err := store.OpenMigrationDB(ctx, dsn)
	must(t, err)
	defer func() { _ = db.Close() }()
	_, err = db.Exec(`DROP SCHEMA public CASCADE; CREATE SCHEMA public`)
	must(t, err)
	provider, err := store.NewProvider(db)
	must(t, err)
	_, err = provider.Up(ctx)
	must(t, err)
	pool, err := store.Open(ctx, dsn)
	must(t, err)
	t.Cleanup(pool.Close)
	f := fixture{pool: pool, org: uuid.New(), other: uuid.New(), id: uuid.New()}
	for _, org := range []uuid.UUID{f.org, f.other} {
		_, err = pool.Exec(ctx, `INSERT INTO organizations(id,name) VALUES ($1,'carrier-test')`, org)
		must(t, err)
	}
	sid := uuid.New()
	_, err = pool.Exec(ctx, `INSERT INTO stores(id,org_id,provider,name,owner_scope_level,owner_scope_id) VALUES ($1,$2,'builtin','test','org',$2)`, sid, f.org)
	must(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO secrets(id,org_id,scope_level,scope_id,name,class,type,store_id,provider_ref) VALUES ($1,$2,'org',$2,'TEST','test','password',$3,'test/ref')`, f.id, f.org, sid)
	must(t, err)
	key, err := fingerprint.GenerateKey("carrierkey")
	must(t, err)
	defer key.Wipe()
	f.fp, err = fingerprint.Compute(key, secret.New([]byte("synthetic fixture")))
	must(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length) VALUES ($1,$2,$3,'v1',$4,17)`, uuid.New(), f.org, f.id, f.fp)
	must(t, err)
	f.in = Registration{SecretID: f.id, Version: "v1", Metadata: Metadata{Host: "runner.example.test", TargetKind: runnerproto.TargetEnvFile, TargetPath: "/etc/app/runtime.env", TargetField: "PASSWORD", Consumer: "app.service", HealthcheckRef: "app-health"}, LastFP: f.fp}
	f.repo = New(pool, approved{org: f.org, secret: f.id, meta: f.in.Metadata})
	return f
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func register(t *testing.T, f fixture) Carrier {
	t.Helper()
	c, err := f.repo.Register(ctx, f.org, f.in)
	must(t, err)
	return c
}

// Each metadata slot gets a syntactically plausible planted value. Shape
// validation alone cannot recognize it: only an approved descriptor can.
func TestMetadataCanary(t *testing.T) {
	f := setup(t)
	register(t, f) // positive database control; the dump must contain this row
	c := canary.New()
	if !c.In(c.Value(1)) {
		t.Fatal("blind detector")
	}
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	slog.Info("carrier capture control")
	for _, field := range []string{"Host", "TargetPath", "TargetField", "Consumer", "HealthcheckRef", "TargetKind", "Version", "LastFP"} {
		t.Run(field, func(t *testing.T) {
			in := f.in
			switch field {
			case "Host":
				in.Host = c.Value(1) + ".example.test"
			case "TargetPath":
				in.TargetPath = "/etc/" + c.Value(1)
			case "TargetField":
				in.TargetField = c.Value(1)
			case "Consumer":
				in.Consumer = c.Value(1)
			case "HealthcheckRef":
				in.HealthcheckRef = c.Value(1)
			case "TargetKind":
				in.TargetKind = runnerproto.TargetKind(c.Value(1))
			case "Version":
				in.Version = c.Value(1)
			case "LastFP":
				in.LastFP = c.Value(1)
			}
			slog.Info("metadata capture", "registration", in)
			_, err := f.repo.Register(ctx, f.org, in)
			if err == nil {
				t.Error("unapproved metadata accepted")
			}
			if c.In(fmt.Sprintf("%v %+v %#v", err, err, err)) {
				t.Error("canary in error")
			}
			if c.In(fmt.Sprintf("%v %+v %#v", in, in, in)) {
				t.Error("canary in formatted input")
			}
			b, e := json.Marshal(in)
			must(t, e)
			if c.In(string(b)) {
				t.Error("canary in input JSON")
			}
		})
	}
	bad := New(f.pool, failedPolicy{fmt.Errorf("policy failed: %s", c.Value(1))})
	_, err := bad.Register(ctx, f.org, f.in)
	if err == nil || c.In(fmt.Sprintf("%v %#v", err, err)) {
		t.Error("unsafe policy failure")
	}
	_, err = New(f.pool, nil).Register(ctx, f.org, f.in)
	if err == nil {
		t.Error("nil policy accepted")
	}
	// A complete data dump rather than selected columns: a future column
	// cannot quietly become a plaintext sink outside the assertion.
	conn, err := f.pool.Acquire(ctx)
	must(t, err)
	var dumped bytes.Buffer
	_, err = conn.Conn().PgConn().CopyTo(ctx, &dumped, `COPY public.carriers TO STDOUT`)
	conn.Release()
	must(t, err)
	dump := dumped.Bytes()
	if !bytes.Contains(dump, []byte("runner.example.test")) {
		t.Fatal("dump captured no carrier row")
	}
	if c.In(string(dump)) || c.In(logs.String()) {
		t.Error("canary in table dump or log")
	}
	if logs.Len() == 0 {
		t.Fatal("log capture is empty")
	}
}

func TestTenantIsolation(t *testing.T) {
	f := setup(t)
	c := register(t, f)
	got, err := f.repo.List(ctx, f.org, f.id)
	must(t, err)
	if len(got) != 1 {
		t.Fatal("positive list failed")
	}
	for _, id := range []uuid.UUID{f.id, uuid.New()} {
		got, err = f.repo.List(ctx, f.other, id)
		if !errors.Is(err, ErrNotFound) || len(got) != 0 {
			t.Error("foreign/missing secret distinguishable or visible")
		}
	}
	// A permissive policy must not remove the repository's tenant boundary.
	r := New(f.pool, approved{org: f.other, secret: f.id, meta: f.in.Metadata})
	_, err = r.Register(ctx, f.other, f.in)
	if !errors.Is(err, ErrNotFound) {
		t.Error("foreign registration not concealed")
	}
	for _, id := range []uuid.UUID{c.ID, uuid.New()} {
		for _, op := range []func() error{
			func() error { return f.repo.MarkStale(ctx, f.other, id, f.fp) },
			func() error { return f.repo.MarkOK(ctx, f.other, id, f.fp) },
			func() error { return f.repo.MarkUnknown(ctx, f.other, id) },
			func() error { return f.repo.Remove(ctx, f.other, id) },
		} {
			if !errors.Is(op(), ErrNotFound) {
				t.Error("foreign/missing update not concealed")
			}
		}
	}
	got, err = f.repo.List(ctx, f.org, f.id)
	must(t, err)
	if len(got) != 1 || got[0].State != Registered {
		t.Fatal("foreign mutation changed owner row")
	}
}

func TestIdempotentRegistration(t *testing.T) {
	f := setup(t)
	first := register(t, f)
	second := register(t, f)
	if first.ID != second.ID || !first.CreatedAt.Equal(second.CreatedAt) {
		t.Error("retry changed identity")
	}
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.repo.Register(ctx, f.org, f.in)
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	got, err := f.repo.List(ctx, f.org, f.id)
	must(t, err)
	if len(got) != 1 {
		t.Fatalf("retries produced %d rows", len(got))
	}
	// Two slots of the same file are two targets, not an accidental overwrite.
	in := f.in
	in.TargetField = "TOKEN"
	r := New(f.pool, approved{org: f.org, secret: f.id, meta: in.Metadata})
	_, err = r.Register(ctx, f.org, in)
	must(t, err)
	got, err = f.repo.List(ctx, f.org, f.id)
	must(t, err)
	if len(got) != 2 {
		t.Fatal("distinct slots collapsed")
	}
}

func TestFingerprintGate(t *testing.T) {
	f := setup(t)
	c := register(t, f)
	for _, fp := range []string{"kfp1:otherkey:abcdefghijklmnop", strings.Repeat("a", 64), "kfp1:carrierkey:invalid", ""} {
		t.Run(fp, func(t *testing.T) {
			in := f.in
			in.LastFP = fp
			_, err := f.repo.Register(ctx, f.org, in)
			if !errors.Is(err, ErrFingerprint) {
				t.Error("bad registration fingerprint accepted")
			}
			if !errors.Is(f.repo.MarkStale(ctx, f.org, c.ID, fp), ErrFingerprint) {
				t.Error("bad stale fingerprint accepted")
			}
			if !errors.Is(f.repo.MarkOK(ctx, f.org, c.ID, fp), ErrFingerprint) {
				t.Error("bad OK fingerprint accepted")
			}
		})
	}
	got, err := f.repo.List(ctx, f.org, f.id)
	must(t, err)
	if got[0].LastFP != f.fp || got[0].State != Registered {
		t.Fatal("rejected input changed row")
	}
}

func TestStatesAndDeployHook(t *testing.T) {
	f := setup(t)
	c := register(t, f)
	different := "kfp1:carrierkey:abcdefghijklmnop"
	must(t, f.repo.MarkStale(ctx, f.org, c.ID, different))
	got, err := f.repo.List(ctx, f.org, f.id)
	must(t, err)
	if got[0].State != Stale || got[0].LastFP != different || got[0].LastVerifiedAt == nil {
		t.Fatal("stale observation lost")
	}
	if !errors.Is(f.repo.MarkOK(ctx, f.org, c.ID, different), ErrFingerprint) {
		t.Fatal("wrong value marked OK")
	}
	must(t, f.repo.MarkUnknown(ctx, f.org, c.ID))
	got, err = f.repo.List(ctx, f.org, f.id)
	must(t, err)
	if got[0].State != Unknown || got[0].LastVerifiedAt != nil {
		t.Fatal("unavailable carrier not unknown")
	}
	must(t, f.repo.MarkOK(ctx, f.org, c.ID, f.fp))
	result := runnerproto.Result{OK: true, Fingerprint: f.fp, Version: "v1"}
	var hook DeploymentHook = f.repo
	must(t, hook.OnDeployed(ctx, f.org, f.in, result))
	result.OK = false
	if !errors.Is(hook.OnDeployed(ctx, f.org, f.in, result), ErrDeployment) {
		t.Fatal("failed deploy accepted")
	}
	result.OK = true
	result.Version = "v2"
	if !errors.Is(hook.OnDeployed(ctx, f.org, f.in, result), ErrDeployment) {
		t.Fatal("wrong deploy version accepted")
	}
	result.Version = "v1"
	result.Fingerprint = different
	if !errors.Is(hook.OnDeployed(ctx, f.org, f.in, result), ErrDeployment) {
		t.Fatal("wrong deploy fingerprint accepted")
	}
	must(t, f.repo.Remove(ctx, f.org, c.ID))
	got, err = f.repo.List(ctx, f.org, f.id)
	must(t, err)
	if len(got) != 0 {
		t.Fatal("remove left a row")
	}
}

func TestClosedSchemaAndDowngrade(t *testing.T) {
	f := setup(t)
	register(t, f)
	rows, err := f.pool.Query(ctx, `SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name='carriers'`)
	must(t, err)
	var got []string
	for rows.Next() {
		var s string
		must(t, rows.Scan(&s))
		got = append(got, s)
	}
	must(t, rows.Err())
	rows.Close()
	want := []string{"id", "org_id", "secret_id", "version", "host", "target_kind", "target_path", "target_field", "consumer", "healthcheck_ref", "last_fp", "state", "created_at", "updated_at", "last_verified_at"}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatal("carrier schema differs from closed column list")
	}
	db, err := store.OpenMigrationDB(ctx, os.Getenv("KEEP_DATABASE_URL"))
	must(t, err)
	defer func() { _ = db.Close() }()
	p, err := store.NewProvider(db)
	must(t, err)
	_, err = p.DownTo(ctx, 14)
	must(t, err)
	var exists bool
	must(t, f.pool.QueryRow(ctx, `SELECT to_regclass('public.carriers') IS NOT NULL`).Scan(&exists))
	if exists {
		t.Fatal("downgrade left carriers table")
	}
	var count int
	must(t, f.pool.QueryRow(ctx, `SELECT count(*) FROM secrets WHERE org_id=$1 AND id=$2`, f.org, f.id).Scan(&count))
	if count != 1 {
		t.Fatal("downgrade changed catalog")
	}
	_, err = p.Up(ctx)
	must(t, err)
}

// An older well-formed fingerprint cannot mark a newer catalog version OK,
// even while the carrier itself still records that old deployed version.
func TestOldFingerprintReplay(t *testing.T) {
	f := setup(t)
	c := register(t, f)
	fresh := "kfp1:carrierkey:abcdefghijklmnop"
	_, err := f.pool.Exec(ctx, `INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length) VALUES ($1,$2,$3,'new-version',$4,18)`, uuid.New(), f.org, f.id, fresh)
	must(t, err)
	if !errors.Is(f.repo.MarkOK(ctx, f.org, c.ID, f.fp), ErrFingerprint) {
		t.Fatal("old fingerprint acknowledged a new version")
	}
	_, err = f.repo.Register(ctx, f.org, f.in)
	if !errors.Is(err, ErrFingerprint) {
		t.Fatal("old deployment registered after a new version")
	}
	must(t, f.repo.MarkStale(ctx, f.org, c.ID, f.fp))
	got, err := f.repo.List(ctx, f.org, f.id)
	must(t, err)
	if got[0].State != Stale || got[0].Version != "v1" {
		t.Fatal("stale deployment history changed")
	}
	must(t, f.repo.MarkOK(ctx, f.org, c.ID, fresh))
	got, err = f.repo.List(ctx, f.org, f.id)
	must(t, err)
	if got[0].Version != "new-version" || got[0].LastFP != fresh {
		t.Fatal("fresh version not recorded")
	}
}

func TestDeploymentFailureIsNotRegistration(t *testing.T) {
	f := setup(t)
	for _, result := range []runnerproto.Result{
		{OK: false, Version: "v1", Fingerprint: f.fp},
		{OK: true, Version: "v1", Fingerprint: f.fp, ErrorClass: runnerproto.ErrClassTargetWrite},
		{OK: true, Version: "v1", Fingerprint: f.fp, Healthcheck: &runnerproto.Healthcheck{Status: runnerproto.HealthFailed}},
	} {
		if !errors.Is(f.repo.OnDeployed(ctx, f.org, f.in, result), ErrDeployment) {
			t.Fatal("failed deployment was not refused")
		}
	}
	got, err := f.repo.List(ctx, f.org, f.id)
	must(t, err)
	if len(got) != 0 {
		t.Fatal("failed deployment created a carrier")
	}
}

// The error path exercises real SQL execution, including an error whose
// PostgreSQL text carries a planted value. No wrapping may resurrect it.
func TestDatabaseErrorsAreSanitized(t *testing.T) {
	f := setup(t)
	c := register(t, f)
	probe := canary.New()
	// Only this synthetic test session handles the trigger. It silences
	// PostgreSQL ERROR messages too: a sanitized application error alone
	// would not stop the database server's primary error text from leaking.
	conn, err := f.pool.Acquire(ctx)
	must(t, err)
	_, err = conn.Exec(ctx, `SET log_min_messages=panic`)
	must(t, err)
	_, err = conn.Exec(ctx, `CREATE FUNCTION carrier_error_probe() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION '`+probe.Value(1)+`'; END $$`)
	must(t, err)
	_, err = conn.Exec(ctx, `CREATE TRIGGER carrier_error_probe BEFORE INSERT OR UPDATE OR DELETE ON carriers FOR EACH ROW EXECUTE FUNCTION carrier_error_probe()`)
	must(t, err)
	conn.Release()
	// The pool reuses its only opened connection in this sequential test.
	for _, op := range []func() error{
		func() error { _, err := f.repo.Register(ctx, f.org, f.in); return err },
		func() error { return f.repo.MarkStale(ctx, f.org, c.ID, f.fp) },
		func() error { return f.repo.MarkOK(ctx, f.org, c.ID, f.fp) },
		func() error { return f.repo.MarkUnknown(ctx, f.org, c.ID) },
		func() error { return f.repo.Remove(ctx, f.org, c.ID) },
	} {
		err := op()
		if !errors.Is(err, ErrInternal) || probe.In(fmt.Sprintf("%v %+v %#v", err, err, err)) || errors.Unwrap(err) != nil {
			t.Fatal("unsafe database error")
		}
	}
	_, err = f.pool.Exec(ctx, `DROP TABLE carriers CASCADE`)
	must(t, err)
	_, err = f.repo.List(ctx, f.org, f.id)
	if !errors.Is(err, ErrInternal) || errors.Unwrap(err) != nil {
		t.Fatal("unsafe list error")
	}
}

type pausingPolicy struct {
	approved
	entered chan struct{}
	resume  chan struct{}
}

func (p pausingPolicy) Approved(ctx context.Context, org, id uuid.UUID, m Metadata) (bool, error) {
	close(p.entered)
	select {
	case <-p.resume:
		return p.approved.Approved(ctx, org, id, m)
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func TestCatalogVersionCannotRaceRegistration(t *testing.T) {
	f := setup(t)
	p := pausingPolicy{approved: approved{org: f.org, secret: f.id, meta: f.in.Metadata}, entered: make(chan struct{}), resume: make(chan struct{})}
	r := New(f.pool, p)
	runctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := r.Register(runctx, f.org, f.in); result <- err }()
	select {
	case <-p.entered:
	case <-runctx.Done():
		t.Fatal("registration never reached policy")
	}
	// Roll back a competing write with a bounded lock timeout. A successful
	// insert would show the version check/write window was unprotected.
	tx, err := f.pool.Begin(runctx)
	must(t, err)
	_, err = tx.Exec(runctx, `SET LOCAL lock_timeout='100ms'`)
	must(t, err)
	_, err = tx.Exec(runctx, `INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length) VALUES($1,$2,$3,'racing-version',$4,18)`, uuid.New(), f.org, f.id, f.fp)
	_ = tx.Rollback(runctx)
	close(p.resume)
	must(t, <-result)
	var pgerr *pgconn.PgError
	if !errors.As(err, &pgerr) || pgerr.Code != "55P03" {
		t.Fatal("catalog version changed between check and registration")
	}
	_, err = f.pool.Exec(ctx, `INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length) VALUES($1,$2,$3,'racing-version',$4,18)`, uuid.New(), f.org, f.id, f.fp)
	must(t, err)
}
