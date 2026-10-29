package carriers

import (
	"bytes"
	"context"
	"encoding"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestRegistrationRejectsDifferentHashUnderCurrentKey(t *testing.T) {
	f := setup(t)
	before := register(t, f)
	in := f.in
	in.LastFP = "kfp1:carrierkey:abcdefghijklmnop"
	if in.LastFP == f.fp {
		t.Fatal("mismatch control is identical")
	}
	_, err := f.repo.Register(ctx, f.org, in)
	if !errors.Is(err, ErrFingerprint) {
		t.Error("different content under current key accepted")
	}
	got, err := f.repo.List(ctx, f.org, f.id)
	must(t, err)
	if len(got) != 1 || !reflect.DeepEqual(got[0], before) {
		t.Fatal("rejected registration changed stored carrier")
	}
}

func TestRegistrationUpdatesAfterRotation(t *testing.T) {
	f := setup(t)
	before := register(t, f)
	fresh := "kfp1:carrierkey:abcdefghijklmnop"
	if fresh == f.fp {
		t.Fatal("rotation control unchanged")
	}
	_, err := f.pool.Exec(ctx, `INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length,created_at) VALUES ($1,$2,$3,'v2',$4,18,now()+interval '1 second')`, uuid.New(), f.org, f.id, fresh)
	must(t, err)
	in := f.in
	in.Version, in.LastFP = "v2", fresh
	for range 2 {
		after, err := f.repo.Register(ctx, f.org, in)
		must(t, err)
		if after.ID != before.ID || !after.CreatedAt.Equal(before.CreatedAt) || after.Version != "v2" || after.LastFP != fresh {
			t.Error("rotation retry lost new version or fingerprint")
		}
	}
	got, err := f.repo.List(ctx, f.org, f.id)
	must(t, err)
	if len(got) != 1 || got[0].Version != "v2" || got[0].LastFP != fresh || got[0].ID != before.ID {
		t.Fatal("rotation upsert did not preserve one updated carrier")
	}
}

func internalError(t *testing.T, err error) {
	t.Helper()
	if err != ErrInternal || errors.Unwrap(err) != nil {
		t.Error("database error escaped its fixed public class")
	}
}

func writeOperations(f fixture, c Carrier, callctx context.Context) map[string]func() error {
	return map[string]func() error{
		"register":   func() error { _, err := f.repo.Register(callctx, f.org, f.in); return err },
		"mark-ok":    func() error { return f.repo.MarkOK(callctx, f.org, c.ID, f.fp) },
		"mark-stale": func() error { return f.repo.MarkStale(callctx, f.org, c.ID, f.fp) },
	}
}

func TestDatabaseBeginErrorsAreSanitized(t *testing.T) {
	for _, closed := range []bool{false, true} {
		t.Run(fmt.Sprintf("closed-%t", closed), func(t *testing.T) {
			f := setup(t)
			c := register(t, f)
			callctx, cancel := context.WithCancel(ctx)
			defer cancel()
			if closed {
				f.pool.Close()
			} else {
				cancel()
			}
			ops := writeOperations(f, c, callctx)
			ops["list"] = func() error { _, err := f.repo.List(callctx, f.org, f.id); return err }
			for name, op := range ops {
				t.Run(name, func(t *testing.T) { internalError(t, op()) })
			}
		})
	}
}

func TestDatabaseCurrentErrorsAreSanitized(t *testing.T) {
	for _, table := range []string{"secrets", "secret_versions"} {
		t.Run(table, func(t *testing.T) {
			f := setup(t)
			c := register(t, f)
			// A fixed test-owned identifier, never caller input.
			_, err := f.pool.Exec(ctx, "ALTER TABLE "+table+" RENAME TO unavailable_catalog")
			must(t, err)
			for name, op := range writeOperations(f, c, ctx) {
				t.Run(name, func(t *testing.T) { internalError(t, op()) })
			}
		})
	}
}

func TestDatabaseListErrorPathsAreSanitized(t *testing.T) {
	for _, stage := range []string{"lookup", "query", "scan", "rows"} {
		t.Run(stage, func(t *testing.T) {
			f := setup(t)
			register(t, f)
			var query string
			switch stage {
			case "lookup":
				query = `ALTER TABLE secrets RENAME TO unavailable_catalog`
			case "query":
				query = `DROP TABLE carriers CASCADE`
			case "scan":
				query = `ALTER TABLE carriers ALTER COLUMN last_verified_at TYPE TEXT USING 'not-a-time'`
			case "rows":
				query = `ALTER TABLE carriers RENAME TO carrier_data;
CREATE FUNCTION carrier_read_error(text) RETURNS text LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic read error'; END $$;
CREATE VIEW carriers AS SELECT id,org_id,secret_id,version,host,target_kind,target_path,target_field,consumer,carrier_read_error(healthcheck_ref) AS healthcheck_ref,last_fp,state,created_at,updated_at,last_verified_at FROM carrier_data`
			}
			_, err := f.pool.Exec(ctx, query)
			must(t, err)
			_, err = f.repo.List(ctx, f.org, f.id)
			internalError(t, err)
		})
	}
}

func TestDatabaseMarkLookupErrorsAreSanitized(t *testing.T) {
	f := setup(t)
	c := register(t, f)
	_, err := f.pool.Exec(ctx, `DROP TABLE carriers CASCADE`)
	must(t, err)
	internalError(t, f.repo.MarkOK(ctx, f.org, c.ID, f.fp))
	internalError(t, f.repo.MarkStale(ctx, f.org, c.ID, f.fp))
}

func TestDatabaseCommitErrorsAreSanitized(t *testing.T) {
	f := setup(t)
	c := register(t, f)
	_, err := f.pool.Exec(ctx, `CREATE FUNCTION carrier_commit_error() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic commit error'; END $$;
CREATE CONSTRAINT TRIGGER carrier_commit_error AFTER INSERT OR UPDATE ON carriers DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION carrier_commit_error()`)
	must(t, err)
	// Prove the error is deferred until Commit, rather than another Exec case.
	tx, err := f.pool.Begin(ctx)
	must(t, err)
	_, err = tx.Exec(ctx, `UPDATE carriers SET updated_at=now() WHERE org_id=$1 AND id=$2`, f.org, c.ID)
	must(t, err)
	if err = tx.Commit(ctx); err == nil {
		t.Fatal("deferred commit control did not fail")
	}
	for name, op := range writeOperations(f, c, ctx) {
		t.Run(name, func(t *testing.T) { internalError(t, op()) })
	}
}

func TestInactiveCatalogCannotRegister(t *testing.T) {
	for _, secretDisabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("secret-disabled-%t", secretDisabled), func(t *testing.T) {
			f := setup(t)
			before := register(t, f)
			query := `UPDATE secret_versions SET disabled=true WHERE org_id=$1 AND secret_id=$2`
			if secretDisabled {
				query = `UPDATE secrets SET status='disabled' WHERE org_id=$1 AND id=$2`
			}
			_, err := f.pool.Exec(ctx, query, f.org, f.id)
			must(t, err)
			_, err = f.repo.Register(ctx, f.org, f.in)
			if !errors.Is(err, ErrNotFound) {
				t.Error("inactive catalog accepted registration")
			}
			got, err := f.repo.List(ctx, f.org, f.id)
			must(t, err)
			if len(got) != 1 || !reflect.DeepEqual(before, got[0]) {
				t.Fatal("inactive catalog registration changed carrier")
			}
		})
	}
}

func TestDirectCarrierConstraints(t *testing.T) {
	f := setup(t)
	insert := func(org, id uuid.UUID, fp, state string) error {
		_, err := f.pool.Exec(ctx, `INSERT INTO carriers(id,org_id,secret_id,version,host,target_kind,target_path,last_fp,state) VALUES($1,$2,$3,'v1','direct.example.test','env-file','/direct',$4,$5)`, uuid.New(), org, id, fp, state)
		return err
	}
	must(t, insert(f.org, f.id, f.fp, "registered"))
	for _, tc := range []struct {
		name, fp, state, code, constraint string
		org                               uuid.UUID
	}{
		{"fingerprint", "sha256", "registered", "23514", "carriers_last_fp_check", f.org},
		{"state", f.fp, "unsupported", "23514", "carriers_state_check", f.org},
		{"secret-fk", f.fp, "registered", "23503", "carriers_org_id_secret_id_fkey", f.other},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var pgerr *pgconn.PgError
			err := insert(tc.org, f.id, tc.fp, tc.state)
			if !errors.As(err, &pgerr) || pgerr.Code != tc.code || pgerr.ConstraintName != tc.constraint {
				t.Error("required direct-insert constraint not enforced")
			}
		})
	}
}

func TestCatalogVersionRowCannotRaceRegistration(t *testing.T) {
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
		t.Fatal("policy not reached")
	}
	tx, err := f.pool.Begin(runctx)
	must(t, err)
	_, err = tx.Exec(runctx, `SET LOCAL lock_timeout='100ms'`)
	must(t, err)
	_, writeErr := tx.Exec(runctx, `UPDATE secret_versions SET disabled=true WHERE org_id=$1 AND secret_id=$2`, f.org, f.id)
	_ = tx.Rollback(runctx)
	close(p.resume)
	must(t, <-result)
	var pgerr *pgconn.PgError
	if !errors.As(writeErr, &pgerr) || pgerr.Code != "55P03" {
		t.Fatal("version row changed while registration held policy lock")
	}
	_, err = f.pool.Exec(ctx, `UPDATE secret_versions SET disabled=true WHERE org_id=$1 AND secret_id=$2`, f.org, f.id)
	must(t, err) // The lock must have been released after registration.
}

func TestMetadataPolicyDeadlineReleasesLock(t *testing.T) {
	f := setup(t)
	p := pausingPolicy{approved: approved{org: f.org, secret: f.id, meta: f.in.Metadata}, entered: make(chan struct{}), resume: make(chan struct{})}
	runctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, ok := runctx.Deadline(); !ok {
		t.Fatal("policy caller has no deadline")
	}
	result := make(chan error, 1)
	go func() { _, err := New(f.pool, p).Register(runctx, f.org, f.in); result <- err }()
	select {
	case <-p.entered:
	case <-runctx.Done():
		t.Fatal("policy not reached")
	}
	cancel()
	select {
	case err := <-result:
		if err != ErrMetadata || errors.Unwrap(err) != nil {
			t.Error("policy cancellation escaped fixed class")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("policy ignored caller cancellation")
	}
	checkctx, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	tx, err := f.pool.Begin(checkctx)
	must(t, err)
	_, err = tx.Exec(checkctx, `SET LOCAL lock_timeout='100ms'`)
	must(t, err)
	_, err = tx.Exec(checkctx, `UPDATE secrets SET updated_at=now() WHERE org_id=$1 AND id=$2`, f.org, f.id)
	_ = tx.Rollback(checkctx)
	must(t, err)
	got, err := f.repo.List(ctx, f.org, f.id)
	must(t, err)
	if len(got) != 0 {
		t.Fatal("cancelled policy registered a carrier")
	}
}

func TestMetadataSerializationRefused(t *testing.T) {
	c := canary.New()
	if !c.In(c.Value(1)) {
		t.Fatal("blind serialization detector")
	}
	m := Metadata{Host: c.Value(1), Consumer: c.Value(1)}
	for _, v := range []any{m, &m, Registration{Metadata: m}, &Registration{Metadata: m}, Carrier{Metadata: m}, &Carrier{Metadata: m}} {
		var out bytes.Buffer
		err := gob.NewEncoder(&out).Encode(v)
		if err == nil || c.In(out.String()) || c.In(fmt.Sprintf("%v %+v %#v", err, err, err)) {
			t.Error("gob did not refuse metadata safely")
		}
	}
	var control bytes.Buffer
	must(t, gob.NewEncoder(&control).Encode("capture-control"))
	if control.Len() == 0 {
		t.Fatal("gob capture blind")
	}
	before := Metadata{Host: "approved.example.test"}
	for _, input := range [][]byte{[]byte(`{"Host":"` + c.Value(1) + `"}`), []byte(`null`), []byte(`"` + c.Value(1) + `"`)} {
		got := before
		err := json.Unmarshal(input, &got)
		if err == nil || got != before || c.In(fmt.Sprintf("%v %+v %#v", err, err, err)) {
			t.Error("JSON metadata decode not refused safely")
		}
	}
	got := before
	if u, ok := any(&got).(encoding.TextUnmarshaler); !ok {
		t.Error("metadata has no text decode refusal")
	} else if err := u.UnmarshalText([]byte(c.Value(1))); err != ErrMetadata || got != before {
		t.Error("text metadata decode accepted")
	}
	got = before
	if u, ok := any(&got).(gob.GobDecoder); !ok {
		t.Error("metadata has no gob decode refusal")
	} else if err := u.GobDecode([]byte(c.Value(1))); err != ErrMetadata || got != before {
		t.Error("gob metadata decode accepted")
	}
}
