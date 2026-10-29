package builtin

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	"github.com/entire-vc/evc-keep/pkg/provider"
)

// A constraint violation's Detail quotes the failing row; for keep_envelope
// that is a wrapped DEK and ciphertext. None of it may survive in the error
// text or be reachable through errors.As.
func TestUnavailable_DropsPgErrorRowText(t *testing.T) {
	const row = "deadbeefcafe0123"
	pgErr := &pgconn.PgError{
		Code:    "23505",
		Message: "duplicate key value violates unique constraint",
		Detail:  "Failing row contains (\\x" + row + ")",
		Where:   "row " + row,
		Hint:    "hint " + row,
	}
	err := unavailable("insert", pgErr)
	if !errors.Is(err, provider.ErrUnavailable) {
		t.Fatalf("not provider.ErrUnavailable: %v", err)
	}
	if strings.Contains(err.Error(), row) || strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("error text carries the database's own message: %q", err)
	}
	if !strings.Contains(err.Error(), "23505") {
		t.Fatalf("error text lost the SQLSTATE: %q", err)
	}
	var got *pgconn.PgError
	if errors.As(err, &got) {
		t.Fatalf("errors.As reaches the PgError (Detail %q)", got.Detail)
	}

	// Positive control: an error that is not a database error stays wrapped.
	if !errors.Is(unavailable("begin", context.Canceled), context.Canceled) {
		t.Fatal("a cancelled context must stay visible through errors.Is")
	}
}

// Admin.ChangeLevel returns sealer and store errors to its caller. When the
// re-wrap UPDATE fails on a constraint, the driver's Detail quotes the failing
// row (the start of the wrapped DEK and ciphertext); none of it may reach the
// caller through the text or errors.As.
func TestAdminChangeLevel_DatabaseErrorCarriesSQLSTATEOnly(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	seal, _ := testSealer(t, pool)
	org := randID(t, "org")
	p := New(pool, seal, sealer.Scope{Org: org, User: "alice"}, nil)
	if _, err := p.Write(ctx, providerRef("s"), secretOf("v")); err != nil {
		t.Fatal(err)
	}

	// Positive control: without the constraint the same call succeeds.
	admin := NewAdmin(pool, seal, org, nil)
	if _, err := admin.ChangeLevel(ctx, sealer.LevelOrg, "admin", true); err != nil {
		t.Fatalf("control ChangeLevel: %v", err)
	}
	if _, err := admin.ChangeLevel(ctx, sealer.LevelUser, "admin", true); err != nil {
		t.Fatalf("control ChangeLevel back: %v", err)
	}

	// Any UPDATE that leaves both columns set now fails, as the re-wrap does.
	if _, err := pool.Exec(ctx, `ALTER TABLE keep_envelope ADD CONSTRAINT probe_rewrap CHECK (kek_id IS NULL OR wrapped_dek IS NULL) NOT VALID`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `ALTER TABLE keep_envelope DROP CONSTRAINT IF EXISTS probe_rewrap`)
	})

	_, err := admin.ChangeLevel(ctx, sealer.LevelOrg, "admin", true)
	if err == nil {
		t.Fatal("ChangeLevel succeeded although the re-wrap UPDATE violates a constraint")
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		t.Fatalf("errors.As reaches the PgError (Detail %q)", pgErr.Detail)
	}
	if strings.Contains(err.Error(), "Failing row") || strings.Contains(err.Error(), "violates") {
		t.Fatalf("error text carries the database's own message: %q", err)
	}
	if !strings.Contains(err.Error(), "sqlstate 23514") {
		t.Fatalf("error text lost the SQLSTATE: %q", err)
	}
}

// Write's seal failure is reported as a bare ErrUnavailable. Seal's own KEK
// INSERT can fail with a constraint violation whose Detail quotes the wrapped
// KEK, so the chain must not be kept.
func TestWrite_SealDatabaseErrorIsNotChained(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	seal, _ := testSealer(t, pool)

	// Positive control: a fresh organisation writes fine before the constraint.
	ok := New(pool, seal, sealer.Scope{Org: randID(t, "org"), User: "alice"}, nil)
	if _, err := ok.Write(ctx, providerRef("s"), secretOf("v")); err != nil {
		t.Fatalf("control Write: %v", err)
	}

	if _, err := pool.Exec(ctx, `ALTER TABLE keep_kek ADD CONSTRAINT probe_kek_insert CHECK (false) NOT VALID`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `ALTER TABLE keep_kek DROP CONSTRAINT IF EXISTS probe_kek_insert`)
	})

	// A new organisation has no KEK yet, so Seal must INSERT one and fails.
	p := New(pool, seal, sealer.Scope{Org: randID(t, "org"), User: "bob"}, nil)
	_, err := p.Write(ctx, providerRef("s"), secretOf("v"))
	if !errors.Is(err, provider.ErrUnavailable) {
		t.Fatalf("Write error = %v, want ErrUnavailable", err)
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		t.Fatalf("errors.As reaches the PgError (Detail %q)", pgErr.Detail)
	}
	if strings.Contains(err.Error(), "Failing row") || strings.Contains(err.Error(), "violates") {
		t.Fatalf("error text carries the database's own message: %q", err)
	}
}

// Admin.Purge deletes retired KEKs. A database failure there is cut down to
// the SQLSTATE like ChangeLevel's: the driver's Detail can quote the KEK row.
func TestAdminPurge_DatabaseErrorCarriesSQLSTATEOnly(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	seal, _ := testSealer(t, pool)
	org := randID(t, "org")
	p := New(pool, seal, sealer.Scope{Org: org, User: "alice"}, nil)
	if _, err := p.Write(ctx, providerRef("s"), secretOf("v")); err != nil {
		t.Fatal(err)
	}
	// user -> org -> user leaves the organisation's KEK retired and unused.
	admin := NewAdmin(pool, seal, org, nil)
	for _, l := range []sealer.Level{sealer.LevelOrg, sealer.LevelUser} {
		if _, err := admin.ChangeLevel(ctx, l, "admin", true); err != nil {
			t.Fatal(err)
		}
	}

	// A trigger fails the DELETE the way a constraint would, quoting a row.
	for _, q := range []string{
		`CREATE FUNCTION probe_purge_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'probe' USING ERRCODE = '23514', DETAIL = 'Failing row contains (probe-detail)'; END $$`,
		`CREATE TRIGGER probe_purge BEFORE DELETE ON keep_kek FOR EACH ROW EXECUTE FUNCTION probe_purge_fail()`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS probe_purge ON keep_kek`)
		_, _ = pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS probe_purge_fail()`)
	})

	_, err := admin.Purge(ctx, "admin")
	if err == nil {
		t.Fatal("Purge succeeded although its DELETE fails")
	}
	requireSQLStateOnly(t, err, "23514")
}

// Opening the sealed fingerprint key can fail in the database (here: the KEK
// read). The error must not chain the driver's error.
func TestFingerprintKey_OpenDatabaseErrorCarriesSQLSTATEOnly(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	seal, _ := testSealer(t, pool)
	p := New(pool, seal, sealer.Scope{Org: randID(t, "org"), User: "alice"}, nil)
	if _, err := p.FingerprintKey(ctx); err != nil {
		t.Fatalf("control FingerprintKey: %v", err)
	}

	if _, err := pool.Exec(ctx, `ALTER TABLE keep_kek RENAME COLUMN wrapped TO wrapped_probe`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `ALTER TABLE keep_kek RENAME COLUMN wrapped_probe TO wrapped`)
	})

	_, err := p.FingerprintKey(ctx)
	if err == nil {
		t.Fatal("FingerprintKey succeeded although the KEK read fails")
	}
	requireSQLStateOnly(t, err, "42703")
}

func requireSQLStateOnly(t *testing.T, err error, sqlstate string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		t.Fatalf("errors.As reaches the PgError (Detail %q)", pgErr.Detail)
	}
	if strings.Contains(err.Error(), "probe-detail") || strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("error text carries the database's own message: %q", err)
	}
	if !strings.Contains(err.Error(), "sqlstate "+sqlstate) {
		t.Fatalf("error text lost the SQLSTATE %s: %q", sqlstate, err)
	}
}
