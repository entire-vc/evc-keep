package builtin

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	persiststore "github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
)

// These tests migrate an empty database from the actual embedded SQL. A
// mutation adding a column to a migration must reach the inventory check,
// rather than run against an already-migrated shared database.
func databaseSecurityPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := pgscratch.New(t, nil)
	ctx := pgscratch.Context(t)
	db, err := persiststore.OpenMigrationDB(ctx, dsn)
	if err != nil {
		t.Fatal("open security migration database")
	}
	defer func() { _ = db.Close() }()
	migrations, err := persiststore.NewProvider(db)
	if err != nil {
		t.Fatal("create security migration provider")
	}
	if _, err := migrations.Up(ctx); err != nil {
		t.Fatal("apply security migrations")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("open security database pool")
	}
	t.Cleanup(pool.Close)
	return pool
}

type databaseColumn struct{ table, name, kind string }

// Every text/bytea column is reviewed explicitly, including metadata. The
// database supplies the inventory; this list must never silently limit it.
func databaseSecurityColumns(t *testing.T, pool *pgxpool.Pool) []databaseColumn {
	t.Helper()
	reviewed := map[string]map[string]string{
		"keep_envelope": {
			"store_org": "text", "store_workspace": "text", "store_project": "text", "store_user": "text",
			"secret_id": "text", "name": "text", "kek_id": "text", "status": "text",
			"wrapped_dek": "bytea", "ciphertext": "bytea",
		},
		"keep_kek": {
			"id": "text", "org_id": "text", "domain_key": "text", "domain_org": "text",
			"domain_workspace": "text", "domain_project": "text", "domain_user": "text",
			"root_key_id": "text", "state": "text", "wrapped": "bytea",
		},
		"keep_org_key_level": {"org_id": "text", "level": "text", "updated_by": "text"},
	}
	rows, err := pool.Query(context.Background(), `SELECT table_name, column_name, data_type
		FROM information_schema.columns WHERE table_schema = 'public'
		AND left(table_name, 5) = 'keep_' AND data_type IN ('text', 'bytea')
		ORDER BY table_name, column_name`)
	if err != nil {
		t.Fatal("query database column inventory")
	}
	defer rows.Close()
	var columns []databaseColumn
	for rows.Next() {
		var col databaseColumn
		if err := rows.Scan(&col.table, &col.name, &col.kind); err != nil {
			t.Fatal("read database column inventory")
		}
		if reviewed[col.table][col.name] != col.kind {
			t.Fatalf("unreviewed database column %s.%s (%s)", col.table, col.name, col.kind)
		}
		delete(reviewed[col.table], col.name)
		columns = append(columns, col)
	}
	if rows.Err() != nil {
		t.Fatal("iterate database column inventory")
	}
	for table, cols := range reviewed {
		for name := range cols {
			t.Fatalf("reviewed database column missing: %s.%s", table, name)
		}
	}
	return columns
}

// Return locations only: a failing witness must never print the cell or key.
func databaseMatches(t *testing.T, pool *pgxpool.Pool, columns []databaseColumn, contains func([]byte) bool) []databaseColumn {
	t.Helper()
	var matches []databaseColumn
	for _, col := range columns {
		func() {
			query := "SELECT " + pgx.Identifier{col.name}.Sanitize() + " FROM " + pgx.Identifier{"public", col.table}.Sanitize()
			rows, err := pool.Query(context.Background(), query)
			if err != nil {
				t.Fatalf("query database column %s.%s", col.table, col.name)
			}
			defer rows.Close()
			for rows.Next() {
				var value any
				if err := rows.Scan(&value); err != nil {
					t.Fatalf("read database column %s.%s", col.table, col.name)
				}
				var data []byte
				switch v := value.(type) {
				case nil:
					continue
				case string:
					data = []byte(v)
				case []byte:
					data = v
				default:
					t.Fatalf("unexpected database type at %s.%s", col.table, col.name)
				}
				found := contains(data)
				clear(data)
				if found {
					matches = append(matches, col)
				}
			}
			if rows.Err() != nil {
				t.Fatalf("iterate database column %s.%s", col.table, col.name)
			}
		}()
	}
	return matches
}

func TestWrappedKEKIsActuallyWrapped(t *testing.T) {
	ctx := context.Background()
	pool := databaseSecurityPool(t)
	seal, root, _ := testSealerWithRoot(t, pool)
	scope := sealer.Scope{Org: randID(t, "org"), User: "alice"}
	p := New(pool, seal, scope, nil)
	if _, err := p.Write(ctx, providerRef("s1"), secretOf("value")); err != nil {
		t.Fatal("write KEK witness")
	}
	row, err := p.db.byVersion(ctx, scope, "s1", 1)
	if err != nil {
		t.Fatal("read DEK witness")
	}
	rec, err := p.db.Get(ctx, scope.Org, row.kekID)
	if err != nil {
		t.Fatal("read KEK witness")
	}
	const keyLen, nonceLen, tagLen = 32, 12, 16
	if len(rec.Wrapped) != keyLen+nonceLen+tagLen {
		t.Fatalf("wrapped KEK length = %d, want %d", len(rec.Wrapped), keyLen+nonceLen+tagLen)
	}
	if len(row.wrapped) != keyLen+nonceLen+tagLen {
		t.Fatal("invalid wrapped DEK witness length")
	}
	openDEK := func(key []byte) ([]byte, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		aad := dekAADForTest(scopeKeyForTest(scope), "s1", "1", rec.ID)
		return aead.Open(nil, row.wrapped[:nonceLen], row.wrapped[nonceLen:], aad)
	}
	if plain, err := openDEK(rec.Wrapped[:keyLen]); err == nil {
		clear(plain)
		t.Fatal("wrapped KEK bytes opened wrapped DEK directly")
	}
	// Positive control: this very DEK opens under the authenticated raw KEK.
	key, err := root.Unwrap(rec.Wrapped, kekAADForTest(rec.ID, rec.Org, scopeKeyForTest(rec.Domain), rec.RootKeyID))
	if err != nil {
		t.Fatal("unwrap KEK positive control")
	}
	defer clear(key)
	dek, err := openDEK(key)
	defer clear(dek)
	if err != nil || len(dek) != keyLen {
		t.Fatal("raw KEK did not open the wrapped DEK positive control")
	}
}

func TestNoRawFingerprintKeyInDatabase(t *testing.T) {
	ctx := context.Background()
	pool := databaseSecurityPool(t)
	seal, _ := testSealer(t, pool)
	scope := sealer.Scope{Org: randID(t, "org"), User: "alice"}
	p := New(pool, seal, scope, nil)
	k, err := p.FingerprintKey(ctx)
	if err != nil {
		t.Fatal("create fingerprint key witness")
	}
	defer k.Wipe()
	var raw []byte
	fingerprint.ExposeKey(k, func(b []byte) { raw = append([]byte(nil), b...) })
	defer clear(raw)
	if len(raw) != 32 {
		t.Fatal("invalid fingerprint key witness length")
	}
	hexed := make([]byte, hex.EncodedLen(len(raw)))
	hex.Encode(hexed, raw)
	defer clear(hexed)
	upper := bytes.ToUpper(hexed)
	defer clear(upper)
	columns := databaseSecurityColumns(t, pool)
	scan := func(t *testing.T) []databaseColumn {
		return databaseMatches(t, pool, columns, func(cell []byte) bool {
			return bytes.Contains(cell, raw) || bytes.Contains(cell, hexed) || bytes.Contains(cell, upper)
		})
	}
	if found := scan(t); len(found) != 0 {
		t.Fatalf("fingerprint key found in %s.%s", found[0].table, found[0].name)
	}
	row, err := p.db.byVersion(ctx, scope, fpKeySecretID, 1)
	if err != nil || len(row.cipher) == 0 {
		t.Fatal("missing persisted fingerprint key witness")
	}
	// Seed both bytea and text cells independently; the shared scanner must
	// find the exact seeded location, not a failure elsewhere in the database.
	for _, control := range []struct {
		name, column string
		value        any
	}{
		{"raw-bytea", "ciphertext", raw},
		{"hex-bytea", "ciphertext", hexed},
		{"hex-text", "name", string(hexed)},
		{"upper-hex-text", "name", string(upper)},
	} {
		t.Run(control.name, func(t *testing.T) {
			t.Cleanup(func() {
				if _, err := pool.Exec(ctx, `UPDATE keep_envelope SET ciphertext = $1, name = $2 WHERE store_org = $3 AND secret_id = $4`, row.cipher, row.name, scope.Org, fpKeySecretID); err != nil {
					t.Fatal("restore fingerprint key positive control")
				}
			})
			query := "UPDATE keep_envelope SET " + pgx.Identifier{control.column}.Sanitize() + " = $1 WHERE store_org = $2 AND secret_id = $3"
			result, err := pool.Exec(ctx, query, control.value, scope.Org, fpKeySecretID)
			if err != nil || result.RowsAffected() != 1 {
				t.Fatal("seed fingerprint key positive control")
			}
			found := scan(t)
			seen := false
			for _, col := range found {
				seen = seen || col.table == "keep_envelope" && col.name == control.column
			}
			if !seen {
				t.Fatal("fingerprint key positive control not detected at seeded column")
			}
		})
	}
}
