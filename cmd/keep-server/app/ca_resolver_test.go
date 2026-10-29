package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"

	"github.com/entire-vc/evc-keep/internal/builtin/orgpki"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestProductionCAResolverUsesAuthenticatedCache(t *testing.T) {
	dsn := pgscratch.New(t, nil)
	migrate(t, buildKeepServer(t), dsn)
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("open test database")
	}
	t.Cleanup(db.Close)
	org := uuid.New()
	if _, err := db.Exec(ctx, `INSERT INTO organizations(id,name) VALUES($1,$2)`, org, "resolver-test"); err != nil {
		t.Fatal("seed organization")
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	repo, err := orgpki.NewRepoFromKey(db, "test-root", key)
	if err != nil {
		t.Fatal(err)
	}
	want, err := repo.Ensure(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE org_ca SET ca_ciphertext=$1 WHERE org_id=$2`, []byte("synthetic-corruption"), org); err != nil {
		t.Fatal("corrupt sealed test material")
	}
	got, ok, err := (orgpkiCAResolver{repo}).CACert(ctx, org)
	if err != nil || !ok || !bytes.Equal(got, want.CACertDER) {
		t.Fatal("resolver reopened sealed material instead of using the authenticated CA")
	}
}
