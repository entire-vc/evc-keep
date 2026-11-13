package orgpki

import (
	"context"
	"errors"
	"testing"
)

func TestReadAuthenticatedRow(t *testing.T) {
	repo, db := newRepo(t)
	ctx := context.Background()
	org := seedOrg(t, db)
	other := seedOrg(t, db)

	// Missing row: reported as absent, and nothing is generated.
	if _, ok, err := ReadAuthenticatedRow(ctx, db, repo.sealer, org); err != nil || ok {
		t.Fatalf("missing row: ok=%v err=%v", ok, err)
	}
	var n int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM org_ca WHERE org_id = $1`, org).Scan(&n); err != nil || n != 0 {
		t.Fatalf("reader generated or wrote a CA: n=%d err=%v", n, err)
	}

	if _, err := repo.Ensure(ctx, org); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if _, err := repo.Ensure(ctx, other); err != nil {
		t.Fatalf("Ensure other: %v", err)
	}
	row, ok, err := ReadAuthenticatedRow(ctx, db, repo.sealer, org)
	if err != nil || !ok || len(row.CACertDER) == 0 {
		t.Fatalf("authentic row: ok=%v err=%v", ok, err)
	}

	// Foreign: org's row presented under another org id is refused.
	if _, ok, err := ReadAuthenticatedRow(ctx, db, repo.sealer, other); err != nil || !ok {
		t.Fatalf("other org's own row must still read: ok=%v err=%v", ok, err)
	}
	if err := AuthenticateRow(ctx, repo.sealer, other, row); !errors.Is(err, ErrRowNotAuthentic) {
		t.Fatalf("foreign row accepted: %v", err)
	}

	// Tamper in the database: refused, bare error.
	if _, err := db.Exec(ctx, `UPDATE org_ca SET sign_ciphertext = set_byte(sign_ciphertext, 0, get_byte(sign_ciphertext, 0) # 1) WHERE org_id = $1`, org); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if _, ok, err := ReadAuthenticatedRow(ctx, db, repo.sealer, org); !errors.Is(err, ErrRowNotAuthentic) || ok {
		t.Fatalf("tampered row accepted: ok=%v err=%v", ok, err)
	}
}
