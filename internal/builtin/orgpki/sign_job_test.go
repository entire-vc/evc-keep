package orgpki

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func signingJob(t *testing.T, org uuid.UUID) runnerproto.Job {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal("generate job id")
	}
	now := time.Now().Truncate(time.Second)
	return runnerproto.Job{JobID: id.String(), OrgID: org.String(), RunnerID: "runner", Secret: runnerproto.SecretRef{StoreID: "store", Provider: "builtin", Name: "name", Scope: "prod"}, ExpectedVersion: "1", ExpectedFingerprint: "kfp1:key:abcdefghijklmnop", Action: runnerproto.ActionDeploy, Target: runnerproto.Target{Kind: runnerproto.TargetFile, Path: "/etc/keep/credential", Mode: 0o600, UID: 1001, GID: 1001}, IssuedAt: now, NotAfter: now.Add(time.Minute), Nonce: make([]byte, 16)}
}

func TestSignJobUsesOrganizationKey(t *testing.T) {
	r, db := newRepo(t)
	ctx := context.Background()
	org := seedOrg(t, db)
	bundle, err := r.Ensure(ctx, org)
	if err != nil {
		t.Fatal("ensure org")
	}
	j := signingJob(t, org)
	signed, err := r.SignJob(ctx, nil, org, j)
	if err != nil {
		t.Fatal("sign job")
	}
	payload, err := runnerproto.EncodeJob(j)
	if err != nil {
		t.Fatal("encode job")
	}
	if signed.KeyID != bundle.SignKeyID || !bytes.Equal(signed.Payload, payload) || !ed25519.Verify(bundle.SignPubKey, signed.Payload, signed.Sig) {
		t.Fatal("organization signature invalid")
	}
	other := seedOrg(t, db)
	otherBundle, err := r.Ensure(ctx, other)
	if err != nil {
		t.Fatal("ensure other org")
	}
	if ed25519.Verify(otherBundle.SignPubKey, signed.Payload, signed.Sig) {
		t.Fatal("signature valid for wrong organization")
	}
	if _, err := r.SignJob(ctx, nil, other, j); err == nil {
		t.Fatal("cross-organization signing accepted")
	}
}

func TestSignJobRejectsCorruptionAndNeverEchoesInput(t *testing.T) {
	r, db := newRepo(t)
	ctx := context.Background()
	org := seedOrg(t, db)
	if _, err := r.Ensure(ctx, org); err != nil {
		t.Fatal("ensure org")
	}
	c := canary.New()
	j := signingJob(t, org)
	j.Secret.Name = c.Value(1) + "\n"
	signed, err := r.SignJob(ctx, nil, org, j)
	if err == nil {
		t.Fatal("invalid job accepted")
	}
	if c.In(err.Error()) || len(signed.Payload) > 0 || len(signed.Sig) > 0 {
		t.Fatal("failed signing exposed input")
	}
	if _, err := db.Exec(ctx, `UPDATE org_ca SET sign_key_id=$2 WHERE org_id=$1`, org, c.Value(2)); err != nil {
		t.Fatal("corrupt test key metadata")
	}
	signed, err = r.SignJob(ctx, nil, org, signingJob(t, org))
	if err == nil {
		t.Fatal("unauthenticated signing metadata accepted")
	}
	if c.In(err.Error()) || len(signed.Payload) > 0 || len(signed.Sig) > 0 {
		t.Fatal("failed signing exposed metadata")
	}
}

func TestSignJobUsesHeldConnection(t *testing.T) {
	r, db := newRepo(t)
	ctx := context.Background()
	org := seedOrg(t, db)
	if _, err := r.Ensure(ctx, org); err != nil {
		t.Fatal("ensure org")
	}
	cfg := db.Config()
	cfg.MaxConns = 1
	limited, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("open limited pool")
	}
	defer limited.Close()
	r.db = limited
	r.sealer = r.sealer.WithStore(builtin.NewKeyStore(limited))
	tx, err := limited.Begin(ctx)
	if err != nil {
		t.Fatal("hold connection")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	signed, err := r.SignJob(bounded, tx, org, signingJob(t, org))
	if err != nil || len(signed.Sig) == 0 {
		t.Fatal("signing borrowed another pool connection")
	}
}
