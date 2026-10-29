package registry

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/enrolltoken"
)

func TestDeliveryTrustIsOrgScopedAndImmutableOnRenewal(t *testing.T) {
	repo, db := newRepo(t)
	org := seedOrg(t, db)
	otherOrg := seedOrg(t, db)
	runner := newRunnerID(t)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate delivery key")
	}
	f := false
	attrs := &enrolltoken.HostAttrs{UIDShared: &f, Labels: map[string]string{"environment": "production"}}
	if err := repo.CreateEnrolled(context.Background(), org, runner, "h", "serial-1", time.Now().Add(time.Hour), Enrollment{HPKEPublicKey: key.PublicKey().Bytes(), HostAttrs: attrs}); err != nil {
		t.Fatal("create enrolled runner")
	}
	trust, err := repo.GetDeliveryTrust(context.Background(), org, runner)
	if err != nil || !trust.AttrsKnown || trust.UIDShared || !trust.EligibleForProd() || trust.HostLabels["environment"] != "production" {
		t.Fatal("trusted enrollment attributes were not retained")
	}
	if string(trust.HPKEPublicKey) != string(key.PublicKey().Bytes()) {
		t.Fatal("delivery public key changed")
	}
	if _, err := repo.GetDeliveryTrust(context.Background(), otherOrg, runner); !errors.Is(err, ErrDeliveryUnavailable) {
		t.Fatal("cross-org delivery lookup was not refused")
	}
	if err := repo.UpdateCert(context.Background(), org, runner, "serial-1", "serial-2", time.Now().Add(2*time.Hour)); err != nil {
		t.Fatal("renew runner certificate")
	}
	after, err := repo.GetDeliveryTrust(context.Background(), org, runner)
	if err != nil || string(after.HPKEPublicKey) != string(trust.HPKEPublicKey) || !after.AttrsKnown || after.UIDShared != trust.UIDShared || after.HostLabels["environment"] != "production" {
		t.Fatal("renewal changed delivery trust")
	}
}

func TestDeliveryTrustTxUsesLockedOrgAndRunnerRows(t *testing.T) {
	repo, db := newRepo(t)
	org := seedOrg(t, db)
	otherOrg := seedOrg(t, db)
	runner := newRunnerID(t)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate delivery key")
	}
	f := false
	if err := repo.CreateEnrolled(context.Background(), org, runner, "h", "serial", time.Now().Add(time.Hour), Enrollment{
		HPKEPublicKey: key.PublicKey().Bytes(),
		HostAttrs:     &enrolltoken.HostAttrs{UIDShared: &f, Labels: map[string]string{}},
	}); err != nil {
		t.Fatal("create runner")
	}
	tx, err := db.Begin(context.Background())
	if err != nil {
		t.Fatal("begin transaction")
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := repo.GetDeliveryTrustTx(context.Background(), tx, otherOrg, runner); !errors.Is(err, ErrDeliveryUnavailable) {
		t.Fatal("transactional cross-org lookup was not refused")
	}
	trust, err := repo.GetDeliveryTrustTx(context.Background(), tx, org, runner)
	if err != nil || !trust.AttrsKnown || trust.UIDShared || string(trust.HPKEPublicKey) != string(key.PublicKey().Bytes()) {
		t.Fatal("transactional delivery trust mismatch")
	}
}

func TestLegacyRunnerCannotReceiveDeliveryKey(t *testing.T) {
	repo, db := newRepo(t)
	org := seedOrg(t, db)
	runner := newRunnerID(t)
	if err := repo.Create(context.Background(), org, runner, "h", "serial-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatal("create legacy runner")
	}
	if _, err := repo.GetDeliveryTrust(context.Background(), org, runner); !errors.Is(err, ErrDeliveryUnavailable) {
		t.Fatal("legacy runner without a delivery key was accepted")
	}
}

func TestDeliveryPublicKeyValidationRejectsMalformedPoints(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate key")
	}
	if err := ValidateDeliveryPublicKey(key.PublicKey().Bytes()); err != nil {
		t.Fatal("valid key rejected")
	}
	for _, bad := range [][]byte{nil, make([]byte, 16), make([]byte, 32)} {
		if err := ValidateDeliveryPublicKey(bad); !errors.Is(err, ErrInvalidDeliveryKey) {
			t.Fatal("malformed or low-order public key accepted")
		}
	}
}

func TestDeliveryTrustRejectsRevokedRunnerAndUnknownAttrsForProd(t *testing.T) {
	repo, db := newRepo(t)
	org := seedOrg(t, db)
	runner := newRunnerID(t)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate key")
	}
	if err := repo.CreateEnrolled(context.Background(), org, runner, "h", "serial-1", time.Now().Add(time.Hour), Enrollment{HPKEPublicKey: key.PublicKey().Bytes()}); err != nil {
		t.Fatal("create key-bearing legacy runner")
	}
	trust, err := repo.GetDeliveryTrust(context.Background(), org, runner)
	if err != nil || trust.AttrsKnown || trust.EligibleForProd() {
		t.Fatal("unknown host attributes were treated as trusted for prod")
	}
	if err := repo.Revoke(context.Background(), org, runner); err != nil {
		t.Fatal("revoke runner")
	}
	if _, err := repo.GetDeliveryTrust(context.Background(), org, runner); !errors.Is(err, ErrDeliveryUnavailable) {
		t.Fatal("revoked runner retained delivery access")
	}
}
