package builtin

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/dispatch"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

func TestLocalDeliveryUsesFrozenReference(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal("generate root")
	}
	local, err := NewLocal(pool, "delivery-root", raw, nil, nopAudit)
	if err != nil {
		t.Fatal("local backend")
	}
	org, st, sec, ver := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	j, v, _, pub, priv, c := deliveryFixture(t)
	j.OrgID = org.String()
	j.Secret.StoreID = st.String()
	p := local.Provider(org.String(), "", "", "")
	ref := "builtin://synthetic-delivery-" + sec.String()
	meta, err := p.Write(ctx, providerRef(ref), v)
	if err != nil {
		t.Fatal("write synthetic value")
	}
	k, err := p.FingerprintKey(ctx)
	if err != nil {
		t.Fatal("fingerprint key")
	}
	defer k.Wipe()
	j.ExpectedFingerprint, err = fingerprint.Compute(k, v)
	if err != nil {
		t.Fatal("compute fingerprint")
	}
	j.ExpectedVersion = meta.Version
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations(id,name) VALUES($1,'delivery')`, []any{org}},
		{`INSERT INTO stores(id,org_id,provider,name,owner_scope_level,owner_scope_id) VALUES($1,$2,'builtin','delivery','org',$2)`, []any{st, org}},
		{`INSERT INTO secrets(id,org_id,scope_level,scope_id,name,class,type,store_id,provider_ref) VALUES($1,$2,'org',$2,$3,'prod','generic',$4,$5)`, []any{sec, org, j.Secret.Name, st, ref}},
		{`INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length) VALUES($1,$2,$3,$4,$5,12)`, []any{ver, org, sec, meta.Version, j.ExpectedFingerprint}},
	} {
		if _, err := pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal("seed delivery catalog")
		}
	}
	snap := dispatch.Snapshot{Job: j, SecretID: sec, VersionID: ver, OwnerScope: tenancy.Org(org), SecretScope: tenancy.Org(org), ProviderRef: ref, ProviderVersion: meta.Version}
	env, err := local.SealMaterial(ctx, snap, pub)
	if err != nil {
		t.Fatal("seal saved material")
	}
	plain, err := openDelivery(t, priv, runnerproto.Info(j), env.Sealed)
	if err != nil {
		t.Fatal("open saved material")
	}
	defer clear(plain)
	if !c.In(string(plain)) {
		t.Fatal("saved material did not match")
	}
	for _, change := range []func(*dispatch.Snapshot){
		func(s *dispatch.Snapshot) { s.Job.OrgID = uuid.NewString() },
		func(s *dispatch.Snapshot) { s.Job.Secret.StoreID = uuid.NewString() },
		func(s *dispatch.Snapshot) { s.ProviderRef = "builtin://other" },
		func(s *dispatch.Snapshot) { s.ProviderVersion = "99" },
		func(s *dispatch.Snapshot) { s.OwnerScope = tenancy.Org(uuid.New()) },
		func(s *dispatch.Snapshot) { s.Job.ExpectedFingerprint = "kfp1:other:abcdefghijklmnop" },
	} {
		candidate := snap
		change(&candidate)
		env, err := local.SealMaterial(ctx, candidate, pub)
		if err == nil {
			t.Fatal("substituted delivery snapshot accepted")
		}
		if c.In(err.Error()) || len(env.Sealed) > 0 {
			t.Fatal("refusal exposed material")
		}
	}
	// An in-flight catalog revocation must block delivery until its outcome
	// is known; a snapshot read alone could release the still-visible version.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal("begin revocation")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `UPDATE secret_versions SET disabled=true WHERE id=$1`, ver); err != nil {
		t.Fatal("stage revocation")
	}
	blocked, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	env, deliveryErr := local.SealMaterial(blocked, snap, pub)
	cancel()
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal("rollback staged revocation")
	}
	if deliveryErr == nil || len(env.Sealed) != 0 || len(env.SealedFingerprintKey) != 0 {
		t.Fatal("delivery raced past a pending catalog revocation")
	}
	if _, err := pool.Exec(ctx, `UPDATE secret_versions SET disabled=true WHERE id=$1`, ver); err != nil {
		t.Fatal("disable catalog version")
	}
	if _, err := local.SealMaterial(ctx, snap, pub); err == nil {
		t.Fatal("disabled version released")
	}
}
