package builtin

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/entire-vc/evc-keep/internal/dispatch"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

// verifyJobOf turns the delivery fixture's job into the verify job the server
// builds: fixed non-owner target, no consumer.
func verifyJobOf(j runnerproto.Job) runnerproto.Job {
	j.Action = runnerproto.ActionVerify
	j.Target = runnerproto.Target{Kind: runnerproto.TargetFile, Path: "/etc/keep/credential", Mode: 0o600}
	return j
}

func TestVerifyKeyEnvelopeCarriesTheKeyAndNoValue(t *testing.T) {
	j, v, k, pub, priv, c := deliveryFixture(t)
	vj := verifyJobOf(j)
	env, err := SealRunnerKey(vj, pub, k)
	if err != nil {
		t.Fatal("seal key")
	}
	if len(env.Sealed) != 0 || len(env.SealedFingerprintKey) == 0 {
		t.Fatal("a verify envelope must carry the key and an empty value")
	}
	b, _ := json.Marshal(env)
	if c.In(string(b)) || c.In(fmt.Sprintf("%+v", env)) {
		t.Fatal("value escaped the verify envelope")
	}
	raw, err := openDelivery(t, priv, runnerproto.VerifyKeyInfo(vj), env.SealedFingerprintKey)
	if err != nil {
		t.Fatal("open key under the verify info")
	}
	defer clear(raw)
	opened, err := fingerprint.NewKey(k.ID(), raw)
	if err != nil {
		t.Fatal("key shape")
	}
	defer opened.Wipe()
	want, _ := fingerprint.Compute(k, v)
	if got, _ := fingerprint.Compute(opened, v); got != want {
		t.Fatal("opened key does not compute the same fingerprint")
	}
	// The key opens under no other info: deploy's, or another job's.
	other := vj
	other.JobID = uuid.NewString()
	for name, info := range map[string][]byte{"deploy key info": runnerproto.FingerprintKeyInfo(vj), "value info": runnerproto.Info(vj), "other job": runnerproto.VerifyKeyInfo(other)} {
		if _, err := openDelivery(t, priv, info, env.SealedFingerprintKey); err == nil {
			t.Fatalf("verify key opened under %s", name)
		}
	}
	// Nonce and expiry are bound.
	for name, mod := range map[string]func(*runnerproto.Job){
		"nonce":  func(x *runnerproto.Job) { x.Nonce = append([]byte{1}, x.Nonce[1:]...) },
		"expiry": func(x *runnerproto.Job) { x.NotAfter = x.NotAfter.Add(1e9) },
	} {
		o := vj
		mod(&o)
		if _, err := openDelivery(t, priv, runnerproto.VerifyKeyInfo(o), env.SealedFingerprintKey); err == nil {
			t.Fatalf("verify key not bound to the job's %s", name)
		}
	}
}

func TestVerifyKeyIsSealedOnlyForVerifyJobs(t *testing.T) {
	j, v, k, pub, _, _ := deliveryFixture(t)
	if _, err := SealRunnerKey(j, pub, k); err == nil {
		t.Fatal("key-only delivery for a deploy job")
	}
	vj := verifyJobOf(j)
	if _, err := SealRunnerMaterial(vj, pub, v, k); err == nil {
		t.Fatal("value delivery for a verify job")
	}
	other, _ := fingerprint.GenerateKey("another")
	defer other.Wipe()
	if _, err := SealRunnerKey(vj, pub, other); err == nil {
		t.Fatal("key of another id sealed for the job")
	}
}

func TestOpenRunnerKeyRefusesAValueAndOtherJobs(t *testing.T) {
	j, _, k, pub, _, _ := deliveryFixture(t)
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	vj := verifyJobOf(j)
	env, err := SealRunnerKey(vj, recipient.PublicKey().Bytes(), k)
	if err != nil {
		t.Fatal("seal")
	}
	key, err := OpenRunnerKey(vj, recipient, env)
	if err != nil {
		t.Fatal("runner could not open its key")
	}
	key.Wipe()
	withValue := env
	withValue.Sealed = []byte("anything")
	if _, err := OpenRunnerKey(vj, recipient, withValue); err == nil {
		t.Fatal("an envelope carrying a value was opened")
	}
	if _, err := OpenRunnerKey(j, recipient, env); err == nil {
		t.Fatal("a deploy job opened a verify key envelope")
	}
	elsewhere := env
	elsewhere.JobID = uuid.NewString()
	if _, err := OpenRunnerKey(vj, recipient, elsewhere); err == nil {
		t.Fatal("an envelope of another job id was opened")
	}
	_ = pub
}

// The server resolves no value for a verify job and issues the key alone; the
// frozen reference is still enforced and a disabled version releases no key.
func TestLocalSealsOnlyTheKeyForVerifyJobs(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal("generate root")
	}
	local, err := NewLocal(pool, "verify-key-root", raw, nil, nopAudit)
	if err != nil {
		t.Fatal("local backend")
	}
	org, st, sec, ver := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	j, v, _, pub, priv, c := deliveryFixture(t)
	j.OrgID, j.Secret.StoreID = org.String(), st.String()
	p := local.Provider(org.String(), "", "", "")
	ref := "builtin://synthetic-verify-" + sec.String()
	meta, err := p.Write(ctx, providerRef(ref), v)
	if err != nil {
		t.Fatal("write synthetic value")
	}
	k, err := p.FingerprintKey(ctx)
	if err != nil {
		t.Fatal("fingerprint key")
	}
	defer k.Wipe()
	if j.ExpectedFingerprint, err = fingerprint.Compute(k, v); err != nil {
		t.Fatal("compute fingerprint")
	}
	j.ExpectedVersion = meta.Version
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations(id,name) VALUES($1,'verify-key')`, []any{org}},
		{`INSERT INTO stores(id,org_id,provider,name,owner_scope_level,owner_scope_id) VALUES($1,$2,'builtin','verify-key','org',$2)`, []any{st, org}},
		{`INSERT INTO secrets(id,org_id,scope_level,scope_id,name,class,type,store_id,provider_ref) VALUES($1,$2,'org',$2,$3,'prod','generic',$4,$5)`, []any{sec, org, j.Secret.Name, st, ref}},
		{`INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length) VALUES($1,$2,$3,$4,$5,12)`, []any{ver, org, sec, meta.Version, j.ExpectedFingerprint}},
	} {
		if _, err := pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal("seed catalog")
		}
	}
	vj := verifyJobOf(j)
	snap := dispatch.Snapshot{Job: vj, SecretID: sec, VersionID: ver, OwnerScope: tenancy.Org(org), SecretScope: tenancy.Org(org), ProviderRef: ref, ProviderVersion: meta.Version}
	env, err := local.SealMaterial(ctx, snap, pub)
	if err != nil {
		t.Fatal("seal verify key")
	}
	if len(env.Sealed) != 0 || len(env.SealedFingerprintKey) == 0 {
		t.Fatal("verify delivery must be the key alone")
	}
	plain, err := openDelivery(t, priv, runnerproto.VerifyKeyInfo(vj), env.SealedFingerprintKey)
	if err != nil {
		t.Fatal("open key")
	}
	defer clear(plain)
	if c.In(string(plain)) || c.In(fmt.Sprint(env)) {
		t.Fatal("value present in the verify delivery")
	}
	// The frozen reference is still enforced: a substituted snapshot is refused.
	for _, change := range []func(*dispatch.Snapshot){
		func(s *dispatch.Snapshot) { s.Job.OrgID = uuid.NewString() },
		func(s *dispatch.Snapshot) { s.ProviderVersion = "99" },
		func(s *dispatch.Snapshot) { s.Job.ExpectedFingerprint = "kfp1:other:abcdefghijklmnop" },
	} {
		candidate := snap
		change(&candidate)
		if env, err := local.SealMaterial(ctx, candidate, pub); err == nil || len(env.SealedFingerprintKey) != 0 {
			t.Fatal("substituted verify snapshot accepted")
		}
	}
	// A disabled version releases no key either.
	if _, err := pool.Exec(ctx, `UPDATE secret_versions SET disabled=true WHERE id=$1`, ver); err != nil {
		t.Fatal("disable version")
	}
	if _, err := local.SealMaterial(ctx, snap, pub); err == nil {
		t.Fatal("key released for a disabled version")
	}
}
