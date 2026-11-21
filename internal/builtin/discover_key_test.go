package builtin

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/entire-vc/evc-keep/internal/dispatch"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

func discoverJobOf(j runnerproto.Job) runnerproto.Job {
	return runnerproto.Job{JobID: j.JobID, OrgID: j.OrgID, RunnerID: j.RunnerID, Secret: runnerproto.SecretRef{StoreID: j.Secret.StoreID, Provider: runnerproto.ProviderBuiltin},
		Action: runnerproto.ActionDiscover, IssuedAt: j.IssuedAt, NotAfter: j.NotAfter, Nonce: j.Nonce}
}

func TestDiscoverKeyRoundTripCarriesKeyAndNoValue(t *testing.T) {
	j, v, k, _, _, c := deliveryFixture(t)
	dj := discoverJobOf(j)
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env, err := SealDiscoverKey(dj, recipient.PublicKey().Bytes(), k)
	if err != nil {
		t.Fatal("seal")
	}
	if len(env.Sealed) != 0 || len(env.SealedFingerprintKey) == 0 {
		t.Fatal("a discover envelope carries the key and an empty value")
	}
	b, _ := json.Marshal(env)
	if c.In(string(b)) || c.In(fmt.Sprintf("%+v", env)) {
		t.Fatal("value escaped the discover envelope")
	}
	opened, err := OpenDiscoverKey(dj, recipient, env)
	if err != nil {
		t.Fatal("runner could not open its key")
	}
	defer opened.Wipe()
	if opened.ID() != k.ID() {
		t.Fatal("key id lost")
	}
	want, _ := fingerprint.Compute(k, v)
	if got, _ := fingerprint.Compute(opened, v); got != want {
		t.Fatal("opened key computes another fingerprint")
	}
	withValue := env
	withValue.Sealed = []byte("x")
	if _, err := OpenDiscoverKey(dj, recipient, withValue); err == nil {
		t.Fatal("an envelope carrying a value was opened")
	}
}

// A verify envelope does not open as a discover key and the other way round,
// and a discover envelope is bound to its job, nonce and window.
func TestDiscoverAndVerifyKeyEnvelopesAreDisjoint(t *testing.T) {
	j, _, k, _, _, _ := deliveryFixture(t)
	dj, vj := discoverJobOf(j), verifyJobOf(j)
	recipient, _ := ecdh.X25519().GenerateKey(rand.Reader)
	pub := recipient.PublicKey().Bytes()
	denv, err := SealDiscoverKey(dj, pub, k)
	if err != nil {
		t.Fatal("seal discover")
	}
	venv, err := SealRunnerKey(vj, pub, k)
	if err != nil {
		t.Fatal("seal verify")
	}
	if _, err := OpenRunnerKey(vj, recipient, runnerproto.ValueEnvelope{JobID: vj.JobID, SealedFingerprintKey: denv.SealedFingerprintKey}); err == nil {
		t.Fatal("a discover envelope opened as a verify key")
	}
	if _, err := OpenDiscoverKey(dj, recipient, runnerproto.ValueEnvelope{JobID: dj.JobID, SealedFingerprintKey: venv.SealedFingerprintKey}); err == nil {
		t.Fatal("a verify envelope opened as a discover key")
	}
	// Kind gates: each side refuses the other's job.
	if _, err := SealRunnerKey(dj, pub, k); err == nil {
		t.Fatal("verify seal for a discover job")
	}
	if _, err := SealDiscoverKey(vj, pub, k); err == nil {
		t.Fatal("discover seal for a verify job")
	}
	if _, err := SealDiscoverKey(j, pub, k); err == nil {
		t.Fatal("discover seal for a deploy job")
	}
	for name, mod := range map[string]func(*runnerproto.Job){
		"job id": func(x *runnerproto.Job) {
			x.JobID = x.JobID[:35] + map[bool]string{true: "1", false: "0"}[x.JobID[35] == '0']
		},
		"nonce":  func(x *runnerproto.Job) { x.Nonce = append([]byte{1}, x.Nonce[1:]...) },
		"expiry": func(x *runnerproto.Job) { x.NotAfter = x.NotAfter.Add(1e9) },
		"store":  func(x *runnerproto.Job) { x.Secret.StoreID = "other" },
		"org":    func(x *runnerproto.Job) { x.OrgID = "other-org" },
		"runner": func(x *runnerproto.Job) { x.RunnerID = "other-runner" },
	} {
		o := dj
		mod(&o)
		if _, err := OpenDiscoverKey(o, recipient, runnerproto.ValueEnvelope{JobID: o.JobID, SealedFingerprintKey: denv.SealedFingerprintKey}); err == nil {
			t.Fatalf("discover key not bound to %s", name)
		}
	}
}

func TestOpenDiscoverKeyRefusesTamperedAndMalformedPayloads(t *testing.T) {
	j, _, k, _, _, _ := deliveryFixture(t)
	dj := discoverJobOf(j)
	recipient, _ := ecdh.X25519().GenerateKey(rand.Reader)
	pub := recipient.PublicKey().Bytes()
	env, err := SealDiscoverKey(dj, pub, k)
	if err != nil {
		t.Fatal("seal")
	}
	flipped := runnerproto.ValueEnvelope{JobID: dj.JobID, SealedFingerprintKey: append([]byte(nil), env.SealedFingerprintKey...)}
	flipped.SealedFingerprintKey[len(flipped.SealedFingerprintKey)-1] ^= 1
	if _, err := OpenDiscoverKey(dj, recipient, flipped); err == nil {
		t.Fatal("a tampered envelope opened")
	}
	if _, err := OpenDiscoverKey(dj, recipient, runnerproto.ValueEnvelope{JobID: j.JobID[:35] + map[bool]string{true: "1", false: "0"}[j.JobID[35] == '0'], SealedFingerprintKey: env.SealedFingerprintKey}); err == nil {
		t.Fatal("an envelope of another job id opened")
	}
	good := make([]byte, fingerprint.KeySize)
	for i := range good {
		good[i] = byte(i + 1)
	}
	id := k.ID()
	idLen := byte(len(id)) //nolint:gosec // G115: a test key id is at most 16 bytes
	for name, plain := range map[string][]byte{
		"empty":          {},
		"zero id len":    append([]byte{0}, good...),
		"id len too big": append([]byte{200}, good...),
		"short key":      append(append([]byte{idLen}, id...), good[:len(good)-1]...),
		"long key":       append(append([]byte{idLen}, id...), append(good, 0)...),
		"bad id chars":   append([]byte{3}, append([]byte("A_!"), good...)...),
	} {
		sealed, err := sealRunnerBytes(pub, runnerproto.DiscoverKeyInfo(dj), plain)
		if err != nil {
			t.Fatalf("%s: seal fixture", name)
		}
		if _, err := OpenDiscoverKey(dj, recipient, runnerproto.ValueEnvelope{JobID: dj.JobID, SealedFingerprintKey: sealed}); err == nil {
			t.Errorf("malformed payload %q opened", name)
		}
	}
}

// The server path: SealMaterial of a discover job reads the store's own key,
// resolves no secret, and refuses a store that is gone, disabled or not builtin.
func TestLocalSealMaterialDiscoverIssuesTheStoreKeyOnly(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal("generate root")
	}
	local, err := NewLocal(pool, "discover-root", raw, nil, nopAudit)
	if err != nil {
		t.Fatal("local backend")
	}
	org, st := uuid.New(), uuid.New()
	j, v, _, _, _, c := deliveryFixture(t)
	j.OrgID, j.Secret.StoreID = org.String(), st.String()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name) VALUES($1,'discover')`, org); err != nil {
		t.Fatal("seed org")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO stores(id,org_id,provider,name,owner_scope_level,owner_scope_id) VALUES($1,$2,'builtin','discover','org',$2)`, st, org); err != nil {
		t.Fatal("seed store")
	}
	p := local.Provider(org.String(), "", "", "")
	if _, err := p.Write(ctx, providerRef("builtin://synthetic-discover-"+uuid.NewString()), v); err != nil { // creates the scope's key
		t.Fatal("write synthetic value")
	}
	k, err := p.FingerprintKey(ctx)
	if err != nil {
		t.Fatal("fingerprint key")
	}
	defer k.Wipe()
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dj := discoverJobOf(j)
	env, err := local.SealMaterial(ctx, dispatch.Snapshot{Job: dj}, recipient.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("discover key: %v", err)
	}
	if len(env.Sealed) != 0 {
		t.Fatal("a discover envelope must carry no value")
	}
	opened, err := OpenDiscoverKey(dj, recipient, env)
	if err != nil {
		t.Fatal("runner could not open the discover key")
	}
	defer opened.Wipe()
	if opened.ID() != k.ID() {
		t.Fatalf("the store's own key id was not delivered: %q != %q", opened.ID(), k.ID())
	}
	if b, _ := json.Marshal(env); c.In(string(b)) {
		t.Fatal("value escaped the envelope")
	}
	for name, change := range map[string]func(*runnerproto.Job){
		"another store": func(x *runnerproto.Job) { x.Secret.StoreID = uuid.NewString() },
		"another org":   func(x *runnerproto.Job) { x.OrgID = uuid.NewString() },
	} {
		bad := dj
		change(&bad)
		if _, err := local.SealMaterial(ctx, dispatch.Snapshot{Job: bad}, recipient.PublicKey().Bytes()); err == nil {
			t.Fatalf("a discover key was issued for %s", name)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE stores SET status='disabled' WHERE id=$1`, st); err != nil {
		t.Fatal("disable store")
	}
	if _, err := local.SealMaterial(ctx, dispatch.Snapshot{Job: dj}, recipient.PublicKey().Bytes()); err == nil {
		t.Fatal("a disabled store's key was issued")
	}
}
