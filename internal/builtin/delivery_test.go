package builtin

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/google/uuid"
)

func deliveryFixture(t *testing.T) (runnerproto.Job, secret.Value, fingerprint.Key, []byte, kem.PrivateKey, canary.Canary) {
	t.Helper()
	c := canary.New()
	v := secret.New([]byte(c.Value(1)))
	t.Cleanup(v.Wipe)
	k, err := fingerprint.GenerateKey("delivery1")
	if err != nil {
		t.Fatal("generate fingerprint key")
	}
	t.Cleanup(k.Wipe)
	fp, err := fingerprint.Compute(k, v)
	if err != nil {
		t.Fatal("compute fingerprint")
	}
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal("generate job id")
	}
	now := time.Now().Truncate(time.Second)
	j := runnerproto.Job{JobID: id.String(), OrgID: "org", RunnerID: "runner", Secret: runnerproto.SecretRef{StoreID: "store", Provider: "builtin", Name: "credential", Scope: "prod"}, ExpectedVersion: "1", ExpectedFingerprint: fp, Action: runnerproto.ActionDeploy, Target: runnerproto.Target{Kind: runnerproto.TargetFile, Path: "/etc/keep/credential", Mode: 0o600, UID: 1001, GID: 1001}, IssuedAt: now, NotAfter: now.Add(time.Minute), Nonce: make([]byte, 16)}
	pub, priv, err := hpke.KEM(runnerproto.HPKEKEM).Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatal("generate recipient")
	}
	public, err := pub.MarshalBinary()
	if err != nil {
		t.Fatal("encode public recipient")
	}
	return j, v, k, public, priv, c
}

func openDelivery(t *testing.T, priv kem.PrivateKey, info, sealed []byte) ([]byte, error) {
	t.Helper()
	if len(sealed) < 32 {
		return nil, fmt.Errorf("short test envelope")
	}
	suite := hpke.NewSuite(hpke.KEM(runnerproto.HPKEKEM), hpke.KDF(runnerproto.HPKEKDF), hpke.AEAD(runnerproto.HPKEAEAD))
	receiver, err := suite.NewReceiver(priv, info)
	if err != nil {
		return nil, err
	}
	opener, err := receiver.Setup(sealed[:32])
	if err != nil {
		return nil, err
	}
	return opener.Open(sealed[32:], nil)
}

func TestRunnerMaterialNeverLeaks(t *testing.T) {
	j, v, k, pub, _, c := deliveryFixture(t)
	env, err := SealRunnerMaterial(j, pub, v, k)
	if err != nil {
		t.Fatal("seal material")
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal("encode envelope")
	}
	if c.In(string(b)) || c.In(fmt.Sprintf("%+v", env)) {
		t.Fatal("value escaped sealed envelope")
	}
	fingerprint.ExposeKey(k, func(raw []byte) {
		if canary.Of(string(raw)).In(string(b)) {
			t.Fatal("fingerprint key escaped sealed envelope")
		}
	})
}

func TestRunnerMaterialRoundTripAndBinding(t *testing.T) {
	j, v, k, pub, priv, _ := deliveryFixture(t)
	env, err := SealRunnerMaterial(j, pub, v, k)
	if err != nil {
		t.Fatal("seal material")
	}
	if env.JobID != j.JobID {
		t.Fatal("wrong envelope job")
	}
	value, err := openDelivery(t, priv, runnerproto.Info(j), env.Sealed)
	if err != nil {
		t.Fatal("open value")
	}
	defer clear(value)
	secret.Expose(v, func(raw []byte) {
		if !bytes.Equal(raw, value) {
			t.Fatal("value differs")
		}
	})
	key, err := openDelivery(t, priv, runnerproto.FingerprintKeyInfo(j), env.SealedFingerprintKey)
	if err != nil {
		t.Fatal("open key")
	}
	defer clear(key)
	fingerprint.ExposeKey(k, func(raw []byte) {
		if !bytes.Equal(raw, key) {
			t.Fatal("key differs")
		}
	})
	for _, change := range []func(*runnerproto.Job){
		func(j *runnerproto.Job) { j.JobID = "01900000-0000-7000-8000-000000000000" },
		func(j *runnerproto.Job) { j.OrgID = "other" },
		func(j *runnerproto.Job) { j.RunnerID = "other" },
		func(j *runnerproto.Job) { j.Secret.StoreID = "other" },
		func(j *runnerproto.Job) { j.Secret.Name = "other" },
		func(j *runnerproto.Job) { j.Secret.Scope = "dev" },
		func(j *runnerproto.Job) { j.Secret.Provider = "other" },
		func(j *runnerproto.Job) { j.ExpectedVersion = "2" },
		func(j *runnerproto.Job) { j.ExpectedFingerprint = "kfp1:other:abcdefghijklmnop" },
	} {
		other := j
		change(&other)
		out, err := openDelivery(t, priv, runnerproto.FingerprintKeyInfo(other), env.SealedFingerprintKey)
		clear(out)
		if err == nil {
			t.Fatal("key envelope accepted changed job binding")
		}
	}
}

func TestRunnerMaterialRejectsInvalidInputs(t *testing.T) {
	j, v, k, pub, _, c := deliveryFixture(t)
	for _, tc := range []struct {
		name   string
		change func(*runnerproto.Job, *[]byte, *fingerprint.Key)
	}{
		{"recipient_missing", func(_ *runnerproto.Job, p *[]byte, _ *fingerprint.Key) { *p = nil }},
		{"recipient_zero", func(_ *runnerproto.Job, p *[]byte, _ *fingerprint.Key) { *p = make([]byte, 32) }},
		{"key_missing", func(_ *runnerproto.Job, _ *[]byte, k *fingerprint.Key) { *k = fingerprint.Key{} }},
		{"key_id", func(j *runnerproto.Job, _ *[]byte, _ *fingerprint.Key) {
			j.ExpectedFingerprint = "kfp1:other:abcdefghijklmnop"
		}},
		{"fingerprint", func(j *runnerproto.Job, _ *[]byte, _ *fingerprint.Key) {
			j.ExpectedFingerprint = "kfp1:delivery1:abcdefghijklmnop"
		}},
		{"no_value_action", func(j *runnerproto.Job, _ *[]byte, _ *fingerprint.Key) { j.Action = runnerproto.ActionVerify }},
		{"invalid_job", func(j *runnerproto.Job, _ *[]byte, _ *fingerprint.Key) { j.Secret.Name = c.Value(2) + "\n" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			job, recipient, key := j, pub, k
			tc.change(&job, &recipient, &key)
			env, err := SealRunnerMaterial(job, recipient, v, key)
			if err == nil {
				t.Fatal("invalid material request accepted")
			}
			if c.In(err.Error()) || len(env.Sealed) != 0 || len(env.SealedFingerprintKey) != 0 {
				t.Fatal("failed sealing exposed material")
			}
		})
	}
}

func TestExternalRunnerMaterialHasKeyOnly(t *testing.T) {
	j, v, k, pub, priv, _ := deliveryFixture(t)
	j.Secret.Provider = "sops"
	env, err := SealRunnerMaterial(j, pub, v, k)
	if err != nil || len(env.Sealed) != 0 || len(env.SealedFingerprintKey) == 0 {
		t.Fatal("external provider material must contain only sealed fingerprint key")
	}
	key, err := openDelivery(t, priv, runnerproto.FingerprintKeyInfo(j), env.SealedFingerprintKey)
	if err != nil {
		t.Fatal("open external fingerprint key")
	}
	defer clear(key)
	fingerprint.ExposeKey(k, func(raw []byte) {
		if !bytes.Equal(raw, key) {
			t.Fatal("external fingerprint key differs")
		}
	})
	k.Wipe()
	if _, err := SealRunnerMaterial(j, pub, v, k); err == nil {
		t.Fatal("wiped fingerprint key accepted for external provider")
	}
}

func TestOpenRunnerMaterialRoundTripAndBindings(t *testing.T) {
	j, v, k, _, _, c := deliveryFixture(t)
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate recipient")
	}
	env, err := SealRunnerMaterial(j, recipient.PublicKey().Bytes(), v, k)
	if err != nil {
		t.Fatal("seal")
	}
	got, key, err := OpenRunnerMaterial(j, recipient, env)
	if err != nil {
		t.Fatal("open")
	}
	t.Cleanup(got.Wipe)
	t.Cleanup(key.Wipe)
	if !got.Equal(v) || key.ID() != k.ID() {
		t.Fatal("round trip changed the material")
	}
	fp, _ := fingerprint.Compute(key, got)
	if fp != j.ExpectedFingerprint {
		t.Fatal("opened key does not reproduce the job fingerprint")
	}
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	otherJob := j
	otherJob.Secret.Scope = "dev"
	swapped := env
	swapped.Sealed, swapped.SealedFingerprintKey = env.SealedFingerprintKey, env.Sealed
	noKey := env
	noKey.SealedFingerprintKey = nil
	noValue := env
	noValue.Sealed = nil
	foreign := env
	foreign.JobID = "0190f6a0-0000-7000-8000-000000000001"
	flipped := env
	flipped.Sealed = append([]byte(nil), env.Sealed...)
	flipped.Sealed[len(flipped.Sealed)-1] ^= 1
	for name, tc := range map[string]struct {
		job runnerproto.Job
		key *ecdh.PrivateKey
		env runnerproto.ValueEnvelope
	}{
		"other-recipient": {j, other, env},
		"other-job":       {otherJob, recipient, env},
		"swapped":         {j, recipient, swapped},
		"no-key-envelope": {j, recipient, noKey},
		"no-value":        {j, recipient, noValue},
		"foreign-job-id":  {j, recipient, foreign},
		"flipped-bit":     {j, recipient, flipped},
		"nil-recipient":   {j, nil, env},
	} {
		v2, k2, err := OpenRunnerMaterial(tc.job, tc.key, tc.env)
		if err == nil || !v2.IsZero() || k2.ID() != "" {
			t.Fatalf("%s: material opened", name)
		}
		if err != nil && (c.In(err.Error())) {
			t.Fatalf("%s: error text carries the value", name)
		}
	}
}

// A valid builtin value is 0 bytes to 1 MiB; the runner side must open both
// ends and the fingerprint comparison, not the opener, rejects substitutes.
func TestOpenRunnerMaterialBoundarySizes(t *testing.T) {
	j, _, k, _, _, _ := deliveryFixture(t)
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate recipient")
	}
	for name, size := range map[string]int{"empty": 0, "64k": 64 << 10, "max": 1 << 20} {
		t.Run(name, func(t *testing.T) {
			v := secret.New(bytes.Repeat([]byte{'x'}, size))
			t.Cleanup(v.Wipe)
			job := j
			fp, err := fingerprint.Compute(k, v)
			if err != nil {
				t.Fatal("compute fingerprint")
			}
			job.ExpectedFingerprint = fp
			env, err := SealRunnerMaterial(job, recipient.PublicKey().Bytes(), v, k)
			if err != nil {
				t.Fatal("seal")
			}
			got, key, err := OpenRunnerMaterial(job, recipient, env)
			if err != nil {
				t.Fatal("open")
			}
			t.Cleanup(got.Wipe)
			t.Cleanup(key.Wipe)
			if got.Len() != size || !got.Equal(v) {
				t.Fatal("round trip changed the value")
			}
		})
	}
}
