package runnerproto

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/hpke"
)

// Exercise real HPKE decapsulation, including positive and negative controls:
// comparing two Info byte slices alone does not prove envelope binding.
func TestInfoHPKEBindsSecret(t *testing.T) {
	suite := hpke.NewSuite(hpke.KEM(HPKEKEM), hpke.KDF(HPKEKDF), hpke.AEAD(HPKEAEAD))
	pub, priv, err := hpke.KEM(HPKEKEM).Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatal("generate test recipient key")
	}
	j := deployJob(t)
	sender, err := suite.NewSender(pub, Info(j))
	if err != nil {
		t.Fatal("create test sender")
	}
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		t.Fatal("set up test sender")
	}
	plain := make([]byte, 32)
	defer clear(plain)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal("generate test plaintext")
	}
	ciphertext, err := sealer.Seal(plain, nil)
	if err != nil {
		t.Fatal("seal test envelope")
	}
	open := func(t *testing.T, candidate Job) ([]byte, error) {
		t.Helper()
		receiver, err := suite.NewReceiver(priv, Info(candidate))
		if err != nil {
			t.Fatal("create test recipient")
		}
		opener, err := receiver.Setup(enc)
		if err != nil {
			t.Fatal("set up test recipient")
		}
		return opener.Open(ciphertext, nil)
	}
	// The same envelope must open for its job. Never print the plaintext or key.
	out, err := open(t, j)
	matched := err == nil && bytes.Equal(out, plain)
	clear(out)
	if !matched {
		t.Fatal("matching-job positive control failed")
	}
	for _, tc := range []struct {
		name   string
		change func(*Job)
	}{
		{"job_id", func(j *Job) { j.JobID = newJobID(t) }},
		{"org", func(j *Job) { j.OrgID = "other-org" }},
		{"runner", func(j *Job) { j.RunnerID = "other-runner" }},
		{"store", func(j *Job) { j.Secret.StoreID = "other-store" }},
		{"name", func(j *Job) { j.Secret.Name = "other-name" }},
		{"scope", func(j *Job) { j.Secret.Scope = "other-scope" }},
		{"provider", func(j *Job) { j.Secret.Provider = "other-provider" }},
		{"version", func(j *Job) { j.ExpectedVersion = "other-version" }},
		{"fingerprint", func(j *Job) { j.ExpectedFingerprint = "kfp1:s1:bbbbbbbbbbbbbbbb" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := j
			tc.change(&candidate)
			out, err := open(t, candidate)
			clear(out)
			if err == nil {
				t.Fatal("envelope opened under a different job binding")
			}
		})
	}
}
