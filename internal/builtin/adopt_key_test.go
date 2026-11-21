package builtin

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

func TestAdoptKeyOnlyEnvelopeHasSeparateBoundContext(t *testing.T) {
	j, v, k, _, _, c := deliveryFixture(t)
	j.Action = runnerproto.ActionAdopt
	j.Target = runnerproto.Target{Kind: runnerproto.TargetYAMLScalar, Path: "/etc/keep/config.yaml", Field: "service.API_KEY", Mode: 0o600}
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate disposable recipient")
	}
	env, err := SealRunnerKey(j, recipient.PublicKey().Bytes(), k)
	if err != nil || len(env.Sealed) != 0 || len(env.SealedFingerprintKey) == 0 {
		t.Fatal("adoption did not seal only the key")
	}
	opened, err := OpenRunnerKey(j, recipient, env)
	if err != nil {
		t.Fatal("adoption key refused its bound job")
	}
	defer opened.Wipe()
	want, _ := fingerprint.Compute(k, v)
	if got, _ := fingerprint.Compute(opened, v); got != want {
		t.Fatal("adoption opened a different key")
	}
	encoded, err := json.Marshal(env)
	if err != nil || c.In(string(encoded)) || c.In(fmt.Sprintf("%+v", env)) {
		t.Fatal("adoption key envelope leaked the value")
	}
	if _, err := SealRunnerMaterial(j, recipient.PublicKey().Bytes(), v, k); err == nil {
		t.Fatal("adoption could receive the value")
	}
	withValue := env
	withValue.Sealed = []byte("forbidden")
	if _, err := OpenRunnerKey(j, recipient, withValue); err == nil {
		t.Fatal("adoption accepted an envelope carrying a value")
	}
	for name, change := range map[string]func(*runnerproto.Job){
		"verify":  func(j *runnerproto.Job) { j.Action = runnerproto.ActionVerify },
		"runner":  func(j *runnerproto.Job) { j.RunnerID += "-other" },
		"org":     func(j *runnerproto.Job) { j.OrgID += "-other" },
		"version": func(j *runnerproto.Job) { j.ExpectedVersion += "-other" },
		"path":    func(j *runnerproto.Job) { j.Target.Path += ".other" },
		"field":   func(j *runnerproto.Job) { j.Target.Field += "_OTHER" },
		"nonce":   func(j *runnerproto.Job) { j.Nonce = append([]byte{1}, j.Nonce[1:]...) },
		"expiry":  func(j *runnerproto.Job) { j.NotAfter = j.NotAfter.Add(time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			other := j
			change(&other)
			if _, err := OpenRunnerKey(other, recipient, env); err == nil {
				t.Fatal("adoption key accepted a substituted context")
			}
		})
	}
	verify := j
	verify.Action = runnerproto.ActionVerify
	other, err := SealRunnerKey(verify, recipient.PublicKey().Bytes(), k)
	if err != nil {
		t.Fatal("seal positive verify control")
	}
	if _, err := OpenRunnerKey(j, recipient, other); err == nil {
		t.Fatal("verify envelope substituted for adoption")
	}
}
