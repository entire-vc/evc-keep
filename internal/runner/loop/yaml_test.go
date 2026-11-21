//go:build unix

package loop

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

func TestYAMLVerifyReadsOnlyAndReportsMatchOrMismatch(t *testing.T) {
	for _, match := range []bool{true, false} {
		t.Run(map[bool]string{true: "match", false: "mismatch"}[match], func(t *testing.T) {
			e := newEnv(t)
			c := canary.New()
			value := c.Value(1)
			body := []byte("service:\n  API_KEY: '" + value + "'\n")
			if err := os.WriteFile(e.target, body, 0o600); err != nil {
				t.Fatal("create YAML fixture")
			}
			e.r.Policy.Targets = []runnerproto.TargetRule{{Kind: runnerproto.TargetYAMLScalar, PathPrefixes: []string{filepath.Dir(e.target)}, Fields: []string{"service.API_KEY"}}}
			j := e.verifyJob(func(j *runnerproto.Job) {
				j.Target.Kind, j.Target.Field = runnerproto.TargetYAMLScalar, "service.API_KEY"
				j.ExpectedFingerprint = e.fpOf(value)
				if !match {
					j.ExpectedFingerprint = e.fpOf(c.Value(2))
				}
			})
			e.once()
			r := e.f.results[j.JobID]
			if r.OK != match || r.Fingerprint != e.fpOf(value) || r.Healthcheck != nil || e.f.fetches != 1 {
				t.Fatal("YAML verify result or key request differed")
			}
			if !match && r.ErrorClass != runnerproto.ErrClassFingerprintMismatch {
				t.Fatal("YAML mismatch error class differed")
			}
			encoded, err := json.Marshal(r)
			if err != nil || c.In(string(encoded)) {
				t.Fatal("YAML verify result leaked canary")
			}
			after, err := os.ReadFile(e.target)
			if err != nil || !bytes.Equal(after, body) {
				t.Fatal("YAML verify changed file")
			}
			if _, err := os.Stat(e.target + ".bak"); !os.IsNotExist(err) {
				t.Fatal("YAML verify created backup")
			}
		})
	}
}
