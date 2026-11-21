//go:build unix

package loop

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

func (e *env) adoptionCarrier() []byte {
	e.t.Helper()
	body := []byte("service:\n  API_KEY: '" + e.value + "'\n")
	if err := os.WriteFile(e.target, body, 0o600); err != nil {
		e.t.Fatal("create disposable YAML carrier")
	}
	e.r.Policy.Targets = []runnerproto.TargetRule{{Kind: runnerproto.TargetYAMLScalar, PathPrefixes: []string{filepath.Dir(e.target)}, Fields: []string{"service.API_KEY"}}}
	e.r.Policy.AdoptionTargets = []runnerproto.AdoptionTarget{{Path: e.target, Field: "service.API_KEY"}}
	return body
}

func (e *env) adoptJob(mod func(*runnerproto.Job)) runnerproto.Job {
	e.t.Helper()
	return e.verifyJob(func(j *runnerproto.Job) {
		j.Action = runnerproto.ActionAdopt
		j.Target.Kind, j.Target.Field = runnerproto.TargetYAMLScalar, "service.API_KEY"
		if mod != nil {
			mod(j)
		}
	})
}

func TestAdoptYAMLAttestsWithoutWriteRestartOrReplay(t *testing.T) {
	for _, match := range []bool{true, false} {
		t.Run(map[bool]string{true: "match", false: "mismatch"}[match], func(t *testing.T) {
			e := newEnv(t)
			body := e.adoptionCarrier()
			before, err := os.Stat(e.target)
			if err != nil {
				t.Fatal("stat disposable carrier")
			}
			j := e.adoptJob(func(j *runnerproto.Job) {
				if !match {
					j.ExpectedFingerprint = e.fpOf(e.c.Value(2))
				}
			})
			e.f.jobs = append(e.f.jobs, e.f.jobs[0])
			e.once()
			e.once()
			res := e.f.results[j.JobID]
			if res.OK != match || res.Fingerprint != e.fpOf(e.value) || res.Healthcheck != nil || e.f.fetches != 1 || e.f.sends != 1 {
				t.Fatal("adoption result, key fetch or replay guard differed")
			}
			if !match && res.ErrorClass != runnerproto.ErrClassFingerprintMismatch {
				t.Fatal("wrong YAML scalar did not report mismatch")
			}
			encoded, err := json.Marshal(res)
			if err != nil || e.c.In(string(encoded)) || e.c.In(e.logbuf.String()) {
				t.Fatal("adoption result or log leaked canary")
			}
			after, err := os.Stat(e.target)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
				t.Fatal("adoption changed file identity or metadata")
			}
			got, err := os.ReadFile(e.target)
			if err != nil || !bytes.Equal(got, body) {
				t.Fatal("adoption changed YAML bytes")
			}
			if _, err := os.Stat(e.target + ".bak"); !os.IsNotExist(err) {
				t.Fatal("adoption created a backup")
			}
		})
	}
}

func TestAdoptYAMLDeniedBeforeRequestingKey(t *testing.T) {
	for name, change := range map[string]func(*env){
		"no-operation-grant": func(e *env) { e.r.Policy.AdoptionTargets = nil },
		"wrong-grant-path":   func(e *env) { e.r.Policy.AdoptionTargets[0].Path += ".other" },
		"wrong-grant-field":  func(e *env) { e.r.Policy.AdoptionTargets[0].Field = "other.API_KEY" },
		"no-read-rule":       func(e *env) { e.r.Policy.Targets = nil },
		"shared-prod":        func(e *env) { e.r.Policy.UIDShared = true },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.adoptionCarrier()
			change(e)
			j := e.adoptJob(nil)
			e.once()
			if e.f.fetches != 0 || e.f.results[j.JobID].ErrorClass != runnerproto.ErrClassPolicyDenied {
				t.Fatal("adoption requested a key outside the exact host grant")
			}
		})
	}
}

func TestAdoptYAMLIdentityAndExpiryDeniedBeforeKey(t *testing.T) {
	for name, change := range map[string]func(*runnerproto.Job){
		"runner": func(j *runnerproto.Job) { j.RunnerID = "runner-2" },
		"org":    func(j *runnerproto.Job) { j.OrgID = "another" },
		"expiry": func(j *runnerproto.Job) { j.IssuedAt, j.NotAfter = t0.Add(-time.Hour), t0.Add(-55*time.Minute) },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.adoptionCarrier()
			j := e.adoptJob(change)
			e.once()
			want := runnerproto.ErrClassWrongRunner
			if name == "expiry" {
				want = runnerproto.ErrClassExpired
			}
			if e.f.fetches != 0 || e.f.results[j.JobID].ErrorClass != want {
				t.Fatal("adoption ignored the enrolled identity or validity window")
			}
		})
	}
}
