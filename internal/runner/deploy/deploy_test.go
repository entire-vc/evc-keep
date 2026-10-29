//go:build unix

package deploy

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"

	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/runner/health"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

const unitName = "systemd:app.service"

type env struct {
	dir    string
	path   string
	policy runnerproto.HostPolicy
	job    runnerproto.Job
	deps   Deps
	calls  int
	logbuf *bytes.Buffer
}

func newEnv(t *testing.T, out health.Outcome) *env {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, -1, unix.Getegid()); err != nil {
		t.Fatal(err)
	}
	key, err := fingerprint.GenerateKey("teststore")
	if err != nil {
		t.Fatal(err)
	}
	e := &env{dir: dir, path: filepath.Join(dir, "app.env"), logbuf: &bytes.Buffer{}}
	e.policy = runnerproto.HostPolicy{
		Version:           1,
		Targets:           []runnerproto.TargetRule{{Kind: runnerproto.TargetEnvFile, PathPrefixes: []string{dir}, Fields: []string{"STRIPE_KEY"}, Units: []string{unitName}}},
		AgentUIDs:         []int64{1},
		AgentGIDs:         []int64{1},
		MaxDeploysPerHour: 10,
	}
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	e.job = runnerproto.Job{
		JobID:               id.String(),
		OrgID:               "acme",
		RunnerID:            "runner-1",
		Secret:              runnerproto.SecretRef{StoreID: "store-1", Provider: runnerproto.ProviderBuiltin, Name: "stripe/api-key", Scope: "prod"},
		ExpectedFingerprint: "kfp1:s1:abcdefghijklmnop",
		IssuedAt:            issued,
		NotAfter:            issued.Add(5 * time.Minute),
		Nonce:               bytes.Repeat([]byte{7}, runnerproto.NonceSize),
		Action:              runnerproto.ActionDeploy,
		ExpectedVersion:     "7",
		Target: runnerproto.Target{
			Kind: runnerproto.TargetEnvFile, Path: e.path, Field: "STRIPE_KEY",
			Mode: 0o600, UID: int64(os.Geteuid()), GID: int64(os.Getegid()), Consumer: unitName,
		},
	}
	e.deps = Deps{
		Key: key,
		Log: obs.New(e.logbuf),
		Now: func() time.Time { return time.Unix(1_800_000_000, 0).UTC() },
		Health: func(context.Context, runnerproto.Target, runnerproto.HealthCheck) health.Outcome {
			e.calls++
			return out
		},
	}
	return e
}

func apply(e *env, v string) runnerproto.Result {
	return Apply(context.Background(), e.job, e.policy, secret.New([]byte(v)), e.deps)
}

func TestApplyHealthyDeploy(t *testing.T) {
	e := newEnv(t, health.Outcome{Status: runnerproto.HealthOK, Kind: runnerproto.HealthKindUnitActive, DurationMs: 5})
	r := apply(e, "value-1")
	if !r.OK || r.Healthcheck == nil || r.Healthcheck.Status != runnerproto.HealthOK || r.Fingerprint == "" || r.Version != "7" {
		t.Fatalf("result: %+v", r)
	}
	if e.calls != 1 {
		t.Fatalf("health calls = %d, want 1", e.calls)
	}
	if got, _ := os.ReadFile(e.path); !strings.Contains(string(got), "value-1") {
		t.Fatalf("target not written")
	}
	if !strings.Contains(e.logbuf.String(), "deploy.healthcheck") {
		t.Fatal("no deploy.healthcheck event")
	}
}

// The acceptance line of the card: a failed check is ok=false.
func TestApplyFailedHealthcheckIsNotOK(t *testing.T) {
	e := newEnv(t, health.Outcome{Status: runnerproto.HealthFailed, Kind: runnerproto.HealthKindHTTP, DurationMs: 9})
	r := apply(e, "value-1")
	if r.OK || r.ErrorClass != runnerproto.ErrClassHealthcheck {
		t.Fatalf("result: %+v", r)
	}
	if r.Healthcheck == nil || r.Healthcheck.Status != runnerproto.HealthFailed || r.Healthcheck.Kind != runnerproto.HealthKindHTTP {
		t.Fatalf("healthcheck: %+v", r.Healthcheck)
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
}

// A restart that fails with no check configured has no kind; the contract
// allows an empty kind only with "skipped", so the class stands alone.
func TestApplyRestartFailedWithoutKind(t *testing.T) {
	e := newEnv(t, health.Outcome{Status: runnerproto.HealthFailed})
	r := apply(e, "value-1")
	if r.OK || r.ErrorClass != runnerproto.ErrClassHealthcheck || r.Healthcheck != nil {
		t.Fatalf("result: %+v", r)
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestApplyNoConsumerSkipsRestart(t *testing.T) {
	e := newEnv(t, health.Outcome{Status: runnerproto.HealthOK, Kind: runnerproto.HealthKindUnitActive})
	e.job.Target.Consumer = ""
	r := apply(e, "value-1")
	if !r.OK || r.Healthcheck == nil || r.Healthcheck.Status != runnerproto.HealthSkipped || e.calls != 0 {
		t.Fatalf("result: %+v calls=%d", r, e.calls)
	}
}

// A refused job writes nothing and restarts nothing.
func TestApplyRefusedJobTouchesNothing(t *testing.T) {
	cases := map[string]func(*env){
		"consumer outside allowlist": func(e *env) { e.job.Target.Consumer = "systemd:other.service" },
		"path outside prefix":        func(e *env) { e.job.Target.Path = "/etc/passwd-keep/app.env" },
		"launchd without unit_uids": func(e *env) {
			e.policy.Targets[0].Units = []string{"launchd:com.example.app"}
			e.job.Target.Consumer = "launchd:com.example.app"
		},
		"verify action": func(e *env) {
			e.job.Action = runnerproto.ActionVerify
			e.job.Target.Consumer = ""
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, health.Outcome{Status: runnerproto.HealthOK, Kind: runnerproto.HealthKindUnitActive})
			mut(e)
			r := apply(e, "value-1")
			if r.OK || r.ErrorClass == "" {
				t.Fatalf("result: %+v", r)
			}
			if _, err := os.Stat(e.path); err == nil {
				t.Fatalf("target written for a refused job")
			}
			if e.calls != 0 {
				t.Fatalf("consumer restarted for a refused job")
			}
		})
	}
}

// The value never leaves Apply but through the target: not in the Result,
// not in the log, for any outcome.
func TestApplyNeverLeaksValue(t *testing.T) {
	c := canary.New()
	outcomes := []health.Outcome{
		{Status: runnerproto.HealthOK, Kind: runnerproto.HealthKindHTTP},
		{Status: runnerproto.HealthFailed, Kind: runnerproto.HealthKindHTTP},
		{Status: runnerproto.HealthFailed},
	}
	for _, out := range outcomes {
		e := newEnv(t, out)
		r := apply(e, c.Value(1))
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if c.In(string(b)) || c.In(e.logbuf.String()) || c.In(slog.AnyValue(r).String()) {
			t.Fatal("canary leaked into result or log")
		}
		if got, _ := os.ReadFile(e.path); !c.In(string(got)) {
			t.Fatalf("positive control: canary not in the target file")
		}
	}
}

// finish is the last gate: an outcome outside the closed kind list must not
// turn into a Result the server would refuse.
func TestApplyOutsideContractNeverLeavesApply(t *testing.T) {
	e := newEnv(t, health.Outcome{Status: runnerproto.HealthOK, Kind: "shell"})
	r := apply(e, "value-1")
	if r.OK || r.ErrorClass != runnerproto.ErrClassInternal || r.Healthcheck != nil {
		t.Fatalf("result: %+v", r)
	}
}
