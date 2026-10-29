// Package deploy is the runner's one deploy step: check the job against the
// host policy, write the value into the target, restart the consumer and run
// the healthcheck, and report a runnerproto.Result. The caller has already
// verified the job's signature and fetched the value; polling and transport
// are not here.
package deploy

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/entire-vc/evc-keep/internal/runner/health"
	"github.com/entire-vc/evc-keep/internal/targets"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// Deps is what Apply needs besides the job and the policy.
type Deps struct {
	// Key computes the fingerprint of the written value.
	Key fingerprint.Key
	// Log receives the deploy.healthcheck event; nil logs nothing. It must
	// be built over internal/obs.
	Log *slog.Logger
	// Now stamps the healthcheck; nil means time.Now.
	Now func() time.Time
	// Health restarts the consumer and checks it; nil means health.Run.
	// A seam for tests of Apply's own mapping.
	Health func(ctx context.Context, t runnerproto.Target, h runnerproto.HealthCheck) health.Outcome
	// WriteOptions are passed to targets.Write.
	WriteOptions []targets.Option
}

// Apply runs one deploy job. It returns a Result that satisfies
// Result.Validate, whatever happened; its only content is the closed list of
// the contract. The value is read by targets.Write and nowhere else.
//
// A target is not rolled back when the healthcheck fails: ok is false, the
// decision is the caller's.
func Apply(ctx context.Context, j runnerproto.Job, p runnerproto.HostPolicy, v secret.Value, d Deps) runnerproto.Result {
	if j.Action != runnerproto.ActionDeploy {
		return fail(runnerproto.ErrClassInvalidJob)
	}
	if err := runnerproto.Check(j, p); err != nil {
		return fail(runnerproto.ClassOf(err))
	}
	opts := d.WriteOptions
	fp, err := targets.Write(j.Target, v, p.AgentUIDs, p.AgentGIDs, d.Key, opts...)
	if err != nil {
		if errors.Is(err, targets.ErrPolicy) {
			return fail(runnerproto.ErrClassPolicyDenied)
		}
		return fail(runnerproto.ErrClassTargetWrite)
	}
	res := runnerproto.Result{OK: true, Fingerprint: fp, Version: j.ExpectedVersion}

	now := d.Now
	if now == nil {
		now = time.Now
	}
	if j.Target.Consumer == "" {
		res.Healthcheck = &runnerproto.Healthcheck{Status: runnerproto.HealthSkipped, CheckedAt: now()}
		return finish(res)
	}
	run := d.Health
	if run == nil {
		run = health.Run
	}
	out := run(ctx, j.Target, runnerproto.ResolveHealth(p, j.Target))
	if d.Log != nil {
		health.EmitEvent(d.Log, out)
	}
	if out.Status == runnerproto.HealthFailed {
		res.OK, res.ErrorClass = false, runnerproto.ErrClassHealthcheck
		// A failed restart with no check configured has no kind, and the
		// contract allows an empty kind only with "skipped": report the
		// class alone.
		if out.Kind != "" {
			res.Healthcheck = &runnerproto.Healthcheck{Status: out.Status, Kind: out.Kind, DurationMs: out.DurationMs, CheckedAt: now()}
		}
		return finish(res)
	}
	res.Healthcheck = &runnerproto.Healthcheck{Status: out.Status, Kind: out.Kind, DurationMs: out.DurationMs, CheckedAt: now()}
	return finish(res)
}

func fail(c runnerproto.ErrorClass) runnerproto.Result {
	return runnerproto.Result{ErrorClass: c}
}

// finish is the last gate: a Result outside the contract never leaves.
func finish(r runnerproto.Result) runnerproto.Result {
	if r.Validate() != nil {
		return fail(runnerproto.ErrClassInternal)
	}
	return r
}
