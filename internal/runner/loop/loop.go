package loop

import (
	"context"
	"crypto/ecdh"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/runner/deploy"
	"github.com/entire-vc/evc-keep/internal/runner/execrun"
	"github.com/entire-vc/evc-keep/internal/targets"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// Runner is one enrolled host's execution loop.
type Runner struct {
	Transport Transport
	// Me is the runner's own identity from its enrollment, never from a job.
	Me       runnerproto.Identity
	Keys     runnerproto.TrustedKeys
	Policy   runnerproto.HostPolicy
	Journal  runnerproto.Journal
	Limiter  *runnerproto.Limiter
	Delivery *ecdh.PrivateKey
	Outbox   *Outbox
	// Deploy carries the Apply seams; Key is set per job.
	Deploy deploy.Deps
	// Exec carries the host's fixed choices for exec_with_secret jobs; nil
	// means this runner does not run them (policy_denied).
	Exec *execrun.Deps
	// ExecSink receives the scrubbed, limited output of an exec job. It stays
	// on the host: Result has no field for it. nil drops it.
	ExecSink func(jobID string, out execrun.Outcome)
	// Log must be built over internal/obs.
	Log *slog.Logger
	Now func() time.Time
	// Sleep waits between failed attempts; nil means a context-aware timer.
	Sleep func(ctx context.Context, d time.Duration)
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Runner) sleep(ctx context.Context, d time.Duration) {
	if r.Sleep != nil {
		r.Sleep(ctx, d)
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

const (
	minBackoff = time.Second
	maxBackoff = 30 * time.Second
)

func next(d time.Duration) time.Duration {
	if d < minBackoff {
		return minBackoff
	}
	if d *= 2; d > maxBackoff {
		return maxBackoff
	}
	return d
}

// Run drains the outbox, then polls until ctx ends. A restart sends what the
// previous run left before it asks for anything new.
func (r *Runner) Run(ctx context.Context) error {
	if err := r.recoverStarted(); err != nil {
		return err
	}
	var wait time.Duration
	for ctx.Err() == nil {
		if err := r.flush(ctx); err != nil {
			wait = next(wait)
			r.Log.Warn("runner.outbox", "status", "retry", "error_class", "transport")
			r.sleep(ctx, wait)
			continue
		}
		did, err := r.Once(ctx)
		switch {
		case errors.Is(err, ErrOutbox):
			return err
		case err != nil:
			wait = next(wait)
			r.Log.Warn("runner.poll", "status", "retry", "error_class", "transport")
			r.sleep(ctx, wait)
		case did:
			wait = 0
		default:
			wait = 0
		}
	}
	return nil
}

// Drain closes jobs a previous run left unfinished and sends every closed
// Result. Run does it before its first poll; -once uses it directly.
func (r *Runner) Drain(ctx context.Context) error {
	if err := r.recoverStarted(); err != nil {
		return err
	}
	return r.flush(ctx)
}

// Once polls once and, if a job arrived, runs it and sends its Result. It
// reports whether a job arrived.
func (r *Runner) Once(ctx context.Context) (bool, error) {
	sj, err := r.Transport.NextJob(ctx)
	if err != nil {
		return false, err
	}
	if sj == nil {
		return false, nil
	}
	if err := r.handle(ctx, *sj); err != nil {
		return true, err
	}
	// A send failure stays in the outbox; Run retries it before the next poll,
	// and the error tells a one-shot caller that a Result is still pending.
	return true, r.flush(ctx)
}

// recoverStarted closes every job a previous run began and did not finish.
// What happened to its target is unknown, so the Result says so.
func (r *Runner) recoverStarted() error {
	pending, err := r.Outbox.List()
	if err != nil {
		return err
	}
	for _, p := range pending {
		if p.Closed {
			continue
		}
		if err := r.Outbox.Close(p.JobID, runnerproto.Result{ErrorClass: runnerproto.ErrClassInternal}); err != nil {
			return err
		}
		r.Log.Warn("runner.job", "job_id", p.JobID, "status", "interrupted", "error_class", string(runnerproto.ErrClassInternal))
	}
	return nil
}

// flush sends every closed entry. A refusal drops the entry; any other
// failure keeps it and is returned.
func (r *Runner) flush(ctx context.Context) error {
	pending, err := r.Outbox.List()
	if err != nil {
		return err
	}
	for _, p := range pending {
		if !p.Closed {
			continue
		}
		switch err := r.Transport.SendResult(ctx, p.JobID, p.Result); {
		case err == nil:
		case errors.Is(err, ErrRefused):
			r.Log.Warn("runner.result", "job_id", p.JobID, "status", "refused")
		default:
			return err
		}
		if err := r.Outbox.Ack(p.JobID); err != nil {
			return err
		}
		r.Log.Info("runner.result", "job_id", p.JobID, "status", "acknowledged")
	}
	return nil
}

// handle runs one signed job to a closed Result in the outbox. Nothing here
// returns a value-bearing error.
// A job whose outcome cannot be put on disk returns ErrOutbox: the loop must
// not go on running jobs it cannot report.
func (r *Runner) handle(ctx context.Context, sj runnerproto.SignedJob) error {
	bf := &beginFirst{r: r}
	j, err := runnerproto.VerifyJob(sj, r.Keys, r.Me, r.now(), bf)
	if err != nil {
		if bf.failed {
			return ErrOutbox
		}
		return r.reject(sj, err)
	}
	res := r.execute(ctx, j)
	if err := r.Outbox.Close(j.JobID, res); err != nil {
		// The entry stays "started"; a restart reports it as interrupted.
		r.Log.Error("runner.job", "job_id", j.JobID, "status", "outbox", "error_class", string(runnerproto.ErrClassInternal))
		return ErrOutbox
	}
	status := "ok"
	if !res.OK {
		status = "failed"
	}
	r.Log.Info("runner.job", "job_id", j.JobID, "status", status, "error_class", string(res.ErrorClass))
	return nil
}

// beginFirst records the job in the outbox before the replay journal claims
// it. A crash between the two leaves a started entry the next run reports; the
// other order would leave a claimed job nobody reports. A claim that fails
// takes the entry back, unless the entry belonged to an earlier run of the job.
type beginFirst struct {
	r      *Runner
	failed bool // the outbox itself refused the entry
}

func (b *beginFirst) Claim(jobID string, notAfter, now time.Time) error {
	if err := b.r.Outbox.Begin(jobID); err != nil {
		b.failed = !errors.Is(err, os.ErrExist)
		b.r.Log.Error("runner.job", "job_id", jobID, "status", "outbox", "error_class", string(runnerproto.ErrClassInternal))
		return fmt.Errorf("%w: outbox", runnerproto.ErrReplay)
	}
	if b.r.Journal == nil {
		_ = b.r.Outbox.Ack(jobID)
		return fmt.Errorf("%w: no replay journal", runnerproto.ErrReplay)
	}
	if err := b.r.Journal.Claim(jobID, notAfter, now); err != nil {
		_ = b.r.Outbox.Ack(jobID)
		return err
	}
	return nil
}

// reject handles a job VerifyJob refused. A bad signature has no trusted job
// id and a replay already has a Result of its own; both are only logged. A
// job whose signature held but whose identity or window failed is reported.
func (r *Runner) reject(sj runnerproto.SignedJob, cause error) error {
	class := runnerproto.ClassOf(cause)
	if errors.Is(cause, runnerproto.ErrSignature) || errors.Is(cause, runnerproto.ErrReplay) {
		r.Log.Warn("runner.job", "status", "rejected", "error_class", string(class))
		return nil
	}
	j, err := runnerproto.DecodeJob(sj.Payload)
	if err != nil {
		r.Log.Warn("runner.job", "status", "rejected", "error_class", string(class))
		return nil
	}
	if err := r.Outbox.CloseIfAbsent(j.JobID, runnerproto.Result{ErrorClass: class}); errors.Is(err, os.ErrExist) {
		// The job already has an outcome; a later rejection must not touch it.
		r.Log.Warn("runner.job", "job_id", j.JobID, "status", "rejected", "error_class", string(class))
		return nil
	} else if err != nil {
		r.Log.Error("runner.job", "job_id", j.JobID, "status", "outbox", "error_class", string(runnerproto.ErrClassInternal))
		return ErrOutbox
	}
	r.Log.Warn("runner.job", "job_id", j.JobID, "status", "rejected", "error_class", string(class))
	return nil
}

func fail(c runnerproto.ErrorClass) runnerproto.Result { return runnerproto.Result{ErrorClass: c} }

// execute is the ordered part: policy and limit before the value, the value's
// HMAC before the write.
func (r *Runner) execute(ctx context.Context, j runnerproto.Job) runnerproto.Result {
	if j.Action != runnerproto.ActionDeploy && j.Action != runnerproto.ActionExec && j.Action != runnerproto.ActionVerify {
		return fail(runnerproto.ErrClassInvalidJob)
	}
	if err := runnerproto.Check(j, r.Policy); err != nil {
		return fail(runnerproto.ClassOf(err))
	}
	if j.Action == runnerproto.ActionVerify {
		return r.verify(ctx, j)
	}
	var plan execrun.Plan
	if j.Action == runnerproto.ActionExec {
		// The host's own policy decides before a limit is spent or a value
		// is fetched; every refusal is the one class policy_denied.
		if r.Exec == nil {
			return fail(runnerproto.ErrClassPolicyDenied)
		}
		var err error
		if plan, err = execrun.Prepare(j, r.Policy); err != nil {
			return fail(runnerproto.ErrClassPolicyDenied)
		}
	}
	if r.Limiter == nil || r.Limiter.Allow(j, r.now()) != nil {
		return fail(runnerproto.ErrClassRateLimited)
	}
	if r.Outbox == nil || r.Delivery == nil {
		return fail(runnerproto.ErrClassInternal)
	}
	env, err := r.Transport.FetchValue(ctx, j.JobID)
	if err != nil {
		return fail(runnerproto.ErrClassValueUnavailable)
	}
	v, key, err := builtin.OpenRunnerMaterial(j, r.Delivery, env)
	if err != nil {
		return fail(runnerproto.ErrClassValueUnavailable)
	}
	defer v.Wipe()
	defer key.Wipe()
	got, err := fingerprint.Compute(key, v)
	if err != nil || got != j.ExpectedFingerprint {
		return fail(runnerproto.ErrClassFingerprintMismatch)
	}
	if j.Action == runnerproto.ActionExec {
		return r.runExec(ctx, j, plan, v, got)
	}
	deps := r.Deploy
	deps.Key = key
	if deps.Log == nil {
		deps.Log = r.Log
	}
	return deploy.Apply(ctx, j, r.Policy, v, deps)
}

// verify answers a verify job: does the carrier hold the expected version?
// Order matters. The file's real owner is read first (lstat, no link followed)
// and an agent-owned or unreadable file is refused before the server is asked
// for anything, so a verify job cannot make this host an oracle for the
// contents of a file an agent can write. A missing file or field needs no key
// and is reported as a mismatch with no fingerprint. Only then is the key of
// the store fetched (never a value), the file read and its fingerprint
// compared. The Result carries the fingerprint, the version or a class.
func (r *Runner) verify(ctx context.Context, j runnerproto.Job) runnerproto.Result {
	owner, exists, err := targets.OwnerOf(j.Target, r.Policy.AgentUIDs, r.Policy.AgentGIDs)
	switch {
	case errors.Is(err, targets.ErrPolicy):
		return fail(runnerproto.ErrClassPolicyDenied)
	case err != nil:
		return fail(runnerproto.ErrClassInternal)
	case !exists:
		return fail(runnerproto.ErrClassFingerprintMismatch)
	}
	if r.Outbox == nil || r.Delivery == nil {
		return fail(runnerproto.ErrClassInternal)
	}
	env, err := r.Transport.FetchValue(ctx, j.JobID)
	if err != nil {
		return fail(runnerproto.ErrClassValueUnavailable)
	}
	key, err := builtin.OpenRunnerKey(j, r.Delivery, env)
	if err != nil {
		return fail(runnerproto.ErrClassValueUnavailable)
	}
	defer key.Wipe()
	got, found, err := targets.Observe(j.Target, owner, r.Policy.AgentUIDs, r.Policy.AgentGIDs, key)
	switch {
	case errors.Is(err, targets.ErrPolicy):
		return fail(runnerproto.ErrClassPolicyDenied)
	case err != nil:
		return fail(runnerproto.ErrClassInternal)
	case !found:
		return fail(runnerproto.ErrClassFingerprintMismatch)
	case !targets.SameFingerprint(got, j.ExpectedFingerprint):
		res := runnerproto.Result{ErrorClass: runnerproto.ErrClassFingerprintMismatch, Fingerprint: got}
		if res.Validate() != nil {
			return fail(runnerproto.ErrClassInternal)
		}
		return res
	}
	res := runnerproto.Result{OK: true, Fingerprint: got, Version: j.ExpectedVersion}
	if res.Validate() != nil {
		return fail(runnerproto.ErrClassInternal)
	}
	return res
}

// runExec runs a prepared exec job. The result carries the fingerprint the
// runner just verified and the version the job expected; the exit code and
// the output stay in the host's journal and sink. A child that exits non-zero
// is reported as internal: the closed list of the contract has no class for
// it, and the exit code is not a thing the server may learn.
func (r *Runner) runExec(ctx context.Context, j runnerproto.Job, plan execrun.Plan, v secret.Value, fp string) runnerproto.Result {
	deps := *r.Exec
	if deps.Log == nil {
		deps.Log = r.Log
	}
	out, class := execrun.Run(ctx, plan, v, r.Policy, deps)
	if class != "" {
		return fail(class)
	}
	if r.ExecSink != nil {
		r.ExecSink(j.JobID, out)
	}
	if out.ExitCode != 0 {
		return fail(runnerproto.ErrClassInternal)
	}
	res := runnerproto.Result{OK: true, Fingerprint: fp, Version: j.ExpectedVersion}
	if res.Validate() != nil {
		return fail(runnerproto.ErrClassInternal)
	}
	return res
}
