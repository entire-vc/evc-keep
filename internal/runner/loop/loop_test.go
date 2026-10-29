//go:build unix

package loop

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"

	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/runner/deploy"
	"github.com/entire-vc/evc-keep/internal/runner/execrun"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/execpolicy"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

var t0 = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

// fake is the server side: it hands out signed jobs, seals real envelopes and
// records every call in order.
type fake struct {
	jobs      []runnerproto.SignedJob
	recipient []byte
	valueFor  func(j runnerproto.Job) (secret.Value, fingerprint.Key)
	fetchErr  error
	sendErrs  []error // consumed one per SendResult call
	calls     []string
	fetches   int
	results   map[string]runnerproto.Result
	sends     int
	onPoll    func() // called when the queue is empty
	onFetch   func() // called when a value is requested
}

func (f *fake) NextJob(context.Context) (*runnerproto.SignedJob, error) {
	f.calls = append(f.calls, "poll")
	if len(f.jobs) == 0 {
		if f.onPoll != nil {
			f.onPoll()
		}
		return nil, nil
	}
	sj := f.jobs[0]
	f.jobs = f.jobs[1:]
	return &sj, nil
}

func (f *fake) FetchValue(_ context.Context, id string) (runnerproto.ValueEnvelope, error) {
	f.calls = append(f.calls, "fetch")
	f.fetches++
	if f.onFetch != nil {
		f.onFetch()
	}
	if f.fetchErr != nil {
		return runnerproto.ValueEnvelope{}, f.fetchErr
	}
	// The job is whatever the test last signed; find it by id.
	j := lastJob[id]
	v, k := f.valueFor(j)
	defer v.Wipe()
	defer k.Wipe()
	if j.Action == runnerproto.ActionVerify {
		return builtin.SealRunnerKey(j, f.recipient, k)
	}
	return builtin.SealRunnerMaterial(j, f.recipient, v, k)
}

func (f *fake) SendResult(_ context.Context, id string, r runnerproto.Result) error {
	f.calls = append(f.calls, "send")
	f.sends++
	if len(f.sendErrs) > 0 {
		err := f.sendErrs[0]
		f.sendErrs = f.sendErrs[1:]
		if err != nil {
			return err
		}
	}
	if f.results == nil {
		f.results = map[string]runnerproto.Result{}
	}
	f.results[id] = r
	return nil
}

var lastJob = map[string]runnerproto.Job{}

type env struct {
	t      *testing.T
	dir    string
	target string
	c      canary.Canary
	value  string
	key    fingerprint.Key
	signer runnerproto.Signer
	pub    ed25519.PublicKey
	f      *fake
	r      *Runner
	logbuf *bytes.Buffer
	policy runnerproto.HostPolicy
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, -1, unix.Getegid()); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := fingerprint.GenerateKey("store1")
	if err != nil {
		t.Fatal(err)
	}
	ob, err := OpenOutbox(filepath.Join(dir, "outbox"))
	if err != nil {
		t.Fatal(err)
	}
	c := canary.New()
	e := &env{t: t, dir: dir, target: filepath.Join(dir, "app.env"), c: c, value: c.Value(1), key: key,
		signer: runnerproto.Signer{KeyID: "org1", Key: priv}, pub: pub, logbuf: &bytes.Buffer{}}
	e.policy = runnerproto.HostPolicy{
		Version:           1,
		Targets:           []runnerproto.TargetRule{{Kind: runnerproto.TargetEnvFile, PathPrefixes: []string{dir}, Fields: []string{"STRIPE_KEY"}}},
		AgentUIDs:         []int64{1},
		AgentGIDs:         []int64{1},
		MaxDeploysPerHour: 10,
	}
	e.f = &fake{recipient: delivery.PublicKey().Bytes()}
	e.f.valueFor = func(runnerproto.Job) (secret.Value, fingerprint.Key) {
		k, _ := fingerprint.NewKey("store1", rawKey(key))
		return secret.New([]byte(e.value)), k
	}
	e.r = &Runner{
		Transport: e.f,
		Me:        runnerproto.Identity{OrgID: "acme", RunnerID: "runner-1"},
		Keys:      runnerproto.TrustedKeys{"org1": pub},
		Policy:    e.policy,
		Journal:   runnerproto.NewMemJournal(),
		Limiter:   runnerproto.NewLimiter(e.policy),
		Delivery:  delivery,
		Outbox:    ob,
		Deploy:    deploy.Deps{},
		Log:       obs.New(e.logbuf),
		Now:       func() time.Time { return t0.Add(time.Second) },
		Sleep:     func(context.Context, time.Duration) {},
	}
	return e
}

func rawKey(k fingerprint.Key) []byte {
	var b []byte
	fingerprint.ExposeKey(k, func(x []byte) { b = append([]byte(nil), x...) })
	return b
}

// job builds, signs and queues a deploy job for the env's value.
func (e *env) job(mod func(*runnerproto.Job)) runnerproto.Job {
	e.t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		e.t.Fatal(err)
	}
	fp, err := fingerprint.Compute(e.key, secret.New([]byte(e.value)))
	if err != nil {
		e.t.Fatal(err)
	}
	j := runnerproto.Job{
		JobID: id.String(), OrgID: "acme", RunnerID: "runner-1",
		Secret:              runnerproto.SecretRef{StoreID: "store-1", Provider: runnerproto.ProviderBuiltin, Name: "stripe/api-key", Scope: "prod"},
		ExpectedVersion:     "7",
		ExpectedFingerprint: fp,
		Action:              runnerproto.ActionDeploy,
		Target: runnerproto.Target{Kind: runnerproto.TargetEnvFile, Path: e.target, Field: "STRIPE_KEY",
			Mode: 0o600, UID: int64(os.Geteuid()), GID: int64(os.Getegid())},
		IssuedAt: t0, NotAfter: t0.Add(5 * time.Minute), Nonce: bytes.Repeat([]byte{7}, runnerproto.NonceSize),
	}
	if mod != nil {
		mod(&j)
	}
	lastJob[j.JobID] = j
	sj, err := e.signer.Sign(j)
	if err != nil {
		e.t.Fatal(err)
	}
	e.f.jobs = append(e.f.jobs, sj)
	return j
}

func (e *env) targetExists() bool {
	_, err := os.Stat(e.target)
	return err == nil
}

func (e *env) outboxFiles() []string {
	ents, _ := os.ReadDir(filepath.Join(e.dir, "outbox"))
	var n []string
	for _, x := range ents {
		n = append(n, x.Name())
	}
	return n
}

func (e *env) once() {
	e.t.Helper()
	// A failed send is the loop's business, not a test failure: the Result
	// stays in the outbox and the tests that care inspect it.
	if _, err := e.r.Once(context.Background()); err != nil && !errors.Is(err, ErrTransport) {
		e.t.Fatal(err)
	}
}

func TestHappyPathWritesAndReportsClosedResult(t *testing.T) {
	e := newEnv(t)
	j := e.job(nil)
	e.once()
	r, ok := e.f.results[j.JobID]
	if !ok || !r.OK || r.Fingerprint != j.ExpectedFingerprint || r.Version != "7" {
		t.Fatalf("result: %+v", r)
	}
	if got, _ := os.ReadFile(e.target); !strings.Contains(string(got), e.value) {
		t.Fatal("target not written with the delivered value")
	}
	if len(e.outboxFiles()) != 0 {
		t.Fatalf("acknowledged result left in the outbox: %v", e.outboxFiles())
	}
}

// The canary must not reach the Result, the outbox, the loop's log or any
// error text (leak test, written before the loop).
func TestCanaryNeverLeavesTheTargetFile(t *testing.T) {
	e := newEnv(t)
	e.f.sendErrs = []error{ErrTransport, ErrTransport} // keep the closed entry on disk to inspect it
	e.job(nil)
	e.job(func(j *runnerproto.Job) { j.Target.Path = "/etc/not-in-policy" })
	e.once()
	e.once()
	var surfaces []string
	surfaces = append(surfaces, e.logbuf.String())
	for _, n := range e.outboxFiles() {
		b, _ := os.ReadFile(filepath.Join(e.dir, "outbox", n)) //nolint:gosec // G304: test-owned temp dir
		surfaces = append(surfaces, string(b))
	}
	for _, r := range e.f.results {
		b, _ := json.Marshal(r)
		surfaces = append(surfaces, string(b))
	}
	if len(e.outboxFiles()) == 0 {
		t.Fatal("test setup: expected a closed entry on disk to inspect")
	}
	probe := canary.Of(e.value)
	for _, s := range surfaces {
		if probe.In(s) {
			t.Fatalf("value reached an outward surface: %q", s[:min(len(s), 40)])
		}
	}
	// Positive control: the detector sees the value in the one place it belongs.
	if got, _ := os.ReadFile(e.target); !probe.In(string(got)) {
		t.Fatal("leak detector does not see the value in the target file")
	}
}

func TestBadSignatureNeverReachesFetchOrWrite(t *testing.T) {
	e := newEnv(t)
	e.job(nil)
	e.f.jobs[0].Payload = append([]byte(nil), e.f.jobs[0].Payload...)
	e.f.jobs[0].Payload[len(e.f.jobs[0].Payload)-1] ^= 1
	e.once()
	if e.f.fetches != 0 || e.targetExists() || e.f.sends != 0 || len(e.outboxFiles()) != 0 {
		t.Fatalf("tampered job had effect: fetches=%d target=%v sends=%d outbox=%v", e.f.fetches, e.targetExists(), e.f.sends, e.outboxFiles())
	}
	// A key the runner does not pin is the same refusal.
	e2 := newEnv(t)
	e2.signer.KeyID = "other"
	e2.job(nil)
	e2.once()
	if e2.f.fetches != 0 || e2.targetExists() {
		t.Fatal("job under an unpinned key had effect")
	}
}

func TestOutsidePolicyRejectedBeforeFetchAndWrite(t *testing.T) {
	e := newEnv(t)
	j := e.job(func(j *runnerproto.Job) { j.Target.Path = filepath.Join(filepath.Dir(e.dir), "elsewhere.env") })
	e.once()
	if e.f.fetches != 0 {
		t.Fatal("value requested for a job outside the host policy")
	}
	if r := e.f.results[j.JobID]; r.OK || r.ErrorClass != runnerproto.ErrClassPolicyDenied {
		t.Fatalf("result: %+v", r)
	}
}

func TestRateLimitedBeforeFetch(t *testing.T) {
	e := newEnv(t)
	e.policy.MaxDeploysPerHour = 1
	e.r.Policy = e.policy
	e.r.Limiter = runnerproto.NewLimiter(e.policy)
	first := e.job(nil)
	second := e.job(nil)
	e.once()
	e.once()
	if e.f.fetches != 1 {
		t.Fatalf("fetches = %d, want 1: the limited job must not request its value", e.f.fetches)
	}
	if !e.f.results[first.JobID].OK || e.f.results[second.JobID].ErrorClass != runnerproto.ErrClassRateLimited {
		t.Fatalf("results: %+v", e.f.results)
	}
}

func TestIdentityAndWindowRejectedBeforeFetch(t *testing.T) {
	for name, mod := range map[string]func(*runnerproto.Job){
		"wrong-runner": func(j *runnerproto.Job) { j.RunnerID = "runner-2" },
		"expired":      func(j *runnerproto.Job) { j.IssuedAt, j.NotAfter = t0.Add(-time.Hour), t0.Add(-55*time.Minute) },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			j := e.job(mod)
			e.once()
			if e.f.fetches != 0 || e.targetExists() {
				t.Fatal("rejected job had effect")
			}
			want := runnerproto.ErrClassWrongRunner
			if name == "expired" {
				want = runnerproto.ErrClassExpired
			}
			if r := e.f.results[j.JobID]; r.ErrorClass != want {
				t.Fatalf("result: %+v", r)
			}
		})
	}
}

func TestReplayedJobDoesNothingTwice(t *testing.T) {
	e := newEnv(t)
	e.job(nil)
	e.f.jobs = append(e.f.jobs, e.f.jobs[0])
	e.once()
	if err := os.Remove(e.target); err != nil {
		t.Fatal(err)
	}
	e.once()
	if e.f.fetches != 1 || e.targetExists() || e.f.sends != 1 {
		t.Fatalf("replay ran again: fetches=%d target=%v sends=%d", e.f.fetches, e.targetExists(), e.f.sends)
	}
	if files := e.outboxFiles(); len(files) != 0 {
		t.Fatalf("a refused replay left an outbox entry: %v", files)
	}
}

// A one-shot caller must learn that a Result is still waiting in the outbox.
func TestOnceReportsAResultThatCouldNotBeSent(t *testing.T) {
	e := newEnv(t)
	e.f.sendErrs = []error{ErrTransport}
	e.job(nil)
	if _, err := e.r.Once(context.Background()); !errors.Is(err, ErrTransport) {
		t.Fatalf("Once hid a failed result send: %v", err)
	}
	if len(e.outboxFiles()) != 1 {
		t.Fatalf("the unsent result must stay in the outbox: %v", e.outboxFiles())
	}
}

type crashJournal struct{}

func (crashJournal) Claim(string, time.Time, time.Time) error { panic("crash") }

// A crash after the job is recorded but before the replay journal claims it
// must not strand the job: the next run reports it.
func TestCrashBeforeTheClaimIsReportedAfterRestart(t *testing.T) {
	e := newEnv(t)
	j := e.job(nil)
	e.r.Journal = crashJournal{}
	func() {
		defer func() { _ = recover() }()
		_, _ = e.r.Once(context.Background())
	}()
	if len(e.outboxFiles()) != 1 || e.f.fetches != 0 {
		t.Fatalf("the job must be on disk before the claim: files=%v fetches=%d", e.outboxFiles(), e.f.fetches)
	}
	e.r.Journal = runnerproto.NewMemJournal()
	if err := e.r.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r, ok := e.f.results[j.JobID]; !ok || r.OK || r.ErrorClass != runnerproto.ErrClassInternal {
		t.Fatalf("the interrupted job was not reported: %+v ok=%v", r, ok)
	}
}

// A value that does not match the job's fingerprint is never written.
func TestWrongValueNeverWritten(t *testing.T) {
	e := newEnv(t)
	e.f.valueFor = func(runnerproto.Job) (secret.Value, fingerprint.Key) {
		k, _ := fingerprint.NewKey("store1", rawKey(e.key))
		return secret.New([]byte(e.c.Value(2))), k
	}
	j := e.job(nil)
	// SealRunnerMaterial itself refuses a mismatching builtin value, so seal
	// the other value by hand under the job's info strings.
	e.f.fetchErr = nil
	e.r.Transport = &forged{fake: e.f, env: e, wrong: e.c.Value(2)}
	e.once()
	if e.targetExists() {
		t.Fatal("a value that fails the fingerprint check was written")
	}
	if r := e.f.results[j.JobID]; r.ErrorClass != runnerproto.ErrClassFingerprintMismatch {
		t.Fatalf("result: %+v", r)
	}
}

// An empty value is a valid delivery, so a substitute that is empty must
// still fail the fingerprint check.
func TestEmptySubstituteNeverWritten(t *testing.T) {
	e := newEnv(t)
	j := e.job(nil)
	e.r.Transport = &forged{fake: e.f, env: e, wrong: ""}
	e.once()
	if e.targetExists() {
		t.Fatal("an empty substitute was written")
	}
	if r := e.f.results[j.JobID]; r.ErrorClass != runnerproto.ErrClassFingerprintMismatch {
		t.Fatalf("result: %+v", r)
	}
}

func TestFetchFailureIsNeverRetried(t *testing.T) {
	e := newEnv(t)
	e.f.fetchErr = ErrTransport
	j := e.job(nil)
	e.once()
	_ = e.r.flush(context.Background())
	if e.f.fetches != 1 || e.targetExists() {
		t.Fatalf("fetches=%d target=%v", e.f.fetches, e.targetExists())
	}
	if r := e.f.results[j.JobID]; r.ErrorClass != runnerproto.ErrClassValueUnavailable {
		t.Fatalf("result: %+v", r)
	}
}

// A lost acknowledgement repeats only the sending: one fetch, one write.
func TestNetworkFailureRepeatsOnlyTheResult(t *testing.T) {
	e := newEnv(t)
	e.f.sendErrs = []error{ErrTransport, ErrTransport}
	j := e.job(nil)
	e.once()
	if len(e.f.results) != 0 || len(e.outboxFiles()) != 1 {
		t.Fatalf("result must stay in the outbox: results=%d files=%v", len(e.f.results), e.outboxFiles())
	}
	if err := e.r.flush(context.Background()); err == nil {
		t.Fatal("second failure must be reported")
	}
	if err := e.r.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !e.f.results[j.JobID].OK || e.f.fetches != 1 || len(e.outboxFiles()) != 0 {
		t.Fatalf("fetches=%d results=%+v files=%v", e.f.fetches, e.f.results, e.outboxFiles())
	}
	st, _ := os.ReadFile(e.target)
	if bytes.Count(st, []byte("STRIPE_KEY")) != 1 {
		t.Fatalf("target written more than once: %q", len(st))
	}
}

// After a restart the outbox is sent before the first poll; a job left
// "started" is reported as interrupted, not run again.
func TestRestartSendsOutboxBeforePoll(t *testing.T) {
	e := newEnv(t)
	closedID := newID(t)
	startedID := newID(t)
	if err := e.r.Outbox.Close(closedID, runnerproto.Result{ErrorClass: runnerproto.ErrClassPolicyDenied}); err != nil {
		t.Fatal(err)
	}
	if err := e.r.Outbox.Begin(startedID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.f.onPoll = cancel
	if err := e.r.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if e.f.calls[0] != "send" || e.f.calls[1] != "send" || e.f.calls[2] != "poll" {
		t.Fatalf("calls: %v", e.f.calls)
	}
	if e.f.results[closedID].ErrorClass != runnerproto.ErrClassPolicyDenied || e.f.results[startedID].ErrorClass != runnerproto.ErrClassInternal {
		t.Fatalf("results: %+v", e.f.results)
	}
	if e.f.fetches != 0 {
		t.Fatal("restart fetched a value")
	}
}

func TestServerRefusalDropsTheEntry(t *testing.T) {
	e := newEnv(t)
	e.f.sendErrs = []error{ErrRefused}
	e.job(nil)
	e.once()
	if len(e.outboxFiles()) != 0 {
		t.Fatal("a refused result must not be retried forever")
	}
}

func TestRunBacksOffOnPollFailure(t *testing.T) {
	e := newEnv(t)
	var slept []time.Duration
	e.r.Sleep = func(_ context.Context, d time.Duration) { slept = append(slept, d) }
	ctx, cancel := context.WithCancel(context.Background())
	polls := 0
	e.r.Transport = pollFail{fake: e.f, n: &polls, stop: func() {
		if polls >= 4 {
			cancel()
		}
	}}
	_ = e.r.Run(ctx)
	if len(slept) < 3 || slept[0] != time.Second || slept[1] != 2*time.Second || slept[2] != 4*time.Second {
		t.Fatalf("backoff: %v", slept)
	}
}

type pollFail struct {
	*fake
	n    *int
	stop func()
}

func (p pollFail) NextJob(context.Context) (*runnerproto.SignedJob, error) {
	*p.n++
	p.stop()
	return nil, ErrTransport
}

// forged serves an envelope whose value is not the one the job fixes.
type forged struct {
	*fake
	env   *env
	wrong string
}

func (f *forged) FetchValue(_ context.Context, id string) (runnerproto.ValueEnvelope, error) {
	f.fetches++
	j := lastJob[id]
	good, err := builtin.SealRunnerMaterial(j, f.recipient, secret.New([]byte(f.env.value)), f.env.key)
	if err != nil {
		return good, err
	}
	// A hostile server seals other bytes under the job's real info string.
	good.Sealed = sealTest(f.env.t, f.recipient, runnerproto.Info(j), []byte(f.wrong))
	return good, nil
}

func sealTest(t *testing.T, recipient, info, plain []byte) []byte {
	t.Helper()
	pub, err := hpke.KEM(runnerproto.HPKEKEM).Scheme().UnmarshalBinaryPublicKey(recipient)
	if err != nil {
		t.Fatal(err)
	}
	suite := hpke.NewSuite(hpke.KEM(runnerproto.HPKEKEM), hpke.KDF(runnerproto.HPKEKDF), hpke.AEAD(runnerproto.HPKEAEAD))
	sender, err := suite.NewSender(pub, info)
	if err != nil {
		t.Fatal(err)
	}
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := sealer.Seal(plain, nil)
	if err != nil {
		t.Fatal(err)
	}
	return append(enc, ct...)
}

func newID(t *testing.T) string {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return id.String()
}

var _ = errors.Is

// The job is on disk as "started" before its value is requested, so a crash
// after the fetch is reported on restart instead of vanishing.
func TestJobIsRecordedStartedBeforeTheValueIsRequested(t *testing.T) {
	e := newEnv(t)
	j := e.job(nil)
	var seen []Pending
	e.f.onFetch = func() { seen, _ = e.r.Outbox.List() }
	e.once()
	if len(seen) != 1 || seen[0].JobID != j.JobID || seen[0].Closed {
		t.Fatalf("outbox at fetch time: %+v", seen)
	}
}

// The same signed job served again after its window must not replace the
// Result of the run that executed it (the Result was not yet acknowledged).
func TestLateReservedJobKeepsTheRealResult(t *testing.T) {
	e := newEnv(t)
	e.f.sendErrs = []error{ErrTransport}
	j := e.job(nil)
	again := e.f.jobs[0]
	e.once()
	e.f.jobs = append(e.f.jobs, again)
	e.r.Now = func() time.Time { return t0.Add(time.Hour) }
	e.f.sendErrs = []error{ErrTransport}
	e.once()
	e.f.sendErrs = nil
	if err := e.r.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r := e.f.results[j.JobID]; !r.OK {
		t.Fatalf("the executed job's result was replaced: %+v", r)
	}
}

// The branch where the value is opened but must not be written leaks nothing
// either, and neither the fingerprint key nor the delivery key reaches a
// surface.
func TestMismatchBranchLeaksNothing(t *testing.T) {
	e := newEnv(t)
	wrong := e.c.Value(2)
	e.r.Transport = &forged{fake: e.f, env: e, wrong: wrong}
	e.f.sendErrs = []error{ErrTransport}
	e.job(nil)
	e.once()
	var surfaces []string
	surfaces = append(surfaces, e.logbuf.String())
	for _, n := range e.outboxFiles() {
		b, _ := os.ReadFile(filepath.Join(e.dir, "outbox", n)) //nolint:gosec // G304: test-owned temp dir
		surfaces = append(surfaces, string(b))
	}
	if len(surfaces) < 2 {
		t.Fatal("test setup: no outbox entry to inspect")
	}
	// Keys are binary: also look for the encodings a careless log line uses.
	keyForms := func(b []byte) []string {
		return []string{string(b), hex.EncodeToString(b), base64.StdEncoding.EncodeToString(b), base64.RawURLEncoding.EncodeToString(b), fmt.Sprintf("%v", b)}
	}
	for name, raw := range map[string][]byte{"fingerprint key": rawKey(e.key), "delivery key": e.r.Delivery.Bytes()} {
		for _, form := range keyForms(raw) {
			for _, s := range surfaces {
				if strings.Contains(s, form) {
					t.Fatalf("%s reached an outward surface", name)
				}
			}
		}
		// Positive control: the detector sees every form it looks for.
		if !strings.Contains(strings.Join(keyForms(raw), "|"), hex.EncodeToString(raw)) {
			t.Fatal("detector blind to key encodings")
		}
	}
	for name, probe := range map[string]canary.Canary{
		"value":      canary.Of(wrong),
		"real value": canary.Of(e.value),
	} {
		for _, s := range surfaces {
			if probe.In(s) {
				t.Fatalf("%s reached an outward surface", name)
			}
		}
	}
}

// When the outcome of a job cannot be put on disk, the loop must say so and
// stop; it must not poll on and run jobs it cannot report. The outbox
// directory is removed under the runner, which also fails for root.
func TestUnrecordableOutcomeStopsTheLoop(t *testing.T) {
	e := newEnv(t)
	e.job(nil)
	dir := filepath.Join(e.dir, "outbox")
	e.f.onFetch = func() { _ = os.RemoveAll(dir) }
	if _, err := e.r.Once(context.Background()); !errors.Is(err, ErrOutbox) {
		t.Fatalf("a Result that could not be recorded was reported as success: %v", err)
	}
	if e.f.sends != 0 {
		t.Fatalf("nothing may be sent for an unrecorded job: %d", e.f.sends)
	}

	e2 := newEnv(t)
	e2.job(nil)
	e2.job(nil)
	dir2 := filepath.Join(e2.dir, "outbox")
	e2.f.onFetch = func() { _ = os.RemoveAll(dir2) }
	// A runner that wrongly goes on would loop forever; bound it.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	e2.r.Sleep = func(context.Context, time.Duration) {}
	if err := e2.r.Run(ctx); !errors.Is(err, ErrOutbox) {
		t.Fatalf("Run went on after an unrecordable outcome: %v", err)
	}
	if e2.f.fetches != 1 {
		t.Fatalf("Run ran another job it could not report: fetches=%d", e2.f.fetches)
	}
}

// ---- exec_with_secret ----

// noIso runs the child as is: these tests are about the loop's ordering and
// what leaves the host, not about the namespace (execrun's own tests).
type noIso struct{ off bool }

func (n noIso) Enforces(execpolicy.NetMode) bool { return !n.off }
func (noIso) Prepare(execpolicy.NetMode, []execrun.Pin) ([]string, func(), error) {
	return []string{"/usr/bin/env"}, func() {}, nil
}

// withExec adds an exec template whose binary is a script with the given body.
func (e *env) withExec(body string) (tpl execpolicy.Template) {
	e.t.Helper()
	bin := filepath.Join(e.dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil { //nolint:gosec // G301: test directory
		e.t.Fatal(err)
	}
	tool := filepath.Join(bin, "tool")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil { //nolint:gosec // G306: a test executable
		e.t.Fatal(err)
	}
	if err := os.Chmod(tool, 0o755); err != nil { //nolint:gosec // G302: a test executable
		e.t.Fatal(err)
	}
	e.policy.AllowExec = true
	e.policy.ExecNetUnenforced = true
	e.policy.ExecBinDirs = []string{bin}
	e.policy.ExecTemplates = []runnerproto.ExecTemplate{{
		ID: "tool-run", Argv: []string{tool, "--name", "{name}"},
		Params:    map[string]runnerproto.ExecParam{"name": {Pattern: `^[a-z0-9]{1,32}$`}},
		SecretEnv: []string{"TOOL_KEY"}, Network: runnerproto.ExecNetwork{Mode: "none"},
	}}
	if err := e.policy.Validate(); err != nil {
		e.t.Fatal(err)
	}
	e.r.Policy = e.policy
	e.r.Limiter = runnerproto.NewLimiter(e.policy)
	home := filepath.Join(e.dir, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		e.t.Fatal(err)
	}
	e.r.Exec = &execrun.Deps{Iso: noIso{}, HomeRoot: home, ChildUID: 65534, ChildGID: 65534, Chown: func(string, int, int) error { return nil },
		CorePiped: func() bool { return false }}
	tpl, err := e.policy.ExecTemplates[0].Template()
	if err != nil {
		e.t.Fatal(err)
	}
	return tpl
}

func (e *env) execJob(tpl execpolicy.Template, mod func(*runnerproto.Job)) runnerproto.Job {
	return e.job(func(j *runnerproto.Job) {
		j.Action = runnerproto.ActionExec
		j.Target = runnerproto.Target{}
		j.Exec = &runnerproto.Exec{TemplateID: "tool-run", Digest: execpolicy.Digest(tpl), Params: map[string]string{"name": "alpha"}}
		if mod != nil {
			mod(j)
		}
	})
}

func TestExecJobRunsAndReportsOnlyTheClosedResult(t *testing.T) {
	e := newEnv(t)
	tpl := e.withExec(`printf '%s' "$TOOL_KEY" | base64; echo "$TOOL_KEY" >&2`)
	var sunk execrun.Outcome
	e.r.ExecSink = func(_ string, o execrun.Outcome) { sunk = o }
	j := e.execJob(tpl, nil)
	e.once()
	res := e.f.results[j.JobID]
	if !res.OK || res.Fingerprint == "" || res.Version != "7" {
		t.Fatalf("result = %+v", res)
	}
	if e.c.In(sunk.Stdout) || e.c.In(sunk.Stderr) || !strings.Contains(sunk.Stdout, "[REDACTED]") {
		t.Fatalf("host output not scrubbed: %q / %q", sunk.Stdout, sunk.Stderr)
	}
	b, _ := json.Marshal(res)
	if e.c.In(string(b)) || e.c.In(e.logbuf.String()) {
		t.Fatal("value in the result or the log")
	}
	if !strings.Contains(e.logbuf.String(), `"exec.run"`) {
		t.Fatalf("no exec.run event: %s", e.logbuf.String())
	}
}

func TestExecNonZeroExitIsInternalAndExitCodeStaysOnTheHost(t *testing.T) {
	e := newEnv(t)
	tpl := e.withExec(`exit 9`)
	var sunk execrun.Outcome
	e.r.ExecSink = func(_ string, o execrun.Outcome) { sunk = o }
	j := e.execJob(tpl, nil)
	e.once()
	if res := e.f.results[j.JobID]; res.OK || res.ErrorClass != runnerproto.ErrClassInternal {
		t.Fatalf("result = %+v", res)
	}
	if sunk.ExitCode != 9 {
		t.Fatalf("host did not see the exit code: %+v", sunk)
	}
}

// Every refusal is policy_denied and happens before the value is fetched.
func TestExecRefusalsAreOneClassAndBeforeFetch(t *testing.T) {
	for name, mod := range map[string]func(e *env, j *runnerproto.Job){
		"unknown-template": func(e *env, j *runnerproto.Job) { j.Exec.TemplateID = "other" },
		"digest-differs":   func(e *env, j *runnerproto.Job) { j.Exec.Digest = strings.Repeat("0", 64) },
		"extra-param":      func(e *env, j *runnerproto.Job) { j.Exec.Params["x"] = "y" },
		"no-exec-deps":     func(e *env, j *runnerproto.Job) { e.r.Exec = nil },
		"option-param":     func(e *env, j *runnerproto.Job) { j.Exec.Params["name"] = "--upload-file=/etc/passwd" },
	} {
		e := newEnv(t)
		tpl := e.withExec(`exit 0`)
		j := e.execJob(tpl, func(j *runnerproto.Job) { mod(e, j) })
		e.once()
		if e.f.fetches != 0 || e.f.results[j.JobID].ErrorClass != runnerproto.ErrClassPolicyDenied {
			t.Errorf("%s: fetches=%d result=%+v", name, e.f.fetches, e.f.results[j.JobID])
		}
	}
}

func TestExecWrongValueNeverRuns(t *testing.T) {
	e := newEnv(t)
	marker := filepath.Join(e.dir, "ran")
	tpl := e.withExec(`touch ` + marker)
	j := e.execJob(tpl, nil)
	e.r.Transport = &forged{fake: e.f, env: e, wrong: e.c.Value(2)}
	e.once()
	if res := e.f.results[j.JobID]; res.OK || res.ErrorClass != runnerproto.ErrClassFingerprintMismatch {
		t.Fatalf("result = %+v", res)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the child ran with a value whose fingerprint did not match")
	}
}

// A host that cannot cut the child off the network refuses the template, and
// the child never starts.
func TestExecHostWithoutIsolationRefuses(t *testing.T) {
	e := newEnv(t)
	marker := filepath.Join(e.dir, "ran")
	tpl := e.withExec(`touch ` + marker)
	e.policy.ExecNetUnenforced = false
	e.r.Policy = e.policy
	e.r.Exec.Iso = noIso{off: true}
	j := e.execJob(tpl, nil)
	e.once()
	if res := e.f.results[j.JobID]; res.OK || res.ErrorClass != runnerproto.ErrClassPolicyDenied {
		t.Fatalf("result = %+v", res)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the child ran on a host that cannot isolate it")
	}
}
