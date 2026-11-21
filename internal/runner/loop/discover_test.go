package loop

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// scanRoot is a private directory under the user's home: the scanner refuses
// a root whose ancestors another user can write, and the system temp
// directory can be one.
func scanRoot(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal("home unavailable")
	}
	root, err := os.MkdirTemp(home, ".keep-loop-discover-")
	if err != nil {
		t.Fatal("create scan root")
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal("resolve scan root")
	}
	return root
}

// discoverEnv is an env whose host policy has a discovery section over root.
func discoverEnv(t *testing.T, root string, perHour int) *env {
	t.Helper()
	e := newEnv(t)
	e.policy.Discovery = &runnerproto.DiscoveryPolicy{
		MaxPerHour: perHour,
		Roots: []runnerproto.DiscoveryRoot{{
			Root: root, TrustedUIDs: []int64{0, int64(os.Geteuid())}, MaxBytes: 1 << 16, MaxFiles: 16,
			Rules: []runnerproto.DiscoveryRule{{Glob: "*.env", Kind: "env-file", Names: []string{"STRIPE_KEY", "OTHER_KEY"}}},
		}},
	}
	if err := e.policy.Validate(); err != nil {
		t.Fatalf("policy: %v", err)
	}
	e.r.Policy = e.policy
	e.r.Discover = runnerproto.NewDiscoverLimiter(e.policy)
	return e
}

// discoverJob queues a signed discover job: a store and nothing else.
func (e *env) discoverJob() runnerproto.Job {
	e.t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		e.t.Fatal(err)
	}
	j := runnerproto.Job{
		JobID: id.String(), OrgID: "acme", RunnerID: "runner-1",
		Secret: runnerproto.SecretRef{StoreID: "store-1", Provider: runnerproto.ProviderBuiltin},
		Action: runnerproto.ActionDiscover, IssuedAt: t0, NotAfter: t0.Add(5 * time.Minute),
		Nonce: bytes.Repeat([]byte{9}, runnerproto.NonceSize),
	}
	lastJob[j.JobID] = j
	sj, err := e.signer.Sign(j)
	if err != nil {
		e.t.Fatal(err)
	}
	e.f.jobs = append(e.f.jobs, sj)
	return j
}

func write(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil { //nolint:gosec // G306: test fixture, mode is the point
		t.Fatal("write fixture")
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal("chmod fixture")
	}
}

// The canary must not reach the report, the outbox, the log or any file the
// loop writes (leak test, written before the loop learned to scan). Positive
// control: the value is in the scanned file and the detector sees it there.
func TestDiscoverReportsFingerprintAndLengthNeverTheValue(t *testing.T) {
	root := scanRoot(t)
	e := discoverEnv(t, root, 5)
	write(t, filepath.Join(root, "app.env"), "STRIPE_KEY="+e.value+"\n", 0o600)
	e.f.sendErrs = []error{ErrTransport} // keep the closed entry on disk to inspect it
	j := e.discoverJob()
	e.once()
	want, err := fingerprint.Compute(e.key, secret.New([]byte(e.value)))
	if err != nil {
		t.Fatal(err)
	}
	var surfaces []string
	surfaces = append(surfaces, e.logbuf.String())
	var entry string
	for _, n := range e.outboxFiles() {
		raw, _ := os.ReadFile(filepath.Join(e.dir, "outbox", n)) //nolint:gosec // G304: test-owned temp dir
		surfaces = append(surfaces, string(raw))
		entry += string(raw)
	}
	// Positive control: the closed entry is on disk and carries the report.
	if !strings.Contains(entry, want) || !strings.Contains(entry, `"kind":"discover"`) {
		t.Fatalf("test setup: no closed discover entry to inspect: %q", entry)
	}
	if err := e.r.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	res, ok := e.f.discovers[j.JobID]
	if !ok || !res.OK || len(res.Findings) != 1 {
		t.Fatalf("report: %+v", res)
	}
	f := res.Findings[0]
	if f.Path != filepath.Join(root, "app.env") || f.Name != "STRIPE_KEY" || f.Fingerprint != want || f.Len != len(e.value) {
		t.Fatalf("finding: %+v", f)
	}
	b, _ := json.Marshal(res)
	surfaces = append(surfaces, string(b), e.logbuf.String())
	for _, probe := range []canary.Canary{canary.Of(e.value), canary.Of(string(rawKey(e.key)))} {
		for _, s := range surfaces {
			if probe.In(s) {
				t.Fatalf("value or key reached an outward surface: %q", s[:min(len(s), 40)])
			}
		}
	}
	if got, _ := os.ReadFile(filepath.Join(root, "app.env")); !canary.Of(e.value).In(string(got)) { //nolint:gosec // G304: test-owned temp dir
		t.Fatal("leak detector does not see the value in the scanned file")
	}
	if len(e.outboxFiles()) != 0 {
		t.Fatalf("acknowledged report left in the outbox: %v", e.outboxFiles())
	}
}

func TestDiscoverIsRefusedWithoutAPolicySection(t *testing.T) {
	e := newEnv(t) // no discovery section
	j := e.discoverJob()
	e.once()
	if e.f.fetches != 0 {
		t.Fatal("the fingerprint key was requested for a host that does not allow discovery")
	}
	if res := e.f.discovers[j.JobID]; res.OK || res.ErrorClass != runnerproto.ErrClassPolicyDenied || len(res.Findings) != 0 {
		t.Fatalf("report: %+v", res)
	}
}

func TestDiscoverRateLimitStopsBeforeTheKeyIsFetched(t *testing.T) {
	root := scanRoot(t)
	e := discoverEnv(t, root, 1)
	e.discoverJob()
	second := e.discoverJob()
	e.once()
	fetches := e.f.fetches
	e.once()
	if e.f.fetches != fetches {
		t.Fatal("the second scan fetched a key although the hourly cap was spent")
	}
	if res := e.f.discovers[second.JobID]; res.OK || res.ErrorClass != runnerproto.ErrClassRateLimited {
		t.Fatalf("report: %+v", res)
	}
}

// One unsafe file fails the whole scan with the one outward class and no
// findings, and the readable file next to it is not reported either.
func TestDiscoverFailureHasNoFindingsAndOneClass(t *testing.T) {
	root := scanRoot(t)
	e := discoverEnv(t, root, 5)
	write(t, filepath.Join(root, "good.env"), "STRIPE_KEY="+e.value+"\n", 0o600)
	write(t, filepath.Join(root, "bad.env"), "OTHER_KEY=x\n", 0o666)
	j := e.discoverJob()
	e.once()
	res := e.f.discovers[j.JobID]
	if res.OK || res.ErrorClass != runnerproto.ErrClassDiscoveryFailed || len(res.Findings) != 0 {
		t.Fatalf("report: %+v", res)
	}
}

// A bare line without "=" is not a carrier: no finding and no failure that
// would tell the server a file has a particular shape.
func TestDiscoverBareLineYieldsNoFinding(t *testing.T) {
	root := scanRoot(t)
	e := discoverEnv(t, root, 5)
	write(t, filepath.Join(root, "bare.env"), "STRIPE_KEY\n", 0o600)
	j := e.discoverJob()
	e.once()
	res := e.f.discovers[j.JobID]
	// The file is not a literal NAME=value carrier, so the scan fails closed
	// in the one outward class; it never yields a finding for it.
	if res.OK || res.ErrorClass != runnerproto.ErrClassDiscoveryFailed || len(res.Findings) != 0 {
		t.Fatalf("a bare line: %+v", res)
	}
}

func TestDiscoverCrashLeavesAFailedDiscoverReport(t *testing.T) {
	root := scanRoot(t)
	e := discoverEnv(t, root, 5)
	id := "01890000-0000-7000-8000-000000000001"
	if err := e.r.Outbox.BeginDiscover(id); err != nil {
		t.Fatal(err)
	}
	if err := e.r.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	res, ok := e.f.discovers[id]
	if !ok || res.OK || res.ErrorClass != runnerproto.ErrClassInternal || len(res.Findings) != 0 {
		t.Fatalf("report: %+v", res)
	}
	if _, wrong := e.f.results[id]; wrong {
		t.Fatal("an interrupted discover job was reported as a deploy Result")
	}
}

func TestHostPolicyRefusesAnAgentUIDAsTrusted(t *testing.T) {
	e := discoverEnv(t, scanRoot(t), 5)
	p := e.policy
	d := *p.Discovery
	d.Roots = append([]runnerproto.DiscoveryRoot(nil), d.Roots...)
	d.Roots[0].TrustedUIDs = []int64{p.AgentUIDs[0]}
	p.Discovery = &d
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "agent uid") {
		t.Fatalf("an agent uid was accepted as a trusted owner: %v", err)
	}
}

// While the scan runs the job's outbox entry is already a discover entry, so a
// crash at that point is reported as a discover failure and not as a deploy.
func TestDiscoverEntryIsBegunAsDiscover(t *testing.T) {
	root := scanRoot(t)
	e := discoverEnv(t, root, 5)
	var started []Pending
	e.f.onFetch = func() { started, _ = e.r.Outbox.List() }
	e.discoverJob()
	e.once()
	if len(started) != 1 || started[0].Closed || !started[0].IsDiscover {
		t.Fatalf("entry during the scan: %+v", started)
	}
}

// A discover job that fails the runner's own checks after the signature held
// is rejected with a discover report, not a deploy Result.
func TestRejectedDiscoverJobGetsADiscoverReport(t *testing.T) {
	root := scanRoot(t)
	e := discoverEnv(t, root, 5)
	e.r.Me = runnerproto.Identity{OrgID: "acme", RunnerID: "someone-else"}
	j := e.discoverJob()
	e.once()
	if res, ok := e.f.discovers[j.JobID]; !ok || res.OK || len(res.Findings) != 0 {
		t.Fatalf("report: %+v (%v)", res, ok)
	}
	if _, wrong := e.f.results[j.JobID]; wrong {
		t.Fatal("a rejected discover job was reported as a deploy Result")
	}
}

// A key the runner cannot fetch is an internal failure with no findings, and
// nothing is scanned.
func TestDiscoverKeyFetchFailureIsInternalAndEmpty(t *testing.T) {
	root := scanRoot(t)
	e := discoverEnv(t, root, 5)
	write(t, filepath.Join(root, "a.env"), "STRIPE_KEY="+e.value+"\n", 0o600)
	e.f.fetchErr = ErrTransport
	j := e.discoverJob()
	e.once()
	res := e.f.discovers[j.JobID]
	if res.OK || res.ErrorClass != runnerproto.ErrClassInternal || len(res.Findings) != 0 {
		t.Fatalf("report: %+v", res)
	}
}

// Findings from every root are reported, each under its own absolute path.
func TestDiscoverReportsEveryRoot(t *testing.T) {
	root1, root2 := scanRoot(t), scanRoot(t)
	e := discoverEnv(t, root1, 5)
	e.policy.Discovery.Roots = append(e.policy.Discovery.Roots, runnerproto.DiscoveryRoot{
		Root: root2, TrustedUIDs: []int64{0, int64(os.Geteuid())}, MaxBytes: 1 << 16, MaxFiles: 16,
		Rules: []runnerproto.DiscoveryRule{{Glob: "*.env", Kind: "env-file", Names: []string{"STRIPE_KEY"}}},
	})
	if err := e.policy.Validate(); err != nil {
		t.Fatalf("policy: %v", err)
	}
	e.r.Policy = e.policy
	write(t, filepath.Join(root1, "a.env"), "STRIPE_KEY="+e.value+"\n", 0o600)
	write(t, filepath.Join(root2, "b.env"), "STRIPE_KEY="+e.value+"\n", 0o600)
	j := e.discoverJob()
	e.once()
	res := e.f.discovers[j.JobID]
	if !res.OK || len(res.Findings) != 2 {
		t.Fatalf("report: %+v", res)
	}
	got := map[string]bool{res.Findings[0].Path: true, res.Findings[1].Path: true}
	if !got[filepath.Join(root1, "a.env")] || !got[filepath.Join(root2, "b.env")] {
		t.Fatalf("paths: %+v", res.Findings)
	}
}

// A late re-served discover job is rejected, and the rejection must not
// replace the report of the run that did the scan.
func TestLateReservedDiscoverJobKeepsTheRealReport(t *testing.T) {
	root := scanRoot(t)
	e := discoverEnv(t, root, 5)
	write(t, filepath.Join(root, "a.env"), "STRIPE_KEY="+e.value+"\n", 0o600)
	e.f.sendErrs = []error{ErrTransport}
	j := e.discoverJob()
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
	if r := e.f.discovers[j.JobID]; !r.OK || len(r.Findings) != 1 {
		t.Fatalf("the scanning run's report was replaced: %+v", r)
	}
}
