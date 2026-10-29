package health

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

// fakeRunner is a scripted runner: call n gets argvs[n] recorded and
// results[n] returned, so tests drive restart/status sequences
// deterministically without a real launchd or systemd.
type fakeRunner struct {
	results [][]byte
	errs    []error
	argvs   [][]string
	n       int
}

func (f *fakeRunner) Run(_ context.Context, argv []string) ([]byte, error) {
	f.argvs = append(f.argvs, argv)
	i := f.n
	f.n++
	var out []byte
	var err error
	if i < len(f.results) {
		out = f.results[i]
	}
	if i < len(f.errs) {
		err = f.errs[i]
	}
	return out, err
}

// withDefaultRunner swaps defaultRunner for r for the duration of the
// caller's test, restoring it on cleanup — the injection point Run itself
// uses, since Run no longer takes a runner parameter.
func withDefaultRunner(t *testing.T, r runner) {
	t.Helper()
	orig := defaultRunner
	defaultRunner = r
	t.Cleanup(func() { defaultRunner = orig })
}

func TestRestartArgv(t *testing.T) {
	cases := []struct {
		consumer string
		uid      int64
		want     []string
	}{
		{"launchd:com.entire.svc", 501, []string{"/bin/launchctl", "kickstart", "-k", "user/501/com.entire.svc"}},
		{"systemd:svc.service", 0, []string{"/usr/bin/systemctl", "restart", "svc.service"}},
	}
	for _, c := range cases {
		got, err := restartArgv(c.consumer, c.uid)
		if err != nil {
			t.Fatalf("restartArgv(%q): %v", c.consumer, err)
		}
		if len(got) != len(c.want) {
			t.Fatalf("restartArgv(%q) = %v, want %v", c.consumer, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("restartArgv(%q) = %v, want %v", c.consumer, got, c.want)
			}
		}
	}
}

func TestSplitConsumerRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"", "launchd", "launchd:", "ssh:host"} {
		if _, _, err := splitConsumer(bad); err == nil {
			t.Fatalf("splitConsumer(%q): want error, got nil", bad)
		}
	}
}

// TestUnitActiveDetectsCrashAfterSettle is red-run case 3:
// the consumer restarts, then crashes within the settle window — is-active
// must observe it as no longer active and the check reports failed.
func TestUnitActiveDetectsCrashAfterSettle(t *testing.T) {
	r := &fakeRunner{
		results: [][]byte{nil, []byte("inactive\n")},
		errs:    []error{nil, errors.New("exit status 3")}, // systemctl restart ok, is-active reports crashed
	}
	if err := restart(context.Background(), r, "systemd:crasher.service", 0); err != nil {
		t.Fatalf("restart: %v", err)
	}
	ok, err := runUnitActive(context.Background(), r, "systemd:crasher.service", 0, time.Millisecond)
	if err != nil {
		t.Fatalf("runUnitActive: unexpected error %v", err)
	}
	if ok {
		t.Fatalf("runUnitActive: got active=true for a crashed consumer, want false")
	}
}

// TestUnitActiveLaunchdListErrorAfterSettle is the launchd counterpart of
// TestUnitActiveDetectsCrashAfterSettle — redrun-checker's Gap 2. After a
// successful restart, `launchctl list` erroring (job unloaded or crashed
// out — list has no output to read a state word from in that case, only a
// non-zero exit) must report inactive, not be mistaken for "couldn't tell".
func TestUnitActiveLaunchdListErrorAfterSettle(t *testing.T) {
	r := &fakeRunner{
		results: [][]byte{nil, nil},
		errs:    []error{nil, errors.New(`Could not find service "com.entire.crasher" in domain for uid 501`)},
	}
	if err := restart(context.Background(), r, "launchd:com.entire.crasher", 501); err != nil {
		t.Fatalf("restart: %v", err)
	}
	ok, err := runUnitActive(context.Background(), r, "launchd:com.entire.crasher", 501, time.Millisecond)
	if err != nil {
		t.Fatalf("runUnitActive: unexpected error %v", err)
	}
	if ok {
		t.Fatalf("runUnitActive: got active=true for a launchctl list error, want false")
	}
}

func TestUnitActiveReportsRunning(t *testing.T) {
	r := &fakeRunner{results: [][]byte{[]byte("active\n")}, errs: []error{nil}}
	ok, err := runUnitActive(context.Background(), r, "systemd:steady.service", 0, time.Millisecond)
	if err != nil {
		t.Fatalf("runUnitActive: %v", err)
	}
	if !ok {
		t.Fatalf("runUnitActive: got active=false for a running consumer, want true")
	}
}

// TestUnitActiveLaunchd exercises `launchctl list`, not `print`: print
// dumps a job's whole EnvironmentVariables block, a real leak surface for
// launchd-env secret targets (see isActive's doc comment) — list's plist
// carries only fixed, non-consumer-controlled keys, and a "PID" entry
// names the job running.
func TestUnitActiveLaunchd(t *testing.T) {
	r := &fakeRunner{results: [][]byte{[]byte("{\n\t\"PID\" = 4242;\n\t\"Label\" = \"com.entire.svc\";\n}\n")}, errs: []error{nil}}
	ok, err := runUnitActive(context.Background(), r, "launchd:com.entire.svc", 501, time.Millisecond)
	if err != nil {
		t.Fatalf("runUnitActive: %v", err)
	}
	if !ok {
		t.Fatalf("runUnitActive: want active=true, got false")
	}
	want := []string{"/bin/launchctl", "list", "com.entire.svc"}
	if len(r.argvs) != 1 || len(r.argvs[0]) != len(want) {
		t.Fatalf("expected a launchctl list call %v, got %v", want, r.argvs)
	}
	for i := range want {
		if r.argvs[0][i] != want[i] {
			t.Fatalf("expected a launchctl list call %v, got %v", want, r.argvs)
		}
	}
}

func TestUnitActiveLaunchdNotRunning(t *testing.T) {
	r := &fakeRunner{results: [][]byte{[]byte("{\n\t\"Label\" = \"com.entire.svc\";\n\t\"LastExitStatus\" = 0;\n}\n")}, errs: []error{nil}}
	ok, err := runUnitActive(context.Background(), r, "launchd:com.entire.svc", 501, time.Millisecond)
	if err != nil {
		t.Fatalf("runUnitActive: %v", err)
	}
	if ok {
		t.Fatalf("runUnitActive: want active=false for a stopped launchd job (no PID key), got true")
	}
}

// TestRestartNeverLeaksSubprocessOutput proves restart's failure path never
// echoes r.Run's own error text — a subprocess's stderr/error can carry
// argv or output content this package doesn't control, including,
// hypothetically, an echoed secret-shaped value from a misbehaving
// consumer's own launch wrapper.
func TestRestartNeverLeaksSubprocessOutput(t *testing.T) {
	c := canary.New()
	leaked := c.Value(1)
	r := &fakeRunner{errs: []error{errors.New("exit status 1: " + leaked)}}
	err := restart(context.Background(), r, "systemd:svc.service", 0)
	if err == nil {
		t.Fatalf("restart: want error, got nil")
	}
	if c.In(err.Error()) {
		t.Fatal("restart: canary leaked into error")
	}
}

// TestIsActiveNeverLeaksSubprocessOutput is isActive's own half of the same
// property: whatever launchctl/systemctl's own output or error text
// contains never surfaces in isActive's returned error.
func TestIsActiveNeverLeaksSubprocessOutput(t *testing.T) {
	c := canary.New()
	leaked := c.Value(1)
	for _, consumer := range []string{"launchd:missing", "systemd:svc.service"} {
		r := &fakeRunner{errs: []error{errors.New(leaked)}}
		_, err := isActive(context.Background(), r, consumer, 501)
		if err != nil && c.In(err.Error()) {
			t.Fatalf("isActive(%s): canary leaked into error", consumer)
		}
	}
}

// TestRunHTTPRequiresMarker is red-run case 2: a 200 response
// without the required body marker must not be treated as healthy — "200
// proves nothing" (fleet rule).
func TestRunHTTPRequiresMarker(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok but no marker here"))
	}))
	defer srv.Close()

	h := runnerproto.HealthCheck{
		Kind: runnerproto.HealthKindHTTP, URL: srv.URL, ExpectStatus: 200,
		BodyMarker: "ready-marker", TimeoutSeconds: 2,
	}
	ok, err := runHTTP(context.Background(), srv.Client(), h)
	if err != nil {
		t.Fatalf("runHTTP: unexpected error %v", err)
	}
	if ok {
		t.Fatalf("runHTTP: got ok=true for a 200 response missing the marker, want false")
	}
}

func TestRunHTTPOKWithMarker(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("status: ready-marker present"))
	}))
	defer srv.Close()

	h := runnerproto.HealthCheck{
		Kind: runnerproto.HealthKindHTTP, URL: srv.URL, ExpectStatus: 200,
		BodyMarker: "ready-marker", TimeoutSeconds: 2,
	}
	ok, err := runHTTP(context.Background(), srv.Client(), h)
	if err != nil {
		t.Fatalf("runHTTP: %v", err)
	}
	if !ok {
		t.Fatalf("runHTTP: got ok=false for a matching 200 response, want true")
	}
}

func TestRunHTTPWrongStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("ready-marker")) // marker present, but status is wrong
	}))
	defer srv.Close()

	h := runnerproto.HealthCheck{
		Kind: runnerproto.HealthKindHTTP, URL: srv.URL, ExpectStatus: 200,
		BodyMarker: "ready-marker", TimeoutSeconds: 2,
	}
	ok, err := runHTTP(context.Background(), srv.Client(), h)
	if err != nil {
		t.Fatalf("runHTTP: %v", err)
	}
	if ok {
		t.Fatalf("runHTTP: got ok=true for a wrong status code, want false")
	}
}

// TestHTTPClientForNeverFollowsRedirect proves a redirect response cannot
// carry a loopback-restricted check anywhere else: the default net/http
// client follows redirects transparently, which would let a compromised or
// misconfigured consumer point the check at a host HostPolicy.Validate
// never approved as loopback-only.
func TestHTTPClientForNeverFollowsRedirect(t *testing.T) {
	external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready-marker")) // would pass the check if ever reached
	}))
	defer external.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, external.URL, http.StatusFound)
	}))
	defer redirector.Close()

	h := runnerproto.HealthCheck{
		Kind: runnerproto.HealthKindHTTP, URL: redirector.URL, ExpectStatus: 200,
		BodyMarker: "ready-marker", TimeoutSeconds: 2,
	}
	ok, err := runHTTP(context.Background(), httpClientFor(h), h)
	if err != nil {
		t.Fatalf("runHTTP: unexpected error %v", err)
	}
	if ok {
		t.Fatalf("runHTTP: got ok=true after following a redirect off the checked host, want false (the 302 itself must be treated as the response)")
	}
}

// TestRunHTTPNeverLeaksBody is red-run case 4: whatever the
// probe's response body contains — including something canary-shaped — it
// must never surface in runHTTP's return values, only in the bool.
func TestRunHTTPNeverLeaksBody(t *testing.T) {
	c := canary.New()
	leaked := c.Value(1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot) // deliberately the "wrong" status, to also exercise that error path
		_, _ = w.Write([]byte(leaked))
	}))
	defer srv.Close()

	h := runnerproto.HealthCheck{
		Kind: runnerproto.HealthKindHTTP, URL: srv.URL, ExpectStatus: 200,
		BodyMarker: "ready-marker", TimeoutSeconds: 2,
	}
	ok, err := runHTTP(context.Background(), srv.Client(), h)
	if ok {
		t.Fatalf("runHTTP: unexpectedly ok=true")
	}
	if err != nil && c.In(err.Error()) {
		t.Fatal("runHTTP: canary leaked into error")
	}

	// And the same on the success/marker path, where the body is actually read.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(leaked))
	}))
	defer srv2.Close()
	h2 := runnerproto.HealthCheck{
		Kind: runnerproto.HealthKindHTTP, URL: srv2.URL, ExpectStatus: 200,
		BodyMarker: "not-present", TimeoutSeconds: 2,
	}
	ok2, err2 := runHTTP(context.Background(), srv2.Client(), h2)
	if ok2 {
		t.Fatalf("runHTTP: unexpectedly ok=true for a body without the marker")
	}
	if err2 != nil && c.In(err2.Error()) {
		t.Fatal("runHTTP: canary leaked into error")
	}
}

func TestRunSkippedWhenNoKind(t *testing.T) {
	withDefaultRunner(t, &fakeRunner{results: [][]byte{nil}, errs: []error{nil}})
	out := Run(context.Background(), runnerproto.Target{Consumer: "systemd:svc.service"}, runnerproto.HealthCheck{})
	if out.Status != runnerproto.HealthSkipped {
		t.Fatalf("Run: status = %q, want %q", out.Status, runnerproto.HealthSkipped)
	}
}

// TestRunFailedWhenRestartFails proves Run short-circuits to HealthFailed
// on a failed restart WITHOUT running the check at all: the http check
// below points at a server that would report ok=true if it ran, so a
// version of Run that skipped the restart-error guard and ran the check
// anyway would return HealthOK here instead of HealthFailed.
func TestRunFailedWhenRestartFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready-marker"))
	}))
	defer srv.Close()

	withDefaultRunner(t, &fakeRunner{errs: []error{errors.New("no such unit")}})
	h := runnerproto.HealthCheck{
		Kind: runnerproto.HealthKindHTTP, URL: srv.URL, ExpectStatus: 200,
		BodyMarker: "ready-marker", TimeoutSeconds: 2,
	}
	out := Run(context.Background(), runnerproto.Target{Consumer: "systemd:missing.service"}, h)
	if out.Status != runnerproto.HealthFailed {
		t.Fatalf("Run: status = %q, want %q (restart failure must short-circuit before the check runs)", out.Status, runnerproto.HealthFailed)
	}
}

// TestRunDispatchesUnitActive is redrun-checker's Gap 1, unit-active half:
// Run's own switch must actually reach runUnitActive and turn a healthy
// result into HealthOK with the right Kind — not just the restart
// short-circuit and skip paths the other Run tests already cover.
func TestRunDispatchesUnitActive(t *testing.T) {
	withDefaultRunner(t, &fakeRunner{
		results: [][]byte{nil, []byte("active\n")},
		errs:    []error{nil, nil},
	})
	h := runnerproto.HealthCheck{Kind: runnerproto.HealthKindUnitActive, SettleSeconds: 0}
	out := Run(context.Background(), runnerproto.Target{Consumer: "systemd:svc.service"}, h)
	if out.Status != runnerproto.HealthOK {
		t.Fatalf("Run: status = %q, want %q", out.Status, runnerproto.HealthOK)
	}
	if out.Kind != runnerproto.HealthKindUnitActive {
		t.Fatalf("Run: kind = %q, want %q", out.Kind, runnerproto.HealthKindUnitActive)
	}
}

// TestRunDispatchesHTTP is redrun-checker's Gap 1, http half: Run's switch
// must reach runHTTP (built from its own httpClientFor) and turn a matching
// response into HealthOK.
func TestRunDispatchesHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("status: ready-marker present"))
	}))
	defer srv.Close()

	withDefaultRunner(t, &fakeRunner{results: [][]byte{nil}, errs: []error{nil}})
	h := runnerproto.HealthCheck{
		Kind: runnerproto.HealthKindHTTP, URL: srv.URL, ExpectStatus: 200,
		BodyMarker: "ready-marker", TimeoutSeconds: 2,
	}
	out := Run(context.Background(), runnerproto.Target{Consumer: "systemd:svc.service"}, h)
	if out.Status != runnerproto.HealthOK {
		t.Fatalf("Run: status = %q, want %q", out.Status, runnerproto.HealthOK)
	}
	if out.Kind != runnerproto.HealthKindHTTP {
		t.Fatalf("Run: kind = %q, want %q", out.Kind, runnerproto.HealthKindHTTP)
	}
}

func TestRunUnitActiveCtxTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	r := &fakeRunner{}
	_, err := runUnitActive(ctx, r, "systemd:svc.service", 0, 5*time.Second)
	if err == nil {
		t.Fatalf("runUnitActive: want context deadline error, got nil")
	}
}

// TestEmitEventNeverLeaksBody is the journal/log half of red-run case 4: an
// Outcome built from a canary-shaped response — via the real Run/runHTTP
// path, not a hand-built Outcome — must never put the canary into the
// "deploy.healthcheck" journal event, through obs's own closed key
// allow-list.
func TestEmitEventNeverLeaksBody(t *testing.T) {
	c := canary.New()
	leaked := c.Value(1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(leaked))
	}))
	defer srv.Close()

	withDefaultRunner(t, &fakeRunner{results: [][]byte{nil}, errs: []error{nil}})
	h := runnerproto.HealthCheck{
		Kind: runnerproto.HealthKindHTTP, URL: srv.URL, ExpectStatus: 200,
		BodyMarker: "not-present", TimeoutSeconds: 2,
	}
	out := Run(context.Background(), runnerproto.Target{Consumer: "systemd:svc.service"}, h)
	if out.Status != runnerproto.HealthFailed {
		t.Fatalf("Run: status = %q, want %q", out.Status, runnerproto.HealthFailed)
	}

	var buf bytes.Buffer
	log := obs.New(&buf)
	EmitEvent(log, out)
	if c.In(buf.String()) {
		t.Fatal("EmitEvent: canary leaked into the journal event")
	}
	if !strings.Contains(buf.String(), "deploy.healthcheck") || !strings.Contains(buf.String(), `"status":"failed"`) {
		t.Fatal("EmitEvent: event missing expected fields")
	}
}
