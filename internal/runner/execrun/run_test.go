package execrun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/execpolicy"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// fakeIso records what Run asks of the isolator and starts the child
// unisolated, so Run's own logic is testable on any host.
type fakeIso struct {
	enforces map[execpolicy.NetMode]bool
	started  []execpolicy.NetMode
	dests    [][]Pin
	startErr error
}

func (f *fakeIso) Enforces(m execpolicy.NetMode) bool { return f.enforces[m] }

func (f *fakeIso) Prepare(m execpolicy.NetMode, d []Pin) ([]string, func(), error) {
	if f.startErr != nil {
		return nil, nil, f.startErr
	}
	f.started = append(f.started, m)
	f.dests = append(f.dests, d)
	return []string{"/usr/bin/env"}, func() {}, nil
}

func fullIso() *fakeIso {
	return &fakeIso{enforces: map[execpolicy.NetMode]bool{execpolicy.NetNone: true, execpolicy.NetAllowlist: true}}
}

func setScript(t *testing.T, w *world, body string) {
	t.Helper()
	p := filepath.Join(w.bin, "tool")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil { //nolint:gosec // G306: a test executable
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o755); err != nil { //nolint:gosec // G302: a test executable
		t.Fatal(err)
	}
}

func (w *world) deps(iso Isolator) (Deps, *bytes.Buffer) {
	var logs bytes.Buffer
	home := filepath.Join(w.bin, "..", "home")
	_ = os.MkdirAll(home, 0o700)
	home, _ = filepath.EvalSymlinks(home)
	return Deps{Iso: iso, HomeRoot: home, Chown: func(string, int, int) error { return nil }, ChildUID: 65534, ChildGID: 65534, Log: obs.New(&logs)}, &logs
}

func (w *world) plan(params map[string]string) Plan {
	w.t.Helper()
	pl, err := Prepare(w.job(params), w.policy)
	if err != nil {
		w.t.Fatalf("prepare: %v", err)
	}
	return pl
}

func TestRunEnvironmentIsBuiltFromNothing(t *testing.T) {
	w := newWorld(t)
	setScript(t, w, `/usr/bin/env`)
	t.Setenv("RUNNER_PRIVATE_MARKER_ZZ", "must-not-reach-the-child")
	t.Setenv("PATH", "/runner/own/path:/usr/bin")
	c := canary.New()
	d, _ := w.deps(fullIso())
	out, class := Run(context.Background(), w.plan(map[string]string{"name": "x"}), secret.New([]byte(c.Value(1))), w.policy, d)
	if class != "" {
		t.Fatalf("class = %q", class)
	}
	if strings.Contains(out.Stdout, "RUNNER_PRIVATE_MARKER_ZZ") || strings.Contains(out.Stdout, "/runner/own/path") {
		t.Fatalf("the runner's environment reached the child: %q", out.Stdout)
	}
	allowed := map[string]bool{"PATH": true, "HOME": true, "TOOL_KEY": true, "TMPDIR": true, "PWD": true, "SHLVL": true, "_": true, "OLDPWD": true}
	for _, line := range strings.Split(strings.TrimSpace(out.Stdout), "\n") {
		name, _, _ := strings.Cut(line, "=")
		if !allowed[name] {
			t.Errorf("unexpected variable in the child: %q", name)
		}
	}
	if !strings.Contains(out.Stdout, "TOOL_KEY=[REDACTED]") {
		t.Errorf("the secret variable is missing or was not scrubbed from the output: %q", out.Stdout)
	}
	if c.In(out.Stdout) || c.In(out.Stderr) {
		t.Fatal("value in the output")
	}
}

func TestRunScrubsEncodedValueFromOutput(t *testing.T) {
	w := newWorld(t)
	setScript(t, w, `printf '%s' "$TOOL_KEY" | base64; printf '%s\n' "$TOOL_KEY" >&2`)
	c := canary.New()
	d, _ := w.deps(fullIso())
	out, class := Run(context.Background(), w.plan(map[string]string{"name": "x"}), secret.New([]byte(c.Value(2))), w.policy, d)
	if class != "" {
		t.Fatalf("class = %q", class)
	}
	if c.In(out.Stdout) || c.In(out.Stderr) {
		t.Fatalf("value survived: %q / %q", out.Stdout, out.Stderr)
	}
	if !strings.Contains(out.Stdout, "[REDACTED]") || !strings.Contains(out.Stderr, "[REDACTED]") {
		t.Fatalf("no marker: %q / %q", out.Stdout, out.Stderr)
	}
}

func TestRunLimitsOutputAndNeverLeaksACutValue(t *testing.T) {
	c := canary.New()
	val := c.Value(3)
	// The value is printed at a range of offsets around the limit, so one of
	// them straddles it and one straddles the capture.
	for pad := 100; pad < 100+3*len(val); pad += 7 {
		w := newWorld(t)
		setScript(t, w, `head -c `+strconv.Itoa(pad)+` /dev/zero | tr '\0' 'a'; printf '%s' "$TOOL_KEY"; head -c 4000 /dev/zero | tr '\0' 'b'`)
		d, _ := w.deps(fullIso())
		d.MaxOutput = 150
		out, class := Run(context.Background(), w.plan(map[string]string{"name": "x"}), secret.New([]byte(val)), w.policy, d)
		if class != "" {
			t.Fatalf("class = %q", class)
		}
		if len(out.Stdout) > 150 || !out.Truncated {
			t.Fatalf("pad %d: output not limited: len=%d truncated=%v", pad, len(out.Stdout), out.Truncated)
		}
		if strings.Contains(out.Stdout, val[:8]) || strings.Contains(out.Stdout, val[len(val)-8:]) {
			t.Fatalf("pad %d: a part of the value reached the host output: %q", pad, out.Stdout)
		}
	}
}

// Whole copies shrink to the marker, so a copy cut by the end of the capture
// lands inside the limit and must be dropped: only Run knows the output went
// on past the capture.
func TestRunDropsTheHalfCopyAtTheEndOfTheCapture(t *testing.T) {
	c := canary.New()
	val := c.Value(5)
	for pad := 0; pad <= len(val)+1; pad++ {
		w := newWorld(t)
		setScript(t, w, `head -c `+strconv.Itoa(pad)+` /dev/zero | tr '\0' 'a'; head -c `+strconv.Itoa(pad)+` /dev/zero | tr '\0' 'a' >&2; i=0; while [ $i -lt 400 ]; do printf '%saaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' "$TOOL_KEY"; printf '%saaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' "$TOOL_KEY" >&2; i=$((i+1)); done`)
		d, _ := w.deps(fullIso())
		d.MaxOutput = 1000
		out, class := Run(context.Background(), w.plan(map[string]string{"name": "x"}), secret.New([]byte(val)), w.policy, d)
		if class != "" {
			t.Fatalf("class = %q", class)
		}
		if !strings.Contains(out.Stdout, "[REDACTED]") {
			t.Fatalf("pad %d: nothing was scrubbed, the test does not exercise the scrubber: %q", pad, out.Stdout)
		}
		for _, got := range []string{out.Stdout, out.Stderr} {
			for _, part := range []string{val[:6], val[len(val)-6:]} {
				if strings.Contains(got, part) {
					t.Fatalf("pad %d: a part of the value reached the host output: %q", pad, got)
				}
			}
		}
	}
}

// Nothing the child started may outlive the run: it holds the value in its
// environment.
func TestRunKillsWhatTheChildLeftRunning(t *testing.T) {
	w := newWorld(t)
	late := filepath.Join(w.bin, "..", "late")
	setScript(t, w, `(/bin/sleep 2; /bin/echo late > `+late+`) >/dev/null 2>&1 & exit 0`)
	d, _ := w.deps(fullIso())
	if _, class := Run(context.Background(), w.plan(map[string]string{"name": "x"}), secret.New([]byte("v")), w.policy, d); class != "" {
		t.Fatalf("class = %q", class)
	}
	time.Sleep(3 * time.Second)
	if _, err := os.Stat(late); err == nil {
		t.Fatal("a process the child started outlived Run")
	}
}

func TestRunExitCodeIsReported(t *testing.T) {
	w := newWorld(t)
	setScript(t, w, `exit 7`)
	d, _ := w.deps(fullIso())
	out, class := Run(context.Background(), w.plan(map[string]string{"name": "x"}), secret.New([]byte("v")), w.policy, d)
	if class != "" || out.ExitCode != 7 {
		t.Fatalf("exit=%d class=%q", out.ExitCode, class)
	}
}

// Fail closed: a host that cannot enforce the network does not run the
// template, with the single class that leaves the host.
func TestRunFailsClosedWithoutIsolation(t *testing.T) {
	w := newWorld(t)
	marker := filepath.Join(t.TempDir(), "ran")
	setScript(t, w, `: > `+marker)
	ran := func() bool { _, err := os.Stat(marker); return err == nil }

	noIso := &fakeIso{enforces: map[execpolicy.NetMode]bool{}}

	// network none, no isolation, no flag: refused.
	d, _ := w.deps(noIso)
	if _, class := Run(context.Background(), w.plan(map[string]string{"name": "x"}), secret.New([]byte("v")), w.policy, d); class != runnerproto.ErrClassPolicyDenied || ran() {
		t.Fatalf("none without isolation: class=%q ran=%v", class, ran())
	}
	// nil isolator is the same as none available.
	d.Iso = nil
	if _, class := Run(context.Background(), w.plan(map[string]string{"name": "x"}), secret.New([]byte("v")), w.policy, d); class != runnerproto.ErrClassPolicyDenied || ran() {
		t.Fatalf("nil isolator: class=%q ran=%v", class, ran())
	}
	// network none with exec_net_unenforced: runs, unisolated.
	p := w.policy
	p.ExecNetUnenforced = true
	if _, class := Run(context.Background(), w.plan(map[string]string{"name": "x"}), secret.New([]byte("v")), p, d); class != "" || !ran() {
		t.Fatalf("none with the flag: class=%q ran=%v", class, ran())
	}
	_ = os.Remove(marker)

	// allowlist: never runs without isolation, flag or not.
	w2 := newWorld(t)
	w2.policy.ExecTemplates[0].Network = runnerproto.ExecNetwork{Mode: "allowlist", Destinations: []runnerproto.ExecDestination{{Host: "93.184.216.34", Port: 443}}}
	w2.policy.ExecTemplates[0].Params = map[string]runnerproto.ExecParam{"name": {Pattern: `^id-[0-9]{1,8}$`}}
	w2.policy.ExecNetUnenforced = true
	setScript(t, w2, `: > `+marker)
	d2, _ := w2.deps(noIso)
	if _, class := Run(context.Background(), w2.plan(map[string]string{"name": "id-1"}), secret.New([]byte("v")), w2.policy, d2); class != runnerproto.ErrClassPolicyDenied || ran() {
		t.Fatalf("allowlist without isolation, with the flag: class=%q ran=%v", class, ran())
	}
}

func TestRunUsesIsolatorForNone(t *testing.T) {
	w := newWorld(t)
	setScript(t, w, `exit 0`)
	iso := fullIso()
	d, _ := w.deps(iso)
	if _, class := Run(context.Background(), w.plan(map[string]string{"name": "x"}), secret.New([]byte("v")), w.policy, d); class != "" {
		t.Fatalf("class = %q", class)
	}
	if len(iso.started) != 1 || iso.started[0] != execpolicy.NetNone {
		t.Fatalf("isolator calls: %v", iso.started)
	}
	// An isolator that cannot start the child must not leave the child
	// running unisolated.
	iso2 := fullIso()
	iso2.startErr = errors.New("netns refused")
	d2, _ := w.deps(iso2)
	marker := filepath.Join(t.TempDir(), "ran")
	setScript(t, w, `: > `+marker)
	if _, class := Run(context.Background(), w.plan(map[string]string{"name": "x"}), secret.New([]byte("v")), w.policy, d2); class != runnerproto.ErrClassInternal {
		t.Fatalf("class = %q", class)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the child ran although isolation failed")
	}
}

// Destinations are resolved before the start, and a name that resolves to
// the host itself, or to nothing, is refused.
func TestRunResolvesDestinationsBeforeStart(t *testing.T) {
	w := newWorld(t)
	w.policy.ExecTemplates[0].Network = runnerproto.ExecNetwork{Mode: "allowlist", Destinations: []runnerproto.ExecDestination{{Host: "api.example.com", Port: 443}}}
	w.policy.ExecTemplates[0].Params = map[string]runnerproto.ExecParam{"name": {Pattern: `^id-[0-9]{1,8}$`}}
	setScript(t, w, `exit 0`)
	pl := w.plan(map[string]string{"name": "id-1"})

	iso := fullIso()
	d, _ := w.deps(iso)
	d.Resolve = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host != "api.example.com" {
			t.Errorf("resolved %q", host)
		}
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	if _, class := Run(context.Background(), pl, secret.New([]byte("v")), w.policy, d); class != "" {
		t.Fatalf("class = %q", class)
	}
	if len(iso.dests) != 1 || len(iso.dests[0]) != 1 || iso.dests[0][0] != (Pin{Host: "api.example.com", Addr: netip.MustParseAddrPort("93.184.216.34:443")}) {
		t.Fatalf("destinations given to the isolator: %v", iso.dests)
	}

	for name, addrs := range map[string][]netip.Addr{
		"loopback":    {netip.MustParseAddr("127.0.0.1")},
		"link-local":  {netip.MustParseAddr("169.254.169.254")},
		"unspecified": {netip.MustParseAddr("0.0.0.0")},
		"multicast":   {netip.MustParseAddr("224.0.0.1")},
		"v6-loopback": {netip.MustParseAddr("::1")},
		"mapped":      {netip.MustParseAddr("::ffff:127.0.0.1")},
		"nothing":     nil,
		"one-bad":     {netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("127.0.0.1")},
	} {
		iso := fullIso()
		d, _ := w.deps(iso)
		a := addrs
		d.Resolve = func(context.Context, string) ([]netip.Addr, error) { return a, nil }
		if _, class := Run(context.Background(), pl, secret.New([]byte("v")), w.policy, d); class != runnerproto.ErrClassPolicyDenied || len(iso.started) != 0 {
			t.Errorf("%s: class=%q started=%d", name, class, len(iso.started))
		}
	}
	// A resolver error is a refusal too.
	d3, _ := w.deps(fullIso())
	d3.Resolve = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("nxdomain") }
	if _, class := Run(context.Background(), pl, secret.New([]byte("v")), w.policy, d3); class != runnerproto.ErrClassPolicyDenied {
		t.Fatalf("resolver error: class=%q", class)
	}
}

// A resolver that never answers must not outlive Deps.Timeout: the limit
// bounds the whole run, resolution included.
func TestRunTimeoutBoundsDestinationResolution(t *testing.T) {
	w := newWorld(t)
	w.policy.ExecTemplates[0].Network = runnerproto.ExecNetwork{Mode: "allowlist", Destinations: []runnerproto.ExecDestination{{Host: "api.example.com", Port: 443}}}
	w.policy.ExecTemplates[0].Params = map[string]runnerproto.ExecParam{"name": {Pattern: `^id-[0-9]{1,8}$`}}
	setScript(t, w, `exit 0`)
	pl := w.plan(map[string]string{"name": "id-1"})
	iso := fullIso()
	d, _ := w.deps(iso)
	d.Timeout = 100 * time.Millisecond
	d.Resolve = func(ctx context.Context, _ string) ([]netip.Addr, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		}
	}
	start := time.Now()
	_, class := Run(context.Background(), pl, secret.New([]byte("v")), w.policy, d)
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("resolution outlived the timeout: %v", el)
	}
	if class == "" || len(iso.started) != 0 {
		t.Fatalf("class=%q started=%d", class, len(iso.started))
	}
}

// The journal event names the template, the network mode, the destinations
// and the exit code; never an argument, the output, or the value.
func TestRunJournalEventHasNoValuesOrOutput(t *testing.T) {
	w := newWorld(t)
	setScript(t, w, `echo "printed-by-child"; exit 3`)
	c := canary.New()
	d, logs := w.deps(fullIso())
	if _, class := Run(context.Background(), w.plan(map[string]string{"name": "argvalue"}), secret.New([]byte(c.Value(4))), w.policy, d); class != "" {
		t.Fatalf("class = %q", class)
	}
	line := logs.String()
	for _, want := range []string{`"exec.run"`, `"template_id":"tool-run"`, `"kind":"none"`, `exit_3`} {
		if !strings.Contains(line, want) {
			t.Errorf("event lacks %s: %s", want, line)
		}
	}
	for _, banned := range []string{"argvalue", "printed-by-child"} {
		if strings.Contains(line, banned) {
			t.Errorf("event carries %q: %s", banned, line)
		}
	}
	if c.In(line) {
		t.Fatal("value in the journal event")
	}
}

// Every run gets a new private directory as HOME, TMPDIR and cwd, owned by the
// child's account and closed to others, and it is gone when the run ends: what
// the first run wrote cannot be seen by the second.
func TestRunGivesEveryRunItsOwnPrivateHome(t *testing.T) {
	w := newWorld(t)
	setScript(t, w, `echo "home=$HOME tmp=$TMPDIR pwd=$(pwd -P)"; ls -ld "$HOME" | cut -c1-10; echo "seen=$(ls -A "$HOME" | tr '\n' ',')"; echo "$TOOL_KEY" > "$HOME/note"; mkdir "$HOME/sub"; echo x > "$HOME/sub/f"`)
	d, _ := w.deps(fullIso())
	var chowned []string
	d.Chown = func(p string, uid, gid int) error {
		chowned = append(chowned, fmt.Sprintf("%s %d:%d", filepath.Dir(p), uid, gid))
		return nil
	}
	var homes []string
	for i := range 2 {
		out, class := Run(context.Background(), w.plan(map[string]string{"name": "x"}), secret.New([]byte(canary.New().Value(6+i))), w.policy, d)
		if class != "" {
			t.Fatalf("run %d: class = %q", i, class)
		}
		lines := strings.Split(strings.TrimSpace(out.Stdout), "\n")
		if len(lines) != 3 || lines[1] != "drwx------" || lines[2] != "seen=" {
			t.Fatalf("run %d: output %q, want a 0700 directory with nothing in it", i, out.Stdout)
		}
		var home, tmp, pwd string
		if _, err := fmt.Sscanf(lines[0], "home=%s tmp=%s pwd=%s", &home, &tmp, &pwd); err != nil {
			t.Fatal(err)
		}
		if home != tmp || home != pwd || filepath.Dir(home) != d.HomeRoot {
			t.Fatalf("run %d: home=%q tmp=%q pwd=%q, want one directory made in %q", i, home, tmp, pwd, d.HomeRoot)
		}
		homes = append(homes, home)
		if ents, _ := os.ReadDir(d.HomeRoot); len(ents) != 0 {
			t.Fatalf("run %d: %d entries left in the home root", i, len(ents))
		}
	}
	if homes[0] == homes[1] {
		t.Fatalf("two runs shared the home %q", homes[0])
	}
	want := d.HomeRoot + " 65534:65534"
	if len(chowned) != 2 || chowned[0] != want || chowned[1] != want {
		t.Fatalf("chown calls = %v, want two of %q", chowned, want)
	}
}

// A directory that cannot be handed to the child's account is not used.
func TestRunRefusesAHomeItCannotGiveToTheChild(t *testing.T) {
	w := newWorld(t)
	setScript(t, w, `touch `+filepath.Join(w.bin, "ran"))
	d, _ := w.deps(fullIso())
	d.Chown = func(string, int, int) error { return errors.New("not permitted") }
	_, class := Run(context.Background(), w.plan(map[string]string{"name": "x"}), secret.New([]byte(canary.New().Value(7))), w.policy, d)
	if class != runnerproto.ErrClassInternal {
		t.Fatalf("class = %q", class)
	}
	if _, err := os.Stat(filepath.Join(w.bin, "ran")); err == nil {
		t.Fatal("the child ran in a home it does not own")
	}
	if ents, _ := os.ReadDir(d.HomeRoot); len(ents) != 0 {
		t.Fatalf("%d entries left in the home root", len(ents))
	}
}

// A home that could not be removed is reported, not shrugged off.
func TestRunReportsAHomeItCouldNotRemove(t *testing.T) {
	w := newWorld(t)
	old := removeChildDir
	removeChildDir = func(string) error { return errors.New("cannot remove") }
	t.Cleanup(func() { removeChildDir = old })
	setScript(t, w, `touch "$HOME/f"`)
	d, _ := w.deps(fullIso())
	_, class := Run(context.Background(), w.plan(map[string]string{"name": "x"}), secret.New([]byte(canary.New().Value(8))), w.policy, d)
	if class != runnerproto.ErrClassInternal {
		t.Fatalf("class = %q", class)
	}
}

// A run directory left by a failed removal is not handed to the next child:
// the next run refuses, and the leftover is never read.
func TestRunRefusesARootWithALeftover(t *testing.T) {
	w := newWorld(t)
	old := removeChildDir
	removeChildDir = func(string) error { return errors.New("cannot remove") }
	t.Cleanup(func() { removeChildDir = old })
	setScript(t, w, `echo "$TOOL_KEY" > "$HOME/note"`)
	d, _ := w.deps(fullIso())
	pl := w.plan(map[string]string{"name": "x"})
	Run(context.Background(), pl, secret.New([]byte(canary.New().Value(8))), w.policy, d)
	removeChildDir = old
	setScript(t, w, `cat "$HOME"/../run-*/note`)
	out, class := Run(context.Background(), pl, secret.New([]byte(canary.New().Value(9))), w.policy, d)
	if class != runnerproto.ErrClassInternal {
		t.Fatalf("second run class = %q, want a refusal", class)
	}
	if strings.Contains(out.Stdout, canary.New().Value(8)) {
		t.Fatal("the first run's value reached the second run")
	}
}

func TestRunTimeoutKillsTheChild(t *testing.T) {
	w := newWorld(t)
	setScript(t, w, `sleep 30`)
	d, _ := w.deps(fullIso())
	d.Timeout = 300 * 1e6 // 300ms
	_, class := Run(context.Background(), w.plan(map[string]string{"name": "x"}), secret.New([]byte("v")), w.policy, d)
	if class != runnerproto.ErrClassInternal {
		t.Fatalf("class = %q", class)
	}
}

func TestRunRequiresAHomeRoot(t *testing.T) {
	w := newWorld(t)
	setScript(t, w, `exit 0`)
	d, _ := w.deps(fullIso())
	d.HomeRoot = ""
	if _, class := Run(context.Background(), w.plan(map[string]string{"name": "x"}), secret.New([]byte("v")), w.policy, d); class != runnerproto.ErrClassInternal {
		t.Fatalf("no home: class=%q", class)
	}
}

// The isolator is given plain IPv4 addresses, not 4-in-6 forms: the firewall
// rule is written from them.
func TestRunPassesUnmappedAddresses(t *testing.T) {
	w := newWorld(t)
	w.policy.ExecTemplates[0].Network = runnerproto.ExecNetwork{Mode: "allowlist", Destinations: []runnerproto.ExecDestination{{Host: "api.example.com", Port: 443}}}
	w.policy.ExecTemplates[0].Params = map[string]runnerproto.ExecParam{"name": {Pattern: `^id-[0-9]{1,8}$`}}
	setScript(t, w, `exit 0`)
	pl := w.plan(map[string]string{"name": "id-1"})
	iso := fullIso()
	d, _ := w.deps(iso)
	d.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("::ffff:93.184.216.34")}, nil
	}
	if _, class := Run(context.Background(), pl, secret.New([]byte("v")), w.policy, d); class != "" {
		t.Fatalf("class = %q", class)
	}
	if got := iso.dests[0][0].Addr.Addr(); !got.Is4() {
		t.Fatalf("isolator got %v, want a plain IPv4 address", got)
	}
}

// No account of its own for the child, no run: the child would be the runner.
func TestRunRequiresAChildAccount(t *testing.T) {
	w := newWorld(t)
	oldEuid := geteuid
	geteuid = func() int { return 4242 }
	t.Cleanup(func() { geteuid = oldEuid })
	marker := filepath.Join(t.TempDir(), "ran")
	setScript(t, w, `: > `+marker)
	for name, mod := range map[string]func(*Deps){
		"uid": func(d *Deps) { d.ChildUID = 0 },
		"gid": func(d *Deps) { d.ChildGID = 0 },
	} {
		d, _ := w.deps(fullIso())
		mod(&d)
		if _, class := Run(context.Background(), w.plan(map[string]string{"name": "x"}), secret.New([]byte("v")), w.policy, d); class != runnerproto.ErrClassInternal {
			t.Errorf("%s: class = %q", name, class)
		}
		if _, err := os.Stat(marker); err == nil {
			t.Fatalf("%s: the child ran without an account of its own", name)
		}
	}
}

// A core file would hold the child's environment: the child gets no room for
// one, even when the runner was started with room.
func TestRunChildCannotDumpCore(t *testing.T) {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &lim); err != nil || lim.Max == 0 {
		t.Skip("this host forbids raising the core limit, so the test cannot start from a limit that allows cores")
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: lim.Max, Max: lim.Max}); err != nil {
		t.Skipf("cannot raise the core limit: %v", err)
	}
	w := newWorld(t)
	setScript(t, w, `ulimit -c`)
	d, _ := w.deps(fullIso())
	out, class := Run(context.Background(), w.plan(map[string]string{"name": "x"}), secret.New([]byte("v")), w.policy, d)
	if class != "" || strings.TrimSpace(out.Stdout) != "0" {
		t.Fatalf("class=%q core limit seen by the child: %q", class, out.Stdout)
	}
}

// The child has no stdin.
func TestRunChildHasNoStdin(t *testing.T) {
	w := newWorld(t)
	setScript(t, w, `cat; echo end`)
	d, _ := w.deps(fullIso())
	out, class := Run(context.Background(), w.plan(map[string]string{"name": "x"}), secret.New([]byte("QQ#QQ")), w.policy, d)
	if class != "" || out.Stdout != "end\n" {
		t.Fatalf("class=%q output=%q, want nothing read from stdin", class, out.Stdout)
	}
}

// Without a wrapper the runner itself gives the child its own account, and a
// runner that cannot (not root) starts nothing: the child would be the runner.
func TestRunRefusesAnUnwrappedChildWhenItCannotDropTheAccount(t *testing.T) {
	w := newWorld(t)
	dropAccount = dropToChild
	oldEuid := geteuid
	geteuid = func() int { return 4242 }
	t.Cleanup(func() { geteuid = oldEuid })
	marker := filepath.Join(t.TempDir(), "ran")
	setScript(t, w, `: > `+marker)
	w.policy.ExecNetUnenforced = true
	d, _ := w.deps(nil)
	if _, class := Run(context.Background(), w.plan(map[string]string{"name": "x"}), secret.New([]byte("v")), w.policy, d); class != runnerproto.ErrClassPolicyDenied {
		t.Fatalf("class = %q", class)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the child ran with the runner's own account")
	}
	if ents, _ := os.ReadDir(d.HomeRoot); len(ents) != 0 {
		t.Fatalf("a run that never started left %d entries in the home root", len(ents))
	}
}

// The child's account is its own: not the runner's, not an agent's. An
// account an agent can use would let the agent read the child's environment.
func TestRunRefusesAChildAccountOfTheRunnerOrAnAgent(t *testing.T) {
	w := newWorld(t)
	oldEuid := geteuid
	geteuid = func() int { return 4242 }
	t.Cleanup(func() { geteuid = oldEuid })
	marker := filepath.Join(t.TempDir(), "ran")
	setScript(t, w, `: > `+marker)
	for name, mod := range map[string]func(*Deps, *runnerproto.HostPolicy){
		"runner": func(d *Deps, _ *runnerproto.HostPolicy) { d.ChildUID = uint32(geteuid()) }, //nolint:gosec // G115: a uid
		"agent":  func(d *Deps, p *runnerproto.HostPolicy) { p.AgentUIDs = append(p.AgentUIDs, int64(d.ChildUID)) },
	} {
		d, _ := w.deps(fullIso())
		p := w.policy
		mod(&d, &p)
		if _, class := Run(context.Background(), w.plan(map[string]string{"name": "x"}), secret.New([]byte("v")), p, d); class != runnerproto.ErrClassInternal {
			t.Errorf("%s: class = %q", name, class)
		}
		if _, err := os.Stat(marker); err == nil {
			t.Fatalf("%s: the child ran under an account it does not own", name)
		}
	}
}

// A kernel that pipes cores to a program records the crashed child's
// environment whatever the limit says.
func TestRunRefusesWhenCoresGoToAHandlerProgram(t *testing.T) {
	w := newWorld(t)
	coreHandlerPiped = func() bool { return true }
	marker := filepath.Join(t.TempDir(), "ran")
	setScript(t, w, `: > `+marker)
	d, _ := w.deps(fullIso())
	if _, class := Run(context.Background(), w.plan(map[string]string{"name": "x"}), secret.New([]byte("v")), w.policy, d); class != runnerproto.ErrClassInternal {
		t.Fatalf("class = %q", class)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the child ran although its core would go to a handler")
	}
}

type bareIso struct{ fakeIso }

func (b *bareIso) Prepare(execpolicy.NetMode, []Pin) ([]string, func(), error) {
	return nil, func() {}, nil
}

// Whoever changes the child's account in the isolated path is the isolator;
// one that wraps nothing would leave the child with the runner's.
func TestRunRefusesAnIsolatorThatWrapsNothing(t *testing.T) {
	w := newWorld(t)
	marker := filepath.Join(t.TempDir(), "ran")
	setScript(t, w, `: > `+marker)
	iso := &bareIso{*fullIso()}
	d, _ := w.deps(iso)
	if _, class := Run(context.Background(), w.plan(map[string]string{"name": "x"}), secret.New([]byte("v")), w.policy, d); class != runnerproto.ErrClassInternal {
		t.Fatalf("class = %q", class)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the child ran without a wrapper")
	}
}

// A refusal that comes before the child starts and a home that cannot be
// removed together are an internal error: the leftover is not hidden behind
// policy_denied, and the first refusal stays in the log line.
func TestRunEarlyRefusalWithUnremovableHomeIsInternal(t *testing.T) {
	w := newWorld(t)
	dropAccount = func(*exec.Cmd, uint32, uint32) error { return errors.New("cannot drop") }
	removeChildDir = func(string) error { return errors.New("cannot remove") }
	t.Cleanup(func() { removeChildDir = os.RemoveAll })
	marker := filepath.Join(t.TempDir(), "ran")
	setScript(t, w, `: > `+marker)
	w.policy.ExecNetUnenforced = true
	d, logs := w.deps(nil)
	val := canary.New().Value(10)
	_, class := Run(context.Background(), w.plan(map[string]string{"name": "x"}), secret.New([]byte(val)), w.policy, d)
	if class != runnerproto.ErrClassInternal {
		t.Fatalf("class = %q, want internal_error", class)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the child ran")
	}
	if !strings.Contains(logs.String(), "failed_after_refusal") {
		t.Fatalf("the first refusal is not in the log: %s", logs.String())
	}
	if strings.Contains(logs.String(), val) || strings.Contains(logs.String(), "cannot") {
		t.Fatal("a reason text or value reached the log")
	}
}

// With the home removed, the same early refusal keeps its own class.
func TestRunEarlyRefusalKeepsItsClassWhenTheHomeIsRemoved(t *testing.T) {
	w := newWorld(t)
	dropAccount = func(*exec.Cmd, uint32, uint32) error { return errors.New("cannot drop") }
	w.policy.ExecNetUnenforced = true
	d, _ := w.deps(nil)
	_, class := Run(context.Background(), w.plan(map[string]string{"name": "x"}), secret.New([]byte("v")), w.policy, d)
	if class != runnerproto.ErrClassPolicyDenied {
		t.Fatalf("class = %q, want policy_denied", class)
	}
}
