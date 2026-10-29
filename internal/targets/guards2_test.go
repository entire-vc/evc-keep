//go:build unix

package targets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"golang.org/x/sys/unix"
)

// writeExisting writes val into a fresh target that already holds content, and
// returns what the file holds afterwards.
func writeExisting(t *testing.T, kind runnerproto.TargetKind, content string, field string, val string) (string, error) {
	t.Helper()
	p := filepath.Join(realDir(t), "x")
	mustWriteFile(t, p, []byte(content), 0o600)
	u, g := noAgents()
	_, err := Write(target(kind, p, field), newValue(val), u, g, testFPKey(t))
	return string(mustReadFile(t, p)), err
}

func TestNestedEnvKeyDecoyAhead(t *testing.T) {
	for name, pl := range map[string]string{
		"nested-dict": `<plist><dict><key>Sockets</key><dict><key>EnvironmentVariables</key><dict><key>X</key><string>1</string></dict></dict><key>EnvironmentVariables</key><dict><key>A</key><string>1</string></dict></dict></plist>`,
		"in-array":    `<plist><dict><key>Stuff</key><array><dict><key>EnvironmentVariables</key><dict><key>X</key><string>1</string></dict></dict></array><key>EnvironmentVariables</key><dict><key>A</key><string>1</string></dict></dict></plist>`,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := writeExisting(t, runnerproto.TargetLaunchdEnv, pl, "NAME", "v")
			want := strings.Replace(pl, `<key>A</key><string>1</string></dict></dict></plist>`, `<key>A</key><string>1</string><key>NAME</key><string>v</string></dict></dict></plist>`, 1)
			if err != nil || got != want {
				t.Fatalf("err=%v got %s", err, show([]byte(got)))
			}
		})
	}
}

func TestTopKeyMustBeExact(t *testing.T) {
	for _, k := range []string{"EnvironmentVariablesX", "XEnvironmentVariables", "NotEnvironmentVariablesAtAll", "environmentvariables", "ENVIRONMENTVARIABLES"} {
		pl := `<plist><dict><key>` + k + `</key><dict><key>A</key><string>1</string></dict></dict></plist>`
		got, err := writeExisting(t, runnerproto.TargetLaunchdEnv, pl, "NAME", "v")
		if err == nil || got != pl {
			t.Errorf("%s: err=%v got %s", k, err, show([]byte(got)))
		}
	}
}

func TestEntryKeyMustBeExact(t *testing.T) {
	for _, k := range []string{"NAME_OLD", "OLD_NAME", "NAM", "AME", "name"} {
		pl := `<plist><dict><key>EnvironmentVariables</key><dict><key>` + k + `</key><string>1</string></dict></dict></plist>`
		got, err := writeExisting(t, runnerproto.TargetLaunchdEnv, pl, "NAME", "v")
		if err != nil || !strings.Contains(got, `<key>`+k+`</key><string>1</string>`) || !strings.Contains(got, `<key>NAME</key><string>v</string>`) {
			t.Errorf("%s: err=%v got %s", k, err, show([]byte(got)))
		}
	}
}

func TestTextInsideEnvDictRefused(t *testing.T) {
	pl := `<plist><dict><key>EnvironmentVariables</key><dict>junk<key>A</key><string>1</string></dict></dict></plist>`
	got, err := writeExisting(t, runnerproto.TargetLaunchdEnv, pl, "NAME", "v")
	if err == nil || got != pl {
		t.Fatalf("accepted: err=%v got %s", err, show([]byte(got)))
	}
}

func TestDictShapeRefused(t *testing.T) {
	for name, inner := range map[string]string{
		"attr-on-string": `<key>A</key><string xml:space="preserve">1</string>`,
		"dangling-key":   `<key>A</key>`,
		"key-key":        `<key>A</key><key>B</key><string>x</string>`,
		"value-no-key":   `<string>x</string>`,
		"pi":             `<?x?><key>A</key><string>1</string>`,
		"directive":      `<!DOCTYPE x><key>A</key><string>1</string>`,
		"attr-on-key":    `<key a="b">A</key><string>1</string>`,
	} {
		t.Run(name, func(t *testing.T) {
			pl := `<plist><dict><key>EnvironmentVariables</key><dict>` + inner + `</dict></dict></plist>`
			got, err := writeExisting(t, runnerproto.TargetLaunchdEnv, pl, "NAME", "v")
			if err == nil || got != pl {
				t.Fatalf("accepted: err=%v got %s", err, show([]byte(got)))
			}
		})
	}
}

func TestEmptyExistingFiles(t *testing.T) {
	for name, k := range map[string]runnerproto.TargetKind{"env": runnerproto.TargetEnvFile, "mcp": runnerproto.TargetMCPConfig} {
		field := "NAME"
		if k == runnerproto.TargetMCPConfig {
			field = "mcpServers.a.env.NAME"
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: an empty existing file crashed the writer", name)
				}
			}()
			if _, err := writeExisting(t, k, "", field, "v"); err != nil {
				t.Errorf("%s: %v", name, err)
			}
		}()
	}
}

// Deadlines of TestBareCharsEachByteThroughShell. Without them a stuck shell
// or fsync ran until the job timeout killed the whole package binary and the
// trace read only "signal: terminated" with no test named. A normal run is
// about a minute; the budget is several times that and still far below the
// CI package deadline.
const (
	bareCharsShellTimeout = 20 * time.Second
	bareCharsBudget       = 5 * time.Minute
)

// consumeEnvFile sources svc.env in dir the way a service manager would and
// returns what $NAME expands to. The shell has no stdin and dies with ctx.
func consumeEnvFile(ctx context.Context, dir, script string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", script) //nolint:gosec // G204: the script is a constant of the calling test
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	cmd.Stdin = nil
	cmd.WaitDelay = time.Second
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("shell did not finish: %w", ctx.Err())
	}
	_ = err // a non-zero exit shows up as a different value below
	return out, nil
}

func TestBareCharsEachByteThroughShell(t *testing.T) {
	const script = `set -a; . ./svc.env >/dev/null 2>&1; printf '%s' "$NAME"`
	start := time.Now()
	for c := 1; c < 256; c++ {
		if c == '\n' || c == '\r' || c == 0 {
			continue
		}
		for _, shape := range []string{"a%sb", "%sb", "b%s", "a:%sb", "%s"} {
			if time.Since(start) > bareCharsBudget {
				t.Fatalf("budget %s exhausted at byte 0x%02x shape %s", bareCharsBudget, c, shape)
			}
			v := strings.Replace(shape, "%s", string([]byte{byte(c)}), 1)
			d := fsyncFreeDir(t)
			p := filepath.Join(d, "svc.env")
			mustWriteFile(t, p, []byte("A=1\n"), 0o600)
			u, g := noAgents()
			// Write cannot be cancelled, so it runs behind a timer: a stuck
			// fsync fails this test in seconds, naming the byte.
			tg, val, key := target(runnerproto.TargetEnvFile, p, "NAME"), newValue(v), testFPKey(t)
			done := make(chan error, 1)
			go func() {
				_, err := Write(tg, val, u, g, key)
				done <- err
			}()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("byte 0x%02x shape %s: refused although every such value is representable: %v", c, shape, err)
					continue
				}
			case <-time.After(bareCharsShellTimeout):
				t.Fatalf("byte 0x%02x shape %s: Write did not return within %s", c, shape, bareCharsShellTimeout)
			}
			ctx, cancel := context.WithTimeout(context.Background(), bareCharsShellTimeout)
			out, err := consumeEnvFile(ctx, d, script)
			cancel()
			if err != nil {
				t.Fatalf("byte 0x%02x shape %s: %v (limit %s)", c, shape, err, bareCharsShellTimeout)
			}
			if string(out) != v {
				t.Errorf("byte 0x%02x shape %s: consumer sees a different value (%d bytes, want %d)", c, shape, len(out), len(v))
			}
		}
	}
}

// The deadline itself must be able to fire: a shell that never ends has to
// fail within the limit, not run to the job timeout.
func TestConsumeEnvFileDeadlineFiresOnAStuckShell(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The deadline is counted from the moment the shell has recorded the
	// sleeper, not from process start: on a loaded runner fork+exec alone can
	// outlast any fixed limit and the test would fail before the property it
	// checks. The 30s ceiling only bounds a shell that never gets that far.
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "sleeper.pid")
	var fired time.Time
	ready := make(chan struct{})
	go func() {
		defer close(ready)
		for end := time.Now().Add(30 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
			if b, err := os.ReadFile(pidFile); err == nil && strings.HasSuffix(string(b), "\n") { //nolint:gosec // G304: test temp dir
				break
			}
		}
		fired = time.Now()
		cancel()
	}()
	// The child sleep outlives the kill of the shell and holds the pipe: only
	// WaitDelay lets Output return. Its pid is kept so the test can show that
	// and then stop it instead of leaving it running.
	_, err := consumeEnvFile(ctx, dir, "sleep 30 & echo $! >sleeper.pid; wait; true")
	<-ready
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("stuck shell not reported as a cancelled run: %v", err)
	}
	if d := time.Since(fired); d > 10*time.Second {
		t.Fatalf("deadline fired after %s, want well under the 30s sleeper", d)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "sleeper.pid")) //nolint:gosec // G304: test temp dir
	if err != nil {
		t.Fatalf("shell did not record the sleeper: %v", err)
	}
	var pid int
	if _, err := fmt.Sscan(string(raw), &pid); err != nil || pid <= 0 {
		t.Fatalf("sleeper pid %q: %v", raw, err)
	}
	if err := unix.Kill(pid, 0); err != nil {
		t.Fatalf("sleeper %d already gone, so the pipe was not held: %v", pid, err)
	}
	if err := unix.Kill(pid, unix.SIGKILL); err != nil {
		t.Fatalf("stop sleeper %d: %v", pid, err)
	}
	out, err := consumeEnvFile(context.Background(), t.TempDir(), "printf ok")
	if err != nil || string(out) != "ok" {
		t.Fatalf("positive control: out=%q err=%v", out, err)
	}
}

func TestFoldingKindsRefuseWritableExisting(t *testing.T) {
	plist := `<plist><dict><key>EnvironmentVariables</key><dict><key>A</key><string>1</string></dict></dict></plist>`
	for name, c := range map[string]struct {
		k       runnerproto.TargetKind
		content string
		field   string
	}{
		"launchd": {runnerproto.TargetLaunchdEnv, plist, "NAME"},
		"mcp":     {runnerproto.TargetMCPConfig, `{"mcpServers":{"a":{"command":"planted"}}}`, "mcpServers.a.env.NAME"},
		"hermes":  {runnerproto.TargetHermesConfig, "A=1\n", "NAME"},
		"env":     {runnerproto.TargetEnvFile, "A=1\n", "NAME"},
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(safeDir(t), "x")
			mustWriteFile(t, p, []byte(c.content), 0o600)
			if err := os.Chmod(p, 0o602); err != nil { //nolint:gosec // G302: the world-writable existing target is the scenario
				t.Fatal(err)
			}
			u, g := noAgents()
			_, err := Write(target(c.k, p, c.field), newValue("v"), u, g, testFPKey(t))
			if err == nil {
				t.Fatalf("world-writable existing %s accepted as base", name)
			}
		})
	}
}

func TestRefuseWritableFileDirect(t *testing.T) {
	a := agentSet{uids: []int64{7}, gids: []int64{8}}
	if a.refuseWritableFile("f", &unix.Stat_t{Uid: 7, Mode: 0o600}) == nil {
		t.Error("agent-owned file not refused")
	}
	if a.refuseWritableFile("f", &unix.Stat_t{Uid: 1, Gid: 8, Mode: 0o020}) == nil {
		t.Error("agent-group-writable file not refused")
	}
	if a.refuseWritableFile("f", &unix.Stat_t{Uid: 1, Gid: 9, Mode: 0o602}) == nil {
		t.Error("file writable by anyone not refused")
	}
	if a.refuseWritableFile("f", &unix.Stat_t{Uid: 1, Gid: 9, Mode: 0o640}) != nil {
		t.Error("a file writable by nobody but its owner was refused")
	}
	if runtime.GOOS == "darwin" && a.refuseWritableFile("f", &unix.Stat_t{Uid: 1, Gid: everyoneGID, Mode: 0o020}) == nil {
		t.Error("everyone-group-writable file not refused")
	}
}

func TestFingerprintAttestsDiskNotInput(t *testing.T) {
	p := filepath.Join(realDir(t), "x.env")
	mustWriteFile(t, p, []byte("A=1\n"), 0o600)
	old := afterRename
	afterRename = func(pfd int, base string) {
		fd, err := unix.Openat(pfd, base, unix.O_WRONLY|unix.O_TRUNC, 0)
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = unix.Write(fd, []byte("NAME=other\n"))
		_ = unix.Close(fd)
	}
	defer func() { afterRename = old }()
	key := testFPKey(t)
	u, g := noAgents()
	fp, err := Write(target(runnerproto.TargetEnvFile, p, "NAME"), newValue("v"), u, g, key)
	want, _ := fingerprint.Compute(key, newValue("other"))
	if err == nil && fp != want {
		t.Fatalf("fingerprint does not attest the disk content")
	}
}

func TestSystemdStatErrorIsNotAbsence(t *testing.T) {
	d := realDir(t)
	f := filepath.Join(d, "notadir")
	mustWriteFile(t, f, []byte("x"), 0o600)
	old := sealToolPath
	sealToolPath = filepath.Join(f, "systemd-creds")
	defer func() { sealToolPath = old }()
	p := filepath.Join(d, "cred")
	u, g := noAgents()
	if _, err := Write(credTarget(p), newValue("v"), u, g, testFPKey(t), WithSystemdCredPlaintextFallback(nil)); err == nil {
		t.Fatalf("stat error on the seal tool treated as absence: plaintext fallback happened")
	}
}

func TestSystemdStatLoopIsNotAbsence(t *testing.T) {
	d := realDir(t)
	loop := filepath.Join(d, "loop")
	if err := os.Symlink("loop", loop); err != nil {
		t.Fatal(err)
	}
	old := sealToolPath
	sealToolPath = filepath.Join(loop, "systemd-creds")
	defer func() { sealToolPath = old }()
	p := filepath.Join(d, "cred")
	u, g := noAgents()
	if _, err := Write(credTarget(p), newValue("v"), u, g, testFPKey(t), WithSystemdCredPlaintextFallback(nil)); err == nil {
		t.Fatalf("a symlink loop on the seal tool's path treated as absence: plaintext fallback happened")
	}
}

func openFDsWithoutCloexec() []int {
	var bad []int
	for fd := 3; fd < 200; fd++ {
		fl, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil {
			continue
		}
		if fl&unix.FD_CLOEXEC == 0 {
			bad = append(bad, fd)
		}
	}
	return bad
}

func TestDescriptorsAreCloexec(t *testing.T) {
	// Descriptors that were already open without the flag before Write (a
	// helper process of an earlier test, a runtime pipe) are not Write's.
	already := map[int]bool{}
	for _, fd := range openFDsWithoutCloexec() {
		already[fd] = true
	}
	ours := func() []int {
		var bad []int
		for _, fd := range openFDsWithoutCloexec() {
			if !already[fd] {
				bad = append(bad, fd)
			}
		}
		return bad
	}
	var seen [][]int
	oa, ob := afterTmpCreate, beforeDirOpen
	afterTmpCreate = func(int, string) { seen = append(seen, ours()) }
	beforeDirOpen = func(int, string) { seen = append(seen, ours()) }
	defer func() { afterTmpCreate, beforeDirOpen = oa, ob }()
	p := filepath.Join(realDir(t), "x")
	u, g := noAgents()
	if _, err := Write(target(runnerproto.TargetFile, p, ""), newValue("v"), u, g, testFPKey(t)); err != nil {
		t.Fatal(err)
	}
	if len(seen) < 2 {
		t.Fatalf("the hooks fired %d times; the check would be vacuous", len(seen))
	}
	for _, b := range seen {
		if len(b) > 0 {
			t.Fatalf("descriptors without O_CLOEXEC open during Write: %v", b)
		}
	}
}

func TestDirFsyncFailureReported(t *testing.T) {
	old := fsyncFD
	n := 0
	fsyncFD = func(fd int) error {
		n++
		if n == 2 {
			return unix.EIO
		}
		return old(fd)
	}
	defer func() { fsyncFD = old }()
	p := filepath.Join(realDir(t), "x")
	u, g := noAgents()
	if _, err := Write(target(runnerproto.TargetFile, p, ""), newValue("v"), u, g, testFPKey(t)); err == nil {
		t.Fatal("directory fsync failure ignored")
	}
}

func TestWalkToParentRefusals(t *testing.T) {
	for _, c := range []struct {
		name string
		p    string
		ag   agentSet
	}{
		{"relative-single", "ab", agentSet{}},
		{"root", "/", agentSet{}},
		{"dot-dot-unclean", "/a/../b", agentSet{}},
		{"trailing-slash", "/usr/bin/", agentSet{}},
		{"double-slash", "/usr//bin", agentSet{}},
		{"root-owned-by-agent", "/x", agentSet{uids: []int64{0}}},
		{"root-reachable-by-agent-group", "/x", agentSet{gids: []int64{0}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			fd, _, err := walkToParent(c.p, c.ag)
			if err == nil {
				_ = unix.Close(fd)
				t.Fatalf("walkToParent(%q) accepted", c.p)
			}
		})
	}
}

// An ancestor that is not the parent is checked for ownership and writability
// only; the agent's uid owning one must refuse, though the parent is fine.
func TestWalkAgentOwnedAncestorRefused(t *testing.T) {
	d := realDir(t)
	if unix.Geteuid() == 0 {
		// Under root the directory is root's, an "agent" uid 0 would own the
		// parent too; hand it to someone else so only the ancestors are.
		if err := os.Chown(d, 65534, -1); err != nil {
			t.Fatal(err)
		}
	}
	fd, _, err := walkToParent(filepath.Join(d, "x"), agentSet{uids: []int64{0}})
	if err == nil {
		_ = unix.Close(fd)
		t.Fatal("a path below a directory owned by an agent was accepted")
	}
}

func TestValidateTargetPermDirect(t *testing.T) {
	for _, m := range []uint32{0, 0o4600, 0o2600, 0o1600, 0o10600} {
		if validateTargetPerm(m, 1, 1, agentSet{}) == nil {
			t.Errorf("mode %o accepted", m)
		}
	}
}

// TestValidateTargetPermUIDDirect calls validateTargetPerm directly, not
// through Write: going through Write for this property (as
// TestAgentOwnedTargetRefused still does, end to end) means the check, if
// mutated away, is next caught by secureCreateAndWrite's Fchown to the
// declared owner — which fails with EPERM for an unprivileged process
// chowning to any uid but its own, whatever validateTargetPerm did or did
// not decide. That still turns the test red, but for the platform's own
// ownership rule, not for this package's policy check — root would not hit
// it at all. Calling the function directly has no such dependency.
func TestValidateTargetPermUIDDirect(t *testing.T) {
	ag := agentSet{uids: []int64{syntheticAgentUID}}
	err := validateTargetPerm(0o600, syntheticAgentUID, 1, ag)
	wantErr(t, err, ErrPolicy, "target owner is an agent")
}

func TestTmpNameRandom(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		n, err := randomTmpName("x")
		if err != nil {
			t.Fatal(err)
		}
		if seen[n] {
			t.Fatal("temporary name repeats: it is predictable")
		}
		seen[n] = true
		if got := len(n[strings.LastIndex(n, "tmp-")+len("tmp-"):]); got < 24 {
			t.Fatalf("temporary name carries %d hex digits of randomness, want at least 24", got)
		}
	}
}

func TestPlistRootAndSecondLevel(t *testing.T) {
	for name, pl := range map[string]string{
		"root-not-plist":  `<other><dict><key>EnvironmentVariables</key><dict><key>A</key><string>1</string></dict></dict></other>`,
		"second-not-dict": `<plist><array><key>EnvironmentVariables</key><dict><key>A</key><string>1</string></dict></array></plist>`,
	} {
		got, err := writeExisting(t, runnerproto.TargetLaunchdEnv, pl, "NAME", "v")
		if err == nil || got != pl {
			t.Errorf("%s: accepted err=%v got %s", name, err, show([]byte(got)))
		}
	}
}

func TestSplitFieldDirect(t *testing.T) {
	for _, f := range []string{"", "a..b", ".a", "a."} {
		if _, err := splitField(f); err == nil {
			t.Errorf("splitField(%q) accepted", f)
		}
	}
}

func TestSystemdCredFoldIsNotUsed(t *testing.T) {
	absentSystemdCreds(t)
	p := filepath.Join(safeDir(t), "cred")
	mustWriteFile(t, p, []byte("old"), 0o600)
	if err := os.Chmod(p, 0o666); err != nil { //nolint:gosec // G302: the world-writable existing target is the scenario
		t.Fatal(err)
	}
	u, g := noAgents()
	if _, err := Write(credTarget(p), newValue("v"), u, g, testFPKey(t), WithSystemdCredPlaintextFallback(nil)); err != nil {
		t.Fatalf("loose existing credential file should be replaced wholesale: %v", err)
	}
}

func TestSystemdChildCwdIsRoot(t *testing.T) {
	bin, _, _ := fakeSystemdCreds(t)
	out := filepath.Join(filepath.Dir(bin), "cwd")
	script := "#!/bin/sh\npwd >> " + out + "\ncat\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	p := filepath.Join(realDir(t), "cred")
	u, g := noAgents()
	if _, err := Write(credTarget(p), newValue("v"), u, g, testFPKey(t)); err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Fields(string(mustReadFile(t, out))) {
		if l != "/" {
			t.Fatalf("child cwd = %q, want /", l)
		}
	}
}

func TestSystemdReadBackRefusesBinaryTurnedUntrusted(t *testing.T) {
	bin, _, _ := fakeSystemdCreds(t)
	old := afterRename
	afterRename = func(int, string) { _ = os.Chmod(bin, 0o777) } //nolint:gosec // G302: the binary turning untrusted is the scenario
	defer func() { afterRename = old }()
	p := filepath.Join(realDir(t), "cred")
	u, g := noAgents()
	if _, err := Write(credTarget(p), newValue("v"), u, g, testFPKey(t), WithSystemdCredPlaintextFallback(nil)); err == nil {
		t.Fatal("round-trip check ran (or was skipped) with a binary that turned group/other-writable")
	}
}
