//go:build unix

package targets

import (
	"bytes"
	"fmt"
	"github.com/entire-vc/evc-keep/internal/testutil/fdredirect"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

// fakeSystemdCreds installs a stand-in for the trusted binary: a shell
// script that records its arguments and its environment to files next to it
// and passes stdin through, so `encrypt` and `decrypt` round-trip. The
// trust rule (root-owned) is pointed at this process's own uid for the test
// — the rule is exercised, only its constant is swapped.
func fakeSystemdCreds(t *testing.T) (bin, argsFile, envFile string) {
	t.Helper()
	dir := realDir(t)
	bin = filepath.Join(dir, "systemd-creds")
	argsFile = filepath.Join(dir, "args")
	envFile = filepath.Join(dir, "env")
	script := fmt.Sprintf("#!/bin/sh\necho \"$@\" >> %s\nenv >> %s\ncat\n", argsFile, envFile)
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil { //nolint:gosec // G306: an executable test double
		t.Fatal(err)
	}
	if err := os.Chmod(bin, 0o755); err != nil { //nolint:gosec // G302: same reason
		t.Fatal(err)
	}
	origPath, origUID := sealToolPath, sealToolTrustedUID
	t.Cleanup(func() { sealToolPath, sealToolTrustedUID = origPath, origUID })
	sealToolPath, sealToolTrustedUID = bin, selfUID()
	return bin, argsFile, envFile
}

// credTarget is a systemd-credential target; the credential's name comes from
// the consuming unit (Field is not used by this kind).
func credTarget(path string) runnerproto.Target {
	tg := target(runnerproto.TargetSystemdCredential, path, "")
	tg.Unit = "keep-test.service"
	return tg
}

func absentSystemdCreds(t *testing.T) {
	t.Helper()
	origPath := sealToolPath
	t.Cleanup(func() { sealToolPath = origPath })
	sealToolPath = filepath.Join(realDir(t), "no-such-systemd-creds")
}

// TestSystemdCredentialFallbackWithoutBinary: no systemd-creds at the fixed
// path, so the value is written as-is, same as the "file" kind — still
// through this package's full symlink/hardlink/agent-read defenses, just
// not sealed to the host.
func TestSystemdCredentialFallbackWithoutBinary(t *testing.T) {
	absentSystemdCreds(t)
	dir := realDir(t)
	path := filepath.Join(dir, "cred")
	uids, gids := noAgents()
	key := testFPKey(t)
	fp, err := Write(target(runnerproto.TargetSystemdCredential, path, ""), newValue("cred-value"), uids, gids, key, WithSystemdCredPlaintextFallback(nil))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := string(mustReadFile(t, path)); got != "cred-value" {
		t.Fatalf("fallback did not write the raw value: %s", show([]byte(got)))
	}
	want, err := fingerprint.Compute(key, newValue("cred-value"))
	if err != nil {
		t.Fatal(err)
	}
	if fp != want {
		t.Fatalf("fingerprint %q != %q", fp, want)
	}
}

// TestSystemdCredentialsBinaryNotLookedUpOnPATH: a systemd-creds planted in
// a PATH directory (on a host where an agent account owns a PATH directory) must not
// receive the value. The positive control first proves the plant *would* be
// found by a PATH lookup, so a green result means the lookup is not made.
func TestSystemdCredentialsBinaryNotLookedUpOnPATH(t *testing.T) {
	absentSystemdCreds(t)
	planted := t.TempDir()
	marker := filepath.Join(planted, "received")
	script := fmt.Sprintf("#!/bin/sh\ncat > %s\ncat %s\n", marker, marker)
	if err := os.WriteFile(filepath.Join(planted, "systemd-creds"), []byte(script), 0o755); err != nil { //nolint:gosec // G306: an executable test double
		t.Fatal(err)
	}
	t.Setenv("PATH", planted+string(os.PathListSeparator)+os.Getenv("PATH"))
	found, err := exec.LookPath("systemd-creds")
	if err != nil || filepath.Dir(found) != planted {
		t.Fatalf("control failed: PATH lookup does not find the planted binary (%q, %v)", found, err)
	}

	dir := realDir(t)
	path := filepath.Join(dir, "cred")
	uids, gids := noAgents()
	if _, err := Write(credTarget(path), newValue("the-secret-value"), uids, gids, testFPKey(t), WithSystemdCredPlaintextFallback(nil)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := os.Stat(marker); err == nil {
		b, _ := os.ReadFile(marker) //nolint:gosec // G304: test path
		t.Fatalf("the planted binary was run and received %d bytes", len(b))
	}
}

// TestSystemdCredentialsChildEnvironmentMinimal: the child does not inherit
// the runner's environment.
func TestSystemdCredentialsChildEnvironmentMinimal(t *testing.T) {
	_, argsFile, envFile := fakeSystemdCreds(t)
	t.Setenv("KEEP_TEST_RUNNER_ONLY", "must-not-reach-the-child")

	dir := realDir(t)
	uids, gids := noAgents()
	key := testFPKey(t)
	fp, err := Write(credTarget(filepath.Join(dir, "cred")), newValue("cred-value"), uids, gids, key)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	want, err := fingerprint.Compute(key, newValue("cred-value"))
	if err != nil {
		t.Fatal(err)
	}
	if fp != want {
		t.Fatalf("round-trip fingerprint %q != %q", fp, want)
	}
	// Exact argv, not just substrings: --name= must be present in both calls
	// at the position credName produced it, not merely somewhere in the file.
	args := string(mustReadFile(t, argsFile))
	wantArgs := "encrypt --name=keep-test.service - -\ndecrypt --name=keep-test.service - -\n"
	if args != wantArgs {
		t.Fatalf("unexpected invocation: got %d bytes across %d lines, want %d bytes across %d lines",
			len(args), strings.Count(args, "\n"), len(wantArgs), strings.Count(wantArgs, "\n"))
	}
	env := mustReadFile(t, envFile)
	// Names only: the runner's environment holds tokens, and a failing guard
	// must not print them into a CI log.
	if slices.Contains(envNames(env), "KEEP_TEST_RUNNER_ONLY") {
		t.Fatalf("the child inherited the runner's environment; variables beyond the allowed set: %v", unexpectedEnvNames(env))
	}
	if strings.Contains(string(env), "cred-value") {
		t.Fatal("the value reached the child's environment")
	}
	if strings.Contains(args, "cred-value") {
		t.Fatal("the value was passed in argv")
	}
}

// TestSystemdCredentialsUntrustedBinaryRefused: a binary at the fixed path
// that is writable by others, owned by someone else, or a symlink is not
// run — and, as importantly, is not silently replaced by the plaintext
// fallback.
func TestSystemdCredentialsUntrustedBinaryRefused(t *testing.T) {
	for name, mutate := range map[string]func(t *testing.T, bin string){
		"group-writable": func(t *testing.T, bin string) {
			if err := os.Chmod(bin, 0o775); err != nil { //nolint:gosec // G302: the untrusted mode is the scenario
				t.Fatal(err)
			}
		},
		"other-writable": func(t *testing.T, bin string) {
			if err := os.Chmod(bin, 0o757); err != nil { //nolint:gosec // G302: the untrusted mode is the scenario
				t.Fatal(err)
			}
		},
		"foreign-owner": func(t *testing.T, _ string) { sealToolTrustedUID = selfUID() + 1 },
		// A directory (mode 0755, right owner) passes every check but the type
		// one — a symlink cannot show that on Linux, where its own mode is
		// always 0777 and trips the writable check first.
		"directory": func(t *testing.T, bin string) {
			if err := os.Remove(bin); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(bin, 0o755); err != nil { //nolint:gosec // G301: a 0755 directory is the scenario
				t.Fatal(err)
			}
		},
		"symlink": func(t *testing.T, bin string) {
			real := bin + ".real"
			if err := os.Rename(bin, real); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(real, bin); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			bin, argsFile, _ := fakeSystemdCreds(t)
			mutate(t, bin)
			dir := realDir(t)
			path := filepath.Join(dir, "cred")
			uids, gids := noAgents()
			_, err := Write(credTarget(path), newValue("cred-value"), uids, gids, testFPKey(t))
			wantErr(t, err, ErrPolicy, "untrusted systemd-creds binary")
			if _, err := os.Stat(argsFile); err == nil {
				t.Fatal("the untrusted binary was run")
			}
			if _, err := os.Stat(path); err == nil {
				t.Fatal("a credential file was written despite the refusal (plaintext fallback)")
			}
		})
	}
}

// TestSystemdCredentialWithBinary runs the real systemd-creds where one is
// installed and trusted at the fixed path (a systemd host; never this
// repo's alpine CI images); everywhere else the fake above covers the same
// call path. Together with the Hermes loader tests (which need
// KEEP_HERMES_PYTHON) it is one of the few tests in this package that may skip.
func TestSystemdCredentialWithBinary(t *testing.T) {
	bin, present, err := findSystemdCreds()
	if err != nil || !present {
		t.Skipf("no trusted systemd-creds at %s on this host", sealToolPath)
	}
	_ = bin
	dir := realDir(t)
	path := filepath.Join(dir, "cred")
	uids, gids := noAgents()
	key := testFPKey(t)
	fp, err := Write(credTarget(path), newValue("cred-value"), uids, gids, key)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	on := mustReadFile(t, path)
	if string(on) == "cred-value" {
		t.Fatal("value was written in the clear despite systemd-creds being available")
	}
	want, err := fingerprint.Compute(key, newValue("cred-value"))
	if err != nil {
		t.Fatal(err)
	}
	if fp != want {
		t.Fatalf("round-trip fingerprint %q != %q", fp, want)
	}
}

// TestSystemdCredentialsFailureDoesNotEchoValue: the tool fails after having
// read the value and echoes it on stderr and stdout, as a badly behaved one
// might. Nothing it printed may reach the error text, and the value is only
// ever on stdin — not in the recorded argv.
func TestSystemdCredentialsFailureDoesNotEchoValue(t *testing.T) {
	c := canary.New()
	dir := realDir(t)
	bin := filepath.Join(dir, "systemd-creds")
	argsFile := filepath.Join(dir, "args")
	script := fmt.Sprintf("#!/bin/sh\necho \"$@\" > %s\nv=$(cat)\necho \"$v\" >&2\necho \"$v\"\nexit 3\n", argsFile)
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil { //nolint:gosec // G306: an executable test double
		t.Fatal(err)
	}
	if err := os.Chmod(bin, 0o755); err != nil { //nolint:gosec // G302: same reason
		t.Fatal(err)
	}
	origPath, origUID := sealToolPath, sealToolTrustedUID
	t.Cleanup(func() { sealToolPath, sealToolTrustedUID = origPath, origUID })
	sealToolPath, sealToolTrustedUID = bin, selfUID()

	uids, gids := noAgents()
	_, err := Write(credTarget(filepath.Join(dir, "cred")), newValue(c.Value(0)), uids, gids, testFPKey(t))
	wantErr(t, err, ErrWrite, "systemd-creds exiting non-zero")
	if c.In(err.Error()) {
		t.Fatalf("the tool's output reached the error text: %v", err)
	}
	if c.In(string(mustReadFile(t, argsFile))) {
		t.Fatal("the value was passed in argv")
	}
}

// TestSystemdCredentialsChildStderrNotConnectedToProcess proves runPiped
// never wires the child's stderr to this process's own — see the comment on
// runPiped. TestSystemdCredentialsFailureDoesNotEchoValue only proves the
// tool's stderr does not reach the *error text*; it says nothing about
// whether the child's stderr fd was ever connected to this process's real
// stderr, where a well-behaved child's own diagnostics would land instead.
func TestSystemdCredentialsChildStderrNotConnectedToProcess(t *testing.T) {
	const marker = "systemd-creds-stderr-marker"
	dir := realDir(t)
	bin := filepath.Join(dir, "systemd-creds")
	script := fmt.Sprintf("#!/bin/sh\necho %s >&2\ncat\n", marker)
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil { //nolint:gosec // G306: an executable test double
		t.Fatal(err)
	}
	if err := os.Chmod(bin, 0o755); err != nil { //nolint:gosec // G302: same reason
		t.Fatal(err)
	}
	origPath, origUID := sealToolPath, sealToolTrustedUID
	t.Cleanup(func() { sealToolPath, sealToolTrustedUID = origPath, origUID })
	sealToolPath, sealToolTrustedUID = bin, selfUID()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origStderr := os.Stderr
	t.Cleanup(func() { os.Stderr = origStderr })
	os.Stderr = w
	uids, gids := noAgents()
	_, werr := Write(credTarget(filepath.Join(dir, "cred")), newValue("cred-value"), uids, gids, testFPKey(t))
	os.Stderr = origStderr
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if werr != nil {
		t.Fatalf("Write: %v", werr)
	}
	captured, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(captured) != 0 {
		t.Fatalf("the child's stderr reached the process's own stderr: %d bytes across %d lines",
			len(captured), strings.Count(string(captured), "\n"))
	}
}

// TestSystemdCredentialsRealStderrFDNotConnectedToChild proves the same
// property one layer deeper than TestSystemdCredentialsChildStderrNotConnectedToProcess:
// that test only reassigns the os.Stderr package variable, which runPiped
// never reads. A regression that wired the child's stderr through the raw
// process file descriptor instead — cmd.Stderr = os.NewFile(2, "stderr"),
// bypassing os.Stderr entirely — would pass that test and still leak here.
// Not t.Parallel: it dups over this process's real fd 2 for the duration.
func TestSystemdCredentialsRealStderrFDNotConnectedToChild(t *testing.T) {
	const marker = "systemd-creds-stderr-fd-marker"
	dir := realDir(t)
	bin := filepath.Join(dir, "systemd-creds")
	script := fmt.Sprintf("#!/bin/sh\necho %s >&2\ncat\n", marker)
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil { //nolint:gosec // G306: an executable test double
		t.Fatal(err)
	}
	if err := os.Chmod(bin, 0o755); err != nil { //nolint:gosec // G302: same reason
		t.Fatal(err)
	}
	origPath, origUID := sealToolPath, sealToolTrustedUID
	t.Cleanup(func() { sealToolPath, sealToolTrustedUID = origPath, origUID })
	sealToolPath, sealToolTrustedUID = bin, selfUID()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	// F_DUPFD_CLOEXEC, not unix.Dup: a plain dup leaves the saved copy of fd 2
	// open across the child's exec, which would let the child write to this
	// process's real stderr through *that* fd and pass the test undetected —
	// the same hole this test exists to catch, one fd number further along.
	savedFD, err := unix.FcntlInt(2, unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		if err := fdredirect.Dup2(savedFD, 2); err != nil {
			t.Fatalf("could not restore the real fd 2: %v", err)
		}
		if err := unix.Close(savedFD); err != nil {
			t.Fatalf("could not close the saved fd 2 copy: %v", err)
		}
	}
	t.Cleanup(restore)
	if err := fdredirect.Dup2(int(w.Fd()), 2); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// fd 2 stays redirected only across this call: a race report the runtime
	// would otherwise print in this window lands in the pipe as opaque bytes
	// instead, read back and reported by count below, not lost. A panic in
	// this window is not that safe: the process dies before io.ReadAll runs,
	// so the trace is lost outright, and a trace bigger than the pipe buffer
	// would block the write and hang this test until its own timeout. The
	// window stays this narrow specifically to keep that risk small.
	uids, gids := noAgents()
	_, werr := Write(credTarget(filepath.Join(dir, "cred")), newValue(canary.New().Value(0)), uids, gids, testFPKey(t))
	restore()
	if werr != nil {
		t.Fatalf("Write: %v", werr)
	}
	captured, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(captured) != 0 {
		t.Fatalf("the child's stderr reached this process's real fd 2: %d bytes across %d lines",
			len(captured), strings.Count(string(captured), "\n"))
	}
}

// childEnvAllowed is what the child may see: the variables childEnv sets, and
// the ones a shell adds to its own environment on start (the stand-in binary is
// a shell script).
var childEnvAllowed = []string{"PATH", "PWD", "OLDPWD", "SHLVL", "_"}

func unexpectedEnvNames(env []byte) []string {
	var extra []string
	for _, n := range envNames(env) {
		if !slices.Contains(childEnvAllowed, n) {
			extra = append(extra, n)
		}
	}
	return extra
}

// TestSystemdCredentialsChildEnvironmentExact: the child's environment is
// exactly the fixed one, not "the runner's minus one variable" — any extra
// variable, HOME included, is a way for the runner's state to reach a binary
// that receives the secret.
func TestSystemdCredentialsChildEnvironmentExact(t *testing.T) {
	_, _, envFile := fakeSystemdCreds(t)
	t.Setenv("HOME", "/nonexistent-home")
	uids, gids := noAgents()
	if _, err := Write(credTarget(filepath.Join(realDir(t), "cred")), newValue("cred-value"), uids, gids, testFPKey(t)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	env := mustReadFile(t, envFile)
	if extra := unexpectedEnvNames(env); len(extra) > 0 {
		t.Fatalf("the child has variables beyond the fixed environment: %v", extra)
	}
	if !strings.Contains(string(env), "PATH=/usr/sbin:/usr/bin:/sbin:/bin\n") {
		t.Fatal("the child's PATH is not the fixed one")
	}
}

// TestSystemdCredentialsDecoyOnPATHNotRunWhenTrustedBinaryExists: with a
// trusted binary at the fixed path *and* a same-named decoy first on PATH, the
// fixed one runs and the decoy never sees the value. (The absent-binary case is
// TestSystemdCredentialsBinaryNotLookedUpOnPATH; this one is where a lookup by
// name would go unnoticed, since the fixed binary works too.)
func TestSystemdCredentialsDecoyOnPATHNotRunWhenTrustedBinaryExists(t *testing.T) {
	_, argsFile, _ := fakeSystemdCreds(t)
	planted := t.TempDir()
	marker := filepath.Join(planted, "received")
	script := fmt.Sprintf("#!/bin/sh\ncat > %s\ncat %s\n", marker, marker)
	if err := os.WriteFile(filepath.Join(planted, "systemd-creds"), []byte(script), 0o755); err != nil { //nolint:gosec // G306: an executable test double
		t.Fatal(err)
	}
	t.Setenv("PATH", planted+string(os.PathListSeparator)+os.Getenv("PATH"))
	if found, err := exec.LookPath("systemd-creds"); err != nil || filepath.Dir(found) != planted {
		t.Fatalf("control failed: a lookup by name does not find the decoy (%q, %v)", found, err)
	}
	uids, gids := noAgents()
	if _, err := Write(credTarget(filepath.Join(realDir(t), "cred")), newValue("cred-value"), uids, gids, testFPKey(t)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the decoy on PATH was run and received the value")
	}
	if _, err := os.Stat(argsFile); err != nil {
		t.Fatal("the trusted binary at the fixed path was not run")
	}
}

// TestSystemdCredentialsTrustDefaults: every other test points the path and
// the trusted owner at a stand-in; the production values are what stops a
// binary planted where the agents can write.
func TestSystemdCredentialsTrustDefaults(t *testing.T) {
	if sealToolPath != "/usr/bin/systemd-creds" {
		t.Fatalf("sealToolPath = %q, want the fixed system path", sealToolPath)
	}
	if sealToolTrustedUID != 0 {
		t.Fatalf("sealToolTrustedUID = %d, want root", sealToolTrustedUID)
	}
}

// TestRunPipedWipesPartialStdoutOnFailure: a decrypt that streams plaintext
// and then fails must leave no copy of what it already wrote. runPiped used to
// read into a bytes.Buffer behind exec's own 32 KiB copy buffer: the buffer
// abandoned its old backing array on every growth, and on error the whole
// partial output was dropped unwiped. Goes through the wipe seam, same as
// TestBuildWipesIntermediateJSONBuffers: records a copy of every slice at the
// moment it is zeroed, then checks that every one is zero afterwards, that the
// full partial output was among them, and that the read chunk and every
// abandoned growth step were too.
func TestRunPipedWipesPartialStdoutOnFailure(t *testing.T) {
	c := canary.New()
	val := c.Value(0)
	const reps = 600
	dir := realDir(t)
	bin := filepath.Join(dir, "partial-then-fail")
	script := fmt.Sprintf("#!/bin/sh\ni=0\nwhile [ $i -lt %d ]; do printf '%%s' '%s'; i=$((i+1)); done\nexit 1\n", reps, val)
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil { //nolint:gosec // G306: an executable test double
		t.Fatal(err)
	}
	if err := os.Chmod(bin, 0o755); err != nil { //nolint:gosec // G302: same reason
		t.Fatal(err)
	}

	type snapshot struct {
		before []byte
		live   []byte
	}
	var snaps []snapshot
	orig := wipe
	defer func() { wipe = orig }()
	wipe = func(b []byte) {
		if len(b) > 0 {
			before := make([]byte, len(b))
			copy(before, b)
			snaps = append(snaps, snapshot{before: before, live: b})
		}
		orig(b)
	}

	out, err := runPiped(bin, nil, []byte("ignored"))
	if err == nil {
		t.Fatal("runPiped: want the child's failure, got nil")
	}
	if out != nil {
		t.Fatalf("runPiped returned %d bytes alongside an error", len(out))
	}
	if c.In(err.Error()) {
		t.Fatal("the error carries the value")
	}
	if len(snaps) == 0 {
		t.Fatal("wipe was never called")
	}
	total := reps * len(val)
	full := []byte(strings.Repeat(val, reps))
	var sawFull, sawChunk, growthSteps int
	for i, s := range snaps {
		for j, b := range s.live {
			if b != 0 {
				t.Fatalf("wiped slice %d not zero at byte %d", i, j)
			}
		}
		switch {
		case bytes.HasPrefix(s.before, full):
			sawFull++
		case len(s.before) == pipeChunk:
			sawChunk++
		case c.In(string(s.before)):
			growthSteps++
		}
	}
	if sawFull != 1 {
		t.Fatalf("the full partial output (%d bytes) was wiped %d times, want once", total, sawFull)
	}
	if sawChunk == 0 {
		t.Fatalf("the %d-byte read chunk was never wiped", pipeChunk)
	}
	if growthSteps == 0 {
		t.Fatal("no abandoned growth step was wiped; the output never outgrew its first allocation")
	}
}

// Keep stdout below the initial output capacity: no output allocation can
// have the read chunk's length. With a large stream, a growth step can also
// be pipeChunk bytes, falsely witnessing the chunk's wipe when it is absent.
func TestRunPipedWipesReadChunk(t *testing.T) {
	for _, exitCode := range []int{0, 1} {
		t.Run(fmt.Sprintf("exit-%d", exitCode), func(t *testing.T) {
			c := canary.New()
			in := []byte(c.Value(0))
			if len(in) == 0 || len(in) >= 512 || len(in) >= pipeChunk {
				t.Fatal("fixture must fit in the initial output allocation and read chunk")
			}
			bin := filepath.Join(realDir(t), "short-stdout")
			script := fmt.Sprintf("#!/bin/sh\ncat\nexit %d\n", exitCode)
			if err := os.WriteFile(bin, []byte(script), 0o755); err != nil { //nolint:gosec // G306: an executable test double
				t.Fatal(err)
			}
			if err := os.Chmod(bin, 0o755); err != nil { //nolint:gosec // G302: same reason
				t.Fatal(err)
			}

			var before, live []byte
			var chunkWipes int
			orig := wipe
			defer func() { wipe = orig }()
			wipe = func(b []byte) {
				if len(b) == pipeChunk {
					chunkWipes++
					before = append([]byte(nil), b...)
					live = b
				}
				orig(b)
			}

			out, err := runPiped(bin, nil, in)
			defer wipe(out)
			if exitCode == 0 {
				if err != nil || !bytes.Equal(out, in) {
					t.Fatal("successful child did not return the complete stdout")
				}
			} else {
				if err == nil || out != nil {
					t.Fatal("failed child must return an error and no stdout")
				}
				if c.In(err.Error()) {
					t.Fatal("the error carries the value")
				}
			}
			if chunkWipes != 1 {
				t.Fatalf("read chunk was wiped %d times, want once", chunkWipes)
			}
			if !bytes.HasPrefix(before, in) {
				t.Fatal("the wiped read chunk did not contain the child's stdout")
			}
			for _, b := range live {
				if b != 0 {
					t.Fatal("read chunk retained stdout after the wipe")
				}
			}
		})
	}
}

// TestRunPipedReturnsOutputOnSuccess: the wiping reader is still a reader.
func TestRunPipedReturnsOutputOnSuccess(t *testing.T) {
	bin, _, _ := fakeSystemdCreds(t)
	in := []byte(strings.Repeat("0123456789", 2000))
	out, err := runPiped(bin, []string{"decrypt", "-", "-"}, in)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(in) {
		t.Fatalf("round trip differs: got %d bytes, want %d", len(out), len(in))
	}
}

// TestSystemdReadBackWipesDecryptedOutput: readBack hands the decrypted bytes
// to secret.New, which copies them; the slice runPiped returned must be wiped
// by readBack, not left for the garbage collector. Through the wipe seam: a
// snapshot equal to the round-trip content must exist and be zero afterwards.
func TestSystemdReadBackWipesDecryptedOutput(t *testing.T) {
	fakeSystemdCreds(t)
	c := canary.New()
	content := []byte(strings.Repeat(c.Value(0), 50))

	var before [][]byte
	var live [][]byte
	orig := wipe
	defer func() { wipe = orig }()
	wipe = func(b []byte) {
		if len(b) > 0 {
			before = append(before, append([]byte(nil), b...))
			live = append(live, b)
		}
		orig(b)
	}
	v, err := systemdCredentialHandler{}.readBack(content, credTarget("/unused"))
	if err != nil {
		t.Fatal(err)
	}
	_ = v
	found := false
	for i, b := range before {
		if bytes.Equal(b, content) {
			found = true
			for _, x := range live[i] {
				if x != 0 {
					t.Fatal("the decrypted output was not zero after readBack")
				}
			}
		}
	}
	if !found {
		t.Fatal("readBack never wiped the decrypted output")
	}
}
