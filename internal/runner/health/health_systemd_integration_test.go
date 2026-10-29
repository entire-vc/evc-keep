package health

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"
)

// TestSystemdRealRestartAndHealthcheck is the systemd counterpart of
// TestLaunchdRealRestartAndHealthcheck: a real, throwaway transient unit —
// started via systemd-run against the real systemd manager, not a unit file
// this test writes by hand — is restarted via restart() and observed via
// runUnitActive() against the real systemctl binary, not the fakeRunner
// every other test in this package uses.
//
// A fakeRunner-based test only proves this package parses the exit code and
// output shape it expects launchctl/systemctl to produce; it says nothing
// about whether that shape is what the real binary actually produces. This
// test is the one that closes that gap for systemd — verified green
// end-to-end inside a container that runs actual systemd as PID 1
// (debian:12 + systemd/systemd-sysv, started with --privileged
// --cgroupns=host and /lib/systemd/systemd as PID 1).
//
// Opt-in: registering even a throwaway unit is worth gating behind an
// explicit request, not running on every `go test` on a shared host — see
// KEEP_SYSTEMD_INTEGRATION below.
func TestSystemdRealRestartAndHealthcheck(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("systemd is linux-only")
	}
	if os.Getenv("KEEP_SYSTEMD_INTEGRATION") == "" {
		t.Skip("KEEP_SYSTEMD_INTEGRATION not set: registers a real transient systemd unit, opt-in only")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		// Same reasoning as the launchd test's bootstrap-privilege skip: a
		// process not actually running under systemd (no PID 1 manager to
		// talk to, e.g. a plain container without --privileged and a real
		// init) gets ENOENT/dial errors from systemd-run/systemctl that are
		// an environment gap, not evidence restart()/isActive() are wrong.
		// Open question, same as the launchd one: does the real
		// CI runner have systemd access? If not, this skips there too and
		// the systemd path stays covered only by the faked-systemctl unit
		// tests above plus the manual container run described in the
		// package doc comment above.
		t.Skipf("no /run/systemd/system: not running under a real systemd manager (%v) — environment gap, not a code defect", err)
	}

	unit := fmt.Sprintf("keep-healthtest-%d-%d", os.Getpid(), time.Now().UnixNano())
	consumer := "systemd:" + unit + ".service"
	ctx := context.Background()

	//nolint:gosec // G204: argv[0] is the fixed systemd-run path; unit is built from this process's own pid/time, never external input.
	run := exec.Command("/usr/bin/systemd-run", "--unit="+unit, "--collect", "/bin/sleep", "300")
	if out, err := run.CombinedOutput(); err != nil {
		t.Skipf("systemd-run --unit=%s: %v: %s (no systemd manager access from this process — environment gap, not a code defect)", unit, err, out)
	}
	// Idempotent safety net: if an assertion below fails the test via
	// Fatalf before the explicit stop later in this function runs, this
	// still tears the unit down. A second stop after the explicit one
	// harmlessly errors on "not loaded" — error discarded on purpose.
	t.Cleanup(func() {
		//nolint:gosec // G204: unit is built from this test's own pid/time, never external input.
		_ = exec.Command("/usr/bin/systemctl", "stop", unit+".service").Run()
	})

	// The unit started running via systemd-run; restart must find it,
	// restart it again, and the health check must observe it running
	// afterward — against the REAL systemctl restart/is-active, not
	// fakeRunner. This also exercises execRunner's own explicit empty Env
	// against a real systemctl invocation, not just the fake in every other
	// test.
	if err := restart(ctx, execRunner{}, consumer, 0); err != nil {
		t.Fatalf("restart: %v", err)
	}
	ok, err := runUnitActive(ctx, execRunner{}, consumer, 0, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("runUnitActive: unexpected error %v", err)
	}
	if !ok {
		t.Fatalf("runUnitActive: want active=true for a freshly restarted real systemd unit, got false")
	}

	// Tear down for real and confirm the health check now correctly
	// reports it gone.
	//nolint:gosec // G204: unit is built from this test's own pid/time, never external input.
	if out, err := exec.Command("/usr/bin/systemctl", "stop", unit+".service").CombinedOutput(); err != nil {
		t.Fatalf("systemctl stop: %v: %s", err, out)
	}
	ok, err = isActive(ctx, execRunner{}, consumer, 0)
	if err != nil {
		t.Fatalf("isActive: unexpected error %v", err)
	}
	if ok {
		t.Fatalf("isActive: want active=false after stop, got true")
	}
}
