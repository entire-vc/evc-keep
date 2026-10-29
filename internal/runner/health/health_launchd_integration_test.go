package health

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
	"time"
)

// TestLaunchdRealRestartAndHealthcheck is the launchd integration test this
// feature needs: a real, throwaway LaunchAgent bootstrapped into this
// user's own user/<uid> domain — the same domain restartArgv targets — is
// restarted via restart() and observed via runUnitActive() against the
// real launchctl binary, not the fakeRunner every other test in this
// package uses.
//
// Opt-in: registering even a throwaway job is worth gating behind an
// explicit request, not running on every `go test` on a shared host — see
// KEEP_LAUNCHD_INTEGRATION below.
func TestLaunchdRealRestartAndHealthcheck(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("launchd is darwin-only")
	}
	if os.Getenv("KEEP_LAUNCHD_INTEGRATION") == "" {
		t.Skip("KEEP_LAUNCHD_INTEGRATION not set: registers a real throwaway LaunchAgent, opt-in only")
	}

	uid := os.Getuid()
	label := fmt.Sprintf("com.entire.keep-healthtest-%d-%d", os.Getpid(), time.Now().UnixNano())
	domainTarget := "user/" + strconv.Itoa(uid) + "/" + label

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>%s</string>
	<key>ProgramArguments</key>
	<array><string>/bin/sleep</string><string>300</string></array>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><false/>
</dict>
</plist>
`, label)

	plistPath := t.TempDir() + "/" + label + ".plist"
	if err := os.WriteFile(plistPath, []byte(plist), 0o600); err != nil {
		t.Fatalf("write plist: %v", err)
	}

	//nolint:gosec // G204: argv[0] is the fixed launchctl path; uid is this process's own os.Getuid() and plistPath a file this test just wrote under t.TempDir(), neither externally controlled.
	bootstrap := exec.Command("/bin/launchctl", "bootstrap", "user/"+strconv.Itoa(uid), plistPath)
	if out, err := bootstrap.CombinedOutput(); err != nil {
		// Confirmed by hand on this host (2026-09-25): an unprivileged,
		// interactively-run process can bootstrap into gui/<uid> but gets
		// "Bootstrap failed: 5: Input/output error" for user/<uid>, with an
		// otherwise-identical, valid plist — gui/<uid> succeeded in the same
		// session. restartArgv/isActive (execpolicy, pinned) target
		// user/<uid>, matching how a deployed keep-runner LaunchAgent
		// would run (itself resident in that domain, or invoked with
		// enough privilege to reach it) — not how this interactive dev
		// session runs. Skip rather than fail: this is an environment/
		// privilege gap in the harness, not evidence the code is wrong.
		// Open question: does the real CI runner (or whatever
		// executes keep-runner in prod) have user/<uid> access? If not,
		// this test skips there too and the launchd path stays covered
		// only by the faked-launchctl unit tests above.
		t.Skipf("launchctl bootstrap user/%d: %v: %s (see comment above — likely no user/<uid> access from this session, not a code defect)", uid, err, out)
	}
	// Idempotent safety net: if an assertion below fails the test via
	// Fatalf before the explicit bootout later in this function runs, this
	// still tears the job down. A second bootout after the explicit one
	// harmlessly errors on "not found" — error discarded on purpose.
	t.Cleanup(func() {
		//nolint:gosec // G204: domainTarget is built from this test's own uid/label, never external input.
		_ = exec.Command("/bin/launchctl", "bootout", domainTarget).Run()
	})

	consumer := "launchd:" + label
	ctx := context.Background()

	// The job started via RunAtLoad; restart must find it, kickstart it
	// again, and the health check must observe it running afterward —
	// against the REAL launchctl list/kickstart, not fakeRunner. This also
	// exercises execRunner's own explicit empty Env against a real
	// launchctl invocation, not just the fake in every other test.
	if err := restart(ctx, execRunner{}, consumer, int64(uid)); err != nil {
		t.Fatalf("restart: %v", err)
	}
	ok, err := runUnitActive(ctx, execRunner{}, consumer, int64(uid), 500*time.Millisecond)
	if err != nil {
		t.Fatalf("runUnitActive: unexpected error %v", err)
	}
	if !ok {
		t.Fatalf("runUnitActive: want active=true for a freshly kickstarted real LaunchAgent, got false")
	}

	// Tear down for real and confirm the health check now correctly
	// reports it gone — the real-world counterpart of
	// TestUnitActiveLaunchdListErrorAfterSettle's faked list error.
	//nolint:gosec // G204: domainTarget is built from this test's own uid/label, never external input.
	if out, err := exec.Command("/bin/launchctl", "bootout", domainTarget).CombinedOutput(); err != nil {
		t.Fatalf("launchctl bootout: %v: %s", err, out)
	}
	ok, err = isActive(ctx, execRunner{}, consumer, int64(uid))
	if err != nil {
		t.Fatalf("isActive: unexpected error %v", err)
	}
	if ok {
		t.Fatalf("isActive: want active=false after bootout, got true")
	}
}
