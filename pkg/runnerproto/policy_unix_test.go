//go:build unix

package runnerproto

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A prefix through a symlink passes Check but every write under it is refused
// by the target writer's O_NOFOLLOW walk; the host check names the component.
// The symlink is made here, not taken from /var: on Linux /var is a plain
// directory and the test would have nothing to catch.
func TestCheckPrefixesOnHost(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	realDir := filepath.Join(base, "real")
	if err := os.MkdirAll(filepath.Join(realDir, "lib"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	pol := func(prefixes ...string) HostPolicy {
		return HostPolicy{Version: 1, Targets: []TargetRule{
			{Kind: TargetEnvFile, PathPrefixes: []string{realDir}},
			{Kind: TargetFile, PathPrefixes: prefixes},
		}}
	}

	for name, pre := range map[string]string{
		"real path":    filepath.Join(realDir, "lib"),
		"missing tail": filepath.Join(realDir, "lib", "not", "yet"),
		"missing dir":  filepath.Join(base, "absent"),
	} {
		if err := CheckPrefixesOnHost(pol(pre)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	for name, tc := range map[string]struct{ prefix, component string }{
		"symlink component": {filepath.Join(link, "lib"), link},
		"symlink leaf":      {link, link},
		"file component":    {filepath.Join(file, "x"), file},
	} {
		err := CheckPrefixesOnHost(pol(tc.prefix))
		if err == nil {
			t.Errorf("%s: prefix %q accepted", name, tc.prefix)
			continue
		}
		msg := err.Error()
		for _, want := range []string{`rule 1 (file)`, `component "` + tc.component + `"`} {
			if !strings.Contains(msg, want) {
				t.Errorf("%s: error %q lacks %q", name, msg, want)
			}
		}
	}
	err = CheckPrefixesOnHost(pol(filepath.Join(link, "lib")))
	if err == nil || !strings.Contains(err.Error(), "is a symlink") || !strings.Contains(err.Error(), filepath.Join(realDir, "lib")) {
		t.Errorf("symlink error does not name the real path: %v", err)
	}
	var pe *PrefixError
	err = CheckPrefixesOnHost(pol(filepath.Join(file, "x"), filepath.Join(link, "y")))
	if !errors.As(err, &pe) || pe.Class != PrefixNotDirectory || pe.Rule != 1 || pe.Prefix != 0 {
		t.Errorf("structured error: %#v", pe)
	}
	if err := CheckPrefixesOnHost(HostPolicy{Version: 1}); err != nil {
		t.Errorf("empty policy: %v", err)
	}
}

const policyFIFOHelperEnv = "RUNNERPROTO_POLICY_FIFO_HELPER"

// The helper runs LoadHostPolicy in a child process so a blocked open(2) can
// be killed instead of leaking a stuck goroutine into the test binary.
func TestLoadHostPolicyFIFOHelper(t *testing.T) {
	path := os.Getenv(policyFIFOHelperEnv)
	if path == "" {
		return // not a child run; returning keeps the suite free of a skip
	}
	begin := time.Now()
	_, err := LoadHostPolicy(path, os.Getuid())
	took := time.Since(begin)
	msg := "nil"
	if err != nil {
		msg = err.Error()
	}
	_, _ = fmt.Fprintf(os.Stdout, "TOOK:%d\nRESULT:%s\n", took.Milliseconds(), msg)
	os.Exit(0)
}

// A FIFO without a writer in place of the policy file must be refused as not
// a regular file within a second; a blocking open(2) would hang runner start.
func TestLoadHostPolicyRefusesFIFOWithoutWriter(t *testing.T) {
	p := filepath.Join(t.TempDir(), "policy.json")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLoadHostPolicyFIFOHelper$") //nolint:gosec // re-exec of the test binary
	cmd.Env = append(os.Environ(), policyFIFOHelperEnv+"="+p)
	var out bytes.Buffer
	cmd.Stdout = &out
	start := time.Now()
	err := cmd.Run() // CommandContext kills the child on timeout; Run waits for it
	if ctx.Err() != nil {
		t.Fatalf("LoadHostPolicy blocked on a FIFO without writer (child killed after %v)", time.Since(start))
	}
	if err != nil {
		t.Fatalf("helper: %v\n%s", err, out.String())
	}
	// The 1s bound is on LoadHostPolicy itself, measured in the child, so
	// process start-up under -race on a loaded host does not count.
	var ms int
	if _, err := fmt.Sscanf(out.String(), "TOOK:%d", &ms); err != nil || ms > 1000 {
		t.Errorf("refusal took %dms (parse err %v), want within 1s", ms, err)
	}
	if !strings.Contains(out.String(), "RESULT:runnerproto: host policy is not a regular file") {
		t.Errorf("want the not-a-regular-file refusal, got %q", out.String())
	}
}

// The O_NONBLOCK change must not weaken the other checks.
func TestLoadHostPolicyKeepsFileChecks(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, []byte(`{"version":1,"max_deploys_per_hour":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHostPolicy(good, os.Getuid()); err != nil {
		t.Fatalf("valid policy refused: %v", err)
	}
	loose := filepath.Join(dir, "loose.json")
	if err := os.WriteFile(loose, []byte(`{"version":1,"max_deploys_per_hour":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o640); err != nil { //nolint:gosec // G302: a deliberately loose mode is the case under test
		t.Fatal(err)
	}
	if _, err := LoadHostPolicy(loose, os.Getuid()); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Errorf("mode 0640 accepted: %v", err)
	}
	if _, err := LoadHostPolicy(good, os.Getuid()+1); err == nil || !strings.Contains(err.Error(), "not owned") {
		t.Errorf("foreign owner accepted: %v", err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHostPolicy(link, os.Getuid()); err == nil {
		t.Error("symlink accepted")
	}
}
