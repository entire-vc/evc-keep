package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestMainRemovesItsBinaryDirectory guards the scratch directory TestMain
// builds the keep binary into. os.Exit skips deferred calls, so a TestMain
// that defers RemoveAll and then calls os.Exit(m.Run()) leaks one directory
// with a full binary in it on every run. The test re-runs this package's own
// suite in a subprocess with a TMPDIR of its own and requires that nothing
// is left in it afterwards — on success, on a failing test and on a failed
// build.
func TestMainRemovesItsBinaryDirectory(t *testing.T) {
	cases := []struct {
		name     string
		env      []string
		wantFail bool
	}{
		{"suite passes", nil, false},
		{"a test fails", []string{"KEEP_E2E_PROBE_FAIL=1"}, true},
		{"build fails", []string{"KEEP_E2E_PROBE_BUILD_FAIL=1"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			cmd := exec.Command("go", "test", "-count=1", "-run", "^TestMainProbe$", ".") //nolint:gosec // G204: fixed argv
			cmd.Env = append(os.Environ(), "TMPDIR="+tmp, "GOTMPDIR="+tmp)
			cmd.Env = append(cmd.Env, tc.env...)
			out, err := cmd.CombinedOutput()
			if tc.wantFail && err == nil {
				t.Fatalf("the probe run was expected to fail and passed:\n%s", out)
			}
			if !tc.wantFail && err != nil {
				t.Fatalf("the probe run was expected to pass: %v\n%s", err, out)
			}
			left, _ := filepath.Glob(filepath.Join(tmp, "keep-cli-e2e-*"))
			if len(left) != 0 {
				t.Fatalf("TestMain left %d scratch director(ies) behind: %v", len(left), left)
			}
		})
	}
}

// TestMainProbe is the inner test TestMainRemovesItsBinaryDirectory selects in
// its subprocess runs; on its own it always passes, and it fails only when the
// probe asks it to.
func TestMainProbe(t *testing.T) {
	if os.Getenv("KEEP_E2E_PROBE_FAIL") == "1" {
		t.Fatal("probe: failing on request")
	}
}
