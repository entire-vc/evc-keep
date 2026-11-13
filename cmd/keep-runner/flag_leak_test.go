package main

import (
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// A mistyped flag, a bad bool or an env default must never be echoed by the
// flag parser: a secret pasted into the wrong place would land in the terminal.
func runFlagCase(t *testing.T, cmd func([]string) int, args []string) (int, string) {
	t.Helper()
	rc, stdout, stderr := captureEnrollOutput(t, "", func() int { return cmd(args) })
	return rc, stdout + stderr
}

func TestRunnerFlagParserNeverEchoesInput(t *testing.T) {
	c := canary.New()
	cmds := map[string]func([]string) int{"enroll": runEnroll, "check": runCheck}
	for name, cmd := range cmds {
		cases := map[string][]string{
			"unknown-flag":      {"-" + c.Value(1)},
			"unknown-flag-eq":   {"--" + c.Value(2) + "=x"},
			"positional-tail":   {"-host", "h", c.Value(3)},
			"after-separator":   {"--", c.Value(4)},
			"bad-flag-value":    {"-cred-dir"},
			"unknown-with-help": {"-" + c.Value(5), "-h"},
		}
		if name == "enroll" {
			cases["invalid-bool"] = []string{"-insecure-skip-verify=" + c.Value(6)}
		}
		for cn, args := range cases {
			t.Run(name+"/"+cn, func(t *testing.T) {
				rc, out := runFlagCase(t, cmd, args)
				if c.In(out) {
					t.Errorf("canary reached the terminal (%d bytes)", len(out))
				}
				if rc == 0 && cn != "unknown-with-help" {
					t.Errorf("exit 0 on bad arguments")
				}
			})
		}
	}
}

func TestRunnerHelpNeverPrintsEnvDefaults(t *testing.T) {
	c := canary.New()
	t.Setenv("KEEP_SERVER", c.Value(1))
	t.Setenv("KEEP_SERVER_CA", c.Value(2))
	for name, cmd := range map[string]func([]string) int{"enroll": runEnroll, "check": runCheck} {
		for _, h := range []string{"-h", "-help", "--help"} {
			t.Run(name+h, func(t *testing.T) {
				rc, out := runFlagCase(t, cmd, []string{h})
				if c.In(out) {
					t.Errorf("env default reached the terminal")
				}
				if rc != 0 {
					t.Errorf("help exit = %d, want 0", rc)
				}
				if !strings.Contains(out, "-policy") {
					t.Errorf("help does not list option names (%d bytes)", len(out))
				}
			})
		}
	}
}

func TestRunnerFlagValidArgsReachValidation(t *testing.T) {
	rc, out := runFlagCase(t, runEnroll, []string{"-host", "h"})
	if rc != 2 || !strings.Contains(out, "-policy") || !strings.Contains(out, "required") {
		t.Errorf("valid flags must reach the required-flags check: rc=%d out_len=%d", rc, len(out))
	}
	rc, out = runFlagCase(t, runCheck, []string{"-cred-dir", t.TempDir()})
	if rc != 2 || !strings.Contains(out, "-policy is required") {
		t.Errorf("rc=%d out_len=%d", rc, len(out))
	}
}

// Positional arguments are rejected even when every required flag is valid,
// so the NArg guard cannot be deleted without a red test.
func TestRunnerFlagPositionalRejectedWithValidFlags(t *testing.T) {
	c := canary.New()
	pol := enrollPolicyFixture(t)
	rc, out := runFlagCase(t, runEnroll, []string{"-host", "h", "-server", "https://127.0.0.1:1", "-policy", pol, c.Value(1)})
	if rc != 2 || !strings.Contains(out, "invalid arguments") || c.In(out) {
		t.Errorf("enroll rc=%d, want 2 with fixed message (leak=%v)", rc, c.In(out))
	}
	rc, out = runFlagCase(t, runCheck, []string{"-policy", pol, c.Value(2)})
	if rc != 2 || !strings.Contains(out, "invalid arguments") || c.In(out) {
		t.Errorf("check rc=%d, want 2 with fixed message (leak=%v)", rc, c.In(out))
	}
}

// A bare "--" is rejected like a positional tail, while "--" as a flag value
// is still just a value.
func TestRunnerFlagBareSeparatorRejected(t *testing.T) {
	pol := enrollPolicyFixture(t)
	base := []string{"-host", "h", "-server", "https://127.0.0.1:1", "-policy", pol}
	rc, out := runFlagCase(t, runEnroll, append(append([]string{}, base...), "--"))
	if rc != 2 || !strings.Contains(out, "invalid arguments") {
		t.Errorf("enroll trailing --: rc=%d out_len=%d", rc, len(out))
	}
	rc, out = runFlagCase(t, runCheck, []string{"-policy", pol, "--"})
	if rc != 2 || !strings.Contains(out, "invalid arguments") {
		t.Errorf("check trailing --: rc=%d out_len=%d", rc, len(out))
	}
	rc, out = runFlagCase(t, runCheck, []string{"-policy", "--"})
	if strings.Contains(out, "invalid arguments") {
		t.Errorf("-- as a flag value must not be treated as a separator: rc=%d out_len=%d", rc, len(out))
	}
}

// "--" as a flag value must not hide a positional tail from the NArg guard
// (the separator probe re-parses prefixes and used to reset fs.Args()).
func TestRunnerFlagSeparatorValueKeepsPositionalGuard(t *testing.T) {
	c := canary.New()
	rc, out := runFlagCase(t, runCheck, []string{"-policy", "--", "-cred-dir", t.TempDir(), c.Value(1)})
	if rc != 2 || !strings.Contains(out, "invalid arguments") || c.In(out) {
		t.Errorf("check rc=%d out_len=%d (leak=%v)", rc, len(out), c.In(out))
	}
	rc, out = runFlagCase(t, runEnroll, []string{"-host", "h", "-server", "https://127.0.0.1:1", "-policy", "--", "unexpected-tail"})
	if rc != 2 || !strings.Contains(out, "invalid arguments") {
		t.Errorf("enroll rc=%d out_len=%d", rc, len(out))
	}
}
