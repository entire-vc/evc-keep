package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// These probes use the real binary without a server: a credential pasted in
// a command or path slot must stay out of both output streams.
func runWrongSlotCLI(t *testing.T, stdin string, args ...string) runResult {
	t.Helper()
	return runWrongSlotCLIEnv(t, nil, stdin, args...)
}

func runWrongSlotCLIEnv(t *testing.T, env []string, stdin string, args ...string) runResult {
	t.Helper()
	cmd := exec.Command(keepBinPath, args...) //nolint:gosec // G204: the test-built binary and fake canary arguments
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH")}, env...)
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("run test binary: %v", err)
	}
	return runResult{stdout: stdout.String(), stderr: stderr.String(), exitCode: code}
}

func assertWrongSlotOutput(t *testing.T, c canary.Canary, res runResult, code int, marker string) {
	t.Helper()
	// Positive control checks both old leak shapes; the marker below proves
	// that the subprocess output was captured.
	if !c.In(fmt.Sprintf("keep: unknown command %q", c.Value(0))) ||
		!c.In("keep: token written to "+c.Value(0)) {
		t.Fatal("canary detector missed the known leak shapes")
	}
	if res.exitCode != code || !strings.Contains(res.stderr, marker) {
		t.Fatalf("exit %d, want %d; missing expected message=%v", res.exitCode, code, !strings.Contains(res.stderr, marker))
	}
	if c.In(res.stdout) || c.In(res.stderr) {
		t.Fatal("wrong-slot canary reached stdout/stderr")
	}
}

func TestCLI_UnknownCommandNeverEchoesArgument(t *testing.T) {
	for _, prefix := range []string{"", "-"} {
		t.Run(fmt.Sprintf("dash=%v", prefix != ""), func(t *testing.T) {
			c := canary.New()
			res := runWrongSlotCLI(t, "", prefix+c.Value(0))
			assertWrongSlotOutput(t, c, res, 2, "unknown command")
			if !strings.Contains(res.stderr, "Usage:") {
				t.Fatal("unknown command omitted static usage")
			}
		})
	}
}

func TestCLI_LoginTokenFileNeverEchoesPath(t *testing.T) {
	c := canary.New()
	path := filepath.Join(t.TempDir(), c.Value(0))
	res := runWrongSlotCLI(t, "test-stdin-value\n", "login", "--token-file", path)
	assertWrongSlotOutput(t, c, res, 0, "token written")
	if res.stderr != "keep: token written\n" || res.stdout != "" {
		t.Fatal("login success message must be static")
	}
	got, err := os.ReadFile(path) //nolint:gosec // G304: this test's own temporary canary path
	if err != nil || string(got) != "test-stdin-value\n" {
		t.Fatal("login did not write the stdin value")
	}
}

func TestCLI_TokenFileErrorsNeverEchoPath(t *testing.T) {
	for _, kind := range []string{"mkdir", "path-too-long", "rename", "read", "wide-mode", "empty"} {
		t.Run(kind, func(t *testing.T) {
			c := canary.New()
			path := filepath.Join(t.TempDir(), c.Value(0))
			args := []string{"login", "--token-file", path}
			switch kind {
			case "mkdir":
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(path, "child", "token")
			case "path-too-long":
				// Deterministically exceeds NAME_MAX on supported filesystems.
				path = filepath.Join(path+strings.Repeat("x", 300), "token")
			case "rename", "read":
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
				if kind == "read" {
					args = []string{"list", "--server", "http://127.0.0.1:1", "--org", "test", "--scope-level", "org", "--scope-id", "test", "--token-file", path}
				}
			case "wide-mode", "empty":
				mode := os.FileMode(0o600)
				if kind == "wide-mode" {
					mode = 0o644
				}
				if err := os.WriteFile(path, nil, mode); err != nil {
					t.Fatal(err)
				} //nolint:gosec // G306: deliberately wide permissions for the refusal probe
				args = []string{"list", "--server", "http://127.0.0.1:1", "--org", "test", "--scope-level", "org", "--scope-id", "test", "--token-file", path}
			}
			args[len(args)-1] = path
			res := runWrongSlotCLI(t, "test-stdin-value\n", args...)
			assertWrongSlotOutput(t, c, res, 1, "keep:")
		})
	}
}

func TestCLI_LoginHelpIsStaticAndSucceeds(t *testing.T) {
	for _, flag := range []string{"-h", "--help"} {
		res := runWrongSlotCLI(t, "", "login", flag)
		if res.exitCode != 0 || !strings.Contains(res.stderr, "Usage:") || !strings.Contains(res.stderr, "keep login") {
			t.Fatalf("login help: exit %d; static usage present=%v", res.exitCode, strings.Contains(res.stderr, "Usage:"))
		}
	}
}

// Every subcommand x every slot a credential can be pasted into. No marker is
// asserted: the property is only that the canary reaches neither stream.
func TestCLI_AnySubcommandNeverEchoesPastedValue(t *testing.T) {
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("[]"))
	}))
	defer empty.Close()
	const unreachable = "http://127.0.0.1:1"
	type probe struct {
		name   string
		server string // KEEP_SERVER ("" = unset); %s becomes the canary
		argv   func(v string) []string
	}
	policy := filepath.Join(t.TempDir(), "policy")
	if err := os.WriteFile(policy, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	const runnerID = "11111111-1111-1111-1111-111111111111"
	scope := []string{"--org", "test", "--scope-level", "org", "--scope-id", "test"}
	with := func(base []string, extra ...string) []string { return append(append([]string{}, base...), extra...) }
	probes := []probe{
		{"list-unknown-flag", "", func(v string) []string { return []string{"list", "-" + v} }},
		{"list-bool-flag-value", "", func(v string) []string { return []string{"list", "--json=" + v} }},
		{"meta-unknown-flag", "", func(v string) []string { return []string{"meta", "-" + v} }},
		{"version-unknown-flag", "", func(v string) []string { return []string{"version", "x", "-" + v} }},
		{"create-ref-unknown-flag", "", func(v string) []string { return []string{"create-ref", "x", "-" + v} }},
		{"audit-unknown-flag", "", func(v string) []string { return []string{"audit", "verify", "-" + v} }},
		{"runner-unknown-command", "", func(v string) []string { return []string{"runner", v} }},
		{"runner-unknown-dash", "", func(v string) []string { return []string{"runner", "-" + v} }},
		{"runner-enroll-unknown-flag", "", func(v string) []string { return []string{"runner", "enroll-token", "-" + v} }},
		{"runner-revoke-unknown-flag", "", func(v string) []string { return []string{"runner", "revoke", "-" + v} }},
		{"runner-help-env-server", "https://u:%s@h", func(string) []string { return []string{"runner", "enroll-token", "-h"} }},
		{"server-flag", "", func(v string) []string {
			return with([]string{"list", "--scope-level", "org", "--scope-id", "t", "--org", "t"}, "--server", v)
		}},
		{"server-flag-http-host", "", func(v string) []string {
			return with([]string{"list", "--scope-level", "org", "--scope-id", "t", "--org", "t"}, "--server", "http://"+v+".example")
		}},
		{"org-flag", unreachable, func(v string) []string {
			return []string{"list", "--org", v, "--scope-level", "org", "--scope-id", "t"}
		}},
		{"scope-id-flag", unreachable, func(v string) []string {
			return []string{"list", "--org", "t", "--scope-level", "org", "--scope-id", v}
		}},
		{"meta-name", empty.URL, func(v string) []string { return with([]string{"meta", v}, scope...) }},
		{"version-name", empty.URL, func(v string) []string { return with([]string{"version", v}, scope...) }},
		{"runner-enroll-server-host", "", func(v string) []string {
			return []string{"runner", "enroll-token", "-host", "h", "-policy", policy, "-server", "https://" + v + ".invalid"}
		}},
		{"runner-enroll-server-bad-url", "", func(v string) []string {
			return []string{"runner", "enroll-token", "-host", "h", "-policy", policy, "-server", "https://u:" + v + "@h%zz"}
		}},
		{"runner-revoke-server-host", "", func(v string) []string {
			return []string{"runner", "revoke", "-server", "https://" + v + ".invalid", runnerID}
		}},
		{"runner-revoke-env-server-bad-url", "https://u:%s@h%%zz", func(string) []string { return []string{"runner", "revoke", runnerID} }},
		{"list-env-server-userinfo-bad-org", "http://u:%s@127.0.0.1:1", func(string) []string {
			return []string{"list", "--org", "o%zz", "--scope-level", "org", "--scope-id", "t"}
		}},
		{"org-flag-bad-escape", unreachable, func(v string) []string {
			return []string{"list", "--org", v + "%zz", "--scope-level", "org", "--scope-id", "t"}
		}},
		{"org-flag-control-char", unreachable, func(v string) []string {
			return []string{"list", "--org", v + "\n", "--scope-level", "org", "--scope-id", "t"}
		}},
		{"debug-org-flag", unreachable, func(v string) []string {
			return []string{"list", "--debug", "--org", v, "--scope-level", "org", "--scope-id", "t"}
		}},
		{"debug-scope-id-flag", unreachable, func(v string) []string {
			return []string{"list", "--debug", "--org", "t", "--scope-level", "org", "--scope-id", v}
		}},
		{"runner-server-ca-path", "", func(v string) []string {
			return []string{"runner", "enroll-token", "-host", "h", "-policy", "p", "-server", "https://127.0.0.1:1", "-server-ca", filepath.Join(os.TempDir(), v)}
		}},
		{"runner-policy-path", "", func(v string) []string {
			return []string{"runner", "enroll-token", "-host", "h", "-policy", filepath.Join(os.TempDir(), v), "-server", "https://127.0.0.1:1"}
		}},
	}
	for _, p := range probes {
		t.Run(p.name, func(t *testing.T) {
			c := canary.New()
			env := []string{"KEEP_TOKEN=test-token-value", "KEEP_ADMIN_TOKEN=test-token-value"}
			if p.server != "" {
				env = append(env, "KEEP_SERVER="+strings.ReplaceAll(p.server, "%s", c.Value(0)))
			}
			res := runWrongSlotCLIEnv(t, env, "", p.argv(c.Value(0))...)
			if strings.TrimSpace(res.stderr+res.stdout) == "" {
				t.Fatal("probe produced no output: it would pass vacuously")
			}
			if c.In(res.stdout) || c.In(res.stderr) {
				t.Fatal("pasted canary reached stdout/stderr")
			}
		})
	}
}

func TestCLI_SubcommandHelpIsStaticAndSucceeds(t *testing.T) {
	for _, argv := range [][]string{{"list", "-h"}, {"meta", "x", "-h"}, {"version", "x", "-h"}, {"create-ref", "x", "-h"}, {"audit", "verify", "-h"}, {"runner", "enroll-token", "-h"}, {"runner", "revoke", "-h"}} {
		res := runWrongSlotCLI(t, "", argv...)
		if res.exitCode != 0 || !strings.Contains(res.stderr, "Usage:") {
			t.Fatalf("%v: exit %d, static usage present=%v", argv, res.exitCode, strings.Contains(res.stderr, "Usage:"))
		}
	}
}
