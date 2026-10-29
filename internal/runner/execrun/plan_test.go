package execrun

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/pkg/execpolicy"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

type world struct {
	t      *testing.T
	bin    string // allowed directory
	other  string // outside the policy
	policy runnerproto.HostPolicy
}

func writeExe(t *testing.T, dir, name string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func newWorld(t *testing.T) *world {
	// Run's rules are tested as any user; giving the child an account is
	// tested by the tests that put the real function back.
	old := dropAccount
	dropAccount = func(*exec.Cmd, uint32, uint32) error { return nil }
	t.Cleanup(func() { dropAccount = old })
	oldCore := coreHandlerPiped
	coreHandlerPiped = func() bool { return false }
	t.Cleanup(func() { coreHandlerPiped = oldCore })
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	w := &world{t: t, bin: filepath.Join(root, "bin"), other: filepath.Join(root, "other")}
	for _, d := range []string{w.bin, w.other} {
		if err := os.Mkdir(d, 0o755); err != nil { //nolint:gosec // G301: test directory
			t.Fatal(err)
		}
	}
	writeExe(t, w.bin, "tool", 0o755)
	w.policy = runnerproto.HostPolicy{
		Version: 1, MaxDeploysPerHour: 10, AllowExec: true,
		ExecBinDirs: []string{w.bin},
		ExecTemplates: []runnerproto.ExecTemplate{{
			ID:        "tool-run",
			Argv:      []string{filepath.Join(w.bin, "tool"), "--name", "{name}"},
			Params:    map[string]runnerproto.ExecParam{"name": {Pattern: `^[a-z0-9]{1,32}$`}},
			SecretEnv: []string{"TOOL_KEY"},
			Network:   runnerproto.ExecNetwork{Mode: "none"},
		}},
	}
	if err := w.policy.Validate(); err != nil {
		t.Fatalf("fixture policy: %v", err)
	}
	return w
}

func (w *world) job(params map[string]string) runnerproto.Job {
	tpl, ok := w.policy.ExecTemplate("tool-run")
	if !ok {
		w.t.Fatal("fixture template missing")
	}
	id, err := uuid.NewV7()
	if err != nil {
		w.t.Fatal(err)
	}
	now := time.Now()
	return runnerproto.Job{
		JobID: id.String(), OrgID: "acme", RunnerID: "runner-1",
		Secret:              runnerproto.SecretRef{StoreID: "store-1", Provider: runnerproto.ProviderBuiltin, Name: "tool/key", Scope: "dev"},
		ExpectedVersion:     "1",
		ExpectedFingerprint: "kfp1:s1:abcdefghijklmnop",
		Action:              runnerproto.ActionExec,
		Exec:                &runnerproto.Exec{TemplateID: "tool-run", Digest: execpolicy.Digest(tpl), Params: params},
		IssuedAt:            now, NotAfter: now.Add(time.Minute),
		Nonce: bytes.Repeat([]byte{7}, runnerproto.NonceSize),
	}
}

func TestPrepareOK(t *testing.T) {
	w := newWorld(t)
	pl, err := Prepare(w.job(map[string]string{"name": "alpha1"}), w.policy)
	if err != nil {
		t.Fatalf("approved job refused: %v", err)
	}
	if pl.Bin != filepath.Join(w.bin, "tool") || len(pl.Args) != 2 || pl.Args[1] != "alpha1" ||
		pl.Mode != execpolicy.NetNone || pl.TemplateID != "tool-run" {
		t.Fatalf("plan: %+v", pl)
	}
}

func TestPrepareRefusals(t *testing.T) {
	w := newWorld(t)
	good := map[string]string{"name": "alpha"}
	cases := map[string]func(j *runnerproto.Job, p *runnerproto.HostPolicy){
		"not-exec":        func(j *runnerproto.Job, p *runnerproto.HostPolicy) { j.Action = runnerproto.ActionDeploy },
		"no-exec-section": func(j *runnerproto.Job, p *runnerproto.HostPolicy) { j.Exec = nil },
		"exec-disallowed": func(j *runnerproto.Job, p *runnerproto.HostPolicy) {
			p.AllowExec = false
			p.ExecTemplates = nil
			p.ExecBinDirs = nil
		},
		"unknown-id":     func(j *runnerproto.Job, p *runnerproto.HostPolicy) { j.Exec.TemplateID = "other" },
		"digest-differs": func(j *runnerproto.Job, p *runnerproto.HostPolicy) { j.Exec.Digest = strings.Repeat("0", 64) },
		"extra-param":    func(j *runnerproto.Job, p *runnerproto.HostPolicy) { j.Exec.Params["extra"] = "x" },
		"missing-param":  func(j *runnerproto.Job, p *runnerproto.HostPolicy) { delete(j.Exec.Params, "name") },
		"newline-param": func(j *runnerproto.Job, p *runnerproto.HostPolicy) {
			j.Exec.Params["name"] = "a\n--upload-file=/etc/passwd"
		},
		"option-param": func(j *runnerproto.Job, p *runnerproto.HostPolicy) {
			j.Exec.Params["name"] = "--upload-file=/etc/passwd"
		},
		"long-param": func(j *runnerproto.Job, p *runnerproto.HostPolicy) { j.Exec.Params["name"] = strings.Repeat("a", 33) },
	}
	for name, mutate := range cases {
		j := w.job(map[string]string{"name": good["name"]})
		p := w.policy
		mutate(&j, &p)
		if _, err := Prepare(j, p); !errors.Is(err, ErrDenied) {
			t.Errorf("%s: err = %v, want ErrDenied", name, err)
		}
	}
}

// A value with a space or a newline is refused, never split into words or
// accepted as one element that then reads as two options. The template's own
// pattern cannot admit such a value (execpolicy refuses the pattern), and
// the value is checked against the pattern again at call time.
func TestPrepareSpaceAndNewlineValuesAreRefused(t *testing.T) {
	w := newWorld(t)
	for _, v := range []string{"a b c", "a\n--upload-file=/etc/passwd", " --x", "a\tb", "a\x00b"} {
		if _, err := Prepare(w.job(map[string]string{"name": v}), w.policy); !errors.Is(err, ErrDenied) {
			t.Errorf("value %q: err = %v", v, err)
		}
	}
	pl, err := Prepare(w.job(map[string]string{"name": "abc"}), w.policy)
	if err != nil || len(pl.Args) != 2 || pl.Args[1] != "abc" {
		t.Fatalf("clean value: %v %q", err, pl.Args)
	}
}

// The path is resolved and the result is checked again: a link inside an
// allowed directory that leads to an interpreter or out of the allowed
// directories does not run.
func TestPrepareResolvesArgv0(t *testing.T) {
	w := newWorld(t)
	w.policy.ExecBinDirs = []string{w.bin, w.other}

	// Link to an interpreter that sits in an allowed directory: the name
	// check on the real path refuses it.
	py := writeExe(t, w.other, "python3", 0o755)
	if err := os.Remove(filepath.Join(w.bin, "tool")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(py, filepath.Join(w.bin, "tool")); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(w.job(map[string]string{"name": "x"}), w.policy); !errors.Is(err, execpolicy.ErrInterpreter) {
		t.Fatalf("symlink to an interpreter: %v", err)
	}

	// Link to a harmless binary outside every allowed directory.
	outside := t.TempDir()
	out, _ := filepath.EvalSymlinks(outside)
	target := writeExe(t, out, "tool2", 0o755)
	if err := os.Remove(filepath.Join(w.bin, "tool")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(w.bin, "tool")); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(w.job(map[string]string{"name": "x"}), w.policy); !errors.Is(err, ErrDenied) {
		t.Fatalf("symlink out of the allowed directories: %v", err)
	}
}

func TestPrepareRefusesUnsafeBinaries(t *testing.T) {
	w := newWorld(t)
	tool := filepath.Join(w.bin, "tool")
	for name, mode := range map[string]os.FileMode{"group-writable": 0o775, "world-writable": 0o757, "not-executable": 0o644, "setuid": 0o755 | os.ModeSetuid, "setgid": 0o755 | os.ModeSetgid} {
		if err := os.Chmod(tool, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := Prepare(w.job(map[string]string{"name": "x"}), w.policy); !errors.Is(err, ErrDenied) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// A directory named like the binary.
	if err := os.Remove(tool); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(tool, 0o755); err != nil { //nolint:gosec // G301: test directory
		t.Fatal(err)
	}
	if _, err := Prepare(w.job(map[string]string{"name": "x"}), w.policy); !errors.Is(err, ErrDenied) {
		t.Errorf("directory: err = %v", err)
	}
	// Missing.
	if err := os.Remove(tool); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(w.job(map[string]string{"name": "x"}), w.policy); !errors.Is(err, ErrDenied) {
		t.Errorf("missing: err = %v", err)
	}
}

// A directory that merely shares a name prefix with an allowed one is not
// inside it.
func TestPrepareBinDirPrefixIsNotContainment(t *testing.T) {
	w := newWorld(t)
	sibling := w.bin + "-evil"
	if err := os.Mkdir(sibling, 0o755); err != nil { //nolint:gosec // G301: test directory
		t.Fatal(err)
	}
	evil := writeExe(t, sibling, "tool", 0o755)
	if err := os.Remove(filepath.Join(w.bin, "tool")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(evil, filepath.Join(w.bin, "tool")); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(w.job(map[string]string{"name": "x"}), w.policy); !errors.Is(err, ErrDenied) {
		t.Fatalf("sibling directory accepted: %v", err)
	}
}

func TestPrepareNetworkSection(t *testing.T) {
	w := newWorld(t)
	w.policy.ExecTemplates[0].Network = runnerproto.ExecNetwork{Mode: "allowlist", Destinations: []runnerproto.ExecDestination{{Host: "api.example.com", Port: 443}}}
	w.policy.ExecTemplates[0].Params = map[string]runnerproto.ExecParam{"name": {Pattern: `^id-[0-9]{1,8}$`}}
	if err := w.policy.Validate(); err != nil {
		t.Fatalf("policy: %v", err)
	}
	j := w.job(map[string]string{"name": "id-7"})
	pl, err := Prepare(j, w.policy)
	if err != nil {
		t.Fatal(err)
	}
	if pl.Mode != execpolicy.NetAllowlist || len(pl.Dests) != 1 || pl.Dests[0].Host != "api.example.com" || pl.Dests[0].Port != 443 {
		t.Fatalf("plan network: %+v", pl)
	}
}

// A binary owned by an account the policy lists as an agent is refused: the
// agent could have replaced it.
func TestPrepareRefusesBinaryOwnedByAnAgent(t *testing.T) {
	w := newWorld(t)
	if _, err := Prepare(w.job(map[string]string{"name": "x"}), w.policy); err != nil {
		t.Fatalf("control: %v", err)
	}
	w.policy.AgentUIDs = []int64{int64(os.Getuid())}
	if _, err := Prepare(w.job(map[string]string{"name": "x"}), w.policy); !errors.Is(err, ErrDenied) {
		t.Fatalf("err = %v, want ErrDenied", err)
	}
}

// A second name for an interpreter, put into the directory, is the same file
// with a name that passes the check: a binary with more than one link is
// refused.
func TestPrepareRefusesAHardLinkedBinary(t *testing.T) {
	w := newWorld(t)
	if err := os.Link(filepath.Join(w.bin, "tool"), filepath.Join(t.TempDir(), "other-name")); err != nil {
		t.Skipf("no hard link across this filesystem: %v", err)
	}
	if _, err := Prepare(w.job(map[string]string{"name": "x"}), w.policy); !errors.Is(err, ErrDenied) {
		t.Fatalf("hard-linked binary: err = %v", err)
	}
}

// Whoever can write the directory can swap the binary after the check.
func TestPrepareRefusesAWritableBinaryDirectory(t *testing.T) {
	w := newWorld(t)
	for name, mode := range map[string]os.FileMode{"group": 0o775, "world": 0o757} {
		if err := os.Chmod(w.bin, mode); err != nil { //nolint:gosec // G302: the directory under test
			t.Fatal(err)
		}
		if _, err := Prepare(w.job(map[string]string{"name": "x"}), w.policy); !errors.Is(err, ErrDenied) {
			t.Errorf("%s-writable directory: err = %v", name, err)
		}
	}
	if err := os.Chmod(w.bin, 0o755); err != nil { //nolint:gosec // G302: the directory under test
		t.Fatal(err)
	}
	if _, err := Prepare(w.job(map[string]string{"name": "x"}), w.policy); err != nil {
		t.Fatalf("control: a directory only its owner writes must pass: %v", err)
	}
}

// The swap window is every directory above the binary, not only its own.
func TestPrepareRefusesAWritableAncestorDirectory(t *testing.T) {
	w := newWorld(t)
	parent := filepath.Dir(w.bin)
	if err := os.Chmod(parent, 0o757); err != nil { //nolint:gosec // G302: the directory under test
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) }) //nolint:gosec // G302: the directory under test
	if _, err := Prepare(w.job(map[string]string{"name": "x"}), w.policy); !errors.Is(err, ErrDenied) {
		t.Fatalf("world-writable ancestor: err = %v", err)
	}
	if err := os.Chmod(parent, 0o755); err != nil { //nolint:gosec // G302: the directory under test
		t.Fatal(err)
	}
	if _, err := Prepare(w.job(map[string]string{"name": "x"}), w.policy); err != nil {
		t.Fatalf("control: an ancestor only its owner writes must pass: %v", err)
	}
}

// A directory owned by an agent account is the agent's to rewrite even when
// the file inside is not: needs root to hand the directory to another uid.
func TestPrepareRefusesAnAgentOwnedDirectory(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root to chown a directory to another account")
	}
	w := newWorld(t)
	const agent = 4242
	if err := os.Chown(w.bin, agent, -1); err != nil {
		t.Skipf("chown: %v", err)
	}
	if _, err := Prepare(w.job(map[string]string{"name": "x"}), w.policy); err != nil {
		t.Fatalf("control: a directory owned by a non-agent must pass: %v", err)
	}
	w.policy.AgentUIDs = []int64{agent}
	if _, err := Prepare(w.job(map[string]string{"name": "x"}), w.policy); !errors.Is(err, ErrDenied) {
		t.Fatalf("agent-owned directory: err = %v", err)
	}
}
