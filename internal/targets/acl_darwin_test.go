//go:build darwin

package targets

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

// TestExtendedACLOnParentDirRefused is the red run for `checkACL` itself,
// missing until now: a real `chmod +a` grant (not a simulated one) on the
// target's immediate parent directory must be refused, with a reason.
func TestExtendedACLOnParentDirRefused(t *testing.T) {
	dir := realDir(t)
	sub := filepath.Join(dir, "acl")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/bin/chmod", "+a", "everyone allow read", sub).CombinedOutput(); err != nil { //nolint:gosec // G204: sub is our own tempdir path, not attacker input
		t.Fatalf("chmod +a: %v: %s", err, out)
	}

	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetFile, filepath.Join(sub, "target"), ""), newValue("v"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrPolicy, "target directory with an extended ACL")
}

// TestNoACLAllowed is the negative control for the test above: a directory
// with no ACL must not be refused by checkACL (it would otherwise be
// trivially "always refuse", which proves nothing).
func TestNoACLAllowed(t *testing.T) {
	dir := realDir(t)
	sub := filepath.Join(dir, "noacl")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	uids, gids := noAgents()
	if _, err := Write(target(runnerproto.TargetFile, filepath.Join(sub, "target"), ""), newValue("v"), uids, gids, testFPKey(t)); err != nil {
		t.Fatalf("Write refused a directory with no ACL: %v", err)
	}
}

// TestCheckACLFailsClosedOnExecError proves checkACL(fail-open fix): an ls
// failure that is NOT "the path vanished" must refuse, not silently pass.
// Simulated by pointing at a path ls cannot stat for a reason other than
// nonexistence — a path one component of which is a file, not a directory,
// so ls's own traversal fails with ENOTDIR rather than ENOENT.
func TestCheckACLFailsClosedOnExecError(t *testing.T) {
	dir := realDir(t)
	notADir := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := checkACL(filepath.Join(notADir, "child"))
	wantErr(t, err, ErrWrite, "checkACL on a path ls cannot stat for a reason other than ENOENT")
}

// TestCheckACLPassesThroughOnENOENT is the companion positive control: a
// path that has genuinely never existed is not this check's job to
// diagnose (the caller's own fd-based operations independently refuse it).
func TestCheckACLPassesThroughOnENOENT(t *testing.T) {
	dir := realDir(t)
	if err := checkACL(filepath.Join(dir, "genuinely-does-not-exist")); err != nil {
		t.Fatalf("checkACL on a nonexistent path: %v", err)
	}
}

// An existing target with a macOS ACL is refused for a kind that folds its
// content into the new file.
func TestExistingTargetWithACLRefusedWhenFolded(t *testing.T) {
	path := filepath.Join(safeDir(t), "svc.env")
	mustWriteFile(t, path, []byte("A=1\n"), 0o600)
	if out, err := exec.Command("/bin/chmod", "+a", "everyone allow write", path).CombinedOutput(); err != nil { //nolint:gosec // G204: our own tempdir path
		t.Fatalf("chmod +a: %v: %s", err, out)
	}
	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetEnvFile, path, "X"), newValue("v"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrPolicy, "existing env-file with an extended ACL")
	if got := mustReadFile(t, path); string(got) != "A=1\n" {
		t.Fatalf("target changed despite the refusal: %s", show(got))
	}
}

// macOS group "everyone" (gid 12) holds every account: as a target group with
// any group bit it is a world grant, and as a directory's group with a group
// write bit it is a world-writable directory. The gid is not in HostPolicy's
// list of agent gids; it is refused all the same.
func TestEveryoneGroupCountsAsAgents(t *testing.T) {
	t.Run("target-group-bits", func(t *testing.T) {
		tg := target(runnerproto.TargetFile, filepath.Join(safeDir(t), "target"), "")
		tg.Mode, tg.GID = 0o640, everyoneGID
		uids, gids := noAgents()
		_, err := Write(tg, newValue("v"), uids, gids, testFPKey(t))
		wantErr(t, err, ErrPolicy, "target group everyone with a group bit")
	})
	t.Run("directory-group-writable", func(t *testing.T) {
		sub := filepath.Join(realDir(t), "sub")
		if err := os.Mkdir(sub, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(sub, -1, everyoneGID); err != nil {
			t.Fatalf("chgrp everyone: %v", err)
		}
		if err := os.Chmod(sub, 0o770); err != nil { //nolint:gosec // G302: the group-writable directory is the scenario
			t.Fatal(err)
		}
		uids, gids := noAgents()
		_, err := Write(target(runnerproto.TargetFile, filepath.Join(sub, "target"), ""), newValue("v"), uids, gids, testFPKey(t))
		wantErr(t, err, ErrPolicy, "directory in group everyone with a group write bit")
	})
	t.Run("directory-group-reach", func(t *testing.T) {
		sub := filepath.Join(realDir(t), "sub")
		if err := os.Mkdir(sub, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(sub, -1, everyoneGID); err != nil {
			t.Fatalf("chgrp everyone: %v", err)
		}
		if err := os.Chmod(sub, 0o750); err != nil { //nolint:gosec // G302: the group-traversable directory is the scenario
			t.Fatal(err)
		}
		uids, gids := noAgents()
		_, err := Write(target(runnerproto.TargetFile, filepath.Join(sub, "target"), ""), newValue("v"), uids, gids, testFPKey(t))
		wantErr(t, err, ErrPolicy, "parent directory in group everyone that the group can traverse")
	})
}

func addACL(t *testing.T, path, rule string) {
	t.Helper()
	if out, err := exec.Command("/bin/chmod", "+a", rule, path).CombinedOutput(); err != nil { //nolint:gosec // G204: our own tempdir path and a fixed rule
		t.Fatalf("chmod +a %q: %v: %s", rule, err, out)
	}
	// A deny-delete entry would also stop the tempdir cleanup.
	t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-N", path).Run() }) //nolint:gosec // G204: our own tempdir path
}

func ancestorWith(t *testing.T) (anc, targetPath string) {
	t.Helper()
	anc = filepath.Join(safeDir(t), "anc")
	parent := filepath.Join(anc, "parent")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	return anc, filepath.Join(parent, "target")
}

func writeThrough(t *testing.T, targetPath string) error {
	t.Helper()
	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetFile, targetPath, ""), newValue("v"), uids, gids, testFPKey(t))
	return err
}

// An ACL that lets someone write, add or delete in a directory above the
// parent is refused, whichever of the permissions it carries.
func TestAncestorACLGrantingWriteRefused(t *testing.T) {
	for _, rule := range []string{
		"everyone allow add_file",
		"everyone allow add_subdirectory",
		"everyone allow delete_child",
		"everyone allow delete",
		"everyone allow chown",
		"everyone allow write",
		"everyone allow read,writesecurity",
	} {
		t.Run(rule, func(t *testing.T) {
			anc, tp := ancestorWith(t)
			addACL(t, anc, rule)
			wantErr(t, writeThrough(t, tp), ErrPolicy, "ancestor ACL "+rule)
			if _, err := os.Lstat(tp); err == nil {
				t.Fatal("target was created despite the refusal")
			}
		})
	}
}

// What the ancestor check must let through: read and search grants, and deny
// entries (every home directory has `everyone deny delete`).
func TestAncestorACLNotGrantingWriteAllowed(t *testing.T) {
	for _, rule := range []string{
		"everyone allow read,search,list",
		"everyone deny delete",
		"everyone deny add_file",
	} {
		t.Run(rule, func(t *testing.T) {
			anc, tp := ancestorWith(t)
			addACL(t, anc, rule)
			if err := writeThrough(t, tp); err != nil {
				t.Fatalf("Write refused: %v", err)
			}
		})
	}
}

// A write grant on an ancestor to root alone is not a reason to refuse.
func TestAncestorACLForRootAllowed(t *testing.T) {
	anc, tp := ancestorWith(t)
	addACL(t, anc, "root allow add_file,delete_child")
	if err := writeThrough(t, tp); err != nil {
		t.Fatalf("Write refused: %v", err)
	}
}
