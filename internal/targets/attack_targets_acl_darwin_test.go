// Attacks with macOS extended ACLs on the directories above a target
// (R-POL-4, threat model I1/I9: whoever may add or delete names in an
// ancestor can swap the subtree under the target, so a value written below
// reaches them). Write must refuse an ACL granting write/add/delete on any
// ancestor, and any extended ACL on the target's parent. A read-only grant on
// an ancestor is allowed. Positive controls: a clean tree writes.
package targets_test

import (
	"errors"
	"os"
	osexec "os/exec"
	"path/filepath"
	"testing"

	"github.com/entire-vc/evc-keep/internal/targets"
	cnry "github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

func setACL(t *testing.T, path, ace string) {
	t.Helper()
	out, err := osexec.Command("/bin/chmod", "+a", ace, path).CombinedOutput() //nolint:gosec // G204: fixed binary, test-controlled ACE and temp path
	if err != nil {
		t.Fatalf("chmod +a %q %s: %v %s", ace, path, err, out) // fixture must not silently SKIP
	}
	// Remove the ACL before TempDir's own cleanup (LIFO), or a deny entry
	// blocks the RemoveAll.
	t.Cleanup(func() { _ = osexec.Command("/bin/chmod", "-N", path).Run() }) //nolint:gosec // G204: fixed binary, test temp path
	ls, _ := osexec.Command("/bin/ls", "-led", path).Output()                //nolint:gosec // G204: fixed binary, test temp path
	if len(ls) == 0 {
		t.Fatal("ls -led printed nothing")
	}
}

// aclTree builds root/gp/p (all 0700) and returns gp, p and the target path.
func aclTree(t *testing.T) (gp, p, target string) {
	t.Helper()
	root := tgtRealDir(t)
	gp = filepath.Join(root, "gp")
	p = filepath.Join(gp, "p")
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatal(err)
	}
	return gp, p, filepath.Join(p, "target")
}

func aclWrite(t *testing.T, path, value string) error {
	t.Helper()
	u, g := tgtNoAgents()
	_, err := targets.Write(tgtTarget(runnerproto.TargetFile, path), tgtValue(value), u, g, tgtKey(t))
	return err
}

func wantRefusedNoFile(t *testing.T, c cnry.Canary, err error, target, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: Write succeeded", what)
	}
	if !errors.Is(err, targets.ErrPolicy) {
		t.Fatalf("%s: want ErrPolicy, got %v", what, err)
	}
	if tgtErrLeaks(c, err) {
		t.Fatalf("%s: value reached the error", what)
	}
	if _, serr := os.Lstat(target); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("%s: target exists after refusal", what)
	}
	if hits := tgtDirHolds(t, filepath.Dir(target), c); len(hits) != 0 {
		t.Fatalf("%s: canary left in %v", what, hits)
	}
}

// TestTargetsACL_CleanTreeWrites — positive control for the family.
func TestTargetsACL_CleanTreeWrites(t *testing.T) {
	_, _, target := aclTree(t)
	if err := aclWrite(t, target, "v"); err != nil {
		t.Fatalf("clean tree refused: %v", err)
	}
}

// TestTargetsACL_GrandparentEveryoneAddDelete — R-POL-4. "everyone allow
// add_file,delete_child" on the grandparent lets any local account replace
// the parent directory; Write must refuse.
func TestTargetsACL_GrandparentEveryoneAddDelete(t *testing.T) {
	c := cnry.New()
	gp, _, target := aclTree(t)
	setACL(t, gp, "everyone allow add_file,delete_child")
	wantRefusedNoFile(t, c, aclWrite(t, target, c.Value(0)), target, "grandparent everyone add_file,delete_child")
}

// TestTargetsACL_GrandparentUserAddSubdir — same, a named non-root user with
// add_subdirectory only (a single write-class permission is enough).
func TestTargetsACL_GrandparentUserAddSubdir(t *testing.T) {
	c := cnry.New()
	gp, _, target := aclTree(t)
	setACL(t, gp, "user:daemon allow add_subdirectory")
	wantRefusedNoFile(t, c, aclWrite(t, target, c.Value(0)), target, "grandparent user:daemon add_subdirectory")
}

// TestTargetsACL_GrandparentWriteSecurity — a grant of writesecurity lets
// the subject rewrite the ACL into a write grant later; refused.
func TestTargetsACL_GrandparentWriteSecurity(t *testing.T) {
	c := cnry.New()
	gp, _, target := aclTree(t)
	setACL(t, gp, "everyone allow writesecurity")
	wantRefusedNoFile(t, c, aclWrite(t, target, c.Value(0)), target, "grandparent everyone writesecurity")
}

// TestTargetsACL_GrandparentReadOnlyAllowed — control: a read/list/search
// grant on an ancestor does not let anyone swap names; allowed.
func TestTargetsACL_GrandparentReadOnlyAllowed(t *testing.T) {
	gp, _, target := aclTree(t)
	setACL(t, gp, "everyone allow list,search,readattr")
	if err := aclWrite(t, target, "v"); err != nil {
		t.Fatalf("read-only ACL on an ancestor was refused: %v", err)
	}
}

// TestTargetsACL_GrandparentDenyAllowed — control: deny entries (as on every
// home directory) do not grant anything; allowed.
func TestTargetsACL_GrandparentDenyAllowed(t *testing.T) {
	gp, _, target := aclTree(t)
	setACL(t, gp, "everyone deny delete")
	if err := aclWrite(t, target, "v"); err != nil {
		t.Fatalf("deny-only ACL on an ancestor was refused: %v", err)
	}
}

// TestTargetsACL_ParentAddFileRefused — an ACL on the target's own
// directory: write grant refused.
func TestTargetsACL_ParentAddFileRefused(t *testing.T) {
	c := cnry.New()
	_, p, target := aclTree(t)
	setACL(t, p, "everyone allow add_file,delete_child")
	wantRefusedNoFile(t, c, aclWrite(t, target, c.Value(0)), target, "parent everyone add_file,delete_child")
}

// TestTargetsACL_ParentReadOnlyRefused — any extended ACL on the parent is
// refused, even read-only: a read grant there lets the subject list and
// open what the runner writes.
func TestTargetsACL_ParentReadOnlyRefused(t *testing.T) {
	c := cnry.New()
	_, p, target := aclTree(t)
	setACL(t, p, "user:daemon allow list,search")
	wantRefusedNoFile(t, c, aclWrite(t, target, c.Value(0)), target, "parent user:daemon list,search")
}
