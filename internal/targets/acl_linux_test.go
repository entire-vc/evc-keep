//go:build linux

package targets

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"golang.org/x/sys/unix"
)

// POSIX ACLs are set here as raw xattrs (the kernel validates the encoding),
// so the tests need no setfacl and the CI image no extra package. The
// filesystem under the test's TempDir must support them; if it does not the
// tests FAIL rather than skip — a skipped ACL test is a guard nobody ran.

const (
	aclUserObj  = 0x01
	aclUser     = 0x02
	aclGroupObj = 0x04
	aclMask     = 0x10
	aclOther    = 0x20
)

// grantUserACL is an ACL that adds "user:uid:perm" on top of the usual
// owner/group/other entries.
func grantUserACL(uid uint32, perm uint16) []byte {
	b := binary.LittleEndian.AppendUint32(nil, 2) // POSIX_ACL_XATTR_VERSION
	for _, e := range []struct {
		tag, perm uint16
		id        uint32
	}{
		{aclUserObj, 7, 0xffffffff},
		{aclUser, perm, uid},
		{aclGroupObj, 0, 0xffffffff},
		{aclMask, perm, 0xffffffff},
		{aclOther, 0, 0xffffffff},
	} {
		b = binary.LittleEndian.AppendUint16(b, e.tag)
		b = binary.LittleEndian.AppendUint16(b, e.perm)
		b = binary.LittleEndian.AppendUint32(b, e.id)
	}
	return b
}

func setACL(t *testing.T, path, attr string, acl []byte) {
	t.Helper()
	if err := unix.Setxattr(path, attr, acl, 0); err != nil {
		t.Fatalf("set %s on %s: %v (the test filesystem must support POSIX ACLs)", attr, path, err)
	}
}

const agentACLUID = 4242

// TestDefaultACLOnParentRefused reproduces the attack where a default ACL
// `d:u:<agent>:r` on the target's directory is inherited by the temporary
// file, and the mode bits alone (0640, mask aside) say nothing about it —
// the agent reads the deployed secret.
func TestDefaultACLOnParentRefused(t *testing.T) {
	dir := safeDir(t)
	setACL(t, dir, xattrACLDefault, grantUserACL(agentACLUID, 4))

	// Control on the premise: without our check the kernel really does hand
	// a new file in this directory an ACL entry for the agent.
	probe := filepath.Join(dir, "probe")
	if err := os.WriteFile(probe, nil, 0o640); err != nil { //nolint:gosec // G306: probing inheritance
		t.Fatal(err)
	}
	if n, err := unix.Getxattr(probe, xattrACLAccess, nil); err != nil || n == 0 {
		t.Fatalf("control failed: a file created under the default ACL has no access ACL (%d, %v)", n, err)
	}
	if err := os.Remove(probe); err != nil {
		t.Fatal(err)
	}

	tg := target(runnerproto.TargetFile, filepath.Join(dir, "target"), "")
	tg.Mode = 0o640
	uids, gids := noAgents()
	_, err := Write(tg, newValue("v"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrPolicy, "parent directory with a default ACL")
	if _, serr := os.Lstat(filepath.Join(dir, "target")); serr == nil {
		t.Fatal("target was created despite the refusal")
	}
}

// TestAccessACLOnParentRefused: an ACL on the directory itself (not a
// default one) lets an agent traverse or list it whatever the mode says.
func TestAccessACLOnParentRefused(t *testing.T) {
	dir := safeDir(t)
	setACL(t, dir, xattrACLAccess, grantUserACL(agentACLUID, 5))
	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetFile, filepath.Join(dir, "target"), ""), newValue("v"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrPolicy, "parent directory with an access ACL")
}

// TestACLOnTemporaryFileRefused isolates the check on the temporary file
// itself: nothing is wrong with the directory when the walk passes it; an ACL
// appears on the temp file only afterwards (afterTmpCreate stands in for
// inheritance from an ACL set in the instant after the walk).
func TestACLOnTemporaryFileRefused(t *testing.T) {
	dir := safeDir(t)
	orig := afterTmpCreate
	t.Cleanup(func() { afterTmpCreate = orig })
	fired := false
	afterTmpCreate = func(parentFD int, name string) {
		fired = true
		fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = unix.Close(fd) }()
		if err := unix.Fsetxattr(fd, xattrACLAccess, grantUserACL(agentACLUID, 4), 0); err != nil {
			t.Fatalf("set ACL on the temporary file: %v", err)
		}
	}
	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetFile, filepath.Join(dir, "target"), ""), newValue("v"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrPolicy, "temporary file with an ACL")
	if !fired {
		t.Fatal("test hook never fired")
	}
	if _, serr := os.Lstat(filepath.Join(dir, "target")); serr == nil {
		t.Fatal("target was created despite the refusal")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("the temporary file was left behind: %d entries", len(entries))
	}
}

// TestNoACLOnLinuxAllowed is the negative control: a plain directory must
// not be refused, or every test above would pass for the wrong reason.
func TestNoACLOnLinuxAllowed(t *testing.T) {
	dir := safeDir(t)
	uids, gids := noAgents()
	if _, err := Write(target(runnerproto.TargetFile, filepath.Join(dir, "target"), ""), newValue("v"), uids, gids, testFPKey(t)); err != nil {
		t.Fatalf("Write refused a directory with no ACL: %v", err)
	}
}

// TestHasXattrFailsClosed: a failure that is neither "no such attribute" nor
// "no xattr support" means the check could not look, and must not read as
// "no ACL". A closed descriptor is such a failure.
func TestHasXattrFailsClosed(t *testing.T) {
	_, err := hasXattr(-1, xattrACLAccess)
	wantErr(t, err, ErrWrite, "xattr read on an invalid descriptor")
}

// aclXattr builds an access-ACL xattr from raw entries, so a test can leave
// out the mask or set one that hides a named entry.
func aclXattr(entries ...[3]uint32) []byte {
	b := binary.LittleEndian.AppendUint32(nil, 2)
	for _, e := range entries {
		b = binary.LittleEndian.AppendUint16(b, uint16(e[0]&0xffff))
		b = binary.LittleEndian.AppendUint16(b, uint16(e[1]&0xffff))
		b = binary.LittleEndian.AppendUint32(b, e[2])
	}
	return b
}

const none = 0xffffffff

// ancestorWith makes <safe>/anc/parent and returns the ancestor and the path
// of a target inside parent.
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

// An ACL that gives an agent write on a directory above the parent is
// refused: it can swap the next component after the walk has passed it.
func TestAncestorACLGrantingWriteRefused(t *testing.T) {
	for name, acl := range map[string][]byte{
		"named user":  grantUserACL(agentACLUID, 7),
		"named group": aclXattr([3]uint32{aclUserObj, 7, none}, [3]uint32{aclGroupObj, 0, none}, [3]uint32{8, 7, 4242}, [3]uint32{aclMask, 7, none}, [3]uint32{aclOther, 0, none}),
	} {
		t.Run(name, func(t *testing.T) {
			anc, tp := ancestorWith(t)
			setACL(t, anc, xattrACLAccess, acl)
			wantErr(t, writeThrough(t, tp), ErrPolicy, "ancestor ACL granting write")
			if _, err := os.Lstat(tp); err == nil {
				t.Fatal("target was created despite the refusal")
			}
		})
	}
}

// What the ancestor check must let through: a read-only grant, a grant the
// mask cancels, a grant to root, and one to the directory's own owner. Without
// these the refusal above could be "refuse every ACL".
func TestAncestorACLNotGrantingWriteAllowed(t *testing.T) {
	owner := uint32(os.Getuid()) //nolint:gosec // G115: a uid is never negative
	for name, acl := range map[string][]byte{
		"read and search only": grantUserACL(agentACLUID, 5),
		"write hidden by mask": aclXattr([3]uint32{aclUserObj, 7, none}, [3]uint32{aclUser, 7, agentACLUID}, [3]uint32{aclGroupObj, 0, none}, [3]uint32{aclMask, 5, none}, [3]uint32{aclOther, 0, none}),
		"write for root":       grantUserACL(0, 7),
		"write for root group": aclXattr([3]uint32{aclUserObj, 7, none}, [3]uint32{aclGroupObj, 0, none}, [3]uint32{8, 7, 0}, [3]uint32{aclMask, 7, none}, [3]uint32{aclOther, 0, none}),
		"write for the owner":  grantUserACL(owner, 7),
	} {
		t.Run(name, func(t *testing.T) {
			anc, tp := ancestorWith(t)
			setACL(t, anc, xattrACLAccess, acl)
			if err := writeThrough(t, tp); err != nil {
				t.Fatalf("Write refused: %v", err)
			}
		})
	}
}

// A default ACL on an ancestor shapes files created later in that directory,
// not the target's: not a reason to refuse.
func TestAncestorDefaultACLAllowed(t *testing.T) {
	anc, tp := ancestorWith(t)
	setACL(t, anc, xattrACLDefault, grantUserACL(agentACLUID, 7))
	if err := writeThrough(t, tp); err != nil {
		t.Fatalf("Write refused: %v", err)
	}
}

// A malformed ACL fails closed. The kernel refuses to store one, so the
// parser is driven with bytes directly.
func TestAncestorACLMalformedRefused(t *testing.T) {
	for name, b := range map[string][]byte{
		"empty":         nil,
		"short header":  {2, 0},
		"wrong version": append([]byte{9, 0, 0, 0}, make([]byte, 8)...),
		"torn entry":    append([]byte{2, 0, 0, 0}, make([]byte, 7)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := aclWriteGrantee(b, 0); err == nil {
				t.Fatal("malformed ACL was accepted")
			}
		})
	}
	if g, err := aclWriteGrantee(grantUserACL(agentACLUID, 7), 0); err != nil || g == "" {
		t.Fatalf("control: well-formed grant gave (%q, %v)", g, err)
	}
}

// The grant check itself, with an owner that is neither root nor the agent:
// who is exempt and what the mask hides, independent of who runs the tests.
func TestACLWriteGranteeExemptions(t *testing.T) {
	const owner, agent = 1000, 4242
	grp := func(id uint32) []byte {
		return aclXattr([3]uint32{aclUserObj, 7, none}, [3]uint32{aclGroupObj, 0, none}, [3]uint32{aclTagGroup, 7, id}, [3]uint32{aclMask, 7, none}, [3]uint32{aclOther, 0, none})
	}
	for name, c := range map[string]struct {
		acl  []byte
		want bool
	}{
		"agent user":        {grantUserACL(agent, 7), true},
		"agent group":       {grp(agent), true},
		"root user":         {grantUserACL(0, 7), false},
		"owner user":        {grantUserACL(owner, 7), false},
		"root group":        {grp(0), false},
		"agent read only":   {grantUserACL(agent, 5), false},
		"agent behind mask": {aclXattr([3]uint32{aclUserObj, 7, none}, [3]uint32{aclUser, 7, agent}, [3]uint32{aclGroupObj, 0, none}, [3]uint32{aclMask, 5, none}, [3]uint32{aclOther, 0, none}), false},
	} {
		t.Run(name, func(t *testing.T) {
			g, err := aclWriteGrantee(c.acl, owner)
			if err != nil {
				t.Fatal(err)
			}
			if (g != "") != c.want {
				t.Fatalf("grantee = %q, want a grantee: %v", g, c.want)
			}
		})
	}
}
