//go:build linux

package targets

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// A file's POSIX ACL lives in the system.posix_acl_access xattr, a
// directory's inheritable one in system.posix_acl_default. The kernel stores
// an ACL as an xattr only when it has entries beyond the owner/group/other
// triple the mode bits already show, so the presence of the xattr alone means
// "an extended ACL exists" — no need to parse it. Mode bits cannot show it:
// with `d:u:<agent>:r` on the directory, a temporary file created in it
// inherits the entry, and after Fchmod(0640) the agent can still read the
// deployed secret.
const (
	xattrACLAccess  = "system.posix_acl_access"
	xattrACLDefault = "system.posix_acl_default"
)

// hasXattr reports whether fd carries the named xattr. An error other than
// "no such attribute" or "this filesystem has no xattrs" — where no ACL can
// exist — fails closed: an ACL check that cannot look must not pass.
func hasXattr(fd int, name string) (bool, error) {
	_, err := unix.Fgetxattr(fd, name, nil)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, unix.ENODATA), errors.Is(err, unix.ENOTSUP):
		return false, nil
	default:
		return false, writeFailed("read %s: %v", name, err)
	}
}

// checkDirACL refuses a directory (the target's immediate parent) that
// carries an access ACL — an agent can be granted traversal or listing
// through it — or a default ACL, which every file created in it inherits.
// It works on the already-open, symlink-safe descriptor, so unlike the macOS
// check it cannot be redirected by swapping the path.
func checkDirACL(fd int, path string) error {
	for _, name := range []string{xattrACLAccess, xattrACLDefault} {
		has, err := hasXattr(fd, name)
		if err != nil {
			return err
		}
		if has {
			return denied("%q carries an extended ACL", path)
		}
	}
	return nil
}

// checkFileACL refuses a file that carries an access ACL. Called on the
// temporary file right before the secret is written, so an entry inherited
// from a default ACL — or set in the instant after the directory was checked
// — is caught where it would actually expose the value.
func checkFileACL(fd int) error {
	has, err := hasXattr(fd, xattrACLAccess)
	if err != nil {
		return err
	}
	if has {
		return denied("file carries an extended ACL")
	}
	return nil
}

// checkExistingFileACL is checkFileACL for a target that already exists,
// found through its descriptor; the path is not needed here.
func checkExistingFileACL(fd int, _ string) error { return checkFileACL(fd) }

// POSIX ACL xattr layout: a little-endian uint32 version, then 8-byte
// entries (uint16 tag, uint16 perm, uint32 id).
const (
	aclXattrVersion = 2
	aclTagUser      = 0x02
	aclTagGroup     = 0x08
	aclTagMask      = 0x10
	aclPermWrite    = 0x02
	aclUndefinedID  = 0xffffffff
)

// checkAncestorACL is checkDirACL for a directory above the target's parent.
// An ancestor is only walked through, so a read or search grant does not
// matter here (mode bits do not police that for ancestors either); what does
// is a grant that lets someone other than the directory's owner and root
// write, add or delete in it: that someone can swap the next component for
// a link or a directory of their own after the walk has passed it. Only the
// access ACL counts (a default ACL shapes files created later in that
// directory, never the target's). Entries are read from the descriptor the
// walk holds, not from the path. A named-user or named-group entry counts
// when its write bit survives the mask; one that cannot be read or parsed is
// refused.
func checkAncestorACL(fd int, path string) error {
	n, err := unix.Fgetxattr(fd, xattrACLAccess, nil)
	switch {
	case err == nil:
	case errors.Is(err, unix.ENODATA), errors.Is(err, unix.ENOTSUP):
		return nil
	default:
		return writeFailed("read %s: %v", xattrACLAccess, err)
	}
	buf := make([]byte, n)
	n, err = unix.Fgetxattr(fd, xattrACLAccess, buf)
	if err != nil {
		return writeFailed("read %s: %v", xattrACLAccess, err)
	}
	buf = buf[:n]
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return writeFailed("stat directory %q: %v", path, err)
	}
	grantee, err := aclWriteGrantee(buf, st.Uid)
	if err != nil {
		return denied("%q carries an ACL that cannot be parsed", path)
	}
	if grantee != "" {
		return denied("%q carries an ACL granting write to %s", path, grantee)
	}
	return nil
}

// aclWriteGrantee names the first user or group other than root and owner
// that the access ACL in buf gives write to (after the mask), or "" if none.
func aclWriteGrantee(buf []byte, owner uint32) (string, error) {
	if len(buf) < 4 || binary.LittleEndian.Uint32(buf) != aclXattrVersion || (len(buf)-4)%8 != 0 {
		return "", errors.New("malformed POSIX ACL")
	}
	type entry struct {
		tag, perm uint16
		id        uint32
	}
	var entries []entry
	mask := uint16(0x07)
	for b := buf[4:]; len(b) > 0; b = b[8:] {
		e := entry{binary.LittleEndian.Uint16(b), binary.LittleEndian.Uint16(b[2:]), binary.LittleEndian.Uint32(b[4:])}
		if e.tag == aclTagMask {
			mask = e.perm
		}
		entries = append(entries, e)
	}
	for _, e := range entries {
		if e.perm&mask&aclPermWrite == 0 {
			continue
		}
		if e.tag == aclTagUser && e.id != 0 && e.id != owner {
			return fmt.Sprintf("user %d", e.id), nil
		}
		if e.tag == aclTagGroup && e.id != 0 {
			return fmt.Sprintf("group %d", e.id), nil
		}
	}
	return "", nil
}
