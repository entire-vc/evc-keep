//go:build darwin

package targets

import (
	"errors"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
)

// checkDirACL is the platform hook walkToParent calls on the target's parent
// directory. On macOS it shells out by path (see checkACL); the file check
// below is a no-op because a temporary file can only inherit an ACL from a
// parent that has one, which checkDirACL has already refused.
func checkDirACL(_ int, p string) error { return checkACL(p) }

func checkFileACL(int) error { return nil }

// checkExistingFileACL: an existing target that carries an ACL may grant an
// agent write access mode bits do not show. The check is by path, as for the
// directory (see checkACL).
func checkExistingFileACL(_ int, p string) error { return checkACL(p) }

// checkACL refuses if p carries a macOS extended ACL (`chmod +a`, e.g. from
// an inheritable ACL on a parent directory). Standard POSIX mode bits do not
// reflect an ACL grant, so the mode-bit checks in this package can pass
// while an ACL still hands an agent access underneath them.
//
// There is no syscall wrapper for the Darwin ACL API in the standard
// library or golang.org/x/sys without cgo, so this shells out to `ls -led`
// (as does every other ACL-aware tool on macOS without cgo) and looks for
// the indexed-entry lines it prints after the normal listing line when an
// ACL is present. This reopens p by path rather than by the already-open,
// symlink-safe descriptor this package holds for it: a symlink swap in the
// window between the fd walk and this call is a real but narrow residual
// gap, on a check that is itself defense in depth on top of the mode-bit
// and ownership checks that do use the safe descriptor.
func checkACL(p string) error {
	lines, err := lsACLEntries(p)
	if err != nil {
		return err
	}
	if len(lines) > 0 {
		return denied("%q carries an extended ACL", p)
	}
	return nil
}

// lsACLEntries returns the ACL entry lines `ls -led` prints for p, indexes
// stripped. A path that has vanished yields none; any other ls failure
// fails closed.
func lsACLEntries(p string) ([]string, error) {
	cmd := exec.Command("/bin/ls", "-led", p) //nolint:gosec // G204: p is our own resolved target/parent path, not attacker input
	cmd.Env = []string{"LC_ALL=C"}            // not the runner's environment
	out, err := cmd.Output()
	if err != nil {
		// Only a path that has genuinely vanished under us passes through:
		// the caller's own fd-based operations will fail on that same
		// condition right after, so this check does not need to diagnose
		// it. Any other failure — ls missing, exec blocked by a sandbox,
		// a transient resource error — must fail closed: silently passing
		// would defeat the one check in this package that catches an ACL
		// grant mode bits cannot show, exactly the gap this exists to close.
		var st unix.Stat_t
		if statErr := unix.Lstat(p, &st); errors.Is(statErr, unix.ENOENT) {
			return nil, nil
		}
		return nil, writeFailed("check ACL on %q: %v", p, err)
	}
	var entries []string
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	for _, l := range lines[1:] {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		// Each ACL entry line `ls -le` prints starts "N: " (its index).
		if i := strings.IndexByte(l, ':'); i > 0 && i <= 3 {
			if _, ok := parseUint(l[:i]); ok {
				entries = append(entries, strings.TrimSpace(l[i+1:]))
			}
		}
	}
	return entries, nil
}

// ancestorWritePerms are the permissions of a directory ACL entry that let
// its subject change what the directory's names point at, or rewrite the
// ACL to give themselves that.
var ancestorWritePerms = map[string]bool{
	"add_file": true, "add_subdirectory": true, "delete": true, "delete_child": true,
	"write": true, "append": true, "writesecurity": true, "chown": true,
}

// checkAncestorACL is the check for a directory above the target's parent,
// by path like checkACL (no descriptor-based ACL API without cgo): an
// "allow" entry carrying a write, add or delete permission for any subject
// but root refuses. Deny entries (every home directory has `everyone deny
// delete`) and read or search grants do not. The directory's owner is not
// exempted by name, since entries print as names, not ids; an ACL that names
// the owner with a write permission is refused too, which is the safe side.
func checkAncestorACL(_ int, p string) error {
	entries, err := lsACLEntries(p)
	if err != nil {
		return err
	}
	for _, e := range entries {
		i := strings.LastIndex(e, " allow ")
		if i < 0 {
			continue
		}
		if strings.TrimSpace(e[:i]) == "user:root" {
			continue
		}
		for _, perm := range strings.Split(strings.TrimSpace(e[i+len(" allow "):]), ",") {
			if ancestorWritePerms[strings.TrimSpace(perm)] {
				return denied("%q carries an ACL granting write", p)
			}
		}
	}
	return nil
}

func parseUint(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}
