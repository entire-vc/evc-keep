//go:build unix

package targets

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// afterTmpCreate is called once, right after the temporary file is created
// and before it is stat'd or written to. Production leaves it a no-op; a
// test overrides it to inject a race (e.g. hardlink the new name to another
// path) at exactly the point the nlink check below is meant to catch.
var afterTmpCreate = func(parentFD int, name string) {}

// beforeDirOpen is called just before walkToParent opens directory
// component i (named seg) of the walk, once per component, in order.
// Production leaves it a no-op; a test overrides it to replace a
// not-yet-opened component with a symlink right before the walk reaches it,
// simulating a directory-to-symlink race between two of the walk's own
// steps rather than one set up before the walk starts.
var beforeDirOpen = func(i int, seg string) {}

// afterExistingOpen is called with the descriptor readExisting has just opened
// on an existing target, so a test can inspect its flags while it is open.
// Production code leaves it a no-op.
var afterExistingOpen = func(fd int) {}

// checkAncestorACLHook is the ACL check run on every directory the walk opens
// above the target's parent (the parent gets the stricter checkDirACL). It is
// a variable only so a test can record which directories the walk really
// reached; production never assigns it.
var checkAncestorACLHook = checkAncestorACL

// beforeStaleUnlink runs in cleanupStaleTmp between the Fstatat that vetted a
// name and the Unlinkat that removes it: the window a swapped name would
// use. Unlinkat removes whatever the name is now without following or
// opening it. Production leaves it a no-op.
var beforeStaleUnlink = func(parentFD int, name string) {}

// walkToParent opens, one path component at a time with O_NOFOLLOW, every
// directory from the filesystem root down to absPath's own parent. A
// symlink or a non-directory anywhere on the way is refused, as is any
// directory writable by an agent (hardlink/race defense) or carrying an ACL
// that lets anyone but the owner and root write, add or delete in it, and —
// for the immediate parent only — readable or traversable by an agent
// (R-POL-4) or carrying any extended ACL at all. It
// returns an open descriptor to the parent directory and absPath's base
// name; every later operation on the target goes through that descriptor,
// so nothing after this call can redirect it by changing the path.
func walkToParent(absPath string, ag agentSet) (parentFD int, base string, err error) {
	if !path.IsAbs(absPath) || path.Clean(absPath) != absPath || absPath == "/" {
		return -1, "", denied("path is not a clean, non-root absolute path")
	}
	segs := strings.Split(absPath[1:], "/")
	base = segs[len(segs)-1]
	dirSegs := segs[:len(segs)-1]

	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", writeFailed("open filesystem root: %v", err)
	}
	rootIsParent := len(dirSegs) == 0
	if err := checkDir(fd, "/", ag, rootIsParent); err != nil {
		_ = unix.Close(fd)
		return -1, "", err
	}
	aclCheck := checkAncestorACLHook
	if rootIsParent {
		aclCheck = checkDirACL
	}
	if err := aclCheck(fd, "/"); err != nil {
		_ = unix.Close(fd)
		return -1, "", err
	}
	acc := ""
	for i, seg := range dirSegs {
		if seg == "" || seg == "." || seg == ".." {
			_ = unix.Close(fd)
			return -1, "", denied("path has an empty or relative component")
		}
		beforeDirOpen(i, seg)
		nfd, oerr := unix.Openat(fd, seg, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if oerr != nil {
			// O_DIRECTORY|O_NOFOLLOW on a symlink component reports ELOOP on
			// Linux but ENOTDIR on Darwin — both mean the same thing here
			// ("this component did not resolve to a plain directory"),
			// which is exactly the class of thing this walk refuses,
			// whether the actual cause is a symlink or something else
			// occupying the name.
			if errors.Is(oerr, unix.ELOOP) || errors.Is(oerr, unix.ENOTDIR) {
				return -1, "", denied("path component %q is not a plain directory", seg)
			}
			return -1, "", writeFailed("open directory %q: %v", seg, oerr)
		}
		fd = nfd
		acc += "/" + seg
		isParent := i == len(dirSegs)-1
		if err := checkDir(fd, seg, ag, isParent); err != nil {
			_ = unix.Close(fd)
			return -1, "", err
		}
		aclCheck := checkAncestorACLHook
		if isParent {
			aclCheck = checkDirACL
		}
		if err := aclCheck(fd, acc); err != nil {
			_ = unix.Close(fd)
			return -1, "", err
		}
	}
	return fd, base, nil
}

func checkDir(fd int, seg string, ag agentSet, isParent bool) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return writeFailed("stat directory %q: %v", seg, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return denied("path component %q is not a directory", seg)
	}
	if err := ag.refuseWritable(fmt.Sprintf("directory %q", seg), &st); err != nil {
		return err
	}
	if isParent {
		if err := ag.refuseReachable(fmt.Sprintf("directory %q", seg), &st); err != nil {
			return err
		}
	}
	return nil
}

// validateTargetPerm re-checks, independently of pkg/runnerproto's
// declarative HostPolicy.Check, that the mode/owner this write is about to
// apply would not leave the target reachable by an agent. Defense in depth:
// this package must not trust that every caller already ran Check.
func validateTargetPerm(mode uint32, uid, gid int64, ag agentSet) error {
	switch {
	case mode == 0 || mode&^0o777 != 0:
		return denied("target mode must be non-zero permission bits only")
	case mode&0o007 != 0:
		return denied("target would be readable by anyone")
	}
	if ag.hasUID(uid) {
		return denied("target owner is an agent")
	}
	if mode&0o070 != 0 && ag.groupIsAgents(gid) {
		return denied("target would be readable by an agent group")
	}
	return nil
}

// randomTmpName is a variable only so a test can make the name predictable,
// the way an attacker would need it to be to plant a file at it; production
// never assigns it.
var randomTmpName = func(base string) (string, error) {
	b := make([]byte, staleTmpSuffixLen/2)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return staleTmpPrefix(base) + hex.EncodeToString(b), nil
}

// staleTmpSuffixLen is hex.EncodeToString's output length for the 12 random
// bytes randomTmpName uses — the exact shape a name must have, on top of the
// prefix, to be considered ours.
const staleTmpSuffixLen = 24

// staleTmpPrefix is the fixed part of the name randomTmpName generates for
// base, shared with cleanupStaleTmp so both stay in step with each other.
func staleTmpPrefix(base string) string {
	return "." + base + ".tmp-"
}

// isOwnedStaleTmp reports whether name/st is a temp file cleanupStaleTmp may
// remove: exactly the shape randomTmpName produces for prefix (never a
// prefix match alone — a longer or non-hex suffix is left untouched), a
// regular file with a single link, owned by self. Split out from
// cleanupStaleTmp so these safety conditions are testable directly against
// synthetic stat values, the same way agentOwnedDir tests refuseWritable —
// fabricating a real file with another uid's ownership needs root, but the
// decision this makes from a Stat_t does not.
func isOwnedStaleTmp(name, prefix string, owners []int64, st *unix.Stat_t) bool {
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	suffix := name[len(prefix):]
	if len(suffix) != staleTmpSuffixLen {
		return false
	}
	if _, err := hex.DecodeString(suffix); err != nil {
		return false
	}
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Nlink == 1 && slices.Contains(owners, int64(st.Uid))
}

// cleanupStaleTmp removes temp files a previous write to this directory left
// behind after being killed between O_CREAT|O_EXCL and the Renameat that
// commits it: secureCreateAndWrite's own deferred unlink only ever runs for
// the write that is still on the stack when the process dies, it does not
// exist to run for one that already ended. Run at the start of the next
// write to the same directory, before the new temp file's own name is even
// chosen, so an old one never accumulates past the write that follows it.
// Only files last modified no later than the start of this write go: a
// temporary file newer than that belongs to a write that began after this
// one, still filling it.
// Best-effort and silent: a directory it cannot list, or a name it cannot
// stat or unlink, is left for the write after this one to try again —
// cleanup is not on this write's own critical path, and its failure must
// never fail the write.
//
// uid is the target's owner, not just this process's own euid: a crash can
// land after the temp file's Fchown to uid (below) but before the rename
// that would have replaced it, and an orphan from that window belongs to
// uid, not necessarily to whoever this process runs as (a root runner
// writing on behalf of a service account, the common case). Matches the
// owners readExisting is handed for the same reason.
func cleanupStaleTmp(parentFD int, base string, uid int64, writeStart time.Time) {
	dfd, err := unix.Openat(parentFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	dir := os.NewFile(uintptr(dfd), ".")
	names, err := dir.Readdirnames(-1)
	_ = dir.Close()
	if err != nil {
		return
	}
	prefix := staleTmpPrefix(base)
	owners := staleTmpOwners(uid)
	for _, name := range names {
		var st unix.Stat_t
		if err := unix.Fstatat(parentFD, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			continue
		}
		if isOwnedStaleTmp(name, prefix, owners, &st) && modifiedBefore(&st, writeStart) {
			beforeStaleUnlink(parentFD, name)
			_ = unix.Unlinkat(parentFD, name, 0)
		}
	}
}

// staleTmpOwners are the uids whose leftover temporary files cleanup may
// remove: this process's own and the target's configured owner.
func staleTmpOwners(uid int64) []int64 {
	return []int64{int64(unix.Geteuid()), uid}
}

// modifiedBefore reports whether a file whose Fstatat result is st was last
// modified no later than t: a leftover of an earlier, ended write, never a
// temporary file a write that began after t is filling right now. It reads
// the same stat that vetted the name (type, owner), so there is no second
// look at the name for a swap to slip into.
func modifiedBefore(st *unix.Stat_t, t time.Time) bool {
	return !statMtime(st).After(t)
}

// beforeRename is called once, after the content is written and synced and
// immediately before the final recheck of the temporary file; afterRename,
// right after the rename, before anything reads the target back. Production
// leaves both a no-op; a test overrides them to inject a race in those two
// windows.
var (
	beforeRename = func(parentFD int, name string) {}
	afterRename  = func(parentFD int, base string) {}
)

// afterChmod is called once, right after the temporary file's owner and
// mode are set and immediately before the recheck below (and before any
// content is written). Production leaves it a no-op; a test overrides it to
// inject a race there, the same way afterTmpCreate does right after the
// file's creation.
var afterChmod = func(parentFD int, name string) {}

// checkTmpFile refuses unless fd — the temporary file, about to receive the
// secret — is what secureCreateAndWrite made it: a regular file with exactly
// one link, owned by uid:gid and carrying exactly mode. Run right before the
// content is written, after the owner and mode are set, so it also reads
// the outcome of Fchown/Fchmod back from the inode rather than trusting
// their return values (a filesystem that ignores a chown is refused here —
// including a filesystem or inherited-group setup that applies the uid half
// of a chown but silently keeps the old group, which would otherwise leave
// the file readable by whatever group it had before, undetected).
func checkTmpFile(fd int, uid, gid int64, mode uint32) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return writeFailed("stat temporary file: %v", err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return denied("temporary file is not a regular file")
	case st.Nlink == 0:
		// Not "more than one link": a concurrent write to this same directory
		// runs its own cleanupStaleTmp first and, on an unlucky interleaving,
		// can unlink this file out from under us before we get here — its
		// name matches the same stale-tmp shape while it is still being
		// written to, since the crash-orphan check has no way to tell "stale
		// from a crash" from "in flight right now". The fd stays valid to
		// write to (removing a name never invalidates an already-open
		// descriptor), but the rename that would publish it has nothing left
		// to replace, so refusing here is correct — just name the actual
		// cause instead of the unrelated wording below.
		return denied("temporary file was removed by a concurrent write to the same directory")
	case st.Nlink != 1:
		return denied("temporary file has more than one link")
	case int64(st.Uid) != uid:
		return denied("temporary file is not owned by the target's owner")
	case int64(st.Gid) != gid:
		return denied("temporary file does not carry the target's group")
	case uint32(st.Mode)&0o7777 != mode:
		return denied("temporary file does not carry the target's mode")
	}
	return nil
}

// secureCreateAndWrite creates a fresh, exclusively-owned temporary file in
// the directory held by parentFD, sets its owner and mode, writes content,
// fsyncs it, and renames it over base — all against the held descriptor, so
// a later change to the directory's path cannot redirect any of this.
//
// O_CREAT|O_EXCL refuses a pre-existing name, so the only way a second link
// to the new inode can exist is one created after our open (afterTmpCreate
// and afterChmod are where a test injects exactly that). The window that
// matters is the one before content is written: without a check, that second
// name would read the secret once we write it. A directory that is writable
// by a non-owner but sticky (allowed: the sticky bit closes the
// *rename/unlink* race — see agents.go) still permits *adding* a new link to
// an existing file one does not own, so the check runs once, as late as
// possible — after Fchown/Fchmod, immediately before the first byte — rather
// than right after creation, where a link added a moment later would slip
// through. The same call also reads owner and mode back, and the platform's
// ACL check (checkFileACL) runs on the same descriptor: a default ACL
// inherited from the directory shows up only on the file, and mode bits do
// not reveal it.
func secureCreateAndWrite(parentFD int, base string, mode uint32, uid, gid int64, content []byte) error {
	cleanupStaleTmp(parentFD, base, uid, time.Now())

	tmp, err := randomTmpName(base)
	if err != nil {
		return writeFailed("generate temporary name: %v", err)
	}
	fd, err := unix.Openat(parentFD, tmp, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return writeFailed("create temporary file: %v", err)
	}
	committed := false
	defer func() {
		_ = unix.Close(fd)
		if !committed {
			_ = unix.Unlinkat(parentFD, tmp, 0)
		}
	}()

	afterTmpCreate(parentFD, tmp)

	if err := unix.Fchown(fd, int(uid), int(gid)); err != nil {
		return writeFailed("set owner: %v", err)
	}
	if err := unix.Fchmod(fd, mode); err != nil {
		return writeFailed("set mode: %v", err)
	}

	afterChmod(parentFD, tmp)

	if err := checkFileACL(fd); err != nil {
		return err
	}
	if err := checkTmpFile(fd, uid, gid, mode); err != nil {
		return err
	}
	if err := writeAllFD(fd, content); err != nil {
		return writeFailed("write: %v", err)
	}
	if err := fsyncFD(fd); err != nil {
		return writeFailed("fsync: %v", err)
	}
	beforeRename(parentFD, tmp)
	// A second name for the inode, added while the content was being written,
	// has by now a way to read it: the target is not renamed into place, and
	// the temporary file goes, if that is what happened.
	if err := checkTmpFile(fd, uid, gid, mode); err != nil {
		return err
	}
	if err := unix.Renameat(parentFD, tmp, parentFD, base); err != nil {
		return writeFailed("rename into place: %v", err)
	}
	committed = true
	afterRename(parentFD, base)
	if err := fsyncFD(parentFD); err != nil {
		return writeFailed("fsync directory: %v", err)
	}
	return nil
}

// fsyncFD is unix.Fsync behind a variable: a test overrides it to prove
// that a failed fsync of the temporary file — the "write interrupted
// midway" red run — leaves the original target untouched, since it aborts
// before Renameat ever runs.
var fsyncFD = unix.Fsync

// readExisting reads base's current content inside parentFD's directory,
// symlink-safe: a symlink at that name is refused rather than followed. A
// missing file reports (nil, false, nil) — several target kinds treat "not
// there yet" as an empty starting point.
//
// An existing target must be a regular file with exactly one link, owned by
// one of owners (the runner itself and the target's consumer). Its content
// is folded into the new file (env-file, JSON, plist keep their other
// entries), so a hardlink an agent placed at the name — macOS has no
// protected_hardlinks — to another service's secret file, or a file owned by
// someone else, would be read and re-emitted into this service's target.
//
// When the kind folds the existing content into the new file (folds: env-file,
// launchd-env, the JSON kinds; not file or systemd-credential, which replace
// it wholesale and never carry a byte of it over), it must also not be
// writable by anyone else: an agent that can write the file can plant content (a launchd argv entry, an mcp-config command, an
// env line) that this write would carry, byte for byte, into a fresh file the
// agent can no longer touch. So a target writable by others, or by an agent
// group, or carrying an extended ACL (which mode bits cannot show), is
// refused, not adopted as the base.
func readExisting(parentFD int, base, full string, owners []int64, ag agentSet, folds bool) (content []byte, exists bool, err error) {
	// O_NONBLOCK: a FIFO placed at the name would otherwise block this open
	// until someone opens its other end. It is refused as not-a-regular-file
	// below, and has no effect on a regular file.
	fd, oerr := unix.Openat(parentFD, base, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if oerr != nil {
		if errors.Is(oerr, unix.ENOENT) {
			return nil, false, nil
		}
		if errors.Is(oerr, unix.ELOOP) {
			return nil, false, denied("target %q is a symlink", base)
		}
		return nil, false, writeFailed("open existing target: %v", oerr)
	}
	defer func() { _ = unix.Close(fd) }()
	afterExistingOpen(fd)

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, false, writeFailed("stat existing target: %v", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, false, denied("target %q is not a regular file", base)
	}
	if st.Nlink != 1 {
		return nil, false, denied("target %q has more than one link", base)
	}
	if !slices.Contains(owners, int64(st.Uid)) {
		return nil, false, denied("target %q is owned by neither the runner nor the target's owner", base)
	}
	if folds {
		if err := ag.refuseWritableFile(fmt.Sprintf("target %q", base), &st); err != nil {
			return nil, false, err
		}
		if err := checkExistingFileACL(fd, full); err != nil {
			return nil, false, err
		}
	}
	if st.Size > maxTargetSize {
		return nil, false, writeFailed("existing target %q is too large", base)
	}
	b, err := readAllFD(fd, st.Size)
	if err != nil {
		return nil, false, writeFailed("read existing target: %v", err)
	}
	return b, true, nil
}

// maxTargetSize bounds how much of an existing target's content this
// package will fold into a new one. Enforced twice: the cheap check above,
// from the Fstat readExisting already did, rejects the common case before a
// single byte is read; readAllFD enforces it again, independently, inside
// its own read loop, in case the file grows after that Fstat and during the
// read itself (a concurrent writer appending to it — anything that could
// instead replace the file or add a second link to it is already refused by
// the nlink/owner checks around this call, not by this bound).
const maxTargetSize = 4 << 20

// readAllFD reads fd to EOF into a buffer sized from the file (plus one byte,
// so the EOF read needs no growth), refusing once the total read exceeds
// maxTargetSize regardless of what sizeHint said going in — sizeHint is a
// stat taken before this call and is not trustworthy against a file still
// growing under it. What it reads may be a file of other services' secrets:
// the scratch buffer is wiped, a buffer outgrown by a file that changed
// under it is wiped after the copy, and so is the partial result of a failed
// or refused read.
func readAllFD(fd int, sizeHint int64) ([]byte, error) {
	out := make([]byte, 0, sizeHint+1)
	buf := make([]byte, 32*1024)
	defer wipe(buf)
	for {
		n, err := unix.Read(fd, buf)
		if n > 0 {
			if int64(len(out)+n) > maxTargetSize {
				wipe(out)
				return nil, fmt.Errorf("target grew past the %d byte limit while being read", maxTargetSize)
			}
			if len(out)+n > cap(out) {
				grown := make([]byte, len(out), 2*cap(out)+n)
				copy(grown, out)
				wipe(out)
				out = grown
			}
			out = append(out, buf[:n]...)
		}
		if err != nil {
			wipe(out)
			return nil, err
		}
		if n == 0 {
			return out, nil
		}
	}
}

func writeAllFD(fd int, content []byte) error {
	for len(content) > 0 {
		n, err := unix.Write(fd, content)
		if err != nil {
			return err
		}
		content = content[n:]
	}
	return nil
}
