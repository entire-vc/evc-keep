//go:build unix

package targets

import (
	"crypto/subtle"
	"errors"
	"slices"

	"golang.org/x/sys/unix"

	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

// OwnerOf reports who owns the file a target names. The file is opened
// without following links, and only to look at it: nothing is read. The runner
// decides on the file before it asks the server for anything. exists is false
// when the file is not there. The path is walked as Write walks it, so a directory on the way that an agent can reach refuses
// first. Errors wrap ErrPolicy or ErrWrite; callers report their class only.
func OwnerOf(t runnerproto.Target, agentUIDs, agentGIDs []int64) (uid int64, exists bool, err error) {
	ag := agentSet{uids: agentUIDs, gids: agentGIDs}
	parentFD, base, err := walkToParent(t.Path, ag)
	if err != nil {
		return 0, false, err
	}
	defer func() { _ = unix.Close(parentFD) }()
	fd, err := unix.Openat(parentFD, base, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return 0, false, nil
		}
		if errors.Is(err, unix.ELOOP) {
			return 0, false, denied("target is a symlink")
		}
		return 0, false, writeFailed("open target: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return 0, false, writeFailed("stat target: %v", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return 0, false, denied("target is not a regular file")
	}
	if st.Nlink != 1 {
		return 0, false, denied("target has more than one link")
	}
	// What an agent can write is what an agent could plant a guess in: refused
	// here, before the runner asks the server for the key. Nothing is read.
	if err := ag.refuseWritableFile("target", &st); err != nil {
		return 0, false, err
	}
	if err := checkExistingFileACL(fd, t.Path); err != nil {
		return 0, false, err
	}
	return int64(st.Uid), true, nil
}

// Observe computes the fingerprint of what the target holds, for a verify
// job. owner is the uid OwnerOf reported: the file is opened again without
// following links and must still be a regular, single-link file owned by owner
// (or by the runner), so a swap after OwnerOf is refused. A target owned by an
// agent is refused whatever owner says: an agent that can write the file could
// use verify as an oracle for its own guesses. Nothing is written. found is
// false when the file or the field is not there; the value never leaves this
// function, only its fingerprint.
func Observe(t runnerproto.Target, owner int64, agentUIDs, agentGIDs []int64, fpKey fingerprint.Key) (fp string, found bool, err error) {
	if t.Kind == runnerproto.TargetSystemdCredential {
		return "", false, denied("target kind cannot be verified")
	}
	h, ok := kindHandlers[t.Kind]
	if !ok {
		return "", false, denied("unknown target kind")
	}
	ag := agentSet{uids: agentUIDs, gids: agentGIDs}
	if slices.Contains(agentUIDs, owner) {
		return "", false, denied("target owner is an agent")
	}
	parentFD, base, err := walkToParent(t.Path, ag)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = unix.Close(parentFD) }()
	content, exists, err := readExisting(parentFD, base, t.Path, []int64{owner, int64(unix.Geteuid())}, ag, true)
	if err != nil {
		return "", false, err
	}
	if !exists {
		return "", false, nil
	}
	defer wipe(content)
	v, err := h.readBack(content, t)
	if err != nil {
		return "", false, nil
	}
	defer v.Wipe()
	got, err := computeFingerprint(fpKey, v)
	if err != nil {
		return "", false, writeFailed("compute fingerprint: %v", err)
	}
	return got, true, nil
}

// SameFingerprint compares two fingerprints in constant time.
func SameFingerprint(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
