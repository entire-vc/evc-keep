//go:build unix

package targets

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"golang.org/x/sys/unix"
)

// TestExistingTargetHardlinkedToForeignSecretRefused is the read-side twin
// of TestHardlinkPreplacedAtTargetIsNotWrittenThrough. macOS has no
// protected_hardlinks: an agent who can add entries to a sticky directory
// makes `svc.env` a hardlink to another service's secret file. Write reads
// the existing target to preserve its other lines, so without a check it
// would fold the foreign file's content into this service's target. The
// canary sits in the foreign file: it must reach neither the target, nor an
// error.
func TestExistingTargetHardlinkedToForeignSecretRefused(t *testing.T) {
	c := canary.New()
	dir := safeDir(t)
	foreign := filepath.Join(dir, "other-service.env")
	foreignBody := []byte("OTHER_SERVICE_TOKEN=" + c.Value(0) + "\n")
	mustWriteFile(t, foreign, foreignBody, 0o600)
	targetPath := filepath.Join(dir, "svc.env")
	if err := os.Link(foreign, targetPath); err != nil {
		t.Fatal(err)
	}

	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetEnvFile, targetPath, "MY_TOKEN"), newValue("v"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrPolicy, "existing target that is a hardlink to another file")
	if c.In(err.Error()) {
		t.Fatalf("foreign content leaked into the error: %v", err)
	}
	if got := string(mustReadFile(t, targetPath)); got != string(foreignBody) {
		t.Fatalf("target was rewritten despite the refusal: %q", show([]byte(got)))
	}
}

// TestExistingTargetForeignOwnerRefused calls readExisting directly: making
// a file owned by another uid needs root, but the rule is only a comparison,
// so "the allowed owners are someone else" is the same situation seen from
// the other side. The second half is the positive control — with the real
// owner allowed the same file reads fine — so the refusal above is the owner
// check and not the file being unreadable.
func TestExistingTargetForeignOwnerRefused(t *testing.T) {
	dir := safeDir(t)
	mustWriteFile(t, filepath.Join(dir, "f"), []byte("x"), 0o600)
	fd, base, err := walkToParent(filepath.Join(dir, "f"), agentSet{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()

	_, _, err = readExisting(fd, base, "", []int64{selfUID() + 1}, agentSet{}, false)
	wantErr(t, err, ErrPolicy, "existing target owned by neither the runner nor the consumer")

	got, exists, err := readExisting(fd, base, "", []int64{selfUID()}, agentSet{}, false)
	if err != nil || !exists || string(got) != "x" {
		t.Fatalf("control read failed: %q %v %v", got, exists, err)
	}
}

// TestSymlinkedTargetContentNotMerged: a symlink at the target name that
// points at another service's env-file. The read of the existing target
// must refuse it (O_NOFOLLOW), otherwise the foreign secret lines are merged
// into the new file — nothing outside the target is *written*, which is all
// TestSymlinkOnTargetItselfRefused looked at.
func TestSymlinkedTargetContentNotMerged(t *testing.T) {
	c := canary.New()
	dir := safeDir(t)
	foreign := filepath.Join(dir, "other-service.env")
	mustWriteFile(t, foreign, []byte("OTHER_SERVICE_TOKEN="+c.Value(0)+"\n"), 0o600)
	targetPath := filepath.Join(dir, "svc.env")
	if err := os.Symlink(foreign, targetPath); err != nil {
		t.Fatal(err)
	}

	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetEnvFile, targetPath, "MY_TOKEN"), newValue("v"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrPolicy, "target is a symlink to another env-file")
	if fi, lerr := os.Lstat(targetPath); lerr != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the symlink was replaced by a regular file: %v %v", fi, lerr)
	}
}

// TestParentDirSwappedForSymlinkAfterWalkWritesToWalkedDir: the directory is
// swapped for a symlink to an attacker's directory *after* the walk, between
// the temporary file's creation and the rename. Every later operation goes
// through the held descriptor, so the value must land in the directory that
// was walked (now under another name) and nothing may appear in the
// attacker's. A rename by path would follow the new symlink.
func TestParentDirSwappedForSymlinkAfterWalkWritesToWalkedDir(t *testing.T) {
	dir := realDir(t)
	parent := filepath.Join(dir, "real")
	moved := filepath.Join(dir, "real.moved")
	evil := filepath.Join(dir, "evil")
	for _, d := range []string{parent, evil} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	orig := afterTmpCreate
	t.Cleanup(func() { afterTmpCreate = orig })
	swapped := false
	afterTmpCreate = func(int, string) {
		swapped = true
		if err := os.Rename(parent, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(evil, parent); err != nil {
			t.Fatal(err)
		}
	}

	uids, gids := noAgents()
	if _, err := Write(target(runnerproto.TargetFile, filepath.Join(parent, "target"), ""), newValue("the-value"), uids, gids, testFPKey(t)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !swapped {
		t.Fatal("test hook never fired")
	}
	if got := string(mustReadFile(t, filepath.Join(moved, "target"))); got != "the-value" {
		t.Fatalf("value did not land in the walked directory: %q", show([]byte(got)))
	}
	entries, err := os.ReadDir(evil)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("the attacker's directory received %d entries", len(entries))
	}
}

// The directory-ownership rule has two call sites — refuseWritable (every
// directory on the path) and refuseReachable (the immediate parent) — and
// they were switched off together by the old mutation script with nothing
// going red. Tested on the functions themselves, sticky and not: ownership
// gives control over the directory whatever the sticky bit says.
func agentOwnedDir(uid uint32, sticky bool) *unix.Stat_t {
	var st unix.Stat_t
	st.Uid = uid
	st.Mode = unix.S_IFDIR | 0o700
	if sticky {
		st.Mode |= unix.S_ISVTX
	}
	return &st
}

func TestAgentOwnedDirRefusedByRefuseWritable(t *testing.T) {
	ag := agentSet{uids: []int64{syntheticAgentUID}}
	for name, sticky := range map[string]bool{"plain": false, "sticky": true} {
		if err := ag.refuseWritable("d", agentOwnedDir(syntheticAgentUID, sticky)); err == nil {
			t.Errorf("%s: directory owned by an agent was accepted", name)
		}
		if err := ag.refuseWritable("d", agentOwnedDir(syntheticAgentUID+1, sticky)); err != nil {
			t.Errorf("%s: control — a directory owned by someone else was refused: %v", name, err)
		}
	}
}

func TestAgentOwnedDirRefusedByRefuseReachable(t *testing.T) {
	ag := agentSet{uids: []int64{syntheticAgentUID}}
	for name, sticky := range map[string]bool{"plain": false, "sticky": true} {
		if err := ag.refuseReachable("d", agentOwnedDir(syntheticAgentUID, sticky)); err == nil {
			t.Errorf("%s: directory owned by an agent was accepted", name)
		}
		if err := ag.refuseReachable("d", agentOwnedDir(syntheticAgentUID+1, sticky)); err != nil {
			t.Errorf("%s: control — a directory owned by someone else was refused: %v", name, err)
		}
	}
}

// TestWriteThroughAgentOwnedParentRefused is the same rule end to end, on a
// real directory: the test process owns everything under the tempdir, so
// declaring its own uid the agent uid makes every directory "agent-owned".
// The target's own owner is a synthetic uid, so validateTargetPerm's
// target-owner check does not fire first.
func TestWriteThroughAgentOwnedParentRefused(t *testing.T) {
	dir := safeDir(t)
	tg := target(runnerproto.TargetFile, filepath.Join(dir, "target"), "")
	tg.UID = syntheticAgentUID
	uids, _ := selfAsAgent()
	_, err := Write(tg, newValue("v"), uids, nil, testFPKey(t))
	wantErr(t, err, ErrPolicy, "path directory owned by an agent")
	if _, serr := os.Lstat(filepath.Join(dir, "target")); serr == nil {
		t.Fatal("target was created despite the refusal")
	}
}

// TestWriteAppliesOwnerGroupAndMode covers the Fchown that hands the file to
// the consumer. As root the owner itself is a foreign uid; otherwise the
// only ownership change the kernel permits is to a group the process
// belongs to, which is just as good for showing the call is made: without
// it the file keeps the runner's own (default) group.
func TestWriteAppliesOwnerGroupAndMode(t *testing.T) {
	uid, gid := selfUID(), selfGID()
	if unix.Geteuid() == 0 {
		uid, gid = 4242, 4243
	} else {
		groups, err := unix.Getgroups()
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, g := range groups {
			if int64(g) != selfGID() && !isEveryoneGID(int64(g)) { // "everyone" is refused as a target group on macOS, see agents.go
				gid, found = int64(g), true
				break
			}
		}
		if !found {
			t.Fatal("this test needs a supplementary group different from the primary one (or root) to observe chown")
		}
	}
	dir := safeDir(t)
	path := filepath.Join(dir, "target")
	tg := target(runnerproto.TargetFile, path, "")
	tg.Mode, tg.UID, tg.GID = 0o640, uid, gid
	uids, gids := noAgents()
	if _, err := Write(tg, newValue("v"), uids, gids, testFPKey(t)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		t.Fatal(err)
	}
	if int64(st.Uid) != uid || int64(st.Gid) != gid {
		t.Fatalf("owner = %d:%d, want %d:%d", st.Uid, st.Gid, uid, gid)
	}
	if st.Mode&0o7777 != 0o640 {
		t.Fatalf("mode = %o, want 640", st.Mode&0o7777)
	}
}

// TestFIFOAtTargetDoesNotBlockWrite: a FIFO placed at the target name (a
// sticky, world-writable parent allows it) makes a plain open block until
// someone opens the other end. The refusal must come without waiting.
func TestFIFOAtTargetDoesNotBlockWrite(t *testing.T) {
	dir := safeDir(t)
	fifo := filepath.Join(dir, "target")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		uids, gids := noAgents()
		_, err := Write(target(runnerproto.TargetFile, fifo, ""), newValue("v"), uids, gids, testFPKey(t))
		done <- err
	}()
	select {
	case err := <-done:
		wantErr(t, err, ErrPolicy, "FIFO at the target name")
	case <-time.After(5 * time.Second):
		// Unblock the stuck open so the goroutine (and the test binary) can end.
		if fd, err := unix.Open(fifo, unix.O_WRONLY|unix.O_NONBLOCK, 0); err == nil {
			_ = unix.Close(fd)
		}
		t.Fatal("Write blocked on a FIFO at the target name")
	}
}

// TestExistingTargetTooLargeRefused: the existing target is read into memory
// (its other entries are kept), so its size is bounded.
func TestExistingTargetTooLargeRefused(t *testing.T) {
	dir := safeDir(t)
	path := filepath.Join(dir, "big.env")
	// Valid env-file lines: only the size limit may refuse this file.
	mustWriteFile(t, path, bytes.Repeat([]byte("A=1\n"), (5<<20)/4+1), 0o600)
	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetEnvFile, path, "X"), newValue("v"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrWrite, "existing target over the size limit")
}

// TestReadAllFDBoundedIndependentlyOfSizeHint: readExisting's size check
// runs once, from a Fstat taken before the read starts. A file that grows
// past maxTargetSize between that Fstat and the end of the read loop — a
// concurrent writer appending to it, the target itself is never replaced or
// hardlinked under this read, those are refused independently — must not be
// read without bound just because the stat handed in was smaller. sizeHint
// is deliberately wrong here, standing in for that race without needing to
// win an actual one: readAllFD must refuse on its own once the total it has
// read crosses the limit, not trust the hint it was given.
func TestReadAllFDBoundedIndependentlyOfSizeHint(t *testing.T) {
	dir := safeDir(t)
	path := filepath.Join(dir, "big")
	content := bytes.Repeat([]byte("A"), maxTargetSize+100)
	mustWriteFile(t, path, content, 0o600)

	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()

	out, err := readAllFD(fd, 10)
	if err == nil {
		t.Fatalf("readAllFD accepted %d bytes past the limit", len(out))
	}
	if out != nil {
		t.Fatalf("readAllFD returned content alongside the error: %d bytes", len(out))
	}
}

// TestOrphanedTempFileFromCrashedWriteCleanedUpOnNextWrite: a process killed
// between secureCreateAndWrite's O_CREAT|O_EXCL and its Renameat leaves a
// ".<base>.tmp-<hex>" file behind — secureCreateAndWrite's own deferred
// unlink never runs for a write that no longer exists to run it. The next
// write to the same target must clean it up rather than let it accumulate.
// The orphan is planted directly, in exactly the shape randomTmpName
// produces, rather than by actually killing a write mid-flight: the crash
// itself is not what this test is about, only what is left behind by one.
func TestOrphanedTempFileFromCrashedWriteCleanedUpOnNextWrite(t *testing.T) {
	dir := safeDir(t)
	targetPath := filepath.Join(dir, "target")
	orphan := filepath.Join(dir, ".target.tmp-"+strings.Repeat("ab", staleTmpSuffixLen/2))
	mustWriteFile(t, orphan, []byte("leftover-from-a-killed-write"), 0o600)

	uids, gids := noAgents()
	if _, err := Write(target(runnerproto.TargetFile, targetPath, ""), newValue("v"), uids, gids, testFPKey(t)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := os.Lstat(orphan); !os.IsNotExist(err) {
		t.Fatalf("orphaned temp file was not cleaned up on the next write: err=%v", err)
	}
}

// TestStaleTmpCleanupSpecificToItsOwnDirectory: an orphan of one target must
// not affect a write to a different target in the same directory — the
// cleanup is scoped by the base name inside the shared prefix, not just by
// directory.
func TestStaleTmpCleanupSpecificToItsOwnDirectory(t *testing.T) {
	dir := safeDir(t)
	other := filepath.Join(dir, ".unrelated.tmp-"+strings.Repeat("ab", staleTmpSuffixLen/2))
	mustWriteFile(t, other, []byte("x"), 0o600)

	uids, gids := noAgents()
	if _, err := Write(target(runnerproto.TargetFile, filepath.Join(dir, "target"), ""), newValue("v"), uids, gids, testFPKey(t)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := os.Lstat(other); err != nil {
		t.Fatalf("a different target's temp file was removed: %v", err)
	}
}

// TestIsOwnedStaleTmpSafetyConditions: the removal decision against
// synthetic stat values — fabricating another uid's ownership on a real
// file needs root, the decision made from a Stat_t does not. owners here
// stands in for cleanupStaleTmp's real {euid, target uid} pair — a root
// runner's own euid and the service account it writes on behalf of are
// different numbers, and an orphan can be owned by either one depending on
// whether the crash landed before or after the temp file's Fchown to the
// target's owner.
func TestIsOwnedStaleTmpSafetyConditions(t *testing.T) {
	prefix := staleTmpPrefix("target")
	goodName := prefix + strings.Repeat("ab", staleTmpSuffixLen/2)
	self := selfUID()
	targetOwner := self + 1000 // stands in for a distinct target uid, e.g. root running on behalf of a service account
	owners := []int64{self, targetOwner}
	selfU32 := uidT(t, self)
	targetOwnerU32 := uidT(t, targetOwner)

	regular := func() unix.Stat_t {
		return unix.Stat_t{Mode: unix.S_IFREG, Nlink: 1, Uid: selfU32}
	}

	cases := []struct {
		name string
		n    string
		st   unix.Stat_t
		want bool
	}{
		{"matches our own orphan", goodName, regular(), true},
		{"matches the target owner's orphan, not our own euid", goodName, func() unix.Stat_t { st := regular(); st.Uid = targetOwnerU32; return st }(), true},
		// Same length as "target" so a disabled prefix check would still
		// pass the suffix-length and hex checks below — otherwise those
		// would catch this case too and the prefix check itself would be
		// unproven.
		{"wrong prefix, same shape otherwise", staleTmpPrefix("abcdef") + strings.Repeat("ab", staleTmpSuffixLen/2), regular(), false},
		{"suffix too short", prefix + "ab", regular(), false},
		{"suffix too long", goodName + "ab", regular(), false},
		{"suffix not hex", prefix + strings.Repeat("zz", staleTmpSuffixLen/2), regular(), false},
		{"second link", goodName, func() unix.Stat_t { st := regular(); st.Nlink = 2; return st }(), false},
		{"owned by someone else", goodName, func() unix.Stat_t { st := regular(); st.Uid = selfU32 + 1; return st }(), false},
		{"not a regular file", goodName, func() unix.Stat_t { st := regular(); st.Mode = unix.S_IFDIR; return st }(), false},
		{"symlink at the name", goodName, func() unix.Stat_t { st := regular(); st.Mode = unix.S_IFLNK; return st }(), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := c.st
			if got := isOwnedStaleTmp(c.n, prefix, owners, &st); got != c.want {
				t.Errorf("isOwnedStaleTmp(%q) = %v, want %v", c.n, got, c.want)
			}
		})
	}
}

// TestTmpFileUnlinkedConcurrentlyRefusedWithCorrectMessage exercises
// checkTmpFile's Nlink==0 branch for real: afterChmod fires after the
// temporary file's owner and mode are set, right before checkTmpFile stats
// it, and unlinks it there — the same race a concurrent write's own
// cleanupStaleTmp could cause, per checkTmpFile's own doc comment. The
// still-open fd stays writable (removing a name never invalidates it), so
// Write must refuse citing removal by a concurrent write, not the unrelated
// "more than one link" wording that Nlink!=1 alone would produce.
func TestTmpFileUnlinkedConcurrentlyRefusedWithCorrectMessage(t *testing.T) {
	dir := realDir(t)

	orig := afterChmod
	t.Cleanup(func() { afterChmod = orig })
	fired := false
	afterChmod = func(parentFD int, name string) {
		fired = true
		if err := unix.Unlinkat(parentFD, name, 0); err != nil {
			t.Fatal(err)
		}
	}

	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetFile, filepath.Join(dir, "target"), ""), newValue("v"), uids, gids, testFPKey(t))
	if !fired {
		t.Fatal("test hook never fired")
	}
	wantErr(t, err, ErrPolicy, "concurrent unlink of the temporary file")
	msg := err.Error()
	if !strings.Contains(msg, "removed by a concurrent write") {
		t.Fatalf("message = %q, want it to name the concurrent-write cause", msg)
	}
	if strings.Contains(msg, "more than one link") {
		t.Fatalf("message = %q, want it not to use the unrelated Nlink!=1 wording", msg)
	}
}

// TestConfirmPhaseReadBackFailureAfterRenameReturnsErrUnconfirmed:
// afterRename fires only once Renameat has already published the new
// content (see its doc comment in securewrite_unix.go and
// TestReadBackRefusesTargetReplacedAfterRename, which uses the same hook) —
// swapping in a directory at that name here reaches exactly the situation
// ErrUnconfirmed exists for: the target holds new content, but the
// post-rename read that would confirm it fails (readExisting refuses a
// non-regular-file target, the same check that guards the pre-write read of
// an existing target — deliberately reused here rather than a synthetic
// failure, to show a real failure of that class gets reclassified too).
//
// Write must report ErrUnconfirmed, not ErrWrite or ErrPolicy (the class
// readExisting's own refusal would naturally carry): the whole reason for
// the separate sentinel is that a caller reading either as "target
// untouched" would be exactly wrong here — Renameat already ran.
// TestConfirmPhaseParseFailureAfterRenameReturnsErrUnconfirmed below covers
// the sibling call site one step later (readBack, once the read itself
// succeeded).
func TestConfirmPhaseReadBackFailureAfterRenameReturnsErrUnconfirmed(t *testing.T) {
	dir := realDir(t)
	targetPath := filepath.Join(dir, "target")

	orig := afterRename
	t.Cleanup(func() { afterRename = orig })
	fired := false
	afterRename = func(_ int, base string) {
		fired = true
		if err := os.Remove(filepath.Join(dir, base)); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(dir, base), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	c := canary.New()
	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetFile, targetPath, ""), newValue(c.Value(0)), uids, gids, testFPKey(t))
	if !fired {
		t.Fatal("test hook never fired")
	}
	wantErr(t, err, ErrUnconfirmed, "post-rename read-back refuses a non-regular-file target")
	if errors.Is(err, ErrWrite) || errors.Is(err, ErrPolicy) {
		t.Fatalf("ErrUnconfirmed must not satisfy errors.Is(err, ErrWrite) or ErrPolicy: %v", err)
	}
	if c.In(err.Error()) {
		t.Fatalf("canary leaked into ErrUnconfirmed text: %v", err)
	}
}

// TestConfirmPhaseParseFailureAfterRenameReturnsErrUnconfirmed: the sibling
// case one step later than the test above — the post-rename read succeeds
// (afterRename here swaps in content that is still a perfectly valid,
// singly-linked, correctly-owned regular file), but the kindHandler's
// readBack cannot find MY_TOKEN in it, the same "field not found after
// write" refusal envFileHandler.readBack already returns for other reasons
// (see envfile-field-missing-ok in check-targets-mutations.sh). That
// refusal is ErrWrite-shaped at its source; Write must still report it as
// ErrUnconfirmed once it happens after Renameat.
func TestConfirmPhaseParseFailureAfterRenameReturnsErrUnconfirmed(t *testing.T) {
	dir := realDir(t)
	targetPath := filepath.Join(dir, "svc.env")

	orig := afterRename
	t.Cleanup(func() { afterRename = orig })
	fired := false
	afterRename = func(parentFD int, base string) {
		fired = true
		mustWriteFile(t, filepath.Join(dir, base), []byte("OTHER=1\n"), 0o600)
	}

	c := canary.New()
	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetEnvFile, targetPath, "MY_TOKEN"), newValue(c.Value(0)), uids, gids, testFPKey(t))
	if !fired {
		t.Fatal("test hook never fired")
	}
	wantErr(t, err, ErrUnconfirmed, "post-rename readBack does not find the written field")
	if errors.Is(err, ErrWrite) {
		t.Fatalf("ErrUnconfirmed must not satisfy errors.Is(err, ErrWrite): %v", err)
	}
	if c.In(err.Error()) {
		t.Fatalf("canary leaked into ErrUnconfirmed text: %v", err)
	}
}

// TestConfirmPhaseFingerprintFailureAfterRenameReturnsErrUnconfirmed is the
// third and last confirm-phase site: the post-rename read-back and the
// kindHandler's readBack both succeed, but fingerprint.Compute itself fails
// on the value that is now on disk. In real use this call cannot fail with
// the same key that already passed Write's pre-flight check a few lines
// earlier (fingerprint.Compute's only error, ErrZeroKey, is a pure function
// of the key, not the value) - which is exactly why this test drives it
// through computeFingerprint rather than a real broken key: the seam lets
// the first (pre-flight) call succeed normally and only the second
// (confirm-phase) call fail, a state no natural input can reach.
func TestConfirmPhaseFingerprintFailureAfterRenameReturnsErrUnconfirmed(t *testing.T) {
	dir := realDir(t)
	targetPath := filepath.Join(dir, "target")

	orig := computeFingerprint
	t.Cleanup(func() { computeFingerprint = orig })
	calls := 0
	computeFingerprint = func(k fingerprint.Key, v secret.Value) (string, error) {
		calls++
		if calls == 1 {
			return orig(k, v)
		}
		return "", fingerprint.ErrZeroKey
	}

	c := canary.New()
	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetFile, targetPath, ""), newValue(c.Value(0)), uids, gids, testFPKey(t))
	if calls < 2 {
		t.Fatalf("computeFingerprint fired %d times, want at least 2 (pre-flight + confirm-phase)", calls)
	}
	wantErr(t, err, ErrUnconfirmed, "post-rename fingerprint.Compute failure")
	if errors.Is(err, ErrWrite) {
		t.Fatalf("ErrUnconfirmed must not satisfy errors.Is(err, ErrWrite): %v", err)
	}
	if c.In(err.Error()) {
		t.Fatalf("canary leaked into ErrUnconfirmed text: %v", err)
	}
	if _, statErr := os.Lstat(targetPath); statErr != nil {
		t.Fatalf("target must still exist on disk after a confirm-phase failure: %v", statErr)
	}
}
