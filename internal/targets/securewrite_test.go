//go:build unix

package targets

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"golang.org/x/sys/unix"
)

func TestSymlinkInMiddleOfPathRefused(t *testing.T) {
	dir := realDir(t)
	outside := filepath.Join(dir, "outside.txt")
	mustWriteFile(t, outside, []byte("SENTINEL-OUTSIDE"), 0o600)

	sub := filepath.Join(dir, "a")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(sub, "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}

	uids, gids := noAgents()
	targetPath := filepath.Join(link, "secret.env")
	_, err := Write(target(runnerproto.TargetFile, targetPath, ""), newValue("v"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrPolicy, "write through a symlinked directory component")

	if got := mustReadFile(t, outside); string(got) != "SENTINEL-OUTSIDE" {
		t.Fatalf("file outside the target was modified: %q", show([]byte(got)))
	}
}

func TestSymlinkOnTargetItselfRefused(t *testing.T) {
	dir := realDir(t)
	outside := filepath.Join(dir, "outside.txt")
	mustWriteFile(t, outside, []byte("SENTINEL-OUTSIDE"), 0o600)

	targetPath := filepath.Join(dir, "target")
	if err := os.Symlink(outside, targetPath); err != nil {
		t.Fatal(err)
	}

	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetFile, targetPath, ""), newValue("v"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrPolicy, "write over a target that is itself a symlink")

	if got := mustReadFile(t, outside); string(got) != "SENTINEL-OUTSIDE" {
		t.Fatalf("the symlink's destination was modified through it: %q", show([]byte(got)))
	}
}

func TestDotDotRefused(t *testing.T) {
	dir := realDir(t)
	uids, gids := noAgents()
	// filepath.Join/Clean would collapse "..", which is exactly the syntax
	// this must reject before that ever happens — build the string by hand.
	targetPath := dir + "/../" + filepath.Base(dir) + "/target"
	_, err := Write(target(runnerproto.TargetFile, targetPath, ""), newValue("v"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrPolicy, "write with a .. component")
}

// TestWalkToParentRejectsDotDot calls walkToParent directly rather than
// through Write, bypassing runnerproto.ValidatePath — which Write also runs
// first and which already refuses ".." on its own (proven by that package's
// own mutation script). This is what isolates and proves this package's own,
// independent ".." defense, in case walkToParent is ever reached by a path
// that ValidatePath did not see.
func TestWalkToParentRejectsDotDot(t *testing.T) {
	dir := realDir(t)
	targetPath := dir + "/../" + filepath.Base(dir) + "/target"
	fd, _, err := walkToParent(targetPath, agentSet{})
	if err == nil {
		_ = unix.Close(fd)
		t.Fatal("walkToParent accepted a path with a .. component")
	}
	wantErr(t, err, ErrPolicy, "walkToParent with a .. component")
}

// TestDirectorySwappedForSymlinkMidWalk simulates the race in which a directory
// that is real when the walk starts is replaced
// by a symlink in the instant before the walk would open it. beforeDirOpen
// fires once per not-yet-opened component, exactly at that instant; the
// walk must still refuse, proving the defense holds against a change that
// happens *during* Write's own walk, not just one set up beforehand.
func TestDirectorySwappedForSymlinkMidWalk(t *testing.T) {
	dir := realDir(t)
	outside := filepath.Join(dir, "outside.txt")
	mustWriteFile(t, outside, []byte("SENTINEL-OUTSIDE"), 0o600)

	sub := filepath.Join(dir, "a")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}

	orig := beforeDirOpen
	t.Cleanup(func() { beforeDirOpen = orig })
	swapped := false
	beforeDirOpen = func(i int, seg string) {
		if seg == "a" && !swapped {
			swapped = true
			if err := os.RemoveAll(sub); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(dir, sub); err != nil {
				t.Fatal(err)
			}
		}
	}

	uids, gids := noAgents()
	targetPath := filepath.Join(sub, "secret.env")
	_, err := Write(target(runnerproto.TargetFile, targetPath, ""), newValue("v"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrPolicy, "directory swapped to a symlink mid-walk")
	if !swapped {
		t.Fatal("test hook never fired — the walk did not reach the swapped component")
	}
	if got := mustReadFile(t, outside); string(got) != "SENTINEL-OUTSIDE" {
		t.Fatalf("file outside the target was modified: %q", show([]byte(got)))
	}
}

// TestHardlinkPreplacedAtTargetIsNotWrittenThrough is the original
// concern: an agent, able to write the target's directory, places a
// hardlink to their own file at the target's path before the deploy runs.
// Write never opens the target path for writing, so the agent's inode is
// never written through; and since an existing target with more than one
// link is refused outright (TestExistingTargetHardlinkedToForeignSecretRefused
// is the other direction of the same defense), the deploy stops instead of
// silently retargeting the name.
func TestHardlinkPreplacedAtTargetIsNotWrittenThrough(t *testing.T) {
	dir := realDir(t)
	agentFile := filepath.Join(dir, "agent-owned.txt")
	mustWriteFile(t, agentFile, []byte("AGENT-SENTINEL"), 0o600)

	targetPath := filepath.Join(dir, "target")
	if err := os.Link(agentFile, targetPath); err != nil {
		t.Fatal(err)
	}

	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetFile, targetPath, ""), newValue("NEW-VALUE"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrPolicy, "target pre-linked to another file")
	if got := mustReadFile(t, agentFile); string(got) != "AGENT-SENTINEL" {
		t.Fatalf("the agent's pre-placed hardlink target was overwritten: %q", show([]byte(got)))
	}
}

// TestHardlinkRaceAfterTmpCreateRefused is the race the nlink check exists
// for: afterTmpCreate fires right after the temporary file is created and
// before a single byte is written. A test injects a second link to that
// exact inode there — the only way one can appear, since O_CREAT|O_EXCL
// already refuses a pre-existing name — standing in for an agent racing a
// writable directory. The nlink check must catch it and refuse before any
// content is written to the now-shared inode.
func TestHardlinkRaceAfterTmpCreateRefused(t *testing.T) {
	dir := realDir(t)

	orig := afterTmpCreate
	t.Cleanup(func() { afterTmpCreate = orig })
	var raceLink string
	afterTmpCreate = func(parentFD int, name string) {
		raceLink = filepath.Join(dir, "agent-link")
		if err := unix.Linkat(parentFD, name, unix.AT_FDCWD, raceLink, 0); err != nil {
			t.Fatalf("inject race hardlink: %v", err)
		}
	}

	c := canary.New()
	val := c.Value(0)
	uids, gids := noAgents()
	targetPath := filepath.Join(dir, "target")
	_, err := Write(target(runnerproto.TargetFile, targetPath, ""), newValue(val), uids, gids, testFPKey(t))
	wantErr(t, err, ErrPolicy, "hardlink race right after temp-file creation")
	if raceLink == "" {
		t.Fatal("test hook never fired")
	}
	if _, err := os.Stat(targetPath); err == nil {
		t.Fatal("target was written despite the detected race")
	}
	if got, err := os.ReadFile(raceLink); err == nil && c.In(string(got)) { //nolint:gosec // G304: test path
		t.Fatal("secret value reached the race-linked path")
	}
}

// TestHardlinkRaceAfterChmodRefused is the second window the nlink check
// closes: a directory can be sticky (so an agent cannot rename/unlink our
// temp file — TestWorldWritableStickyDirAllowed) while still allowing an
// agent to add a *new* link to our file's existing inode, since the sticky
// bit only restricts renaming/unlinking entries one does not own, not
// creating one. That race is injected here, after Fchown/Fchmod and right
// before content would be written — later than TestHardlinkRaceAfterTmpCreateRefused
// covers, and content must never reach the race-linked path.
func TestHardlinkRaceAfterChmodRefused(t *testing.T) {
	dir := realDir(t)
	sub := filepath.Join(dir, "sticky")
	if err := os.Mkdir(sub, 0o777|os.ModeSticky); err != nil { //nolint:gosec // G301: sticky world-writable is the scenario under test
		t.Fatal(err)
	}
	if err := os.Chmod(sub, 0o777|os.ModeSticky); err != nil { //nolint:gosec // G302: same reason
		t.Fatal(err)
	}

	origCreate, origChmod := afterTmpCreate, afterChmod
	t.Cleanup(func() { afterTmpCreate, afterChmod = origCreate, origChmod })
	afterTmpCreate = func(int, string) {} // let the first check pass cleanly
	var raceLink string
	afterChmod = func(parentFD int, name string) {
		raceLink = filepath.Join(dir, "agent-link-2")
		if err := unix.Linkat(parentFD, name, unix.AT_FDCWD, raceLink, 0); err != nil {
			t.Fatalf("inject race hardlink: %v", err)
		}
	}

	c := canary.New()
	val := c.Value(0)
	uids, gids := noAgents()
	targetPath := filepath.Join(sub, "target")
	_, err := Write(target(runnerproto.TargetFile, targetPath, ""), newValue(val), uids, gids, testFPKey(t))
	wantErr(t, err, ErrPolicy, "hardlink race right after chmod, before write")
	if raceLink == "" {
		t.Fatal("test hook never fired")
	}
	if _, err := os.Stat(targetPath); err == nil {
		t.Fatal("target was written despite the detected race")
	}
	if got, err := os.ReadFile(raceLink); err == nil && c.In(string(got)) { //nolint:gosec // G304: test path
		t.Fatal("secret value reached the race-linked path")
	}
}

func TestWorldReadableModeRefused(t *testing.T) {
	dir := realDir(t)
	uids, gids := noAgents()
	tg := target(runnerproto.TargetFile, filepath.Join(dir, "target"), "")
	tg.Mode = 0o644
	_, err := Write(tg, newValue("v"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrPolicy, "world-readable target mode")
}

func TestAgentReadableParentDirRefused(t *testing.T) {
	dir := realDir(t)
	sub := filepath.Join(dir, "keeptargets")
	if err := os.Mkdir(sub, 0o750); err != nil { // group-readable+executable
		t.Fatal(err)
	}
	// Only the gid is declared as an agent's — not the uid, which the
	// helper target() also uses as the target's own owner and would
	// otherwise be caught first by validateTargetPerm, never reaching this
	// directory-level check.
	_, gids := selfAsAgent()
	_, err := Write(target(runnerproto.TargetFile, filepath.Join(sub, "target"), ""), newValue("v"), nil, gids, testFPKey(t))
	wantErr(t, err, ErrPolicy, "target directory readable by an agent group")
}

// TestAgentOwnedTargetRefused isolates validateTargetPerm's own uid check
// from the directory-level ownership check in agents.go: the parent
// directory (safeDir) is mode 0700 and owned by us, not the declared agent,
// so only the target's own UID field — set to a synthetic agent uid that
// does not otherwise appear anywhere on the path — can be what triggers the
// refusal.
func TestAgentOwnedTargetRefused(t *testing.T) {
	dir := safeDir(t)
	tg := target(runnerproto.TargetFile, filepath.Join(dir, "target"), "")
	tg.UID = syntheticAgentUID
	_, err := Write(tg, newValue("v"), []int64{syntheticAgentUID}, nil, testFPKey(t))
	wantErr(t, err, ErrPolicy, "target owner is an agent")
}

// TestAgentWritableDirRefused uses a group-write-only mode (no read or
// execute bit) so agents.go's refuseWritable is the only check that can
// fire — refuseReachable, which only looks at read/execute, would not.
func TestAgentWritableDirRefused(t *testing.T) {
	dir := realDir(t)
	sub := filepath.Join(dir, "writable")
	if err := os.Mkdir(sub, 0o720); err != nil { //nolint:gosec // G301: the loose, group-writable mode is exactly what this test is refusing
		t.Fatal(err)
	}
	// Mkdir's mode is masked by umask (e.g. 022 would strip a bare
	// group-write bit down to nothing); force the exact bits this test needs.
	if err := os.Chmod(sub, 0o720); err != nil { //nolint:gosec // G302: same reason
		t.Fatal(err)
	}
	_, gids := selfAsAgent()
	_, err := Write(target(runnerproto.TargetFile, filepath.Join(sub, "target"), ""), newValue("v"), nil, gids, testFPKey(t))
	wantErr(t, err, ErrPolicy, "target directory writable by an agent group")
}

func TestWorldWritableDirRefused(t *testing.T) {
	dir := realDir(t)
	sub := filepath.Join(dir, "worldwritable")
	if err := os.Mkdir(sub, 0o777); err != nil { //nolint:gosec // G301: the loose, world-writable mode is exactly what this test is refusing
		t.Fatal(err)
	}
	// Mkdir's mode is masked by umask; force the exact bits this test needs.
	if err := os.Chmod(sub, 0o777); err != nil { //nolint:gosec // G302: same reason
		t.Fatal(err)
	}
	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetFile, filepath.Join(sub, "target"), ""), newValue("v"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrPolicy, "target directory writable by anyone")
}

// TestWorldWritableStickyDirAllowed is the positive control for the sticky
// bit exception: a directory shaped exactly like /tmp on any real Unix
// (1777 — world-writable, sticky) must be ALLOWED, because the sticky bit
// is precisely what makes such a directory safe against the rename/unlink
// race this check exists for (see the doc comment on refuseWritable). This
// is not a hypothetical — CI's own /tmp is exactly this shape, and every
// target under it (which is where t.TempDir() lives on Linux) would
// otherwise be refused regardless of the target's own, correctly private
// permissions.
func TestWorldWritableStickyDirAllowed(t *testing.T) {
	dir := realDir(t)
	sub := filepath.Join(dir, "sticky")
	if err := os.Mkdir(sub, 0o777|os.ModeSticky); err != nil { //nolint:gosec // G301: 1777 is the point of this test
		t.Fatal(err)
	}
	if err := os.Chmod(sub, 0o777|os.ModeSticky); err != nil { //nolint:gosec // G302: same reason
		t.Fatal(err)
	}
	uids, gids := noAgents()
	fp, err := Write(target(runnerproto.TargetFile, filepath.Join(sub, "target"), ""), newValue("v"), uids, gids, testFPKey(t))
	if err != nil {
		t.Fatalf("Write refused a world-writable-but-sticky directory: %v", err)
	}
	if fp == "" {
		t.Fatal("empty fingerprint")
	}
}

// TestAgentGroupReadableTargetModeRefused isolates validateTargetPerm's own
// mode/gid check the same way TestAgentOwnedTargetRefused does: safeDir
// keeps the directory-level checks from firing, and the target's own GID
// field is set to a synthetic agent gid unrelated to the directory's real
// group.
func TestAgentGroupReadableTargetModeRefused(t *testing.T) {
	dir := safeDir(t)
	tg := target(runnerproto.TargetFile, filepath.Join(dir, "target"), "")
	tg.Mode = 0o640 // owner rw, group r — group is the synthetic agent's below
	tg.GID = syntheticAgentGID
	_, err := Write(tg, newValue("v"), nil, []int64{syntheticAgentGID}, testFPKey(t))
	wantErr(t, err, ErrPolicy, "target mode readable by an agent group")
}

// TestFsyncFailureLeavesOldContent is the "failure mid-write" red run:
// fsync of the temporary file is made to fail after the new content is
// already written to it but before rename ever runs. The target must be
// left exactly as it was.
func TestFsyncFailureLeavesOldContent(t *testing.T) {
	dir := realDir(t)
	targetPath := filepath.Join(dir, "target")
	mustWriteFile(t, targetPath, []byte("OLD-CONTENT"), 0o600)

	orig := fsyncFD
	t.Cleanup(func() { fsyncFD = orig })
	fsyncFD = func(int) error { return errors.New("injected fsync failure") }

	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetFile, targetPath, ""), newValue("NEW-CONTENT"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrWrite, "fsync failure mid-write")

	if got := mustReadFile(t, targetPath); string(got) != "OLD-CONTENT" {
		t.Fatalf("target changed despite the failed fsync: %q", show([]byte(got)))
	}
	// No stray temp files left behind either.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "target" {
			t.Fatalf("stray file left behind: %s", e.Name())
		}
	}
}

// TestCanaryNeverInErrors is the "canary never reaches the error text"
// red run: every refusal path above, plus a couple more, is driven with a
// canary value and its error text checked in six encodings. A leak test
// written after the fact would only prove today's code doesn't leak; this
// drives every refusal branch this file already established, so a future
// change to any of them is caught the same way.
func TestCanaryNeverInErrors(t *testing.T) {
	c := canary.New()
	val := newValue(c.Value(0))
	uids, gids := noAgents()

	dir := realDir(t)
	outside := filepath.Join(dir, "outside.txt")
	mustWriteFile(t, outside, []byte("x"), 0o600)
	sub := filepath.Join(dir, "a")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(sub, "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	symlinkTarget := filepath.Join(dir, "symtarget")
	if err := os.Symlink(outside, symlinkTarget); err != nil {
		t.Fatal(err)
	}
	worldReadable := target(runnerproto.TargetFile, filepath.Join(dir, "wr"), "")
	worldReadable.Mode = 0o644

	agentUIDs, _ := selfAsAgent()

	cases := []struct {
		name string
		t    runnerproto.Target
		uids []int64
		gids []int64
	}{
		{"symlink-mid-path", target(runnerproto.TargetFile, filepath.Join(link, "t"), ""), uids, gids},
		{"symlink-on-target", target(runnerproto.TargetFile, symlinkTarget, ""), uids, gids},
		{"world-readable-mode", worldReadable, uids, gids},
		{"agent-owned-target", target(runnerproto.TargetFile, filepath.Join(dir, "t2"), ""), agentUIDs, nil},
	}
	for _, c2 := range cases {
		t.Run(c2.name, func(t *testing.T) {
			_, err := Write(c2.t, val, c2.uids, c2.gids, testFPKey(t))
			if err == nil {
				t.Fatal("expected this case to be refused")
			}
			if c.In(err.Error()) {
				t.Fatalf("canary leaked into error text: %v", err)
			}
		})
	}

	t.Run("launchd-env-target-missing", func(t *testing.T) {
		_, err := Write(target(runnerproto.TargetLaunchdEnv, filepath.Join(dir, "nope.plist"), "VAR"), val, uids, gids, testFPKey(t))
		if err == nil {
			t.Fatal("expected this case to be refused")
		}
		if c.In(err.Error()) {
			t.Fatalf("canary leaked into error text: %v", err)
		}
	})

	t.Run("env-file-newline-in-value", func(t *testing.T) {
		valWithNL := newValue(c.Value(1) + "\n" + c.Value(2))
		_, err := Write(target(runnerproto.TargetEnvFile, filepath.Join(dir, "canary.env"), "X"), valWithNL, uids, gids, testFPKey(t))
		if err == nil {
			t.Fatal("expected this case to be refused")
		}
		if c.In(err.Error()) {
			t.Fatalf("canary leaked into error text: %v", err)
		}
	})
}
