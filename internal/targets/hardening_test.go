//go:build unix

package targets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

func staleTmpName(base string) string {
	return staleTmpPrefix(base) + strings.Repeat("ab", staleTmpSuffixLen/2)
}

// dirHoldsCanary reports whether any regular file under dir carries the
// canary in any encoding.
func dirHoldsCanary(t *testing.T, dir string, c canary.Canary) bool {
	t.Helper()
	found := false
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		b, rerr := os.ReadFile(p) //nolint:gosec // G304: test-controlled path
		if rerr != nil {
			return rerr
		}
		if c.In(string(b)) {
			found = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// A write that died between creating its temporary file and the rename
// leaves the value in a ".<base>.tmp-*" file. The next write to that
// directory removes it: no file carrying the canary is left.
func TestStaleTmpWithValueGoneAfterNextWrite(t *testing.T) {
	c := canary.New()
	dir := safeDir(t)
	orphan := filepath.Join(dir, staleTmpName("target"))
	mustWriteFile(t, orphan, []byte("DB_PASSWORD="+c.Value(0)+"\n"), 0o600)
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(orphan, past, past); err != nil {
		t.Fatal(err)
	}

	uids, gids := noAgents()
	if _, err := Write(target(runnerproto.TargetFile, filepath.Join(dir, "target"), ""), newValue("fresh"), uids, gids, testFPKey(t)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if dirHoldsCanary(t, dir, c) {
		t.Fatal("a file carrying the canary survived the next write to the directory")
	}
}

// Positive control for the test above: the canary check does see a planted
// file, so a green result is not a blind scan.
func TestDirHoldsCanarySeesAPlantedFile(t *testing.T) {
	c := canary.New()
	dir := safeDir(t)
	mustWriteFile(t, filepath.Join(dir, "x"), []byte(c.Value(0)), 0o600)
	if !dirHoldsCanary(t, dir, c) {
		t.Fatal("dirHoldsCanary did not find a planted canary")
	}
}

// Only files older than the write go: one modified after the write began
// belongs to a write that started later and is still filling it.
func TestStaleTmpNewerThanTheWriteIsKept(t *testing.T) {
	dir := safeDir(t)
	newer := filepath.Join(dir, staleTmpName("target"))
	mustWriteFile(t, newer, []byte("in flight"), 0o600)
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(newer, future, future); err != nil {
		t.Fatal(err)
	}
	uids, gids := noAgents()
	if _, err := Write(target(runnerproto.TargetFile, filepath.Join(dir, "target"), ""), newValue("v"), uids, gids, testFPKey(t)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := os.Lstat(newer); err != nil {
		t.Fatalf("a temporary file newer than the write was removed: %v", err)
	}
}

// A symlink with a temporary file's name is not followed and not unlinked as
// if it were one, and what it points at stays.
func TestStaleTmpSymlinkNotFollowed(t *testing.T) {
	dir := safeDir(t)
	victim := filepath.Join(dir, "victim")
	mustWriteFile(t, victim, []byte("keep me"), 0o600)
	link := filepath.Join(dir, staleTmpName("target"))
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	uids, gids := noAgents()
	if _, err := Write(target(runnerproto.TargetFile, filepath.Join(dir, "target"), ""), newValue("v"), uids, gids, testFPKey(t)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := string(mustReadFile(t, victim)); got != "keep me" {
		t.Fatalf("the symlink's destination was touched: %s", show([]byte(got)))
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("the symlink was removed: %v", err)
	}
}

// With no systemd-creds on the host and no policy flag, the target is
// refused as a policy denial: nothing is written, and neither the error nor
// the directory holds the value.
func TestSystemdCredentialWithoutBinaryRefusedByDefault(t *testing.T) {
	absentSystemdCreds(t)
	c := canary.New()
	dir := safeDir(t)
	uids, gids := noAgents()
	_, err := Write(credTarget(filepath.Join(dir, "cred")), newValue(c.Value(0)), uids, gids, testFPKey(t))
	wantErr(t, err, ErrPolicy, "systemd-credential without systemd-creds and without the policy flag")
	if c.In(err.Error()) {
		t.Fatal("the value reached the error")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("%d entries were left in the directory", len(entries))
	}
}

// The same host with the flag set: the plain 0600 file is written and the
// notice fires once, with the target's path.
func TestSystemdCredentialPlaintextFallbackWithFlag(t *testing.T) {
	absentSystemdCreds(t)
	c := canary.New()
	dir := safeDir(t)
	path := filepath.Join(dir, "cred")
	var noticed []string
	uids, gids := noAgents()
	_, err := Write(credTarget(path), newValue(c.Value(0)), uids, gids, testFPKey(t),
		WithSystemdCredPlaintextFallback(func(p string) { noticed = append(noticed, p) }))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if len(noticed) != 1 || noticed[0] != path {
		t.Fatalf("notice calls = %v, want exactly [%s]", noticed, path)
	}
	if !c.In(string(mustReadFile(t, path))) {
		t.Fatal("the fallback did not write the value")
	}
}

// The plaintext fallback never writes a file wider than 0600, whatever mode
// the target asked for. The positive control: the same 0640 mode on a "file"
// target is kept as asked, so the narrowing comes from the fallback and not
// from the writer in general.
func TestSystemdCredentialFallbackModeNeverWiderThan0600(t *testing.T) {
	absentSystemdCreds(t)
	uids, gids := noAgents()

	dir := safeDir(t)
	ctl := target(runnerproto.TargetFile, filepath.Join(dir, "control"), "")
	ctl.Mode = 0o640
	if _, err := Write(ctl, newValue("v"), uids, gids, testFPKey(t)); err != nil {
		t.Fatalf("control Write: %v", err)
	}
	if fi, err := os.Stat(ctl.Path); err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("control: want 0640, got %v (%v)", fi, err)
	}

	tg := credTarget(filepath.Join(dir, "cred"))
	tg.Mode = 0o640
	if _, err := Write(tg, newValue("v"), uids, gids, testFPKey(t), WithSystemdCredPlaintextFallback(nil)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	fi, err := os.Stat(tg.Path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("fallback file mode = %#o, want 0600", got)
	}
}

// The notice that the fallback was used fires only once the file is written:
// a write that fails after the value was built reports nothing.
func TestSystemdCredentialFallbackNoticeOnlyAfterWrite(t *testing.T) {
	absentSystemdCreds(t)
	dir := safeDir(t)
	orig := afterChmod
	t.Cleanup(func() { afterChmod = orig })
	afterChmod = func(parentFD int, name string) {
		if err := unix.Fchmodat(parentFD, name, 0o644, 0); err != nil {
			t.Fatalf("inject mode change: %v", err)
		}
	}
	noticed := 0
	uids, gids := noAgents()
	_, err := Write(credTarget(filepath.Join(dir, "cred")), newValue("v"), uids, gids, testFPKey(t),
		WithSystemdCredPlaintextFallback(func(string) { noticed++ }))
	wantErr(t, err, ErrPolicy, "temporary file mode changed before the write")
	if noticed != 0 {
		t.Fatalf("notice fired %d times for a write that failed", noticed)
	}
}

// The flag lifts the refusal only where there is no systemd-creds: a binary
// that is present but untrusted is still a refusal, flag or not.
func TestSystemdCredentialFlagDoesNotExcuseUntrustedBinary(t *testing.T) {
	bin, _, _ := fakeSystemdCreds(t)
	if err := os.Chmod(bin, 0o777); err != nil { //nolint:gosec // G302: the group/other-writable binary is the scenario
		t.Fatal(err)
	}
	dir := safeDir(t)
	uids, gids := noAgents()
	_, err := Write(credTarget(filepath.Join(dir, "cred")), newValue("v"), uids, gids, testFPKey(t), WithSystemdCredPlaintextFallback(nil))
	wantErr(t, err, ErrPolicy, "untrusted systemd-creds with the fallback flag set")
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("%d entries were left in the directory", len(entries))
	}
}

// The walk applies the ancestor ACL check to every directory above the
// parent, the filesystem root included, and the stricter parent check to the
// parent alone.
func TestWalkChecksACLOnEveryAncestor(t *testing.T) {
	dir := safeDir(t)
	deep := filepath.Join(dir, "a", "b")
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	var seen []string
	orig := checkAncestorACLHook
	t.Cleanup(func() { checkAncestorACLHook = orig })
	checkAncestorACLHook = func(fd int, p string) error {
		seen = append(seen, p)
		return orig(fd, p)
	}
	uids, gids := noAgents()
	if _, err := Write(target(runnerproto.TargetFile, filepath.Join(deep, "target"), ""), newValue("v"), uids, gids, testFPKey(t)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	want := []string{"/"}
	acc := ""
	for _, seg := range strings.Split(deep[1:], "/") {
		acc += "/" + seg
		want = append(want, acc)
	}
	want = want[:len(want)-1] // the parent gets checkDirACL, not the ancestor check
	if strings.Join(seen, "|") != strings.Join(want, "|") {
		t.Fatalf("ancestor ACL check ran on %v, want %v", seen, want)
	}
}

// staleTmpOwners must carry the target's owner as well as this process's
// uid: a root runner writing for a service account has to clean what the
// service account's writer left.
func TestStaleTmpOwnersIncludeTargetOwner(t *testing.T) {
	got := staleTmpOwners(54321)
	has := func(u int64) bool {
		for _, o := range got {
			if o == u {
				return true
			}
		}
		return false
	}
	if !has(int64(os.Geteuid())) || !has(54321) {
		t.Fatalf("owners %v lack the process uid or the target owner", got)
	}
}

// A name swapped for a symlink between the check and the unlink is not
// followed: what it points at stays untouched.
func TestStaleTmpSwappedForSymlinkNotFollowed(t *testing.T) {
	dir := safeDir(t)
	victim := filepath.Join(dir, "victim")
	mustWriteFile(t, victim, []byte("keep me"), 0o600)
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(victim, past, past); err != nil {
		t.Fatal(err)
	}
	name := staleTmpName("target")
	orphan := filepath.Join(dir, name)
	mustWriteFile(t, orphan, []byte("old"), 0o600)
	if err := os.Chtimes(orphan, past, past); err != nil {
		t.Fatal(err)
	}
	old := beforeStaleUnlink
	beforeStaleUnlink = func(_ int, n string) {
		if n != name {
			return
		}
		_ = os.Remove(orphan)
		_ = os.Symlink(victim, orphan)
	}
	defer func() { beforeStaleUnlink = old }()
	uids, gids := noAgents()
	if _, err := Write(target(runnerproto.TargetFile, filepath.Join(dir, "target"), ""), newValue("v"), uids, gids, testFPKey(t)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := string(mustReadFile(t, victim)); got != "keep me" {
		t.Fatalf("the symlink's destination was touched")
	}
}

// A name swapped for a FIFO between the check and the open must not block
// the write waiting for a writer that never comes.
func TestStaleTmpSwappedForFIFODoesNotBlock(t *testing.T) {
	dir := safeDir(t)
	name := staleTmpName("target")
	orphan := filepath.Join(dir, name)
	past := time.Now().Add(-time.Hour)
	mustWriteFile(t, orphan, []byte("old"), 0o600)
	if err := os.Chtimes(orphan, past, past); err != nil {
		t.Fatal(err)
	}
	old := beforeStaleUnlink
	beforeStaleUnlink = func(_ int, n string) {
		if n != name {
			return
		}
		_ = os.Remove(orphan)
		_ = unix.Mkfifo(orphan, 0o600)
	}
	defer func() { beforeStaleUnlink = old }()
	done := make(chan error, 1)
	go func() {
		uids, gids := noAgents()
		_, err := Write(target(runnerproto.TargetFile, filepath.Join(dir, "target"), ""), newValue("v"), uids, gids, testFPKey(t))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
	case <-time.After(5 * time.Second):
		// Release the blocked open so the goroutine ends, then fail.
		if fd, err := unix.Open(orphan, unix.O_WRONLY|unix.O_NONBLOCK, 0); err == nil {
			_ = unix.Close(fd)
		}
		<-done
		t.Fatal("the write blocked on a FIFO that replaced a temporary file's name")
	}
}
