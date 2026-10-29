//go:build unix

// Attacks on the stale-temporary-file cleanup of internal/targets.Write
// (threat model I1 — a value left in a crash orphan next to the
// target is a value readable outside its carrier; ADR-001 Appendix C.5).
// Write may remove ONLY its own crash orphans: ".<base>.tmp-<24 hex>", a
// regular single-link file owned by the runner or the target owner, last
// modified before the write began. Anything else is left alone.
package targets_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/entire-vc/evc-keep/internal/targets"
	cnry "github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

const orphanHex = "0123456789abcdef01234567" // 24 hex chars, the generated shape

func orphanName(base string) string { return "." + base + ".tmp-" + orphanHex }

func plantOld(t *testing.T, p string, content []byte) {
	t.Helper()
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, dir, base, value string) error {
	t.Helper()
	u, g := tgtNoAgents()
	_, err := targets.Write(tgtTarget(runnerproto.TargetFile, filepath.Join(dir, base)), tgtValue(value), u, g, tgtKey(t))
	return err
}

// TestTargetsStaleTmp_CanaryOrphanRemoved — I1 / C.5. A crash orphan
// holding the previous value (canary) is gone after the next Write to the
// same directory; no file in the directory still carries the canary.
// Positive control: the scan finds the planted orphan before the write.
func TestTargetsStaleTmp_CanaryOrphanRemoved(t *testing.T) {
	c := cnry.New()
	dir := tgtRealDir(t)
	orphan := filepath.Join(dir, orphanName("target"))
	plantOld(t, orphan, []byte("API_TOKEN="+c.Value(0)+"\n"))
	if hits := tgtDirHolds(t, dir, c); len(hits) != 1 {
		t.Fatalf("positive control: scan saw %v, want the planted orphan", hits)
	}
	if err := writeFile(t, dir, "target", "fresh-value"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if hits := tgtDirHolds(t, dir, c); len(hits) != 0 {
		t.Fatalf("canary survived the next write in %v", hits)
	}
	if _, err := os.Lstat(orphan); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphan still present: %v", err)
	}
}

// TestTargetsStaleTmp_SymlinkOrphanNotFollowed — I9 (spoilage) / C.5. A
// symlink with the orphan's exact name pointing at a victim file elsewhere:
// the cleanup must neither follow it nor treat it as its own file — the
// victim keeps its content and the symlink itself is not touched.
func TestTargetsStaleTmp_SymlinkOrphanNotFollowed(t *testing.T) {
	c := cnry.New()
	dir := tgtRealDir(t)
	victimDir := tgtRealDir(t)
	victim := filepath.Join(victimDir, "other-service.key")
	plantOld(t, victim, []byte(c.Value(0)))
	link := filepath.Join(dir, orphanName("target"))
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	// Make the link itself old too, so only the "not a regular file" rule
	// protects it.
	old := time.Now().Add(-time.Hour)
	_ = lutimes(link, old)

	if err := writeFile(t, dir, "target", "fresh-value"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	b, err := os.ReadFile(victim) //nolint:gosec // G304: test path
	if err != nil {
		t.Fatalf("victim gone: %v", err)
	}
	if string(b) != c.Value(0) {
		t.Fatal("victim content changed")
	}
	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("symlink named like an orphan was removed (cleanup followed it to a regular file): %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink replaced")
	}
}

// TestTargetsStaleTmp_FIFOOrphanDoesNotHang — I9 (denial of a deploy). A
// FIFO with the orphan's exact name must not block Write (no reader ever
// comes). Write must finish within 10s and the FIFO must be left alone.
func TestTargetsStaleTmp_FIFOOrphanDoesNotHang(t *testing.T) {
	dir := tgtRealDir(t)
	fifo := filepath.Join(dir, orphanName("target"))
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	_ = os.Chtimes(fifo, old, old)

	done := make(chan error, 1)
	go func() {
		u, g := tgtNoAgents()
		_, err := targets.Write(tgtTarget(runnerproto.TargetFile, filepath.Join(dir, "target")), tgtValue("fresh-value"), u, g, tgtKey(t))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
	case <-time.After(10 * time.Second):
		// Unblock the stuck open so the goroutine can finish, then fail.
		if w, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil { //nolint:gosec // G304: test path
			_ = w.Close()
		}
		<-done
		t.Fatal("Write hung on a FIFO named like a stale temporary file")
	}
	if fi, err := os.Lstat(fifo); err != nil || fi.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("FIFO was removed or replaced: %v", err)
	}
}

// TestTargetsStaleTmp_ForeignNamesKept — I9. Cleanup must remove only the
// exact orphan shape for THIS base, older than the write. Kept: another
// base's orphan, the same prefix with a short / long / non-hex suffix, and
// an orphan of this base modified after the write began (a concurrent
// writer still filling it). Positive control in the same run: this base's
// old orphan does go.
func TestTargetsStaleTmp_ForeignNamesKept(t *testing.T) {
	c := cnry.New()
	dir := tgtRealDir(t)
	keep := []string{
		orphanName("other"),                       // another base
		".target.tmp-1",                           // short suffix
		".target.tmp-" + orphanHex + "0",          // long suffix
		".target.tmp-" + strings.Repeat("zz", 12), // non-hex
		".target.tmpx" + orphanHex,                // near-prefix
	}
	for _, name := range keep {
		plantOld(t, filepath.Join(dir, name), []byte(c.Value(0)))
	}
	ours := filepath.Join(dir, orphanName("target"))
	plantOld(t, ours, []byte(c.Value(1)))
	newer := filepath.Join(dir, ".target.tmp-"+strings.Repeat("9", 24))
	if err := os.WriteFile(newer, []byte(c.Value(2)), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(newer, future, future); err != nil {
		t.Fatal(err)
	}

	if err := writeFile(t, dir, "target", "fresh-value"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := os.Lstat(ours); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("positive control: this base's old orphan was not removed: %v", err)
	}
	for _, name := range keep {
		if _, err := os.Lstat(filepath.Join(dir, name)); err != nil {
			t.Errorf("cleanup removed a file that is not its own orphan: %q (%v)", name, err)
		}
	}
	if _, err := os.Lstat(newer); err != nil {
		t.Errorf("cleanup removed a temporary file newer than the write (in-flight writer): %v", err)
	}
}

func lutimes(p string, tm time.Time) error {
	ts := []unix.Timespec{unix.NsecToTimespec(tm.UnixNano()), unix.NsecToTimespec(tm.UnixNano())}
	return unix.UtimesNanoAt(unix.AT_FDCWD, p, ts, unix.AT_SYMLINK_NOFOLLOW)
}
