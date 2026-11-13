//go:build unix

package runnerproto

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	journalChildEnv   = "KEEP_TEST_JOURNAL_PATH"
	journalRefuseWait = time.Second
	journalHardCap    = 10 * time.Second
)

// TestJournalOpenChild is the child half of TestJournalOpenFIFO. Without the
// env var it returns at once (a pass, not a SKIP); the parent's positive
// control (an ordinary journal must report "opened") proves the child does
// real work. Output is one class word, never journal content.
func TestJournalOpenChild(t *testing.T) {
	path := os.Getenv(journalChildEnv)
	if path == "" {
		return
	}
	type result struct {
		err error
		d   time.Duration
	}
	ch := make(chan result, 1)
	go func() {
		start := time.Now()
		j, err := OpenFileJournal(path, t0)
		if j != nil {
			_ = j.Close()
		}
		ch <- result{err, time.Since(start)}
	}()
	select {
	case r := <-ch:
		switch {
		case r.err == nil:
			fmt.Print("RESULT=opened\n")
		case r.d > journalRefuseWait:
			fmt.Print("RESULT=slow-refusal\n")
		case strings.Contains(r.err.Error(), filepath.Base(path)):
			fmt.Print("RESULT=echoes-path\n")
		case strings.Contains(r.err.Error(), "not a regular file"):
			fmt.Print("RESULT=refused-not-regular\n")
		default:
			fmt.Print("RESULT=refused-other\n")
		}
	case <-time.After(journalRefuseWait):
		fmt.Print("RESULT=blocked\n")
	}
}

// openJournalChild opens the journal at path in a separate process so a
// blocking open cannot hang the test binary. CommandContext kills the child
// on timeout and Run always waits, so no process is left behind.
func openJournalChild(t *testing.T, path string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), journalHardCap)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestJournalOpenChild$", "-test.v") //nolint:gosec // G204: re-executes this test binary
	cmd.Env = append(os.Environ(), journalChildEnv+"="+path)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if ctx.Err() != nil {
		return "child-hung"
	}
	if err != nil {
		t.Fatalf("child failed: %v", err)
	}
	for _, line := range strings.Split(out.String(), "\n") {
		if r, ok := strings.CutPrefix(line, "RESULT="); ok {
			return r
		}
	}
	return "no-result"
}

func TestJournalOpenFIFO(t *testing.T) {
	const id = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"

	t.Run("positive control: new journal opens", func(t *testing.T) {
		if got := openJournalChild(t, filepath.Join(t.TempDir(), "canary-path-segment")); got != "opened" {
			t.Fatalf("new journal in a child: %s", got)
		}
	})

	t.Run("positive control: claim survives reopen, duplicate is a replay", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "canary-path-segment")
		j, err := OpenFileJournal(path, t0)
		if err != nil {
			t.Fatal(err)
		}
		if err := j.Claim(id, t0.Add(time.Minute), t0); err != nil {
			t.Fatal(err)
		}
		_ = j.Close()
		if got := openJournalChild(t, path); got != "opened" {
			t.Fatalf("existing journal in a child: %s", got)
		}
		j, err = OpenFileJournal(path, t0)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = j.Close() }()
		if err := j.Claim(id, t0.Add(time.Minute), t0); err != ErrReplay {
			t.Fatalf("duplicate after reopen: %v", err)
		}
	})

	t.Run("fifo without writer is refused at once", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "canary-path-segment")
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
		if got := openJournalChild(t, path); got != "refused-not-regular" { // not "echoes-path": the refusal is static
			t.Fatalf("FIFO journal: want refused-not-regular, got %s", got)
		}
	})

	t.Run("symlink to a journal is refused", func(t *testing.T) {
		dir := t.TempDir()
		real := filepath.Join(dir, "real")
		j, err := OpenFileJournal(real, t0)
		if err != nil {
			t.Fatal(err)
		}
		_ = j.Close()
		link := filepath.Join(dir, "canary-path-segment")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		if got := openJournalChild(t, link); got != "refused-not-regular" {
			t.Fatalf("symlinked journal: want refused-not-regular, got %s", got)
		}
	})

	t.Run("symlink to a fifo is refused without blocking", func(t *testing.T) {
		dir := t.TempDir()
		fifo := filepath.Join(dir, "f")
		if err := syscall.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "canary-path-segment")
		if err := os.Symlink(fifo, link); err != nil {
			t.Fatal(err)
		}
		if got := openJournalChild(t, link); got != "refused-not-regular" {
			t.Fatalf("symlink to FIFO: want refused-not-regular, got %s", got)
		}
	})
}
