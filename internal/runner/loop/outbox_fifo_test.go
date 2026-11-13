//go:build unix

package loop

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

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

const (
	outboxFIFOEnv  = "KEEP_TEST_OUTBOX_FIFO_DIR"
	outboxFIFOWait = time.Second
	outboxHardCap  = 10 * time.Second
)

// TestOutboxFIFOChild is the child half of TestOutboxFIFO. It returns at once
// (a pass, not a SKIP) unless the parent set outboxFIFOEnv. It first checks
// that the fixture is what the parent claims, so an early setup error cannot
// be mistaken for a refusal, then runs List with a deadline. Output is one
// class word, never entry content.
func TestOutboxFIFOChild(t *testing.T) {
	dir := os.Getenv(outboxFIFOEnv)
	if dir == "" {
		return
	}
	// Not OpenOutbox: the directory comes from the environment, and routing
	// that into OpenOutbox trips gosec taint analysis in production code.
	// The parent already created it through OpenOutbox (0700, own uid).
	ob := &Outbox{dir: dir}
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 || !ownedByUs(fi) { //nolint:gosec // G703: test-only path from the parent process
		fmt.Println("RESULT=setup-open-outbox")
		return
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		fmt.Println("RESULT=setup-readdir")
		return
	}
	fifos := 0
	for _, e := range ents {
		fi, err := os.Lstat(filepath.Join(dir, e.Name())) //nolint:gosec // G703: test-only path from the parent process
		if err == nil && fi.Mode()&os.ModeNamedPipe != 0 && fi.Mode().Perm() == 0o600 && ownedByUs(fi) && jobIDRe.MatchString(strings.TrimSuffix(e.Name(), ".json")) {
			fifos++
		}
	}
	if fifos != 1 {
		fmt.Println("RESULT=setup-no-fifo")
		return
	}
	type result struct {
		n   int
		err error
		d   time.Duration
	}
	ch := make(chan result, 1)
	go func() {
		start := time.Now()
		l, err := ob.List()
		ch <- result{len(l), err, time.Since(start)}
	}()
	select {
	case r := <-ch:
		switch {
		case r.err == nil:
			fmt.Println("RESULT=listed")
		case r.d > outboxFIFOWait:
			fmt.Println("RESULT=slow-refusal")
		case r.err.Error() == "loop: outbox entry is damaged":
			fmt.Println("RESULT=refused")
		default:
			fmt.Println("RESULT=refused-other")
		}
	case <-time.After(outboxFIFOWait):
		fmt.Println("RESULT=blocked")
	}
}

// runOutboxChild runs the child in a separate process so a blocking open
// cannot hang the test binary. It is always killed and reaped.
func runOutboxChild(t *testing.T, dir string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), outboxHardCap)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOutboxFIFOChild$", "-test.v") //nolint:gosec // G204: re-executes this test binary
	cmd.Env = append(os.Environ(), outboxFIFOEnv+"="+dir)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run() // CommandContext kills on timeout; Run always waits (reaps)
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

func plantFIFO(t *testing.T, p string) {
	t.Helper()
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestOutboxFIFO(t *testing.T) {
	t.Run("fifo without writer is refused at once", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "outbox")
		if _, err := OpenOutbox(dir); err != nil {
			t.Fatal(err)
		}
		plantFIFO(t, filepath.Join(dir, newID(t)+".json"))
		if got := runOutboxChild(t, dir); got != "refused" {
			t.Fatalf("FIFO entry: want refused, got %s", got)
		}
	})

	t.Run("positive control: Begin then List returns the started entry", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "outbox")
		ob, err := OpenOutbox(dir)
		if err != nil {
			t.Fatal(err)
		}
		id := newID(t)
		if err := ob.Begin(id); err != nil {
			t.Fatal(err)
		}
		l, err := ob.List()
		if err != nil || len(l) != 1 || l[0].JobID != id || l[0].Closed {
			t.Fatalf("started entry: %v %v", l, err)
		}
		if err := ob.Close(id, runnerproto.Result{ErrorClass: runnerproto.ErrClassInternal}); err != nil {
			t.Fatal(err)
		}
		if l, err := ob.List(); err != nil || len(l) != 1 || !l[0].Closed {
			t.Fatalf("closed entry: %v %v", l, err)
		}
	})

	t.Run("positive control: damaged regular entry is refused", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "outbox")
		ob, _ := OpenOutbox(dir)
		p := filepath.Join(dir, newID(t)+".json")
		if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ob.List(); err == nil {
			t.Fatal("damaged entry accepted")
		}
	})

	t.Run("fifo and a regular entry are left untouched", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "outbox")
		ob, _ := OpenOutbox(dir)
		good := newID(t)
		if err := ob.Begin(good); err != nil {
			t.Fatal(err)
		}
		before, _ := os.ReadFile(filepath.Join(dir, good+".json")) //nolint:gosec // G304: test fixture path
		fifo := filepath.Join(dir, newID(t)+".json")
		plantFIFO(t, fifo)
		if got := runOutboxChild(t, dir); got != "refused" {
			t.Fatalf("want refused, got %s", got)
		}
		fi, err := os.Lstat(fifo)
		if err != nil || fi.Mode()&os.ModeNamedPipe == 0 {
			t.Fatalf("FIFO was replaced or removed: %v", err)
		}
		after, _ := os.ReadFile(filepath.Join(dir, good+".json")) //nolint:gosec // G304: test fixture path
		if !bytes.Equal(before, after) {
			t.Fatal("regular entry changed by the refusal")
		}
	})

	t.Run("symlink to a fifo is still refused", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "outbox")
		ob, _ := OpenOutbox(dir)
		target := filepath.Join(t.TempDir(), "f")
		plantFIFO(t, target)
		if err := os.Symlink(target, filepath.Join(dir, newID(t)+".json")); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, err := ob.List(); done <- err }()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("symlink accepted")
			}
		case <-time.After(outboxHardCap):
			t.Fatal("List hung on a symlink to a FIFO")
		}
	})
}

// A refusal names no path and echoes no entry content.
func TestOutboxRefusalLeaksNoCanary(t *testing.T) {
	c := canary.New()
	if !c.In("x "+c.Value(1)) || !c.In(fmt.Sprintf("%x", c.Value(1))) {
		t.Fatal("canary detector is blind; the test proves nothing")
	}
	dir := filepath.Join(t.TempDir(), "d-"+c.Value(1), "outbox")
	ob, err := OpenOutbox(dir)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(p string){
		"damaged-content": func(p string) {
			if err := os.WriteFile(p, []byte(`{"job_id":"`+c.Value(2)+`"`), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"fifo": func(p string) { plantFIFO(t, p) },
	}
	for name, plant := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(dir, newID(t)+".json")
			plant(p)
			defer func() { _ = os.Remove(p) }()
			// The FIFO case runs List in a goroutine so a regression fails
			// the canary check below instead of hanging the binary.
			type res struct{ err error }
			ch := make(chan res, 1)
			go func() { _, err := ob.List(); ch <- res{err} }()
			select {
			case r := <-ch:
				if r.err == nil {
					t.Fatal("damaged entry accepted")
				}
				for _, s := range []string{r.err.Error(), fmt.Sprintf("%v", r.err), fmt.Sprintf("%+v", r.err), fmt.Sprintf("%#v", r.err)} {
					if c.In(s) {
						t.Fatalf("canary leaked: %q", s)
					}
				}
			case <-time.After(outboxHardCap):
				t.Fatal("List did not return")
			}
		})
	}
}
