//go:build unix

package runner

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
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
	fifoChildEnv   = "KEEP_TEST_CREDENTIAL_FIFO_DIR"
	fifoRefuseWait = time.Second
	fifoHardCap    = 10 * time.Second
)

// TestCredentialLoadFIFOChild is the child half of TestCredentialLoadFIFO.
// It returns at once (a pass, not a SKIP: scripts/check-no-silent-skip.sh
// rejects unlisted skips) unless the parent set fifoChildEnv; the parent's
// positive control (an ordinary credential must report "loaded") proves the
// child does real work. Output is one class word, never file content.
func TestCredentialLoadFIFOChild(t *testing.T) {
	dir := os.Getenv(fifoChildEnv)
	if dir == "" {
		return
	}
	type result struct {
		err error
		d   time.Duration
	}
	ch := make(chan result, 1)
	go func() {
		start := time.Now()
		_, err := Load(dir)
		ch <- result{err, time.Since(start)}
	}()
	select {
	case r := <-ch:
		switch {
		case r.err == nil:
			fmt.Println("RESULT=loaded")
		case r.d > fifoRefuseWait:
			fmt.Println("RESULT=slow-refusal")
		case strings.Contains(r.err.Error(), "not a regular file"):
			fmt.Println("RESULT=refused-not-regular")
		default:
			fmt.Println("RESULT=refused-other")
		}
	case <-time.After(fifoRefuseWait):
		fmt.Println("RESULT=blocked")
	}
}

// runLoadChild runs Load(dir) in a separate process so a blocking open cannot
// hang the test binary. The child is always killed and reaped.
func runLoadChild(t *testing.T, dir string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), fifoHardCap)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCredentialLoadFIFOChild$", "-test.v") //nolint:gosec // G204: re-executes this test binary
	cmd.Env = append(os.Environ(), fifoChildEnv+"="+dir)
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

func TestCredentialLoadFIFO(t *testing.T) {
	files := []string{keyFileName, certFileName, caCertFileName, signPubKeyFileName, signKeyIDFileName, hostFileName, deliveryKeyFileName}

	newDir := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		cred := testCredential(t)
		dk, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cred.DeliveryKey = dk
		if err := Save(dir, cred); err != nil {
			t.Fatalf("save: %v", err)
		}
		return dir
	}

	t.Run("positive control: ordinary credential loads", func(t *testing.T) {
		if got := runLoadChild(t, newDir(t)); got != "loaded" {
			t.Fatalf("ordinary Save→Load in a child: %s", got)
		}
	})

	for _, name := range files {
		t.Run("fifo without writer replaces "+name, func(t *testing.T) {
			dir := newDir(t)
			p := filepath.Join(dir, name)
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(p, 0o600); err != nil {
				t.Fatal(err)
			}
			if got := runLoadChild(t, dir); got != "refused-not-regular" {
				t.Fatalf("FIFO at %s: want refused-not-regular, got %s", name, got)
			}
		})
	}

	t.Run("symlink to fifo is still refused", func(t *testing.T) {
		dir := newDir(t)
		fifo := filepath.Join(t.TempDir(), "f")
		if err := syscall.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, hostFileName)
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(fifo, p); err != nil {
			t.Fatal(err)
		}
		if got := runLoadChild(t, dir); got != "refused-other" {
			t.Fatalf("symlink to FIFO: want refused-other, got %s", got)
		}
	})

	t.Run("in-process: regular file still read after non-blocking open", func(t *testing.T) {
		dir := newDir(t)
		if _, err := Load(dir); err != nil {
			t.Fatalf("load: %v", err)
		}
		if _, err := readSecureFile(filepath.Join(dir, "absent")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("missing optional file must stay ErrNotExist, got %v", err)
		}
	})
}
