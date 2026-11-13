//go:build unix

package main

import (
	"bytes"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestPolicyFileReadGuards: the -policy reader refuses FIFOs (with and
// without a writer), directories, devices and limit+1 bytes quickly, with a
// static error that carries neither the path nor file bytes; a regular file
// up to the limit is returned byte-for-byte.
func TestPolicyFileReadGuards(t *testing.T) {
	dir := t.TempDir()
	const pathMarker = "pathcanaryq7"

	read := func(t *testing.T, path string) ([]byte, error) {
		t.Helper()
		type res struct {
			b   []byte
			err error
		}
		ch := make(chan res, 1)
		go func() { b, err := readPolicyFile(path); ch <- res{b, err} }()
		select {
		case r := <-ch:
			return r.b, r.err
		case <-time.After(3 * time.Second):
			t.Fatal("readPolicyFile hung")
			return nil, nil
		}
	}
	refused := func(t *testing.T, path string) {
		t.Helper()
		b, err := read(t, path)
		if err == nil || b != nil {
			t.Fatalf("expected refusal, got %d bytes err=%v", len(b), err)
		}
		if strings.Contains(err.Error(), pathMarker) || strings.Contains(err.Error(), dir) {
			t.Errorf("error leaks path: %q", err)
		}
	}

	t.Run("fifo-no-writer", func(t *testing.T) {
		p := filepath.Join(dir, "fifo-"+pathMarker)
		if err := unix.Mkfifo(p, 0o600); err != nil {
			t.Fatal(err)
		}
		refused(t, p)
	})
	t.Run("fifo-with-writer", func(t *testing.T) {
		p := filepath.Join(dir, "fifow-"+pathMarker)
		if err := unix.Mkfifo(p, 0o600); err != nil {
			t.Fatal(err)
		}
		w, err := unix.Open(p, unix.O_RDWR, 0) // O_RDWR: a writer exists, never blocks
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = unix.Close(w) }()
		refused(t, p)
	})
	t.Run("directory", func(t *testing.T) { refused(t, dir) })
	t.Run("device", func(t *testing.T) { refused(t, "/dev/null") })
	t.Run("missing", func(t *testing.T) { refused(t, filepath.Join(dir, "nope-"+pathMarker)) })
	t.Run("limit-plus-one", func(t *testing.T) {
		p := filepath.Join(dir, "big-"+pathMarker)
		if err := os.WriteFile(p, bytes.Repeat([]byte("a"), maxPolicyFileBytes+1), 0o600); err != nil {
			t.Fatal(err)
		}
		refused(t, p)
	})
	t.Run("exactly-limit", func(t *testing.T) {
		p := filepath.Join(dir, "lim")
		want := bytes.Repeat([]byte("a"), maxPolicyFileBytes)
		if err := os.WriteFile(p, want, 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := read(t, p)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("limit-sized file: len=%d err=%v", len(got), err)
		}
	})
	t.Run("regular-and-symlink-bytes-hash-unchanged", func(t *testing.T) {
		p := filepath.Join(dir, "ok")
		want := []byte("rule one\nrule two\n")
		if err := os.WriteFile(p, want, 0o600); err != nil {
			t.Fatal(err)
		}
		ln := filepath.Join(dir, "ln")
		if err := os.Symlink(p, ln); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{p, ln} {
			got, err := read(t, path)
			if err != nil || sha256.Sum256(got) != sha256.Sum256(want) {
				t.Fatalf("%s: bytes differ or err=%v", path, err)
			}
		}
	})

	t.Run("cli", func(t *testing.T) {
		var calls atomic.Int32
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()
		ca := writePEMCert(t, srv.Certificate())
		credDir := t.TempDir()
		fifo := filepath.Join(dir, "cli-fifo-"+pathMarker)
		if err := unix.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}
		big := filepath.Join(dir, "cli-big-"+pathMarker)
		if err := os.WriteFile(big, bytes.Repeat([]byte("a"), maxPolicyFileBytes+1), 0o600); err != nil {
			t.Fatal(err)
		}
		for name, p := range map[string]string{"fifo": fifo, "oversize": big, "dir": dir} {
			done := make(chan struct{})
			var rc int
			var stdout, stderr string
			go func() {
				defer close(done)
				rc, stdout, stderr = runPolicyCLI(t, srv.URL, ca, credDir, p)
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatalf("%s: CLI hung on policy path", name)
			}
			if rc == 0 {
				t.Errorf("%s: CLI accepted the policy path", name)
			}
			for _, out := range []string{stdout, stderr} {
				if strings.Contains(out, pathMarker) || strings.Contains(out, dir) {
					t.Errorf("%s: output leaks the path: %q", name, out)
				}
			}
		}
		if calls.Load() != 0 {
			t.Errorf("network contacted %d times for refused policy", calls.Load())
		}
		if entries, _ := os.ReadDir(credDir); len(entries) != 0 {
			t.Errorf("state written: %d entries", len(entries))
		}
	})
}

func runPolicyCLI(t *testing.T, server, ca, credDir, policy string) (int, string, string) {
	t.Setenv("KEEP_ADMIN_TOKEN", testAdminTokenFixture)
	return captureOutput(t, func() int {
		return runRunnerEnrollToken([]string{"-host", "h1", "-policy", policy, "-server", server, "-server-ca", ca})
	})
}
