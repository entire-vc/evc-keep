//go:build unix

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const caCanary = "CANARY-server-ca-7f3a91"

// loadWithDeadline fails the test instead of hanging when the loader blocks.
func loadWithDeadline(t *testing.T, path string) (*x509.CertPool, error) {
	t.Helper()
	type res struct {
		pool *x509.CertPool
		err  error
	}
	ch := make(chan res, 1)
	go func() {
		p, err := loadServerCAPool(path)
		ch <- res{p, err}
	}()
	select {
	case r := <-ch:
		return r.pool, r.err
	case <-time.After(3 * time.Second):
		t.Fatal("loadServerCAPool did not return within 3s")
		return nil, nil
	}
}

func requireStaticRefusal(t *testing.T, err, want error, path string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a refusal, got nil")
	}
	for _, bad := range []string{path, filepath.Base(path), caCanary, "BEGIN CERTIFICATE"} {
		if strings.Contains(err.Error(), bad) {
			t.Fatalf("error text leaks %q", bad)
		}
	}
	if want != nil && err != want { //nolint:errorlint // sentinel identity is the point
		t.Fatalf("want the specific refusal %q, got %v", want, err)
	}
}

func TestServerCAFileReadGuards(t *testing.T) {
	dir := t.TempDir()

	t.Run("fifo without writer", func(t *testing.T) {
		p := filepath.Join(dir, "fifo-"+caCanary)
		if err := syscall.Mkfifo(p, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := loadWithDeadline(t, p)
		requireStaticRefusal(t, err, errServerCANotRegular, p)
	})

	t.Run("fifo with idle writer", func(t *testing.T) {
		p := filepath.Join(dir, "fifo-w")
		if err := syscall.Mkfifo(p, 0o600); err != nil {
			t.Fatal(err)
		}
		w, err := os.OpenFile(p, os.O_RDWR, 0) //nolint:gosec // test temp path; O_RDWR never blocks on a FIFO
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = w.Close() }()
		_, err = loadWithDeadline(t, p)
		requireStaticRefusal(t, err, errServerCANotRegular, p)
	})

	t.Run("missing file", func(t *testing.T) {
		p := filepath.Join(dir, "missing-"+caCanary)
		_, err := loadWithDeadline(t, p)
		requireStaticRefusal(t, err, errServerCAUnreadable, p)
	})

	t.Run("directory", func(t *testing.T) {
		_, err := loadWithDeadline(t, dir)
		requireStaticRefusal(t, err, errServerCANotRegular, dir)
	})

	t.Run("device", func(t *testing.T) {
		_, err := loadWithDeadline(t, "/dev/zero")
		requireStaticRefusal(t, err, errServerCANotRegular, "/dev/zero")
	})

	t.Run("oversized regular file", func(t *testing.T) {
		p := filepath.Join(dir, "big-"+caCanary)
		data := bytes.Repeat([]byte(caCanary+"\n"), (maxServerCABytes/len(caCanary))+2)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := loadWithDeadline(t, p)
		requireStaticRefusal(t, err, errServerCATooLarge, p)
	})

	t.Run("symlink to regular file still allowed", func(t *testing.T) {
		_, cert := newDistinctTLSServer(t)
		real := filepath.Join(dir, "ca.pem")
		writeCertPEM(t, real, cert)
		link := filepath.Join(dir, "ca-link.pem")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		if _, err := loadWithDeadline(t, link); err != nil {
			t.Fatalf("symlink to a regular CA must keep working: %v", err)
		}
	})

	t.Run("limit and limit+1 at reader level", func(t *testing.T) {
		const lim = 64
		b, err := readLimited(bytes.NewReader(bytes.Repeat([]byte("a"), lim)), lim)
		if err != nil || len(b) != lim {
			t.Fatalf("exactly limit bytes must pass: len=%d err=%v", len(b), err)
		}
		if _, err := readLimited(bytes.NewReader(bytes.Repeat([]byte("a"), lim+1)), lim); err == nil {
			t.Fatal("limit+1 bytes must be refused, not truncated")
		}
	})

	t.Run("reader error stays static", func(t *testing.T) {
		r := io.MultiReader(strings.NewReader(caCanary), errReader{errors.New(caCanary + " /secret/path")})
		_, err := readLimited(r, 64)
		requireStaticRefusal(t, err, errServerCAUnreadable, "/secret/path")
	})

	t.Run("empty and invalid PEM still rejected", func(t *testing.T) {
		for name, content := range map[string]string{"empty": "", "invalid": "not a pem " + caCanary} {
			p := filepath.Join(dir, name+".pem")
			if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := loadWithDeadline(t, p)
			requireStaticRefusal(t, err, nil, p)
		}
	})

	t.Run("generated CA trusts its server and rejects another", func(t *testing.T) {
		good, goodCert := newDistinctTLSServer(t)
		other, _ := newDistinctTLSServer(t)
		p := filepath.Join(dir, "good.pem")
		writeCertPEM(t, p, goodCert)
		pool, err := loadWithDeadline(t, p)
		if err != nil || pool == nil {
			t.Fatalf("valid CA refused: %v", err)
		}
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
		if _, err := c.Get(good.URL); err != nil {
			t.Fatalf("matching server must be trusted: %v", err)
		}
		if resp, err := c.Get(other.URL); err == nil {
			_ = resp.Body.Close()
			t.Fatal("foreign server must be rejected")
		}
	})

	t.Run("empty path means system roots", func(t *testing.T) {
		pool, err := loadServerCAPool("")
		if pool != nil || err != nil {
			t.Fatalf("want nil,nil got %v,%v", pool, err)
		}
	})
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }
