package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// A transport failure must not print the request URL, host, port or the
// error text: -server may carry a credential in userinfo, path or query, and
// *url.Error quotes all of it.
func TestEnrollTransportErrorSafe(t *testing.T) {
	c := canary.New()

	refusedAddr := func() string {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		a := l.Addr().String()
		_ = l.Close()
		return a
	}

	cases := []struct {
		name    string
		prepare func(t *testing.T) (hostPort string, extraArgs []string)
		want    string
	}{
		{"refused", func(t *testing.T) (string, []string) { return refusedAddr(), nil }, "could not reach the server"},
		{"timeout", func(t *testing.T) (string, []string) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			var mu sync.Mutex
			var conns []net.Conn
			t.Cleanup(func() {
				_ = l.Close()
				mu.Lock()
				defer mu.Unlock()
				for _, conn := range conns {
					_ = conn.Close()
				}
			})
			go func() {
				for {
					conn, err := l.Accept()
					if err != nil {
						return
					}
					mu.Lock()
					conns = append(conns, conn)
					mu.Unlock()
				}
			}()
			return l.Addr().String(), nil
		}, "timeout"},
		{"tls-unknown-authority", func(t *testing.T) (string, []string) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			t.Cleanup(srv.Close)
			u, _ := url.Parse(srv.URL)
			return u.Host, nil
		}, "TLS certificate verification failed"},
		{"tls-peer-alert", func(t *testing.T) (string, []string) {
			// The server demands a client certificate the enroll client never
			// offers, so the peer answers with a TLS alert.
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
			srv.StartTLS()
			t.Cleanup(srv.Close)
			u, _ := url.Parse(srv.URL)
			return u.Host, []string{"-server-ca", writePEMCert(t, srv.Certificate())}
		}, "TLS handshake failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old := enrollTimeout
			enrollTimeout = 300 * time.Millisecond
			t.Cleanup(func() { enrollTimeout = old })

			hostPort, extra := tc.prepare(t)
			server := "https://" + c.Value(4) + ":" + c.Value(1) + "@" + hostPort + "/" + c.Value(2) + "?k=" + c.Value(3)
			args := append([]string{"-host", "h1", "-policy", enrollPolicyFixture(t), "-server", server, "-cred-dir", t.TempDir()}, extra...)
			rc, stdout, stderr := captureEnrollOutput(t, testTokenFixture+"\n", func() int { return runEnroll(args) })

			if rc == 0 {
				t.Fatalf("enroll succeeded on a transport failure")
			}
			if c.In(stdout) || c.In(stderr) {
				t.Errorf("canary reached the terminal (stdout %d bytes, stderr %d bytes)", len(stdout), len(stderr))
			}
			if strings.Contains(stdout+stderr, hostPort) || strings.Contains(stdout+stderr, "127.0.0.1") || strings.Contains(stdout+stderr, "https://") {
				t.Errorf("URL or host reached the terminal (stderr %d bytes)", len(stderr))
			}
			if !strings.Contains(stderr, "request failed: "+tc.want) {
				t.Errorf("stderr does not carry the static classification %q (stderr %d bytes)", tc.want, len(stderr))
			}
		})
	}
}

// Positive control: the detector sees the canary when the old raw %v output is
// reproduced, so a green run above is not a blind detector.
func TestEnrollTransportLeakDetectorControl(t *testing.T) {
	c := canary.New()
	_, err := (&http.Client{Timeout: time.Second}).Get("https://user:" + c.Value(1) + "@127.0.0.1:1/" + c.Value(2))
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if !c.In(err.Error()) {
		t.Fatal("detector missed the canary in a raw *url.Error")
	}
}
