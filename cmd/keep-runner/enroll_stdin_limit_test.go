package main

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// TestEnrollStdinBoundary: the enrollment token is read from stdin under a
// 4096-byte cap. Input over the cap is refused before any HTTP request and
// before any credential is saved; it is never truncated into a shorter token.
func TestEnrollStdinBoundary(t *testing.T) {
	// Per-test random canary head (internal/testutil/canary), never a real token.
	marker := canary.New().Value(1)
	const tail = "ZK9tailQ" // distinct tail bytes: a leak of the end of the input is caught too
	pad := func(n int) string { return marker + strings.Repeat("a", n-len(marker)-len(tail)) + tail }

	if !canary.Of(marker[:6]).In(hex.EncodeToString([]byte("x" + marker[:12]))) {
		t.Fatal("canary detector is blind to hex")
	}
	cases := []struct {
		name     string
		stdin    string
		wantSent int // token length the peer must receive; 0 = no request at all
		wantRC   int
		wantErr  string // substring expected in stderr
	}{
		{"normal-fixture-newline", testTokenFixture + "\n", len(testTokenFixture), 1, "not_found"},
		{"empty-input", "", 0, 2, "must be provided on stdin"},
		{"exactly-4096-with-newline", pad(4095) + "\n", 4095, 1, "not_found"},
		{"exactly-4096-no-newline", pad(4096), 4096, 1, "not_found"},
		{"4097", pad(4097), 0, 2, "exceeds"},
		{"4097-trailing-newline", pad(4096) + "\n", 0, 2, "exceeds"},
		{"long-stream", pad(48 << 10), 0, 2, "exceeds"},
		{"oversized-whitespace", strings.Repeat(" ", 5000) + testTokenFixture, 0, 2, "exceeds"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var mu sync.Mutex
			var calls int
			var sentLen int
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				var req struct {
					Token string `json:"token"`
				}
				_ = json.Unmarshal(b, &req)
				mu.Lock()
				calls++
				sentLen = len(req.Token)
				mu.Unlock()
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error_class":"not_found","message":"m","request_id":"req1"}`))
			}))
			defer srv.Close()
			credDir := t.TempDir()
			rc, stdout, stderr := captureEnrollOutput(t, c.stdin, func() int {
				return runEnroll([]string{
					"-host", "h1", "-policy", enrollPolicyFixture(t), "-server", srv.URL,
					"-cred-dir", credDir, "-server-ca", writePEMCert(t, srv.Certificate()),
				})
			})
			mu.Lock()
			defer mu.Unlock()
			if rc != c.wantRC {
				t.Fatalf("rc=%d want %d stderr=%q", rc, c.wantRC, stderr)
			}
			if !strings.Contains(stderr, c.wantErr) {
				t.Errorf("stderr missing %q: %q", c.wantErr, stderr)
			}
			if c.wantSent == 0 {
				if calls != 0 {
					t.Errorf("HTTP request made for refused input: calls=%d sent_bytes=%d", calls, sentLen)
				}
			} else if calls != 1 || sentLen != c.wantSent {
				t.Errorf("calls=%d sent_bytes=%d want 1/%d", calls, sentLen, c.wantSent)
			}
			if entries, _ := os.ReadDir(credDir); len(entries) != 0 {
				t.Errorf("credential saved: %d entries", len(entries))
			}
			for _, out := range []string{stdout, stderr} {
				if strings.Contains(out, "keep_renr_") {
					t.Errorf("input bytes leaked into output: %q", out)
				}
				// Partial echoes: any 4-byte raw window, and any 6-byte window in
				// the canary's encodings (hex, base64, percent, reversed), of the
				// head and the tail of the input.
				if strings.HasPrefix(c.stdin, marker) {
					head, end := marker, c.stdin[len(c.stdin)-len(tail)-1:]
					for _, part := range []string{head, end} {
						for i := 0; i+4 <= len(part); i++ {
							if strings.Contains(out, part[i:i+4]) {
								t.Errorf("input window %q leaked into output: %q", part[i:i+4], out)
							}
						}
						for i := 0; i+6 <= len(part); i++ {
							if canary.Of(part[i : i+6]).In(out) {
								t.Errorf("encoded input window at %d leaked into output: %q", i, out)
							}
						}
					}
				}
			}
		})
	}
}
