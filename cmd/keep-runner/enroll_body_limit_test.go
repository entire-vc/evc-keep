package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

// padJSON returns valid JSON of exactly n bytes: doc followed by spaces. The
// decoder accepts it at any size, so only a byte cap can refuse it.
func padJSON(doc string, n int) string {
	return doc + strings.Repeat(" ", n-len(doc))
}

// TestEnrollResponseBodyLimit: enroll reads at most maxEnrollResponseBytes of
// the server's answer, on the success path and on the error path.
func TestEnrollResponseBodyLimit(t *testing.T) {
	okJSON, err := json.Marshal(validEnrollResponse(t, enrollFixtureRunnerID))
	if err != nil {
		t.Fatal(err)
	}
	okDoc := string(okJSON)
	const errDoc = `{"error_class":"not_found","message":"m","request_id":"req1"}`
	limit := maxEnrollResponseBytes

	plain := func(w http.ResponseWriter, doc string, n int) { _, _ = w.Write([]byte(padJSON(doc, n))) }
	chunked := func(w http.ResponseWriter, doc string, n int) {
		body := padJSON(doc, n)
		fl := w.(http.Flusher)
		for len(body) > 0 {
			k := min(len(body), 32<<10)
			_, _ = w.Write([]byte(body[:k]))
			fl.Flush()
			body = body[k:]
		}
	}
	var sent atomic.Int64
	endless := func(w http.ResponseWriter, doc string, _ int) {
		fl := w.(http.Flusher)
		_, _ = w.Write([]byte(doc))
		chunk := []byte(strings.Repeat(" ", 32<<10))
		for range 2048 { // 64 MiB ceiling so an unbounded reader still terminates
			if _, err := w.Write(chunk); err != nil {
				return
			}
			sent.Add(int64(len(chunk)))
			fl.Flush()
		}
	}
	modes := []struct {
		name string
		n    int
		fn   func(http.ResponseWriter, string, int)
		pass bool
	}{
		{"exact-limit", limit, plain, true},
		{"limit-plus-one", limit + 1, plain, false},
		{"chunked-limit-plus-one", limit + 1, chunked, false},
		{"endless", 0, endless, false},
	}
	paths := []struct {
		name   string
		status int
		doc    string
		bad    string
	}{
		{"success-body", http.StatusOK, okDoc, "decoding response"},
		{"error-body", http.StatusForbidden, errDoc, "server rejected the request"},
	}
	for _, p := range paths {
		for _, m := range modes {
			t.Run(p.name+"/"+m.name, func(t *testing.T) {
				srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(p.status)
					m.fn(w, p.doc, m.n)
				}))
				sent.Store(0)
				defer srv.Close()
				caPath := writePEMCert(t, srv.Certificate())
				credDir := t.TempDir()
				rc, stdout, stderr := captureEnrollOutput(t, testTokenFixture+"\n", func() int {
					return runEnroll([]string{
						"-host", "h1", "-policy", enrollPolicyFixture(t), "-server", srv.URL,
						"-cred-dir", credDir, "-server-ca", caPath,
					})
				})
				if m.pass {
					switch p.status {
					case http.StatusOK:
						if rc != 0 {
							t.Fatalf("exactly-limit answer refused: rc=%d stderr=%q", rc, stderr)
						}
					default:
						if !strings.Contains(stderr, "not_found") {
							t.Fatalf("exactly-limit error body not parsed: stderr=%q", stderr)
						}
					}
					return
				}
				if m.name == "endless" {
					srv.Close() // waits for the handler, which stops once the client hangs up
					if got := sent.Load(); got > 16<<20 {
						t.Errorf("client kept reading an endless body: server sent %d bytes", got)
					}
				}
				if rc == 0 {
					t.Fatalf("oversized answer accepted: stdout-len=%d", len(stdout))
				}
				if entries, _ := os.ReadDir(credDir); len(entries) != 0 {
					t.Errorf("credentials saved after a refused answer: %d entries", len(entries))
				}
				if !strings.Contains(stderr, p.bad) {
					t.Errorf("stderr lost its static diagnostic: %q", stderr)
				}
				if strings.Contains(stderr, "not_found") {
					t.Errorf("oversized error body was parsed: %q", stderr)
				}
			})
		}
	}
}
