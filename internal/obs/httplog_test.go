package obs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestServerErrorLogRoutesThroughAllowList: net/http's own log lines are free
// text that can carry a remote address or a fragment of what the peer sent.
// None of it may reach the output; only a fixed message and error_class.
func TestServerErrorLogRoutesThroughAllowList(t *testing.T) {
	var buf bytes.Buffer
	l := ServerErrorLog(New(&buf))
	l.Printf("http: TLS handshake error from 203.0.113.9:4444: tls: CANARY-PEER-TEXT")
	l.Printf("http: panic serving 203.0.113.9:4444: CANARY-PANIC-VALUE\ngoroutine 1 [running]:")
	l.Printf("http: Accept error: CANARY-OTHER; retrying in 5ms")
	out := buf.String()
	if strings.Count(out, "\n") != 3 {
		t.Fatalf("want 3 records, got: %q", out)
	}
	for _, f := range freeTextFindings(out, serverErrorLogForbidden) {
		t.Error(f)
	}
	for _, c := range []string{`"error_class":"tls_handshake"`, `"error_class":"handler_panic"`, `"error_class":"http_server"`} {
		if !strings.Contains(out, c) {
			t.Errorf("missing %s in: %s", c, out)
		}
	}
}

// serverErrorLogForbidden is what net/http's free text carries in the probes
// above: peer text, the peer address and port, and a goroutine dump.
var serverErrorLogForbidden = []string{"CANARY", "203.0.113.9", "4444", "goroutine"}

// freeTextFindings parses every line of out as one JSON record, drops the
// record's own "time" (an RFC3339Nano stamp whose digits can contain "4444"
// with no leak at all) and searches every remaining key and value for the
// forbidden substrings. Keys are searched too: a leak into a field name is
// still a leak. A line that is not a JSON object is itself a finding.
func freeTextFindings(out string, forbidden []string) []string {
	var findings []string
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			findings = append(findings, fmt.Sprintf("record is not a JSON object (%v): %s", err, line))
			continue
		}
		if rec == nil { // valid JSON null decodes into a nil map without error
			findings = append(findings, fmt.Sprintf("record is not a JSON object: %s", line))
			continue
		}
		delete(rec, "time")
		rest, err := json.Marshal(rec)
		if err != nil {
			findings = append(findings, fmt.Sprintf("record does not re-encode (%v): %s", err, line))
			continue
		}
		for _, bad := range forbidden {
			if strings.Contains(string(rest), bad) {
				findings = append(findings, fmt.Sprintf("free text %q reached the log: %s", bad, line))
			}
		}
	}
	return findings
}

// TestFreeTextFindingsIgnoresOnlyTime pins the checker itself: a record whose
// timestamp happens to contain "4444" is clean, the same port in msg, in any
// other field or in a key is caught, and an unparsable line is never clean.
func TestFreeTextFindingsIgnoresOnlyTime(t *testing.T) {
	cases := []struct {
		name   string
		record string
		leak   bool
	}{
		{"port digits only in time", `{"time":"2026-11-15T10:51:15.538444494Z","level":"ERROR","msg":"http server error","error_class":"http_server"}`, false},
		{"peer address in msg", `{"time":"2026-11-15T10:51:15.5Z","level":"ERROR","msg":"http: TLS handshake error from 203.0.113.9:4444","error_class":"tls_handshake"}`, true},
		{"port alone in msg", `{"time":"2026-11-15T10:51:15.5Z","level":"ERROR","msg":"retry 4444","error_class":"http_server"}`, true},
		{"port in another field", `{"time":"2026-11-15T10:51:15.5Z","level":"ERROR","msg":"x","error_class":"4444"}`, true},
		{"address in a key", `{"time":"2026-11-15T10:51:15.5Z","level":"ERROR","msg":"x","203.0.113.9":1}`, true},
		{"nested value", `{"time":"2026-11-15T10:51:15.5Z","msg":"x","g":{"k":"goroutine 1"}}`, true},
		{"not JSON", `http: panic serving 203.0.113.9:4444`, true},
		{"JSON null", `null`, true},
		{"JSON string", `"203.0.113.9:4444"`, true},
		{"JSON array", `["goroutine 1"]`, true},
	}
	for _, c := range cases {
		got := freeTextFindings(c.record+"\n", serverErrorLogForbidden)
		if c.leak && len(got) == 0 {
			t.Errorf("%s: leak not caught: %s", c.name, c.record)
		}
		if !c.leak && len(got) != 0 {
			t.Errorf("%s: clean record flagged: %v", c.name, got)
		}
	}
}

// TestServerErrorLogCatchesRealTLSFailure drives a genuine handshake failure
// through a real http.Server and checks the global logger stays silent.
func TestServerErrorLogCatchesRealTLSFailure(t *testing.T) {
	var buf, std lockedBuf
	restore := captureStdLog(&std)
	defer restore()

	ts := httptest.NewUnstartedServer(http.NotFoundHandler())
	ts.Config.ErrorLog = ServerErrorLog(New(&buf))
	ts.StartTLS()
	defer ts.Close()

	c, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")) // plaintext into a TLS port
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.Read(make([]byte, 64))
	_ = c.Close()

	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(buf.String(), "tls_handshake") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(buf.String(), `"error_class":"tls_handshake"`) {
		t.Fatalf("handshake failure not logged through obs: %q", buf.String())
	}
	if std.Len() != 0 {
		t.Errorf("net/http wrote to the global log: %q", std.String())
	}
	if strings.Contains(buf.String(), "127.0.0.1") {
		t.Errorf("remote address leaked: %s", buf.String())
	}
}

// lockedBuf is a bytes.Buffer safe to read while net/http's connection
// goroutine is still writing to it.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func (l *lockedBuf) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Len()
}

func TestClassifyServerErrorHTTP2Panic(t *testing.T) {
	if got := classifyServerError("http2: panic serving 203.0.113.9:4444: boom"); got != "handler_panic" {
		t.Errorf("class = %q, want handler_panic", got)
	}
}

// TestStdLogCaptureSeesNetHTTPWithoutErrorLog is the positive control for the
// "global log stays silent" assertions: with ErrorLog unset, a recovered
// handler panic must show up in the captured global logger, otherwise the
// capture proves nothing.
func TestStdLogCaptureSeesNetHTTPWithoutErrorLog(t *testing.T) {
	var std lockedBuf
	restore := captureStdLog(&std)
	defer restore()

	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("control") }))
	defer ts.Close()
	if resp, err := http.Get(ts.URL); err == nil {
		_ = resp.Body.Close()
	}
	deadline := time.Now().Add(2 * time.Second)
	for std.Len() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if std.Len() == 0 {
		t.Fatal("captureStdLog saw nothing from net/http without ErrorLog: the silence assertions are blind")
	}
}
