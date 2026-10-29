package obs

import (
	"bytes"
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
	for _, bad := range []string{"CANARY", "203.0.113.9", "4444", "goroutine"} {
		if strings.Contains(out, bad) {
			t.Errorf("free text %q reached the log: %s", bad, out)
		}
	}
	for _, c := range []string{`"error_class":"tls_handshake"`, `"error_class":"handler_panic"`, `"error_class":"http_server"`} {
		if !strings.Contains(out, c) {
			t.Errorf("missing %s in: %s", c, out)
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
