package app

import (
	"bytes"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/obs"
)

// dialOnListeningWriter dials both addresses synchronously from inside the
// log write that announces "listening" — the latest moment an observer could
// react to that line — and records the outcome.
type dialOnListeningWriter struct {
	addrs []string
	mu    sync.Mutex
	errs  []error
	seen  bool
}

func (w *dialOnListeningWriter) Write(p []byte) (int, error) {
	if !strings.Contains(string(p), "listening") {
		return len(p), nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.seen = true
	for _, a := range w.addrs {
		c, err := net.DialTimeout("tcp", a, time.Second)
		if err != nil {
			w.errs = append(w.errs, err)
			continue
		}
		_ = c.Close()
	}
	return len(p), nil
}

// TestListeningLogMeansSocketsAreBound: the "keep-server listening" line is
// what process-level tests and supervisors wait for, so a TCP connect made at
// that moment must succeed on both listeners. Logging it before the sockets
// were bound let a starved CI runner refuse the first connection (flaky
// TestRunnerEnrollmentLiveRoundTrip, main pipeline 10174).
func TestListeningLogMeansSocketsAreBound(t *testing.T) {
	// One P: a goroutine started before the log call cannot run until the
	// logging goroutine blocks, which is what a starved runner looks like.
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))

	for i := 0; i < 20; i++ {
		a, b := freeAddr(t), freeAddr(t)
		w := &dialOnListeningWriter{addrs: []string{a, b}}
		logger := slog.New(slog.NewTextHandler(w, nil))
		srv := newHTTPServer(a, http.NotFoundHandler(), logger)
		tlsSrv := newHTTPServer(b, http.NotFoundHandler(), logger)
		done := make(chan int, 1)
		go func() { done <- serveBoth(srv, tlsSrv, logger) }()

		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			w.mu.Lock()
			seen := w.seen
			w.mu.Unlock()
			if seen {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		w.mu.Lock()
		seen, errs := w.seen, w.errs
		w.mu.Unlock()
		_ = srv.Close()
		_ = tlsSrv.Close()
		<-done
		if !seen {
			t.Fatalf("run %d: the listening line was never logged", i)
		}
		if len(errs) > 0 {
			t.Fatalf("run %d: %d listener(s) refused a connection made while the listening line was being logged: %v", i, len(errs), errs[0])
		}
	}
}

// A bind failure ends the process with a fixed error_class and nothing from
// the OS error (which names the address), and releases the listener that was
// already bound.
func TestServeBothBindFailureIsStaticAndReleasesFirstListener(t *testing.T) {
	for _, plainBusy := range []bool{true, false} {
		busy, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		free := freeAddr(t)
		plainAddr, runnerAddr := free, busy.Addr().String()
		if plainBusy {
			plainAddr, runnerAddr = busy.Addr().String(), free
		}

		var buf bytes.Buffer
		logger := obs.New(&buf)
		code := serveBoth(newHTTPServer(plainAddr, http.NotFoundHandler(), logger), newHTTPServer(runnerAddr, http.NotFoundHandler(), logger), logger)
		if code != 1 {
			t.Fatalf("plainBusy=%v: exit code = %d, want 1", plainBusy, code)
		}
		out := buf.String()
		if !strings.Contains(out, "listen_failed") || strings.Contains(out, busy.Addr().String()) || strings.Contains(out, "address already in use") {
			t.Fatalf("plainBusy=%v: bind failure log is not the static form: %q", plainBusy, out)
		}
		l, err := net.Listen("tcp", free)
		if err != nil {
			t.Fatalf("plainBusy=%v: free listener was not released after the bind failure: %v", plainBusy, err)
		}
		_ = l.Close()
		_ = busy.Close()
	}
}
