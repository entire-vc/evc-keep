package pgscratch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// lateProxy listens on a loopback port and drops every connection until
// opened, then forwards to the real test server: a postgres service that
// accepts connections late.
func lateProxy(t *testing.T, target string) (dsn string, open func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var up atomic.Bool
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if !up.Load() {
				_ = c.Close()
				continue
			}
			s, err := net.Dial("tcp", target)
			if err != nil {
				_ = c.Close()
				continue
			}
			go func() { _, _ = io.Copy(s, c); _ = s.Close() }()
			go func() { _, _ = io.Copy(c, s); _ = c.Close() }()
		}
	}()
	base := os.Getenv("KEEP_DATABASE_URL")
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal("KEEP_DATABASE_URL is not a URL")
	}
	u.Host = ln.Addr().String()
	return DSN(t, u.String()), func() { up.Store(true) }
}

func serverAddr(t *testing.T) string {
	t.Helper()
	base := os.Getenv("KEEP_DATABASE_URL")
	if base == "" {
		t.Skip("KEEP_DATABASE_URL not set — see CONTRIBUTING.md")
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal("KEEP_DATABASE_URL is not a URL")
	}
	host := u.Host
	if u.Port() == "" {
		host += ":5432"
	}
	return host
}

func TestConnectWithRetryRidesOutLateServer(t *testing.T) {
	dsn, open := lateProxy(t, serverAddr(t))
	// Control: one attempt against the not-yet-answering server fails, so
	// the pass below is the retry's doing.
	if err := connectOnce(dsn); err == nil {
		t.Fatal("single attempt succeeded against a server that was not answering")
	}
	time.AfterFunc(1500*time.Millisecond, open)
	start := time.Now()
	if err := connectWithRetry(dsn, 20*time.Second, 100*time.Millisecond); err != nil {
		t.Fatalf("retry did not ride out a late server: %v", err)
	}
	if time.Since(start) < time.Second {
		t.Fatal("connected before the server was opened: the proxy control is broken")
	}
}

// TestNewWaitsForLateServer is the helper-level form of the CI failure: the
// first test of a package asks for a scratch database while the service is
// still not answering. New must wait, not fail.
func TestNewWaitsForLateServer(t *testing.T) {
	dsn, open := lateProxy(t, serverAddr(t))
	t.Setenv("KEEP_DATABASE_URL", dsn)
	ready.mu.Lock()
	saved := struct {
		done bool
		err  error
	}{ready.done, ready.err}
	ready.done, ready.err = false, nil
	ready.mu.Unlock()
	t.Cleanup(func() {
		ready.mu.Lock()
		ready.done, ready.err = saved.done, saved.err
		ready.mu.Unlock()
	})
	time.AfterFunc(2*time.Second, open)
	start := time.Now()
	New(t, nil)
	if time.Since(start) < time.Second {
		t.Fatal("New returned before the server was opened: the proxy control is broken")
	}
}

func TestConnectWithRetryGivesUpWithClearReason(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // nothing listens here now
	dsn := DSN(t, "postgres://keep:hunter2canary@"+addr+"/keep?sslmode=disable")
	done := make(chan error, 1)
	go func() { done <- connectWithRetry(dsn, time.Second, 100*time.Millisecond) }()
	select {
	case err = <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("the wait outlived its one-second budget")
	}
	if err == nil {
		t.Fatal("connect to a closed port succeeded")
	}
	text := err.Error()
	var attempts int
	if _, scanErr := fmt.Sscanf(text, "test database not ready after %d attempts", &attempts); scanErr != nil {
		t.Fatalf("failure does not count attempts: %q", text)
	}
	// One second at a 100 ms pause is about ten tries; a loop that does not
	// pause spins thousands of times against a refused port.
	if attempts < 2 || attempts > 12 {
		t.Fatalf("attempts = %d, want paced retries (2..12)", attempts)
	}
	if !strings.Contains(text, "not ready after") || !strings.Contains(text, "network unreachable or refused") {
		t.Fatalf("failure does not say what expired: %q", text)
	}
	for _, leak := range []string{"hunter2canary", "keep@", addr, "127.0.0.1"} {
		if strings.Contains(text, leak) {
			t.Fatal("failure text repeats part of the DSN")
		}
	}
}

func TestConnectWithRetryDoesNotRetryRejectedCredentials(t *testing.T) {
	base := os.Getenv("KEEP_DATABASE_URL")
	if base == "" {
		t.Skip("KEEP_DATABASE_URL not set — see CONTRIBUTING.md")
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal("KEEP_DATABASE_URL is not a URL")
	}
	u.User = url.UserPassword("keep_no_such_role", "wrong")
	start := time.Now()
	err = connectWithRetry(DSN(t, u.String()), 30*time.Second, time.Second)
	if err == nil {
		t.Fatal("connect with an unknown role succeeded")
	}
	if !strings.Contains(err.Error(), "refused the connection") {
		t.Fatalf("rejected credentials were treated as a slow server: %q", err.Error())
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("rejected credentials were retried")
	}
	for _, leak := range []string{"keep_no_such_role", "wrong", "127.0.0.1", "@"} {
		if strings.Contains(err.Error(), leak) {
			t.Fatal("refusal text repeats part of the DSN")
		}
	}
}

// resetReady clears the process-wide readiness outcome for one test and
// restores it afterwards.
func resetReady(t *testing.T) {
	t.Helper()
	ready.mu.Lock()
	done, err := ready.done, ready.err
	ready.done, ready.err = false, nil
	ready.mu.Unlock()
	t.Cleanup(func() {
		ready.mu.Lock()
		ready.done, ready.err = done, err
		ready.mu.Unlock()
	})
}

func TestNewRoleWaitsForLateServer(t *testing.T) {
	scratch := New(t, nil) // real server, before the proxy takes over
	dsn, open := lateProxy(t, serverAddr(t))
	t.Setenv("KEEP_DATABASE_URL", dsn)
	resetReady(t)
	time.AfterFunc(2*time.Second, open)
	start := time.Now()
	NewRole(t, scratch)
	if time.Since(start) < time.Second {
		t.Fatal("NewRole returned before the server was opened: the proxy control is broken")
	}
}

func TestNewWarmsTheScratchDatabase(t *testing.T) {
	base := os.Getenv("KEEP_DATABASE_URL")
	if base == "" {
		t.Skip("KEEP_DATABASE_URL not set — see CONTRIBUTING.md")
	}
	var calls atomic.Int32
	var seen atomic.Value
	real := warm
	warm = func(dsn string, budget, interval time.Duration) error {
		calls.Add(1)
		seen.Store(dsn)
		return real(dsn, budget, interval)
	}
	t.Cleanup(func() { warm = real })
	dsn := New(t, nil)
	if calls.Load() != 1 || seen.Load() != dsn {
		t.Fatalf("New did not warm the database it returned (%d calls)", calls.Load())
	}
}

// fatalRecorder is a testing.TB whose Fatal ends only the calling goroutine, so a
// test can observe what WaitReady reports.
type fatalRecorder struct {
	testing.TB
	msg string
}

func (r *fatalRecorder) Helper()                   {}
func (r *fatalRecorder) Fatal(args ...any)         { r.msg = fmt.Sprint(args...); runtime.Goexit() }
func (r *fatalRecorder) Skip(args ...any)          { r.msg = "skipped"; runtime.Goexit() }
func (r *fatalRecorder) Fatalf(f string, a ...any) { r.Fatal(fmt.Sprintf(f, a...)) }

func callWaitReady(t *testing.T) string {
	t.Helper()
	r := &fatalRecorder{TB: t}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); WaitReady(r) }()
	wg.Wait()
	return r.msg
}

// A server that never comes up costs one budget, not one per test, and the
// failure is reported to every caller.
func TestWaitReadyCachesItsOutcome(t *testing.T) {
	serverAddr(t)                          // skips without a database
	base := os.Getenv("KEEP_DATABASE_URL") // read before the environment points at a dead port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	t.Setenv("KEEP_DATABASE_URL", "postgres://keep:keep@"+addr+"/keep?sslmode=disable")
	resetReady(t)
	oldBudget := readyBudget
	readyBudget = 600 * time.Millisecond
	t.Cleanup(func() { readyBudget = oldBudget })

	if msg := callWaitReady(t); !strings.Contains(msg, "not ready after") {
		t.Fatalf("a dead server was not reported: %q", msg)
	}
	// The server is now reachable, but the first outcome stands and answers
	// at once.
	t.Setenv("KEEP_DATABASE_URL", base)
	start := time.Now()
	if msg := callWaitReady(t); !strings.Contains(msg, "not ready after") {
		t.Fatalf("the cached failure was not re-raised: %q", msg)
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Fatal("a cached failure was retried")
	}
}

func TestTransientClassification(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"deadline", context.DeadlineExceeded, true},
		{"wrapped deadline", fmt.Errorf("x: %w", context.DeadlineExceeded), true},
		{"starting up", &pgconn.PgError{Code: "57P03"}, true},
		{"connection exception", &pgconn.PgError{Code: "08006"}, true},
		{"bad password", &pgconn.PgError{Code: "28P01"}, false},
		{"no such database", &pgconn.PgError{Code: "3D000"}, false},
		{"syntax", &pgconn.PgError{Code: "42601"}, false},
		{"dial", &net.OpError{Op: "dial", Err: errors.New("refused")}, true},
		{"unrelated", errors.New("boom"), false},
	} {
		if got := transient(tc.err); got != tc.want {
			t.Errorf("%s: transient = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestWarmUpFailsWhenWarmFails(t *testing.T) {
	real := warm
	var budget time.Duration
	warm = func(dsn string, b, interval time.Duration) error {
		budget = b
		return errors.New("warm refused")
	}
	t.Cleanup(func() { warm = real })
	rec := &fatalRecorder{}
	done := make(chan struct{})
	go func() { defer close(done); warmUp(rec, "postgres://x") }()
	<-done
	if rec.msg != "warm refused" {
		t.Fatalf("warmUp swallowed the warm-up failure: %q", rec.msg)
	}
	if budget != 30*time.Second {
		t.Fatalf("warm-up budget is %v, want 30s", budget)
	}
}
