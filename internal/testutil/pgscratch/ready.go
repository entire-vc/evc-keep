package pgscratch

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// A freshly started CI postgres service answers late: the runner's own
// readiness wait has been seen to run 33–44 s against its 30 s limit, and the
// first CREATE DATABASE plus first connection on such a server took 5–10 s
// where later ones take 0.4 s. A test whose first connection lands in that
// window used to fail with "database operation deadline exceeded". The waits
// below absorb it, at the open stage only: a query that fails after the
// connection is up is never retried.
const (
	readyInterval = time.Second
	readyAttempt  = 6 * time.Second // a little over connect_timeout=5
	warmBudget    = 30 * time.Second
)

// readyBudget and warm are variables only so the package's own tests can
// shorten the wait and observe the warm-up call.
var (
	readyBudget = 90 * time.Second
	warm        = connectWithRetry
)

var ready struct {
	mu   sync.Mutex
	done bool
	err  error
}

// WaitReady blocks until the server KEEP_DATABASE_URL names accepts a
// connection and answers SELECT 1, retrying only while it is unreachable or
// still starting up. The first outcome, failure included, is kept for the
// life of the test process, so a server that never comes up costs one budget,
// not one per test. The failure text never repeats the DSN.
func WaitReady(t testing.TB) {
	t.Helper()
	base := os.Getenv("KEEP_DATABASE_URL")
	if base == "" {
		t.Skip("KEEP_DATABASE_URL not set — see CONTRIBUTING.md")
	}
	ready.mu.Lock()
	defer ready.mu.Unlock()
	if !ready.done {
		ready.err = connectWithRetry(DSN(t, base), readyBudget, readyInterval)
		ready.done = true
	}
	if ready.err != nil {
		t.Fatal(ready.err)
	}
}

// connectWithRetry opens a connection to dsn, runs SELECT 1 and closes it,
// trying again until budget is spent while the failure is one a starting
// server explains. Anything else (bad credentials, unknown database, a
// refused statement) is returned at once.
func connectWithRetry(dsn string, budget, interval time.Duration) error {
	deadline := time.Now().Add(budget)
	var last error
	attempts := 0
	for {
		attempts++
		last = connectOnce(dsn)
		if last == nil {
			return nil
		}
		if !transient(last) {
			return fmt.Errorf("test database refused the connection (%s)", reason(last))
		}
		if time.Now().Add(interval).After(deadline) {
			return fmt.Errorf("test database not ready after %d attempts in %s (%s)",
				attempts, budget, reason(last))
		}
		time.Sleep(interval)
	}
}

func connectOnce(dsn string) error {
	ctx, cancel := context.WithTimeout(context.Background(), readyAttempt)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(context.Background()) }()
	_, err = conn.Exec(ctx, "SELECT 1")
	return err
}

// transient reports whether err is what an unreachable or still-starting
// server produces: a dial failure or deadline (context.DeadlineExceeded is a net.Error), or SQLSTATE 57P03
// (cannot_connect_now) / class 08 (connection exception). pgx wraps the dial
// error in a text that names host and user, so this inspects types, not text.
func transient(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "57P03" || (len(pgErr.Code) == 5 && pgErr.Code[:2] == "08")
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var connErr *pgconn.ConnectError
	return errors.As(err, &connErr)
}

// reason is a fixed-vocabulary description of a failed attempt; pgx's own
// text names host, user and database, so it is never printed.
func reason(err error) string {
	var netErr net.Error
	if !errors.Is(err, context.DeadlineExceeded) && !errors.As(err, new(*pgconn.PgError)) && errors.As(err, &netErr) {
		return "network unreachable or refused"
	}
	return sqlState(err)
}
