package app

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/entire-vc/evc-keep/internal/audit"
)

// keyLevelClaims is how a key-level change tells every keep-server instance
// that its outcome is still on its way to the journal. Before a change journals
// its request it takes a session advisory lock keyed by (org, request id), and
// the lock is given up only once the outcome of that request is in the journal,
// or once no outcome will come. A reconcile in any process tries the same key
// and writes `interrupted` only when the lock is free: the owner finished and
// the outcome is journaled, or the owner's session is gone with the process.
//
// The locks live on one connection of their own, outside the pool: a claim is
// held past the level lock and past the handler, and a pool connection held
// that long could starve the change it belongs to. So each instance holds one
// connection more than its pool's MaxConns, and needs a session to the
// database: a pooler in transaction mode does not keep session locks.
//
// A connection that broke takes its claims with it. While claims are held it
// is pinged every keyLevelClaimKeepEvery and, when broken, opened again with
// every claim taken again; the writer does the same before each outcome it
// appends. A broken session therefore leaves its claims free for about
// keyLevelClaimKeepEvery plus two keyLevelClaimIOTimeout (ping, reconnect), and
// longer while this instance cannot reach the database: well inside
// keyLevelReconcileGrace in the first case, so only a change that ran longer
// than the grace and lost its session in that window can still be reconciled.
// Even then a request gets one outcome: the reconcile writes it while it holds
// the claim key in its transaction, and the writer appends on the claim
// connection only after it took the claim again and found no outcome of the
// request in the journal (appendOutcome).
type keyLevelClaims struct {
	connect func(context.Context) (*pgx.Conn, error)

	mu   sync.Mutex
	conn *pgx.Conn
	held map[string]struct{}

	stop chan struct{} // closed by Close, once
	once sync.Once
}

// Claim timing: every query on the claim connection runs on its own deadline,
// never on a request's context, so a client that hangs up does not drop the
// claims of other changes.
const (
	keyLevelClaimIOTimeout = 5 * time.Second
)

// keyLevelClaimKeepEvery is how often held claims are checked; a var for tests.
var keyLevelClaimKeepEvery = 2 * time.Second

func newKeyLevelClaims(pool *pgxpool.Pool) *keyLevelClaims {
	cfg := pool.Config().ConnConfig
	c := &keyLevelClaims{
		connect: func(ctx context.Context) (*pgx.Conn, error) { return pgx.ConnectConfig(ctx, cfg.Copy()) },
		held:    map[string]struct{}{},
		stop:    make(chan struct{}),
	}
	go c.keep(keyLevelClaimKeepEvery)
	return c
}

// keep re-checks the connection while claims are held, until Close.
func (c *keyLevelClaims) keep(every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			c.ensure()
		}
	}
}

// ensure makes sure every held claim is held on a live session. Safe on nil.
func (c *keyLevelClaims) ensure() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.held) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), keyLevelClaimIOTimeout)
	defer cancel()
	if c.conn != nil && c.conn.Ping(ctx) != nil {
		c.drop()
	}
	_ = c.ready(ctx) // a failure is retried on the next check
}

// keyLevelClaimKey is the advisory-lock key of one request's claim. It is
// distinct from the org's level lock key (keep_org_key_level:<org>).
func keyLevelClaimKey(org, id string) string { return "keep_org_key_level_claim:" + org + ":" + id }

var errKeyLevelClaim = errors.New("key level claim unavailable")

// take holds the claim of request id of org until release. Driver errors can
// echo statement text: a fixed one is returned.
func (c *keyLevelClaims) take(ctx context.Context, org, id string) error {
	key := keyLevelClaimKey(org, id)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), keyLevelClaimIOTimeout)
	defer cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ready(ctx); err != nil {
		return errKeyLevelClaim
	}
	if _, err := c.conn.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended($1, 0))`, key); err != nil {
		c.drop()
		return errKeyLevelClaim
	}
	c.held[key] = struct{}{}
	return nil
}

// release gives up the claim of request id of org; a claim not held is a no-op.
func (c *keyLevelClaims) release(org, id string) {
	if c == nil {
		return
	}
	key := keyLevelClaimKey(org, id)
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.held[key]; !ok {
		return
	}
	delete(c.held, key)
	if c.conn == nil {
		return // the broken session took the lock with it
	}
	ctx, cancel := context.WithTimeout(context.Background(), keyLevelClaimIOTimeout)
	defer cancel()
	if _, err := c.conn.Exec(ctx, `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, key); err != nil {
		// The lock may still be held on this session: a new session holds
		// only what is still claimed.
		c.drop()
	}
}

// ready opens the connection when there is none and takes every held claim
// again on it. Called with mu held.
func (c *keyLevelClaims) ready(ctx context.Context) error {
	if c.conn != nil && !c.conn.IsClosed() {
		return nil
	}
	c.drop()
	conn, err := c.connect(ctx)
	if err != nil {
		return err
	}
	for key := range c.held {
		if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended($1, 0))`, key); err != nil {
			_ = conn.Close(context.WithoutCancel(ctx))
			return err
		}
	}
	c.conn = conn
	return nil
}

// drop closes the connection, which frees its locks. Called with mu held.
func (c *keyLevelClaims) drop() {
	if c.conn == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), keyLevelClaimIOTimeout)
	defer cancel()
	_ = c.conn.Close(ctx)
	c.conn = nil
}

// Close frees every claim of this process and stops the checks. Safe on nil.
func (c *keyLevelClaims) Close() {
	if c == nil {
		return
	}
	c.once.Do(func() { close(c.stop) })
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		// Closing alone frees the locks only once the server has ended the
		// session, after Close returned: unlock first, so they are free on return.
		ctx, cancel := context.WithTimeout(context.Background(), keyLevelClaimIOTimeout)
		_, _ = c.conn.Exec(ctx, `SELECT pg_advisory_unlock_all()`)
		cancel()
	}
	c.drop()
	clear(c.held)
}

var errKeyLevelOutcome = errors.New("key level outcome not journaled")

// appendOutcome journals r, the outcome of a claimed request, in a transaction
// on the claim connection, so the claim of the request is held while it is
// written. A reconcile writes its outcome only while it holds the same key in
// its own transaction: when the claim was lost and a reconcile wrote first,
// taking the claim again waits for that transaction, and the check below sees
// its outcome. It reports false when the request already has an outcome; r is
// not journaled then. A session that breaks mid-way rolls the transaction back.
// Driver errors can echo statement text: a fixed one is returned.
func (c *keyLevelClaims) appendOutcome(ctx context.Context, j audit.TransactionalJournaler, r audit.Record) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ready(ctx); err != nil {
		return false, errKeyLevelOutcome
	}
	tx, err := c.conn.Begin(ctx)
	if err != nil {
		return false, errKeyLevelOutcome
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful Commit
	var answered bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM audit_records WHERE org_id = $1 AND request_id = $2 AND action = ANY($3))`,
		r.OrgID, r.RequestID, keyLevelOutcomeActions).Scan(&answered); err != nil {
		return false, errKeyLevelOutcome
	}
	if answered {
		return false, nil
	}
	out, err := j.AppendTx(ctx, tx, r)
	if err != nil {
		return false, errKeyLevelOutcome
	}
	if err := tx.Commit(ctx); err != nil {
		return false, errKeyLevelOutcome
	}
	j.LogCommitted(ctx, out)
	return true, nil
}

// freeKeyLevelClaims returns which of ids of org have no claim held by any
// session. Each key is tried as a transaction lock: on a pool it is held for
// the one statement, so nothing stays locked after it; in a transaction the
// keys returned stay held until it ends, and no claim of them can be taken
// meanwhile.
func freeKeyLevelClaims(ctx context.Context, db querier, org string, ids []string) (map[string]bool, error) {
	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = keyLevelClaimKey(org, id)
	}
	rows, err := db.Query(ctx, `SELECT i FROM unnest($1::text[]) WITH ORDINALITY AS k(key, i)
		WHERE pg_try_advisory_xact_lock(hashtextextended(k.key, 0))`, keys)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	free := map[string]bool{}
	for rows.Next() {
		var i int64
		if err := rows.Scan(&i); err != nil {
			return nil, err
		}
		free[ids[i-1]] = true
	}
	return free, rows.Err()
}
