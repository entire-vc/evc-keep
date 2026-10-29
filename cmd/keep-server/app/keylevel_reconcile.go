package app

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/builtin"
)

// Reconcile timing: a change whose outcome is still on its way to the journal
// holds its claim (keyLevelClaims); the grace is a second margin, for a claim
// connection that broke while the outcome was queued, so only requests older
// than keyLevelReconcileGrace count as interrupted. A handler that waits for a pool connection
// or the level lock, however long, has journaled nothing yet, so the grace
// need not cover that wait. The loop re-checks every
// keyLevelReconcileEvery, which also covers a restart inside the grace.
const (
	keyLevelReconcileGrace = 2 * time.Minute
	keyLevelReconcileEvery = time.Minute
)

// keyLevelReconcileActor is the actor of an outcome the server writes itself;
// the requester stays on the request row it answers.
const keyLevelReconcileActor = "keep-server"

// keyLevelClock is the app clock the journal stamps a request with and the
// reconcile measures its age by: one clock for both, never the database's.
var keyLevelClock = time.Now

// defaultKeyLevel is the level of an org that never changed it, as the sealer
// and the settings page read it.
const defaultKeyLevel = "user"

// keyLevelRecord is one org.key_level.* journal row, metadata only.
type keyLevelRecord struct {
	org, action, actor, reason string
	reqID                      string
	seq                        int64
	age                        time.Duration
}

var keyLevelTo = regexp.MustCompile(`(?:^| )to=([a-z]+)`)

// levelOf is the requested or reached level a row names (`to=`), or "".
// The request journals the name the settings sent ("org"), the sealer's outcome
// the canonical one ("organization"): both are read as the canonical name.
func levelOf(r keyLevelRecord) string {
	if m := keyLevelTo.FindStringSubmatch(r.reason); m != nil {
		if c, ok := builtin.CanonicalKeyLevel(m[1]); ok {
			return c
		}
		return m[1]
	}
	return ""
}

// keyLevelOutcomeActions are the actions that answer a key-level request.
var keyLevelOutcomeActions = []string{string(audit.ActionOrgKeyLevelChanged), string(audit.ActionOrgKeyLevelChangeDenied), string(audit.ActionOrgKeyLevelChangeFailed)}

func isKeyLevelOutcome(action string) bool {
	return slices.Contains(keyLevelOutcomeActions, action)
}

// danglingRequests returns the requests with no outcome. The sealer's outcome
// carries the id of the request it answers, and an outcome closes the latest
// open request of that org with that id. An outcome without an id, or with an id
// no request has, closes nothing: a retry by the same requester never closes
// someone else's request. The server issues a fresh id per request; should a
// repeated id still occur, the outcome answers the later request and the
// earlier one stays open. recs must be ordered by org, then seq.
func danglingRequests(recs []keyLevelRecord) []keyLevelRecord {
	type key struct{ org, id string }
	open := map[key][]keyLevelRecord{}
	for _, r := range recs {
		switch {
		case r.action == string(audit.ActionOrgKeyLevelRequested) && r.reqID != "":
			k := key{r.org, r.reqID}
			open[k] = append(open[k], r)
		case isKeyLevelOutcome(r.action) && r.reqID != "":
			k := key{r.org, r.reqID}
			if n := len(open[k]); n > 1 {
				open[k] = open[k][:n-1]
			} else {
				delete(open, k)
			}
		}
	}
	out := make([]keyLevelRecord, 0, len(open))
	for _, rs := range open {
		out = append(out, rs...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].org != out[j].org {
			return out[i].org < out[j].org
		}
		return out[i].seq < out[j].seq
	})
	return out
}

// querier is a pool, or a transaction on the connection the level lock is held on.
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// keyLevelRecords reads the key-level rows of org, or of every org when org is "".
func keyLevelRecords(ctx context.Context, db querier, org string) ([]keyLevelRecord, error) {
	rows, err := db.Query(ctx, `SELECT org_id, org_seq, action, actor_id, intent_reason, request_id, ts
		FROM audit_records WHERE action LIKE 'org.key_level.%' AND ($1 = '' OR org_id = $1) ORDER BY org_id, org_seq`, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []keyLevelRecord
	for rows.Next() {
		var r keyLevelRecord
		var ts time.Time
		if err := rows.Scan(&r.org, &r.seq, &r.action, &r.actor, &r.reason, &r.reqID, &ts); err != nil {
			return nil, err
		}
		r.age = keyLevelClock().Sub(ts)
		out = append(out, r)
	}
	return out, rows.Err()
}

// reconcileKeyLevels gives every journaled key-level request that has no
// outcome, and is older than minAge, its outcome, so a process that died
// between the request and the outcome does not leave a bare `requested`
// behind. It returns how many outcomes it wrote.
//
// It reads the journal and the persisted level and appends to the journal; it
// never re-runs a change and never writes `changed`. What it cannot prove it
// does not claim: when the persisted level is the requested one it writes
// interrupted_unverified (the re-wrap may be partial; every envelope stays
// readable and the change can be repeated), otherwise interrupted_level_differs.
// Whether a change is over is read from the database, so any instance decides
// alike: a request whose claim is still held belongs to a change whose outcome
// is on its way (keyLevelClaims), and a change of the same org running anywhere
// holds the level lock; such requests are left for the next pass. Names,
// levels and counts only. Under the lock it reads and appends only on the
// lock's connection, in one transaction per org.
func reconcileKeyLevels(ctx context.Context, pool *pgxpool.Pool, j audit.TransactionalJournaler, log *slog.Logger, minAge time.Duration) (int, error) {
	all, err := keyLevelRecords(ctx, pool, "")
	if err != nil {
		return 0, fmt.Errorf("read key level journal: database error")
	}
	byOrg := map[string][]string{}
	for _, r := range danglingRequests(all) {
		if r.age >= minAge {
			byOrg[r.org] = append(byOrg[r.org], r.reqID)
		}
	}
	names := make([]string, 0, len(byOrg))
	for o := range byOrg {
		names = append(names, o)
	}
	sort.Strings(names)
	wrote := 0
	for _, org := range names {
		// A cheap first look: requests whose claim is held now are not
		// tried under the level lock. A claim seen free here can be taken
		// again later; reconcileOrg holds the key itself before it writes.
		free, err := freeKeyLevelClaims(ctx, pool, org, byOrg[org])
		if err != nil {
			return wrote, fmt.Errorf("read key level claims: database error")
		}
		if len(free) == 0 {
			log.Info("key level reconcile skipped: outcome pending", "org_id", org)
			continue
		}
		lctx, release, ok, err := builtin.TryLockKeyLevel(ctx, pool, org)
		if err != nil {
			return wrote, fmt.Errorf("lock key level: database error")
		}
		if !ok {
			log.Info("key level reconcile skipped: change running", "org_id", org)
			continue
		}
		n, err := reconcileOrg(lctx, j, org, minAge, free)
		release(ctx)
		wrote += n
		if err != nil {
			return wrote, err
		}
	}
	if wrote > 0 {
		log.Warn("key level requests without outcome reconciled")
	}
	return wrote, nil
}

// reconcileOrg writes the outcome of each request of org whose claim was found
// free and is still free, all in one transaction on the connection the lock is
// held on: a second pool connection taken under the lock can wait forever while
// writers queued behind the lock hold the rest of the pool. It first takes the
// claim key of each such request in the transaction, then re-reads the journal:
// a writer that got its claim back before cannot be missed by the re-read, and
// one that takes it back after waits until the commit and finds this outcome
// (keyLevelClaims.appendOutcome). ctx is the one TryLockKeyLevel returned.
func reconcileOrg(ctx context.Context, j audit.TransactionalJournaler, org string, minAge time.Duration, free map[string]bool) (int, error) {
	c, ok := builtin.LockConn(ctx)
	if !ok {
		return 0, fmt.Errorf("reconcile key level: lock connection missing")
	}
	// Driver errors can echo statement text: return fixed ones.
	tx, err := c.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin reconcile transaction: database error")
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful Commit
	ids := make([]string, 0, len(free))
	for id := range free {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	held, err := freeKeyLevelClaims(ctx, tx, org, ids)
	if err != nil {
		return 0, fmt.Errorf("read key level claims: database error")
	}
	recs, err := keyLevelRecords(ctx, tx, org)
	if err != nil {
		return 0, fmt.Errorf("read key level journal: database error")
	}
	var level string
	var read bool
	var out []audit.Record
	for _, p := range danglingRequests(recs) {
		if p.age < minAge || !held[p.reqID] {
			continue
		}
		if !read {
			if err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT level FROM keep_org_key_level WHERE org_id = $1), $2)`, org, defaultKeyLevel).Scan(&level); err != nil {
				return 0, fmt.Errorf("read key level: database error")
			}
			read = true
		}
		to := levelOf(p)
		why := "interrupted_level_differs"
		if to != "" && level == to {
			why = "interrupted_unverified"
		}
		r, err := j.AppendTx(ctx, tx, audit.Record{
			RequestID: p.reqID,
			OrgID:     p.org,
			Scope:     keyLevelScope,
			Actor:     audit.Actor{Type: audit.ActorSystem, ID: keyLevelReconcileActor, Via: audit.ViaAPI},
			Action:    audit.ActionOrgKeyLevelChangeFailed,
			Result:    audit.Result{Status: audit.StatusFailed, ErrorClass: audit.ErrClassInternal},
			Intent:    audit.Intent{Reason: audit.NewReason(fmt.Sprintf("to=%s reason=%s request_seq=%d", to, why, p.seq))},
		})
		if err != nil {
			return 0, fmt.Errorf("journal reconciled outcome: audit journal unavailable")
		}
		out = append(out, r)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit reconciled outcomes: database error")
	}
	for _, r := range out {
		j.LogCommitted(ctx, r)
	}
	return len(out), nil
}

// reconcileKeyLevelsLoop re-checks until ctx ends: a request that was still
// inside the grace at start, whose claim was still held, or whose lock holder
// died, is picked up here.
func reconcileKeyLevelsLoop(ctx context.Context, pool *pgxpool.Pool, j audit.TransactionalJournaler, log *slog.Logger) {
	t := time.NewTicker(keyLevelReconcileEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := reconcileKeyLevels(ctx, pool, j, log, keyLevelReconcileGrace); err != nil {
				log.Error("key level reconcile failed", "error_class", "reconcile")
			}
		}
	}
}
