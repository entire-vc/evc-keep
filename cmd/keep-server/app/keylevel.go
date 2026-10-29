package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/entire-vc/evc-keep/internal/api"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/reqid"
)

// keyLevelScope is the journal scope of organization-wide key operations.
const keyLevelScope = "organization"

// journalWriteTimeout bounds one best-effort outcome write, which runs after
// the sealer finished and so has no request context of its own.
const journalWriteTimeout = 5 * time.Second

// keyLevelAuditor writes the sealer's events to the audit journal. The
// sealer's Auditor cannot report a failure, so a write that fails is retried
// and then logged by action name only; the change itself is not undone. The
// refusal to start a change without a journaled request is keyLevelService's
// job.
type keyLevelAuditor struct {
	j      audit.Journaler
	log    *slog.Logger
	mu     sync.Mutex
	pend   []pendingOutcome
	wake   chan struct{} // never closed: record may send after Drain began
	stop   chan struct{} // closed by Drain, under mu, once
	closed bool

	// claims holds each change's claim until its outcome is journaled; nil
	// when nothing is claimed (a sink with no change service behind it).
	claims *keyLevelClaims

	// ctx bounds the writer's retries: Drain cancels it at its deadline.
	// done closes when the writer goroutine has returned.
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	backoff time.Duration
}

// pendingOutcome is an outcome on its way to the journal, or, when org is
// set, the mark that the change of request id of org has reported all it will:
// its claim is released when the writer reaches the mark, after every outcome
// queued before it.
type pendingOutcome struct {
	rec     audit.Record
	org, id string
}

// journalWriteAttempts is how many failures pass before the retry is logged;
// journalRetryCap bounds the pause between retries.
const (
	journalWriteAttempts = 3
	journalRetryCap      = 5 * time.Second
)

// newKeyLevelAuditor returns the event sink handed to builtin.NewLocal. The
// sealer calls it while it holds the organization's level lock, and a journal
// append takes a second pool connection and the journal's own lock: writing
// inline could starve the pool behind the lock. So the sink only enqueues and
// one writer goroutine appends, after the sealer has moved on. The queue does
// not drop: an outcome that is accepted stays until it is written or its
// retries are spent, so a completed change is not left with a bare request.
func newKeyLevelAuditor(j audit.Journaler, log *slog.Logger, claims *keyLevelClaims) *keyLevelAuditor {
	a := &keyLevelAuditor{j: j, log: log, claims: claims, wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{}), backoff: 200 * time.Millisecond}
	a.ctx, a.cancel = context.WithCancel(context.Background())
	go a.drain()
	return a
}

// Drain is the stop-time flush of the outcome queue, called after the
// listeners were shut down. A handler that outlived the shutdown may still
// report: such an outcome is refused and logged as audit_stopped. It
// returns when every accepted outcome is journaled, or at ctx's deadline,
// when it stops the retries and reports only how many outcomes were left.
// The queue lives in memory, so what is left at the deadline is lost; the
// change itself and its level row are already durable, and the request
// record is in the journal. Safe to call twice.
func (a *keyLevelAuditor) Drain(ctx context.Context) error {
	a.mu.Lock()
	if !a.closed {
		a.closed = true
		close(a.stop)
	}
	a.mu.Unlock()
	select {
	case <-a.done:
		return nil
	case <-ctx.Done():
	}
	a.cancel()
	<-a.done
	a.mu.Lock()
	left := 0
	for _, p := range a.pend {
		if p.org == "" {
			left++
		}
	}
	a.mu.Unlock()
	if left == 0 {
		return nil
	}
	a.log.Error("key level outcomes not journaled at stop", "error_class", "audit_undelivered", "count", left)
	return fmt.Errorf("key level outcomes not journaled at stop: %d left", left)
}

// claim holds the claim of request id of org until settle has been called
// and every outcome queued before it is journaled.
func (a *keyLevelAuditor) claim(ctx context.Context, org, id string) error {
	if a == nil || a.claims == nil {
		return errKeyLevelClaim
	}
	return a.claims.take(ctx, org, id)
}

// settle marks that the change of request id of org has reported all it will.
// The sealer reports an outcome before the change returns, so the mark queues
// behind it. After Drain began the mark still queues: an outcome queued before
// the stop may still be on its way, and the stop-time flush reaches the mark
// after it. A mark the flush never reaches keeps its claim until the claims
// are closed as the process ends.
func (a *keyLevelAuditor) settle(org, id string) {
	a.mu.Lock()
	a.pend = append(a.pend, pendingOutcome{org: org, id: id})
	a.mu.Unlock()
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

func (a *keyLevelAuditor) record(e builtin.KeyEvent) {
	r, ok := eventRecord(e)
	if !ok {
		a.log.Error("audit event not journaled", "error_class", "audit_unmapped", "action_name", e.Action)
		return
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		a.log.Error("audit event after stop not journaled", "error_class", "audit_stopped", "action_name", string(r.Action))
		return
	}
	a.pend = append(a.pend, pendingOutcome{rec: r})
	a.mu.Unlock()
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

func (a *keyLevelAuditor) next() (pendingOutcome, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.pend) == 0 {
		return pendingOutcome{}, false
	}
	r := a.pend[0]
	a.pend = a.pend[1:]
	return r, true
}

func (a *keyLevelAuditor) drain() {
	defer close(a.done)
	for {
		select {
		case <-a.wake:
			a.flush()
		case <-a.stop:
			a.flush()
			return
		}
	}
}

// flush writes the queue empty, or stops when the retries were cancelled. A
// claim is released only when its mark is reached, after the outcomes before it.
func (a *keyLevelAuditor) flush() {
	for {
		p, ok := a.next()
		if !ok {
			return
		}
		if p.org != "" {
			a.claims.release(p.org, p.id)
			continue
		}
		if !a.write(p.rec) {
			a.mu.Lock()
			a.pend = append([]pendingOutcome{p}, a.pend...)
			a.mu.Unlock()
			return
		}
	}
}

// write retries one outcome until the journal takes it, backing off between
// attempts. The record stays at the head of the queue meanwhile: a completed
// change is never left with a bare request because the journal was briefly
// down. Only the failure class is logged, once per outage of this record.
// It reports false when Drain cancelled the retries before the record was taken.
func (a *keyLevelAuditor) write(r audit.Record) bool {
	for i := 1; ; i++ {
		// A claim lost with its session is taken again before the outcome
		// lands, so it is not free while the outcome is still on its way.
		a.claims.ensure()
		ctx, cancel := context.WithTimeout(a.ctx, journalWriteTimeout)
		written, err := a.append(ctx, r)
		cancel()
		if err == nil {
			if !written {
				a.log.Error("audit event superseded", "error_class", "outcome_superseded", "action_name", string(r.Action))
			}
			return true
		}
		if i == journalWriteAttempts {
			a.log.Error("audit event not journaled yet, retrying", "error_class", "audit_write", "action_name", string(r.Action))
		}
		select {
		case <-time.After(min(time.Duration(i)*a.backoff, journalRetryCap)):
		case <-a.ctx.Done():
			return false
		}
	}
}

// append journals r. The outcome of a request is written under the request's
// claim and only when the request has none yet (keyLevelClaims.appendOutcome);
// it reports false when one was there. A record of no request, such as a KEK
// purge, and a journal that cannot append in a transaction, take a plain Append.
func (a *keyLevelAuditor) append(ctx context.Context, r audit.Record) (bool, error) {
	tj, ok := a.j.(audit.TransactionalJournaler)
	if a.claims == nil || !ok || r.RequestID == "" || !isKeyLevelOutcome(string(r.Action)) {
		_, err := a.j.Append(ctx, r)
		return err == nil, err
	}
	return a.claims.appendOutcome(ctx, tj, r)
}

// eventRecord maps a key event onto the closed journal schema. Only
// names, levels and counts travel; the sealer holds nothing else to give.
func eventRecord(e builtin.KeyEvent) (audit.Record, bool) {
	r := audit.Record{
		RequestID: e.RequestID,
		OrgID:     e.Org,
		Scope:     keyLevelScope,
		Actor:     audit.Actor{Type: audit.ActorUser, ID: e.Actor, Via: audit.ViaAPI},
		Secret:    audit.SecretRef{ID: e.SecretID, Version: e.Version},
		Result:    audit.Result{Status: audit.StatusOK},
	}
	detail := ""
	switch e.Action {
	case "key_level_changed":
		r.Action = audit.ActionOrgKeyLevelChanged
		detail = fmt.Sprintf("from=%s to=%s rewrapped=%d unchanged=%d retired=%d", e.From, e.To, e.Rewrapped, e.Unchanged, e.Retired)
	case "key_level_change_denied":
		r.Action = audit.ActionOrgKeyLevelChangeDenied
		r.Result = audit.Result{Status: audit.StatusFailed, ErrorClass: audit.ErrClassPolicyDenied}
		detail = fmt.Sprintf("from=%s to=%s reason=%s", e.From, e.To, e.Reason)
	case "key_level_change_failed":
		r.Action = audit.ActionOrgKeyLevelChangeFailed
		r.Result = audit.Result{Status: audit.StatusFailed, ErrorClass: audit.ErrClassInternal}
		detail = fmt.Sprintf("from=%s to=%s rewrapped=%d unchanged=%d reason=%s", e.From, e.To, e.Rewrapped, e.Unchanged, e.Reason)
	case "kek_purged":
		r.Action = audit.ActionKEKPurge
		detail = fmt.Sprintf("purged=%d", e.Purged)
	case "kek_purge_failed":
		r.Action = audit.ActionKEKPurge
		r.Result = audit.Result{Status: audit.StatusFailed, ErrorClass: audit.ErrClassInternal}
		detail = "reason=" + e.Reason
	default:
		return audit.Record{}, false
	}
	r.Intent.Reason = audit.NewReason(detail)
	return r, true
}

// keyLevelService is the server side of the key-level page: the read side from
// the persisted level row, and the change through builtin.Admin. It holds no
// key material.
type keyLevelService struct {
	pool  *pgxpool.Pool
	local *builtin.Local
	j     audit.Journaler
	log   *slog.Logger
	// outcomes is the sink local reports to: it holds a change's claim until
	// the change's outcome is journaled.
	outcomes *keyLevelAuditor
}

func (k keyLevelService) Get(ctx context.Context, org uuid.UUID) (api.KeyLevelState, error) {
	var st api.KeyLevelState
	err := k.pool.QueryRow(ctx, `SELECT level, updated_by, updated_at FROM keep_org_key_level WHERE org_id = $1`, org.String()).Scan(&st.Level, &st.ChangedBy, &st.ChangedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return api.KeyLevelState{Level: defaultKeyLevel}, nil
	}
	if err != nil {
		return api.KeyLevelState{}, fmt.Errorf("read key level: database error")
	}
	return st, nil
}

// Change moves org to level to. The request is journaled by a hook the sealer
// calls under the org's level lock, before it reads or writes anything, and
// the change does not start unless that write succeeded: an administrative
// operation nobody can later account for is refused. Journaling under the lock
// means a request exists only while its change can run, so a reconcile pass
// never closes the request of a process that merely stalled before the lock.
// The organization comes from the caller's session, never from the request body.
func (k keyLevelService) Change(ctx context.Context, org, actor uuid.UUID, to string, confirmWeakening bool) (api.KeyLevelChange, error) {
	to, ok := builtin.CanonicalKeyLevel(to)
	if !ok {
		return api.KeyLevelChange{}, api.ErrKeyLevelInvalid
	}
	// The outcome is paired with this request by its id, so the id is issued here:
	// a client repeats its X-Request-Id on a retry, and two requests sharing one
	// id would close each other. The client's id is never journaled: it is
	// caller-chosen text, and the journal takes only what the server issued.
	id := reqid.New()
	ctx = reqid.WithContext(ctx, id)
	// The claim is taken before the request exists and outlives the handler
	// until the outcome is journaled: a reconcile in any instance sees the
	// change as running until then (keyLevelClaims).
	if err := k.outcomes.claim(ctx, org.String(), id); err != nil {
		k.log.Error("key level change refused", "error_class", "claim", "org_id", org.String())
		return api.KeyLevelChange{}, errors.New("key level change refused: request claim unavailable")
	}
	defer k.outcomes.settle(org.String(), id)
	request := func(ctx context.Context) error {
		_, err := appendOnLockConn(ctx, k.j, audit.Record{
			RequestID: id,
			OrgID:     org.String(),
			Scope:     keyLevelScope,
			Actor:     audit.Actor{Type: audit.ActorUser, ID: actor.String(), Via: audit.ViaAPI},
			Intent:    audit.Intent{Reason: audit.NewReason(fmt.Sprintf("to=%s confirm_weakening=%t", to, confirmWeakening))},
			Action:    audit.ActionOrgKeyLevelRequested,
			Result:    audit.Result{Status: audit.StatusPending},
		})
		if err != nil {
			k.log.Error("key level change refused", "error_class", "audit_write", "org_id", org.String())
		}
		return err
	}
	res, err := builtin.NewAdmin(k.pool, k.local.Sealer(), org.String(), k.log).ChangeLevelByName(ctx, to, actor.String(), confirmWeakening, request)
	switch {
	case errors.Is(err, builtin.ErrLevelRequest):
		return api.KeyLevelChange{}, errors.New("key level change refused: audit journal unavailable")
	case errors.Is(err, builtin.ErrLevelWeakening):
		return api.KeyLevelChange{}, api.ErrKeyLevelWeakening
	case errors.Is(err, builtin.ErrLevelInvalid):
		return api.KeyLevelChange{}, api.ErrKeyLevelInvalid
	case err != nil:
		return api.KeyLevelChange{}, errors.New("key level change failed")
	}
	return api.KeyLevelChange{Level: res.Level, Rewrapped: res.Rewrapped, Unchanged: res.Unchanged, Retired: res.Retired}, nil
}

// appendOnLockConn journals r in a transaction on the connection the level
// lock is held on, when ctx carries it and j can append in a caller
// transaction. A second pool connection taken while the lock is held can
// starve: writers queued behind the lock hold the rest of the pool, and the
// hook would wait for one until its deadline. Otherwise it appends as usual.
func appendOnLockConn(ctx context.Context, j audit.Journaler, r audit.Record) (audit.Record, error) {
	c, ok := builtin.LockConn(ctx)
	tj, tok := j.(audit.TransactionalJournaler)
	if !ok || !tok {
		return j.Append(ctx, r)
	}
	// Driver errors can echo statement text: return fixed ones.
	tx, err := c.Begin(ctx)
	if err != nil {
		return audit.Record{}, errors.New("begin request transaction on the lock connection")
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful Commit
	out, err := tj.AppendTx(ctx, tx, r)
	if err != nil {
		return audit.Record{}, err // the caller drops its text, see Change
	}
	if err := tx.Commit(ctx); err != nil {
		return audit.Record{}, errors.New("commit request transaction on the lock connection")
	}
	tj.LogCommitted(ctx, out)
	return out, nil
}
