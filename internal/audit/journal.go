package audit

import (
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/oklog/ulid/v2"
)

// Journaler is the interface issuance code depends on — never *Journal
// directly. A future guard (issuing a value without a matching journal
// entry must be an error) substitutes a test double implementing this
// interface to assert that a value is never handed to a runner without a
// matching Append call first; keeping issuance code depending on the
// interface, not the concrete type, is what makes that substitution
// possible without editing the issuance code itself. This is the hook the
// threat model's §4.2 asks this task to provide.
type Journaler interface {
	// Append writes r to the journal and returns the stored record — with
	// ID, TS, and PrevHash filled in by Append itself, see Record's doc —
	// or an error if the write did not happen. A returned error means the
	// record is NOT in the journal: there is no partial-write state a
	// caller needs to handle.
	Append(ctx context.Context, r Record) (Record, error)
}

// Journal is the R-AUD-1 journal, backed by the audit_records and
// audit_chain_heads tables (internal/store/migrations/00005_audit.sql). It
// implements Journaler.
// TransactionalJournaler supports issuance within a caller-owned transaction.
type TransactionalJournaler interface {
	Journaler
	AppendTx(context.Context, pgx.Tx, Record) (Record, error)
	LogCommitted(context.Context, Record)
}

type Journal struct {
	pool *pgxpool.Pool
	log  *slog.Logger // nil: Append logs nothing
	now  func() time.Time
}

// WithLogger returns a Journal that, after each successful Append, writes
// one line carrying exactly the record's id, action and request_id (threat
// model §4.2) and nothing else from the record. l must be an internal/obs
// logger so its allow-list stays the second barrier behind this fixed set
// of attributes.
func (j *Journal) WithLogger(l *slog.Logger) *Journal {
	c := *j
	c.log = l
	return &c
}

// WithClock returns a Journal that stamps records with now: the app clock the
// reconcile of a key-level request measures its age against.
func (j *Journal) WithClock(now func() time.Time) *Journal {
	c := *j
	c.now = now
	return &c
}

// NewJournal wraps an already-open pool. The pool's connections authenticate
// as whatever role KEEP_DATABASE_URL names (internal/config) — Append
// itself narrows to the keep_app role for the duration of each write; see
// Append's doc and internal/store/migrations/00005_audit.sql.
func NewJournal(pool *pgxpool.Pool) *Journal {
	return &Journal{pool: pool, now: time.Now}
}

var _ Journaler = (*Journal)(nil)

// entropySource is a per-process monotonic ULID entropy source: ULIDs
// sharing a millisecond still sort in call order, which keeps ULID-derived
// display order consistent with insertion order even though it is org_seq
// (not the ULID) that actually defines chain order — see doc.go.
// crypto/rand.Reader (never math/rand — see reqid.New's UUIDv7 choice for
// the same reasoning applied to request ids) already implements io.Reader.
//
// *ulid.MonotonicEntropy is stateful and NOT safe for concurrent use on its
// own — caught by -race on this exact line during development (two
// goroutines mutating its internal counter at once) before this comment and
// entropyMu existed. Every read of entropySource goes through entropyMu;
// see newRecordID.
var (
	entropyMu     sync.Mutex
	entropySource = ulid.Monotonic(cryptorand.Reader, 0)
)

// newRecordID generates a fresh ULID under entropyMu — see entropySource's
// doc for why this can't just call ulid.MustNew directly at each call site.
func newRecordID() string {
	entropyMu.Lock()
	defer entropyMu.Unlock()
	return ulid.MustNew(ulid.Timestamp(time.Now()), entropySource).String()
}

// Append implements Journaler. It fills r.ID (a fresh ULID), r.TS (now),
// and r.PrevHash (this organization's current chain head) itself — any
// value a caller set on those three fields is discarded, never trusted;
// see Record's doc for why they are still ordinary fields of Record rather
// than a separate output-only type.
//
// The whole operation — locking the organization's head row, computing the
// new hash, inserting the record, advancing the head — runs inside one
// transaction that immediately does `SET LOCAL ROLE keep_app` after BEGIN,
// so this call genuinely cannot UPDATE or DELETE an existing audit_records
// row even though the pool's own login role may itself be a superuser (as
// it is in CI and local dev, via the official postgres docker image) — see
// internal/store/migrations/00005_audit.sql's comment and
// rights_test.go.
func (j *Journal) Append(ctx context.Context, r Record) (Record, error) {
	if r.OrgID == "" {
		return Record{}, errors.New("audit: Append: OrgID is required")
	}
	tx, err := j.pool.Begin(ctx)
	if err != nil {
		return Record{}, dbErr("begin append transaction", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful Commit

	r, err = j.AppendTx(ctx, tx, r)
	if err != nil {
		return Record{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Record{}, dbErr("commit append", err)
	}
	j.LogCommitted(ctx, r)
	return r, nil
}

// insertRecord writes r as one audit_records row at position seq with the
// given hash. It is the single place Record's fields are flattened into
// columns — verify.go's readChain is its read-side counterpart and must be
// kept in step with it field for field.
func insertRecord(ctx context.Context, tx pgx.Tx, r Record, seq int64, hash string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO audit_records (
			id, org_id, org_seq, ts, request_id, scope,
			actor_type, actor_id, actor_sponsor_id, actor_via,
			intent_task_ref, intent_session_ref, intent_reason,
			action,
			secret_id, secret_name, secret_version,
			target_runner_id, target_host, target_kind, target_path,
			policy_decision, policy_rule_id,
			approval_id, approval_approver_id, approval_decided_at,
			result_status, result_fingerprint, result_length, result_health, result_error_class,
			prev_hash, hash
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10,
			$11, $12, $13,
			$14,
			$15, $16, $17,
			$18, $19, $20, $21,
			$22, $23,
			$24, $25, $26,
			$27, $28, $29, $30, $31,
			$32, $33
		)
	`,
		r.ID, r.OrgID, seq, r.TS, r.RequestID, r.Scope,
		string(r.Actor.Type), r.Actor.ID, r.Actor.SponsorID, string(r.Actor.Via),
		r.Intent.TaskRef, r.Intent.SessionRef, r.Intent.Reason,
		string(r.Action),
		r.Secret.ID, r.Secret.Name, r.Secret.Version,
		r.Target.RunnerID, r.Target.Host, r.Target.Kind, r.Target.Path,
		string(r.Policy.Decision), r.Policy.RuleID,
		r.Approval.ID, r.Approval.ApproverID, nullableTime(r.Approval.DecidedAt),
		string(r.Result.Status), r.Result.Fingerprint, r.Result.Length, string(r.Result.Health), string(r.Result.ErrorClass),
		r.PrevHash, hash,
	)
	if err != nil {
		return dbErr("insert record", err)
	}
	return nil
}

// nullableTime returns nil for a zero time.Time (Postgres NULL) rather than
// storing time.Time's zero value ("0001-01-01") — approval_decided_at means
// "no approval was involved" for most records, and NULL says that directly.
func nullableTime(t time.Time) interface{} {
	if t.IsZero() {
		return nil
	}
	return t
}

// dbErr turns a database error into one that is safe to return and log: a
// *pgconn.PgError carries the offending row in Detail ("Failing row
// contains (...)") and the server's own message, both of which can hold
// whatever a caller put in a free-text field, and pgx connection errors
// echo host and user. Only the SQLSTATE survives — the same rule as
// internal/store's sqlStateOf — plus the context sentinels callers test for.
func dbErr(op string, err error) error {
	var pgErr *pgconn.PgError
	switch {
	case errors.As(err, &pgErr):
		return fmt.Errorf("audit: %s: database error (SQLSTATE %s)", op, pgErr.Code)
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("audit: %s: %w", op, context.Canceled)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("audit: %s: %w", op, context.DeadlineExceeded)
	default:
		return fmt.Errorf("audit: %s: database error (unclassified)", op)
	}
}

// AppendTx appends in the caller transaction; callers must roll back on error.
func (j *Journal) AppendTx(ctx context.Context, tx pgx.Tx, r Record) (Record, error) {
	if tx == nil {
		return Record{}, errors.New("audit: transaction is required")
	}
	if r.OrgID == "" {
		return Record{}, errors.New("audit: OrgID is required")
	}
	if err := r.validate(); err != nil {
		return Record{}, err
	}
	var role string
	if err := tx.QueryRow(ctx, `SELECT current_user`).Scan(&role); err != nil {
		return Record{}, dbErr("read caller role", err)
	}
	var err error
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE keep_app"); err != nil {
		return Record{}, dbErr("set local role", err)
	}

	// Lock (or create, if this organization has never appended before) the
	// head row first — this is what serializes concurrent Append calls
	// within one organization; see doc.go.
	var prevHash string
	var nextSeq int64
	err = tx.QueryRow(ctx, `
		INSERT INTO audit_chain_heads (org_id, position, hash)
		VALUES ($1, 0, $2)
		ON CONFLICT (org_id) DO UPDATE SET org_id = audit_chain_heads.org_id
		RETURNING position, hash
	`, r.OrgID, GenesisHash).Scan(&nextSeq, &prevHash)
	if err != nil {
		return Record{}, dbErr("lock chain head", err)
	}
	// The row above is now locked for the rest of this transaction — an
	// INSERT ... ON CONFLICT DO UPDATE always takes a row lock on the
	// resulting row, including on first insert, so a second Append racing
	// for the same org_id blocks here until this transaction commits or
	// rolls back, rather than reading a stale head.
	nextSeq++

	r.PrevHash = prevHash
	r.ID = newRecordID()
	// Truncated to microsecond precision — Postgres' timestamptz columns
	// only carry microsecond resolution, so the value read back by Verify
	// later would otherwise differ from the value hashed here (Go's
	// time.Time carries nanoseconds) and every chain would fail to verify
	// on its very first record. Same reasoning applies to
	// r.Approval.DecidedAt when a caller sets one.
	r.TS = j.now().UTC().Truncate(time.Microsecond)
	if !r.Approval.DecidedAt.IsZero() {
		r.Approval.DecidedAt = r.Approval.DecidedAt.UTC().Truncate(time.Microsecond)
	}

	hash, err := computeHash(prevHash, r)
	if err != nil {
		return Record{}, fmt.Errorf("audit: compute hash: %w", err)
	}

	if err := insertRecord(ctx, tx, r, nextSeq, hash); err != nil {
		return Record{}, err
	}

	if _, err := tx.Exec(ctx, `
		UPDATE audit_chain_heads SET position = $2, hash = $3 WHERE org_id = $1
	`, r.OrgID, nextSeq, hash); err != nil {
		return Record{}, dbErr("advance chain head", err)
	}

	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
		return Record{}, dbErr("restore caller role", err)
	}
	return r, nil
}

// LogCommitted logs safe metadata after the caller transaction commits.
func (j *Journal) LogCommitted(ctx context.Context, r Record) {
	if j.log != nil {
		j.log.InfoContext(ctx, "audit record appended",
			slog.String("id", r.ID),
			slog.String("action", string(r.Action)),
			slog.String("request_id", r.RequestID),
		)
	}
}
