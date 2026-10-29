// Package restart is the queue of lane restart requests. After a service key
// is activated the hook enqueues a request; a poller on the lane's host claims
// it, restarts the lane and acknowledges the result. The queue holds names, a
// key version label and a kfp1 fingerprint: never a key value.
package restart

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"time"

	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// PendingTTL is how long a request may wait for a claim.
	PendingTTL = 15 * time.Minute
	// Lease is how long a claim holds a request before it returns to pending.
	Lease = 5 * time.Minute
	// MaxClaim bounds one claim call.
	MaxClaim = 10
	// tokenBytes is the size of a claim token: 128 bits from crypto/rand.
	tokenBytes = 16
)

// DefaultLanes is the allowlist of lanes a restart may be requested for.
var DefaultLanes = []string{"Hugh", "Test"}

// Result is what the poller reports for a claimed request.
type Result string

const (
	ResultOK             Result = "ok"
	ResultNothingRunning Result = "nothing_running"
	ResultFailed         Result = "failed"
)

// Valid reports whether r is one of the three results.
func (r Result) Valid() bool {
	return r == ResultOK || r == ResultNothingRunning || r == ResultFailed
}

// state maps a result to the stored state.
func (r Result) state() string {
	if r == ResultOK {
		return "done"
	}
	return string(r)
}

var (
	// ErrLane: the lane is not on the allowlist.
	ErrLane = errors.New("restart: lane is not allowed")
	// ErrInvalid: key version or fingerprint has the wrong shape.
	ErrInvalid = errors.New("restart: invalid request")
	// ErrNotFound: the request is unknown, belongs to another organization or is not claimed.
	ErrNotFound = errors.New("restart: request not found")
	// ErrConflict: the request already finished with another result.
	ErrConflict = errors.New("restart: request already finished with another result")
)

// Request is one claimed entry: exactly the fields the poller is told.
type Request struct {
	RequestID   uuid.UUID
	Lane        string
	KeyVersion  string
	Fingerprint string
	// ClaimToken fences this claim: only the holder of the latest one may ack.
	// It is a random label, not a key value.
	ClaimToken string
}

// Repo is the queue over restart_requests.
type Repo struct {
	db    *pgxpool.Pool
	lanes map[string]bool
	now   func() time.Time
}

// NewRepo returns a queue that accepts only the given lanes; none means DefaultLanes.
func NewRepo(db *pgxpool.Pool, lanes ...string) *Repo {
	if len(lanes) == 0 {
		lanes = DefaultLanes
	}
	r := &Repo{db: db, lanes: make(map[string]bool, len(lanes)), now: time.Now}
	for _, l := range lanes {
		r.lanes[l] = true
	}
	return r
}

// Allows reports whether lane is on the allowlist.
func (r *Repo) Allows(lane string) bool { return r.lanes[lane] }

// Enqueue puts a pending request for lane. An unlisted lane is refused here,
// before anything is stored.
func (r *Repo) Enqueue(ctx context.Context, org uuid.UUID, lane, keyVersion, fp string) (uuid.UUID, error) {
	if !r.lanes[lane] {
		return uuid.Nil, ErrLane
	}
	if !fingerprint.Valid(fp) || !validVersion(keyVersion) {
		return uuid.Nil, ErrInvalid
	}
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, err
	}
	_, err = r.db.Exec(ctx, `
		INSERT INTO restart_requests (request_id, org_id, lane, key_version, fingerprint, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, id, org, lane, keyVersion, fp, r.now())
	if err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

// Claim moves up to limit pending requests of org to claimed and returns them,
// oldest first. Before it picks, a lease that ran out returns to pending and a
// pending request older than PendingTTL expires, so a request is handed out
// at most once per lease and never after its TTL.
func (r *Repo) Claim(ctx context.Context, org uuid.UUID, limit int) ([]Request, error) {
	limit = max(1, min(limit, MaxClaim))
	now := r.now()
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		UPDATE restart_requests SET state = 'pending', lease_until = NULL
		WHERE org_id = $1 AND state = 'claimed' AND lease_until <= $2`, org, now); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE restart_requests SET state = 'expired', finished_at = $2
		WHERE org_id = $1 AND state = 'pending' AND created_at <= $3`, org, now, now.Add(-PendingTTL)); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `
		SELECT request_id FROM restart_requests
		WHERE org_id = $1 AND state = 'pending' AND created_at > $3
		ORDER BY created_at, request_id LIMIT $2 FOR UPDATE SKIP LOCKED`, org, limit, now.Add(-PendingTTL))
	if err != nil {
		return nil, err
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]Request, 0, len(ids))
	for _, id := range ids {
		raw := make([]byte, tokenBytes)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		x := Request{RequestID: id, ClaimToken: hex.EncodeToString(raw)}
		// Every claim, a reissue after a lapsed lease included, gets a new token.
		// Only the digest is stored: a reader of the table cannot forge an ack.
		digest := sha256.Sum256(raw)
		err := tx.QueryRow(ctx, `
			UPDATE restart_requests SET state = 'claimed', claimed_at = $2, lease_until = $3, claim_token = $4
			WHERE request_id = $1
			RETURNING lane, key_version, fingerprint`, id, now, now.Add(Lease), digest[:]).Scan(&x.Lane, &x.KeyVersion, &x.Fingerprint)
		clear(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

// Ack records the result of a claimed request whose lease still runs and whose
// claim token is the one the caller was given. A repeat with the same token and
// result is a no-op; another result for a finished request is ErrConflict. An
// unknown request, one of another organization, one that is not claimed
// (pending, expired, or a claim whose lease ran out), and any request whose
// token does not match (a stale holder after a reissue, a missing token) are
// all ErrNotFound, so the answer tells nothing about which of them it was.
func (r *Repo) Ack(ctx context.Context, org, id uuid.UUID, token string, res Result) error {
	if !res.Valid() {
		return ErrInvalid
	}
	given, err := hex.DecodeString(token)
	if err != nil || len(given) != tokenBytes {
		return ErrNotFound
	}
	now := r.now()
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var state string
	var stored []byte
	var lease *time.Time
	err = tx.QueryRow(ctx, `
		SELECT state, claim_token, lease_until FROM restart_requests
		WHERE request_id = $1 AND org_id = $2 FOR UPDATE`, id, org).Scan(&state, &stored, &lease)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	digest := sha256.Sum256(given)
	if len(stored) != len(digest) || subtle.ConstantTimeCompare(stored, digest[:]) != 1 {
		return ErrNotFound
	}
	switch state {
	case "claimed":
		if lease == nil || !lease.After(now) {
			return ErrNotFound
		}
		if _, err := tx.Exec(ctx, `
			UPDATE restart_requests SET state = $2, lease_until = NULL, finished_at = $3
			WHERE request_id = $1`, id, res.state(), now); err != nil {
			return err
		}
		return tx.Commit(ctx)
	case res.state():
		return nil
	case "done", "nothing_running", "failed":
		return ErrConflict
	default: // pending, expired
		return ErrNotFound
	}
}

// Outcome reports whether the key of request id counts as applied: after an
// ack of ok or nothing_running. failed and expired do not, and a request
// still open is neither (applied=false, final=false). It reads the clock as
// Claim does, so a request no poller comes back for still settles.
func (r *Repo) Outcome(ctx context.Context, org, id uuid.UUID) (applied, final bool, err error) {
	var state string
	var created time.Time
	var lease *time.Time
	err = r.db.QueryRow(ctx, `SELECT state, created_at, lease_until FROM restart_requests WHERE request_id = $1 AND org_id = $2`, id, org).Scan(&state, &created, &lease)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false, ErrNotFound
	}
	if err != nil {
		return false, false, err
	}
	switch state {
	case "done", "nothing_running":
		return true, true, nil
	case "failed", "expired":
		return false, true, nil
	case "pending":
		// An unclaimed request past its TTL is expired even if no claim ran.
		return false, !created.After(r.now().Add(-PendingTTL)), nil
	case "claimed":
		// Ack refuses once the lease is over, and the next Claim would return
		// the request to pending and expire it, so a lapsed lease past the TTL
		// can no longer be applied.
		now := r.now()
		lapsed := lease == nil || !lease.After(now)
		return false, lapsed && !created.After(now.Add(-PendingTTL)), nil
	}
	return false, false, nil
}

func validVersion(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}
