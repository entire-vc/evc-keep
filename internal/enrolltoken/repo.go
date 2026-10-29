package enrolltoken

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MaxTTL is the spec's own bound (ADR-001 §3.2, lead's decisions): an
// enrollment token's lifetime never exceeds 15 minutes.
const MaxTTL = 15 * time.Minute

var (
	// ErrTokenRejected is the one error [Repo.Redeem] ever returns for a
	// caller-facing failure — this package's own design decision, mirroring
	// internal/identity.ErrUnauthenticated: a reused, expired, wrong-host,
	// wrong-policy or unknown token all look identical to the runner
	// presenting it, so redemption failure is never an oracle for which of
	// those it was (card's red-run test #1).
	ErrTokenRejected = errors.New("enrolltoken: token rejected")

	ErrInvalidHost       = errors.New("enrolltoken: host is required")
	ErrInvalidPolicyHash = errors.New("enrolltoken: policy_sha256 must be a lowercase hex sha256")
	ErrTTLTooLong        = errors.New("enrolltoken: ttl exceeds the 15 minute maximum")
	ErrOrgNotFound       = errors.New("enrolltoken: organization not found")
	ErrIssuerNotFound    = errors.New("enrolltoken: issuing user not found in this organization")
)

var policySHA256Re = regexp.MustCompile(`^[a-f0-9]{64}$`)

// Repo is enrollment-token storage: a thin layer over the enroll_tokens
// table, with no dependency on internal/builtin/sealer — a token's hash is
// not secret material the way a private key is, so it needs no envelope.
type Repo struct {
	db *pgxpool.Pool
	// redeemTestHook, when set, runs once every validity check in Redeem has
	// passed and right before its mark-used UPDATE. Test-only (never set in
	// production): it lets a test force two Redeem calls to interleave
	// exactly at the race window the UPDATE's "AND used_at IS NULL" guard
	// exists for, rather than relying on real goroutine scheduling to
	// collide there (crypto-review finding: the concurrency test that did
	// rely on scheduling luck only caught a broken guard 1 run in 20).
	redeemTestHook func()
}

// NewRepo wraps an already-open pool (see internal/store.Open) as a Repo.
func NewRepo(db *pgxpool.Pool) *Repo {
	return &Repo{db: db}
}

// IssueParams describes the token [Repo.Issue] should mint.
type IssueParams struct {
	OrgID        uuid.UUID
	Host         string
	PolicySHA256 string
	CreatedBy    uuid.UUID
	// HostAttrs are asserted by the authenticated issuer, never the runner.
	// Nil preserves legacy registration with unknown host attributes.
	HostAttrs *HostAttrs
	// TTL is the token's lifetime; zero means [MaxTTL]. A TTL above MaxTTL
	// is refused rather than silently capped — the caller asked for
	// something this package's own contract does not allow.
	TTL time.Duration
}

// IssueResult is [Repo.Issue]'s return value — Keep's own internal
// bookkeeping shape, never serialized directly onto the wire. It is the only
// place anywhere in Keep a token's plaintext exists once Issue returns; the
// database holds only its hash. Mirrors internal/identity.IssueResult.
type IssueResult struct {
	TokenID      uuid.UUID
	Token        Token // ⚠ the only copy that will ever exist outside the caller who generated it.
	Last4        string
	OrgID        uuid.UUID
	Host         string
	PolicySHA256 string
	ExpiresAt    time.Time
	CreatedAt    time.Time
}

func (r IssueResult) redacted() string {
	return fmt.Sprintf("IssueResult{TokenID:%s Token:[REDACTED] Last4:%s OrgID:%s Host:%q PolicySHA256:%s ExpiresAt:%v CreatedAt:%v}",
		r.TokenID, r.Last4, r.OrgID, r.Host, r.PolicySHA256, r.ExpiresAt, r.CreatedAt)
}

// String never prints Token — %v and %+v both route through this — so a
// stray fmt.Sprintf("%+v", result) in a log line or an error can't turn
// into a leak.
func (r IssueResult) String() string   { return r.redacted() }
func (r IssueResult) GoString() string { return r.redacted() }

// Format makes every fmt verb redact Token, not just the %v-family String
// covers as a Stringer.
func (r IssueResult) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, r.redacted()) }

// MarshalJSON always fails: IssueResult is never serialized directly onto
// the wire — a handler must call [IssueResult.Response] first.
func (r IssueResult) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("enrolltoken: IssueResult must not be marshaled directly, call Response() first")
}

// LogValue redacts Token the same way [IssueResult.String] does, so this
// applies even when IssueResult is logged under a key internal/obs's
// allow-list permits.
func (r IssueResult) LogValue() slog.Value { return slog.StringValue(r.redacted()) }

// IssueResponse is the ONLY shape anywhere in Keep that carries an
// enrollment token's plaintext onto the wire: a distinct type from
// [IssueResult] with its own closed json tags. It reaches the wire only
// through [IssueResponse.WireJSON]; json.Marshal refuses it.
type IssueResponse struct {
	TokenID      uuid.UUID `json:"token_id"`
	Token        Token     `json:"token"`
	Last4        string    `json:"last4"`
	OrgID        uuid.UUID `json:"org_id"`
	Host         string    `json:"host"`
	PolicySHA256 string    `json:"policy_sha256"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
}

type issueWire struct {
	TokenID      uuid.UUID `json:"token_id"`
	Token        string    `json:"token"`
	Last4        string    `json:"last4"`
	OrgID        uuid.UUID `json:"org_id"`
	Host         string    `json:"host"`
	PolicySHA256 string    `json:"policy_sha256"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
}

// WireJSON is the one place a token is written out: the body of the
// issuance response, shown to the admin exactly once.
func (r IssueResponse) WireJSON() ([]byte, error) {
	return json.Marshal(issueWire{
		TokenID:      r.TokenID,
		Token:        r.Token.Reveal(),
		Last4:        r.Last4,
		OrgID:        r.OrgID,
		Host:         r.Host,
		PolicySHA256: r.PolicySHA256,
		ExpiresAt:    r.ExpiresAt,
		CreatedAt:    r.CreatedAt,
	})
}

// MarshalJSON always fails, like [IssueResult.MarshalJSON]: use
// [IssueResponse.WireJSON] for the issuance response.
func (r IssueResponse) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("enrolltoken: IssueResponse must not be marshaled directly, call WireJSON() for the issuance response")
}

func (r IssueResponse) redacted() string {
	return fmt.Sprintf("IssueResponse{TokenID:%s Token:[REDACTED] Last4:%s OrgID:%s Host:%q PolicySHA256:%s ExpiresAt:%v CreatedAt:%v}",
		r.TokenID, r.Last4, r.OrgID, r.Host, r.PolicySHA256, r.ExpiresAt, r.CreatedAt)
}

func (r IssueResponse) String() string             { return r.redacted() }
func (r IssueResponse) GoString() string           { return r.redacted() }
func (r IssueResponse) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, r.redacted()) }
func (r IssueResponse) LogValue() slog.Value       { return slog.StringValue(r.redacted()) }

// Response converts r into the shape an API handler returns.
func (r IssueResult) Response() IssueResponse { return IssueResponse(r) }

// Issue mints a new enrollment token bound to (p.OrgID, p.Host,
// p.PolicySHA256), stores its hash, and returns the plaintext exactly once.
func (r *Repo) Issue(ctx context.Context, p IssueParams) (IssueResult, error) {
	if p.Host == "" {
		return IssueResult{}, ErrInvalidHost
	}
	if !policySHA256Re.MatchString(p.PolicySHA256) {
		return IssueResult{}, ErrInvalidPolicyHash
	}
	var attrsJSON []byte
	if p.HostAttrs != nil {
		if err := p.HostAttrs.Validate(); err != nil {
			return IssueResult{}, err
		}
		var err error
		attrsJSON, err = json.Marshal(p.HostAttrs)
		if err != nil {
			return IssueResult{}, ErrInvalidHostAttrs
		}
	}
	ttl := p.TTL
	switch {
	case ttl <= 0:
		ttl = MaxTTL
	case ttl > MaxTTL:
		return IssueResult{}, ErrTTLTooLong
	}

	token, err := GenerateToken()
	if err != nil {
		return IssueResult{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return IssueResult{}, fmt.Errorf("enrolltoken: issue: %w", err)
	}
	hash := HashToken(token)
	last4 := Last4(token)
	now := time.Now().UTC()
	expiresAt := now.Add(ttl)

	_, err = r.db.Exec(ctx, `
		INSERT INTO enroll_tokens (id, org_id, token_hash, last4, host, policy_sha256, expires_at, created_at, created_by, host_attrs)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		id, p.OrgID, hash, last4, p.Host, p.PolicySHA256, expiresAt, now, p.CreatedBy, attrsJSON)
	if err != nil {
		if name, ok := fkViolationConstraint(err); ok {
			if strings.Contains(name, "created_by") {
				return IssueResult{}, ErrIssuerNotFound
			}
			return IssueResult{}, ErrOrgNotFound
		}
		return IssueResult{}, fmt.Errorf("enrolltoken: issue: %w", err)
	}

	return IssueResult{
		TokenID:      id,
		Token:        token,
		Last4:        last4,
		OrgID:        p.OrgID,
		Host:         p.Host,
		PolicySHA256: p.PolicySHA256,
		ExpiresAt:    expiresAt,
		CreatedAt:    now,
	}, nil
}

// RedeemParams is what a runner presents alongside the token text: the host
// and policy hash it was issued for. Both are checked against the stored
// values (the spec's red-run requirement's third case: wrong host).
type RedeemParams struct {
	Host         string
	PolicySHA256 string
}

// Redeemed is what a successful [Repo.Redeem] proves: which organization the
// token belonged to. Nothing else — the caller (internal/mtls, Phase
// 3) is the one that goes on to issue a certificate.
type Redeemed struct {
	OrgID     uuid.UUID
	HostAttrs *HostAttrs

	// id and usedAt are unexported: they exist only so [Repo.Release] can
	// hand the token back if a step after Redeem fails for reasons that
	// have nothing to do with the token itself (see Release's own doc).
	id     uuid.UUID
	usedAt time.Time
}

// Redeem consumes token exactly once: unknown, already-used, expired,
// wrong-host and wrong-policy tokens are all refused with the same
// [ErrTokenRejected] (see that error's doc). The mark-used UPDATE is guarded
// by `WHERE used_at IS NULL`, closing the race between two concurrent
// redemption attempts of the same token — the same idiom
// internal/identity.Repo.Revoke uses for its own single-use guarantee.
func (r *Repo) Redeem(ctx context.Context, token Token, p RedeemParams) (Redeemed, error) {
	hash := HashToken(token)

	var (
		id         uuid.UUID
		orgID      uuid.UUID
		storedHash []byte
		host       string
		policy     string
		expiresAt  time.Time
		usedAt     *time.Time
		attrsJSON  []byte
	)
	row := r.db.QueryRow(ctx, `
		SELECT id, org_id, token_hash, host, policy_sha256, expires_at, used_at, host_attrs
		FROM enroll_tokens WHERE token_hash = $1`, hash)
	if err := row.Scan(&id, &orgID, &storedHash, &host, &policy, &expiresAt, &usedAt, &attrsJSON); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Redeemed{}, ErrTokenRejected
		}
		return Redeemed{}, fmt.Errorf("enrolltoken: redeem: %w", err)
	}
	// The database lookup above already narrowed to at most one row by an
	// indexed equality on token_hash. This second, constant-time compare is
	// this package's own design decision, mirroring
	// internal/identity.Repo.Authenticate: the check that decides "is this
	// the right token" does not rest on SQL's `=` alone.
	if !EqualHash(storedHash, hash) {
		return Redeemed{}, ErrTokenRejected
	}
	if usedAt != nil {
		return Redeemed{OrgID: orgID}, ErrTokenRejected
	}
	if !expiresAt.After(time.Now()) {
		return Redeemed{OrgID: orgID}, ErrTokenRejected
	}
	if host != p.Host {
		return Redeemed{OrgID: orgID}, ErrTokenRejected
	}
	if policy != p.PolicySHA256 {
		return Redeemed{OrgID: orgID}, ErrTokenRejected
	}
	var attrs *HostAttrs
	if attrsJSON != nil {
		attrs = new(HostAttrs)
		if err := json.Unmarshal(attrsJSON, attrs); err != nil || attrs.Validate() != nil {
			return Redeemed{}, errors.New("enrolltoken: stored host attributes invalid")
		}
	}

	if r.redeemTestHook != nil {
		r.redeemTestHook()
	}

	redeemedAt := time.Now().UTC()
	tag, err := r.db.Exec(ctx, `UPDATE enroll_tokens SET used_at = $1 WHERE id = $2 AND used_at IS NULL`,
		redeemedAt, id)
	if err != nil {
		return Redeemed{}, fmt.Errorf("enrolltoken: redeem: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// A concurrent Redeem of the same token won the race between the
		// SELECT above and this UPDATE.
		return Redeemed{OrgID: orgID}, ErrTokenRejected
	}
	return Redeemed{OrgID: orgID, HostAttrs: attrs, id: id, usedAt: redeemedAt}, nil
}

// Release hands a redeemed token back so it can be presented again. It
// exists solely for the enroll handler's own recovery path: cert issuance
// and runner-row creation both happen after Redeem necessarily has, because
// only Redeem reveals which org's CA to sign with (see handleEnrollRunner's
// doc) — so an infrastructure failure in either of those later steps would
// otherwise burn the operator's one-time token for a reason that had
// nothing to do with the token itself.
//
// Release is best-effort and silent: it only clears used_at if the row
// still holds exactly the value this Redeem call set (nothing else writes
// used_at today, but the guard costs nothing and means a Release racing
// some future second writer can never resurrect a token from under it). A
// failed Release leaves the token spent, which is always the safe
// direction — the operator asks for a new one rather than a stale token
// coming back to life unexpectedly.
func (r *Repo) Release(ctx context.Context, redeemed Redeemed) {
	_, _ = r.db.Exec(ctx, `UPDATE enroll_tokens SET used_at = NULL WHERE id = $1 AND used_at = $2`,
		redeemed.id, redeemed.usedAt)
}

// pgForeignKeyViolation is the SQLSTATE Postgres raises for a foreign key
// violation.
const pgForeignKeyViolation = "23503"

func fkViolationConstraint(err error) (name string, ok bool) {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgForeignKeyViolation {
		return pgErr.ConstraintName, true
	}
	return "", false
}
