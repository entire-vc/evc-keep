package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrUnauthenticated is the one error [Repo.Authenticate] ever returns to
// its caller for a caller-facing failure — this package's own acceptance requirement: every
// authentication failure looks identical to the client. The sentinel
// errors below (ErrTokenMalformed, ErrTokenUnknown, ErrTokenExpired,
// ErrTokenRevoked) all wrap this one, so errors.Is(err, ErrUnauthenticated)
// is the only check most callers need; they exist so a future local-only
// log can tell the specific reason apart without that reason ever reaching
// the client or containing the token itself — every sentinel below is a
// fixed, static string.
//
// An error [Repo.Authenticate] returns that does NOT wrap ErrUnauthenticated
// (e.g. a database failure) is a different kind of failure entirely — see
// [RequireAuth], which answers it with 503, not 401: a dependency being
// unreachable must never look like "everyone's token is wrong".
var (
	ErrUnauthenticated = errors.New("identity: unauthenticated")
	ErrTokenMalformed  = fmt.Errorf("%w: malformed", ErrUnauthenticated)
	ErrTokenUnknown    = fmt.Errorf("%w: unknown", ErrUnauthenticated)
	ErrTokenExpired    = fmt.Errorf("%w: expired", ErrUnauthenticated)
	ErrTokenRevoked    = fmt.Errorf("%w: revoked", ErrUnauthenticated)
)

// ErrPrincipalNotFound is returned by [Repo.Issue] when the (org, kind, id)
// it was asked to issue a token for doesn't name a real user/agent/service
// in that organization.
var ErrPrincipalNotFound = errors.New("identity: principal not found")

// Repo is Keep's identity storage: tokens, and the sponsor/grant lookups
// [Repo.EffectiveAgentPermissions] needs. It never caches anything — every
// method reads the database fresh, which is what makes "sponsor loses a
// role, the agent loses it on its very next request" true without any
// invalidation logic (this package's own acceptance requirement).
type Repo struct {
	db *pgxpool.Pool
}

// NewRepo wraps an already-open pool (see internal/store.Open) as a Repo.
func NewRepo(db *pgxpool.Pool) *Repo {
	return &Repo{db: db}
}

// IssueParams describes the token [Repo.Issue] should mint.
type IssueParams struct {
	OrgID       uuid.UUID
	Kind        Kind
	PrincipalID uuid.UUID
	Scope       string
	ExpiresAt   *time.Time
}

// IssueResult is [Repo.Issue]'s return value — Keep's own internal
// bookkeeping shape, never serialized directly onto the wire. It is the
// only place anywhere in Keep a token's plaintext exists once Issue
// returns (this package's own acceptance requirement, checked by
// [TestTokenFieldAppearsOnlyOnIssueResponse] against [IssueResponse], the
// type an API handler actually returns). Once this value has left the
// process in the issuance response, it is gone: the database holds only
// its hash, and no other method on Repo — or anywhere else in Keep — ever
// reconstructs or re-returns it.
type IssueResult struct {
	TokenID   uuid.UUID
	Token     Token // ⚠ the only copy that will ever exist outside the caller who generated it.
	Last4     string
	Kind      Kind
	Scope     string
	ExpiresAt *time.Time
	CreatedAt time.Time
}

// String never prints Token — %v and %+v both route through this (Go's
// fmt package uses a Stringer for every %v-family verb) — so a stray
// fmt.Sprintf("%+v", result) in a log line or an error can't turn into a
// leak the way relying on struct-tag discipline alone would.
func (r IssueResult) String() string {
	return fmt.Sprintf("IssueResult{TokenID:%s Token:[REDACTED] Last4:%s Kind:%s Scope:%q ExpiresAt:%v CreatedAt:%v}",
		r.TokenID, r.Last4, r.Kind, r.Scope, r.ExpiresAt, r.CreatedAt)
}

// GoString is %#v's own hook (GoStringer takes priority over the default
// Go-syntax struct dump, which would otherwise print every field including
// Token) — same redaction as [IssueResult.String].
func (r IssueResult) GoString() string { return r.String() }

// Format makes every fmt verb redact Token, not just the %v-family
// [IssueResult.String] covers as a Stringer: %d or %t applied to a struct
// falls back to per-field reflection rather than Stringer, and would print
// Token's raw bytes (oddly formatted, but present) if this weren't here.
// Implementing fmt.Formatter takes priority over Stringer for every verb.
func (r IssueResult) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, r.String())
}

// MarshalJSON always fails: IssueResult is never serialized directly onto
// the wire (see this type's own doc) — a handler must call [IssueResult.Response]
// first. A caller that reaches this method anyway (e.g. handing an
// IssueResult straight to json.Marshal or an http.ResponseWriter encoder)
// gets a loud error instead of the token silently reaching a response body.
func (r IssueResult) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("identity: IssueResult must not be marshaled directly, call Response() first")
}

// LogValue redacts Token the same way [IssueResult.String] does. slog
// resolves a LogValuer before handing a value to any handler, so this
// applies even when IssueResult is logged under a key internal/obs's
// allow-list permits (e.g. "token_id") — obs filters keys, not values, so
// without this the allow-list would do nothing to stop the leak.
func (r IssueResult) LogValue() slog.Value {
	return slog.StringValue(r.String())
}

// IssueResponse is the ONLY shape anywhere in Keep that carries a token's
// plaintext onto the wire (this package's own acceptance requirement,
// checked by [TestTokenFieldAppearsOnlyOnIssueResponse]): a distinct type
// from [IssueResult] with its own closed json tags, so an API handler
// writing it can never accidentally reach for the wrong field name or
// pick up a field this package didn't mean to expose. See [IssueResult.Response].
//
// It reaches the wire only through [IssueResponse.WireJSON]. json.Marshal
// refuses it: a generic encoder is also what a log call or an error path
// reaches for when this value sits inside some other value, and the token
// would go with it.
type IssueResponse struct {
	TokenID   uuid.UUID  `json:"token_id"`
	Token     Token      `json:"token"`
	Last4     string     `json:"last4"`
	Kind      Kind       `json:"kind"`
	Scope     string     `json:"scope"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// issueWire is IssueResponse as it is written to the client, with the
// token as text. It exists only inside [IssueResponse.WireJSON].
type issueWire struct {
	TokenID   uuid.UUID  `json:"token_id"`
	Token     string     `json:"token"`
	Last4     string     `json:"last4"`
	Kind      Kind       `json:"kind"`
	Scope     string     `json:"scope"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// WireJSON is the one place a token is written out: the body of the
// issuance response, shown to its holder exactly once. An API handler
// writes these bytes; it never passes an IssueResponse to json.Marshal or
// an encoder.
func (r IssueResponse) WireJSON() ([]byte, error) {
	return json.Marshal(issueWire{
		TokenID:   r.TokenID,
		Token:     Reveal(r.Token),
		Last4:     r.Last4,
		Kind:      r.Kind,
		Scope:     r.Scope,
		ExpiresAt: r.ExpiresAt,
		CreatedAt: r.CreatedAt,
	})
}

// MarshalJSON always fails, like [IssueResult.MarshalJSON]: use
// [IssueResponse.WireJSON] for the issuance response.
func (r IssueResponse) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("identity: IssueResponse must not be marshaled directly, call WireJSON() for the issuance response")
}

// issueResponseRedacted renders r with Token replaced, shared by
// [IssueResponse.String], [IssueResponse.GoString] and [IssueResponse.LogValue]
// — the text-shaped paths a token must never reach. json.Marshal is not one
// of them: [IssueResponse.MarshalJSON] refuses outright, and the wire form
// is [IssueResponse.WireJSON].
func (r IssueResponse) issueResponseRedacted() string {
	return fmt.Sprintf("IssueResponse{TokenID:%s Token:[REDACTED] Last4:%s Kind:%s Scope:%q ExpiresAt:%v CreatedAt:%v}",
		r.TokenID, r.Last4, r.Kind, r.Scope, r.ExpiresAt, r.CreatedAt)
}

func (r IssueResponse) String() string   { return r.issueResponseRedacted() }
func (r IssueResponse) GoString() string { return r.issueResponseRedacted() }

// Format redacts Token for every fmt verb, including %d/%t — see
// [IssueResult.Format]'s doc for why those need their own hook rather than
// relying on Stringer.
func (r IssueResponse) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, r.issueResponseRedacted())
}

// LogValue redacts Token so a call site that logs an IssueResponse via
// slog — the one type that legitimately carries a token onto the wire —
// never turns a log line into a second copy of it. See
// [IssueResult.LogValue]'s doc for why this can't rely on internal/obs's
// key allow-list alone.
func (r IssueResponse) LogValue() slog.Value {
	return slog.StringValue(r.issueResponseRedacted())
}

// Response converts r into the shape an API handler returns — the one and
// only place [IssueResult]'s Token field is meant to be read back out. The
// two types' fields match exactly (order and type), so this is a plain
// conversion, not a field-by-field copy that could quietly drift out of
// sync with either type.
func (r IssueResult) Response() IssueResponse {
	return IssueResponse(r)
}

// Issue mints a new token for the principal named in p, stores its hash,
// and returns the plaintext exactly once.
func (r *Repo) Issue(ctx context.Context, p IssueParams) (IssueResult, error) {
	if !p.Kind.Valid() {
		return IssueResult{}, fmt.Errorf("identity: invalid kind %q", p.Kind)
	}
	if err := r.principalExists(ctx, p.Kind, p.OrgID, p.PrincipalID); err != nil {
		return IssueResult{}, err
	}

	token, err := GenerateToken(p.Kind)
	if err != nil {
		return IssueResult{}, err
	}
	id, err := newID()
	if err != nil {
		return IssueResult{}, fmt.Errorf("identity: issue token: %w", err)
	}
	hash := HashToken(token)
	last4 := Last4(token)
	now := time.Now().UTC()

	_, err = r.db.Exec(ctx, `
		INSERT INTO tokens (id, org_id, kind, principal_id, token_hash, last4, scope, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		id, p.OrgID, string(p.Kind), p.PrincipalID, hash, last4, p.Scope, p.ExpiresAt, now)
	if err != nil {
		return IssueResult{}, fmt.Errorf("identity: issue token: %w", err)
	}

	return IssueResult{
		TokenID:   id,
		Token:     token,
		Last4:     last4,
		Kind:      p.Kind,
		Scope:     p.Scope,
		ExpiresAt: p.ExpiresAt,
		CreatedAt: now,
	}, nil
}

// principalExists checks that id names a real row of the right kind in
// org. [Repo.Issue] uses it to refuse minting a token for a principal that
// doesn't exist or belongs to a different organization; [Repo.Authenticate]
// uses it to refuse a token whose principal has since been deleted — a
// still-valid, unexpired, unrevoked token row must not keep authenticating
// once the user/agent/service it names is gone.
func (r *Repo) principalExists(ctx context.Context, kind Kind, org, id uuid.UUID) error {
	var table string
	switch kind {
	case KindAgent:
		table = "agents"
	case KindService:
		table = "services"
	case KindUser:
		table = "users"
	default:
		return fmt.Errorf("identity: invalid kind %q", kind)
	}
	var exists bool
	q := fmt.Sprintf(`SELECT EXISTS(SELECT 1 FROM %s WHERE id = $1 AND org_id = $2)`, table)
	if err := r.db.QueryRow(ctx, q, id, org).Scan(&exists); err != nil {
		return fmt.Errorf("identity: check principal: %w", err)
	}
	if !exists {
		return ErrPrincipalNotFound
	}
	return nil
}

// AgentSponsor returns the user_id that sponsors agentID in org, or
// [ErrPrincipalNotFound] if no such agent exists there. internal/api's
// token-issuance route uses this to gate who may mint that agent's token in
// the first place: [Repo.Issue] itself mints for whatever principal it is
// asked to, without an opinion on who is allowed to ask — that policy
// decision belongs to the caller, which has the request's own identity to
// weigh it against.
func (r *Repo) AgentSponsor(ctx context.Context, org, agentID uuid.UUID) (uuid.UUID, error) {
	var sponsor uuid.UUID
	err := r.db.QueryRow(ctx, `SELECT sponsor_user_id FROM agents WHERE id = $1 AND org_id = $2`, agentID, org).Scan(&sponsor)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, ErrPrincipalNotFound
		}
		return uuid.Nil, fmt.Errorf("identity: agent sponsor: %w", err)
	}
	return sponsor, nil
}

// Authenticate resolves token to the Principal it proves, or one of the
// ErrToken* sentinels (all wrapping [ErrUnauthenticated]) if it doesn't:
// malformed, unknown, expired, revoked, or naming a principal that no
// longer exists. See [ErrUnauthenticated]'s doc — a caller talking to a
// client must collapse every case to the same response. An error that does
// NOT wrap ErrUnauthenticated is a database failure, not an authentication
// verdict; see [RequireAuth].
func (r *Repo) Authenticate(ctx context.Context, token Token) (Principal, error) {
	kind, err := ParseKind(token)
	if err != nil {
		return Principal{}, ErrTokenMalformed
	}
	hash := HashToken(token)

	var (
		orgID       uuid.UUID
		principalID uuid.UUID
		storedHash  []byte
		scope       string
		expiresAt   *time.Time
		revokedAt   *time.Time
	)
	row := r.db.QueryRow(ctx, `
		SELECT org_id, principal_id, token_hash, scope, expires_at, revoked_at
		FROM tokens WHERE token_hash = $1 AND kind = $2`,
		hash, string(kind))
	if err := row.Scan(&orgID, &principalID, &storedHash, &scope, &expiresAt, &revokedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Principal{}, ErrTokenUnknown
		}
		return Principal{}, fmt.Errorf("identity: authenticate: %w", err)
	}
	// The database lookup above already narrowed to at most one row by an
	// indexed equality on token_hash. This second, constant-time compare
	// is what this package's own design actually calls for — the decision to compare
	// hashes doesn't get satisfied implicitly by relying on SQL's `=`.
	if !EqualHash(storedHash, hash) {
		return Principal{}, ErrTokenUnknown
	}
	if revokedAt != nil {
		return Principal{}, ErrTokenRevoked
	}
	if expiresAt != nil && expiresAt.Before(time.Now()) {
		return Principal{}, ErrTokenExpired
	}

	return r.livePrincipal(ctx, kind, orgID, principalID, scope)
}

// livePrincipal turns an already-validated token (or session) row into a
// Principal, checking that the principal it names still exists.
func (r *Repo) livePrincipal(ctx context.Context, kind Kind, orgID, principalID uuid.UUID, scope string) (Principal, error) {
	// A token surviving every check above still names a principal that may
	// have been deleted since it was issued — a live token for a gone user,
	// agent, or service must stop authenticating, not keep working forever.
	if err := r.principalExists(ctx, kind, orgID, principalID); err != nil {
		if errors.Is(err, ErrPrincipalNotFound) {
			return Principal{}, ErrTokenUnknown
		}
		return Principal{}, fmt.Errorf("identity: authenticate: %w", err)
	}

	p := Principal{Kind: kind, ID: principalID, OrgID: orgID, Scope: scope}
	if kind == KindAgent {
		var sponsor uuid.UUID
		err := r.db.QueryRow(ctx, `SELECT sponsor_user_id FROM agents WHERE id = $1 AND org_id = $2`, principalID, orgID).Scan(&sponsor)
		if err != nil {
			// principalExists just confirmed this row exists; a failure
			// here is either a race with a concurrent delete or a real
			// backend error, and either way this must not look like a
			// caller-facing 401 authentication verdict.
			if errors.Is(err, pgx.ErrNoRows) {
				return Principal{}, ErrTokenUnknown
			}
			return Principal{}, fmt.Errorf("identity: authenticate: %w", err)
		}
		p.SponsorUserID = &sponsor
	}
	return p, nil
}

// Revoke marks tokenID revoked, but only if it belongs to p's own
// organization — a caller may never revoke a token issued in someone
// else's org (verified by [TestRevokeRejectsTokenFromAnotherOrg] and the
// check-identity-mutations.sh revoke-no-org-filter mutation). It is
// idempotent in the sense that revoking an already-revoked token, a token
// from another org, and a token that never existed all return the same
// ErrTokenUnknown sentinel — a caller cannot distinguish any of those three
// from the error alone, on purpose.
func (r *Repo) Revoke(ctx context.Context, p Principal, tokenID uuid.UUID) error {
	now := time.Now().UTC()
	tag, err := r.db.Exec(ctx, `UPDATE tokens SET revoked_at = $1 WHERE id = $2 AND org_id = $3 AND revoked_at IS NULL`,
		now, tokenID, p.OrgID)
	if err != nil {
		return fmt.Errorf("identity: revoke token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrTokenUnknown
	}
	return nil
}

// UserRole looks up a user's role in exactly one scope of one
// organization — no upward resolution through the scope hierarchy here;
// that walk is internal/tenancy.Resolve's (tenancy model §3). This is the
// exact-scope check §3 step 5 makes against whatever scope Resolve found a
// secret in — see internal/catalog.ResolveAuthorized, this package's own
// [Repo.EffectiveAgentPermissions] (the agent counterpart), and
// [Repo.UserPermissions] (the user counterpart, built directly on this
// method). ok is false when the user has no membership row in that exact
// (org, scope) pair (including: never had one, or it was just deleted, or
// it belongs to a different organization).
func (r *Repo) UserRole(ctx context.Context, org, userID uuid.UUID, scope string) (role Role, ok bool, err error) {
	var s string
	dbErr := r.db.QueryRow(ctx, `SELECT role FROM memberships WHERE user_id = $1 AND org_id = $2 AND scope = $3`,
		userID, org, scope).Scan(&s)
	if dbErr != nil {
		if errors.Is(dbErr, pgx.ErrNoRows) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("identity: user role: %w", dbErr)
	}
	return Role(s), true, nil
}

// AgentExplicitGrants returns the permissions agentID was explicitly
// granted beyond the defaults — see [DefaultAgentGrants]. Scoped to org so
// a grant row can only ever be read back under the organization it was
// written in.
//
// Exported for internal/catalog.ResolveAuthorized: an agent resolving a
// secret in its own sponsor's personal scope (tenancy model §4) has no
// sponsor "role" to intersect with — a user's own scope carries no
// membership row at all (see [Repo.UserRole]'s doc and
// tenancy.CreateMembership) — so that scope's rights are simply the
// agent's own grants (defaults ∪ explicit), unrestricted. See
// [DefaultAgentGrants] for the default half of that union.
func (r *Repo) AgentExplicitGrants(ctx context.Context, org, agentID uuid.UUID) (map[Permission]bool, error) {
	rows, err := r.db.Query(ctx, `SELECT permission FROM agent_grants WHERE agent_id = $1 AND org_id = $2`, agentID, org)
	if err != nil {
		return nil, fmt.Errorf("identity: agent grants: %w", err)
	}
	defer rows.Close()

	out := map[Permission]bool{}
	for rows.Next() {
		var perm string
		if err := rows.Scan(&perm); err != nil {
			return nil, fmt.Errorf("identity: agent grants: %w", err)
		}
		out[Permission(perm)] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("identity: agent grants: %w", err)
	}
	return out, nil
}

// EffectiveAgentPermissions computes what p — an agent's own authenticated
// Principal, as [Repo.Authenticate] produced it — may do in scope right
// now: its sponsor's current role in that scope, intersected with the
// agent's own grants (see [AgentPermissions]). It reads p.SponsorUserID
// rather than taking a sponsor id as its own parameter, so the only route
// that value can take to reach here is through a Principal [Repo.Authenticate]
// itself produced by reading the agents table — a caller can still build a
// Principal literal directly (nothing in the type stops that), but cannot
// make this function see a sponsor other than the one on the Principal it
// passes in. Every call re-reads both inputs from the database; there is no
// cache to invalidate, which is exactly what makes a sponsor's lost role
// take effect immediately.
func (r *Repo) EffectiveAgentPermissions(ctx context.Context, p Principal, scope string) (map[Permission]bool, error) {
	if p.Kind != KindAgent || p.SponsorUserID == nil {
		return nil, fmt.Errorf("identity: effective permissions: principal is not an agent")
	}
	role, ok, err := r.UserRole(ctx, p.OrgID, *p.SponsorUserID, scope)
	if err != nil {
		return nil, err
	}
	if !ok {
		// No membership at all in this scope grants nothing, the same way
		// an unrecognized Role grants nothing in PermissionsForRole.
		return map[Permission]bool{}, nil
	}
	grants, err := r.AgentExplicitGrants(ctx, p.OrgID, p.ID)
	if err != nil {
		return nil, err
	}
	return AgentPermissions(role, grants), nil
}

// UserPermissions computes what userID may do in scope from their own
// membership role there alone — [PermissionsForRole] applied to
// [Repo.UserRole]. It is the plain-user counterpart to
// [Repo.EffectiveAgentPermissions]'s agent computation: internal/catalog's
// rights check (tenancy model §3 step 5, see
// internal/catalog.ResolveAuthorized) is its first caller. No membership
// row in that exact scope grants nothing, the same fail-closed rule
// [Repo.EffectiveAgentPermissions] applies for an unsponsored agent.
func (r *Repo) UserPermissions(ctx context.Context, org, userID uuid.UUID, scope string) (map[Permission]bool, error) {
	role, ok, err := r.UserRole(ctx, org, userID, scope)
	if err != nil {
		return nil, err
	}
	if !ok {
		return map[Permission]bool{}, nil
	}
	return PermissionsForRole(role), nil
}
