package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SessionTTL bounds a console session; the token it was opened with can end it sooner.
const SessionTTL = 8 * time.Hour

// ErrNoSession is the one answer for an unknown, expired or ended session.
var ErrNoSession = fmt.Errorf("%w: no session", ErrUnauthenticated)

// Session is a signed-in console visit: who, and the per-session CSRF token.
type Session struct {
	Principal Principal
	CSRF      string
}

// OpenSession exchanges a valid token for a console session. The returned
// handle is the cookie value; only its SHA-256 is stored, so a database read
// cannot replay it. The CSRF token is random and kept next to the session.
func (r *Repo) OpenSession(ctx context.Context, token Token) (handle string, s Session, err error) {
	p, err := r.Authenticate(ctx, token)
	if err != nil {
		return "", Session{}, err
	}
	raw := make([]byte, tokenBytes)
	csrf := make([]byte, tokenBytes)
	if _, err = rand.Read(raw); err != nil {
		return "", Session{}, fmt.Errorf("identity: open session: %w", err)
	}
	if _, err = rand.Read(csrf); err != nil {
		return "", Session{}, fmt.Errorf("identity: open session: %w", err)
	}
	handle = "ks_" + lower(b32.EncodeToString(raw))
	s = Session{Principal: p, CSRF: lower(b32.EncodeToString(csrf))}
	idHash := sha256.Sum256([]byte(handle))
	now := time.Now().UTC()
	_, err = r.db.Exec(ctx, `INSERT INTO console_sessions(id_hash,org_id,kind,principal_id,token_hash,csrf,created_at,expires_at)
	 VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, idHash[:], p.OrgID, string(p.Kind), p.ID, HashToken(token), s.CSRF, now, now.Add(SessionTTL))
	if err != nil {
		return "", Session{}, fmt.Errorf("identity: open session: database error")
	}
	return handle, s, nil
}

// LookupSession resolves a cookie handle. The session is valid only while its
// own expiry has not passed AND the token it was opened with is still neither
// revoked nor expired AND the principal still exists.
func (r *Repo) LookupSession(ctx context.Context, handle string) (Session, error) {
	if len(handle) < 8 || len(handle) > 128 {
		return Session{}, ErrNoSession
	}
	idHash := sha256.Sum256([]byte(handle))
	var (
		kind                        string
		org, principal              uuid.UUID
		csrf, scope                 string
		sessionExpires              time.Time
		tokenRevoked, tokenExpireAt *time.Time
	)
	err := r.db.QueryRow(ctx, `SELECT t.org_id,t.kind,t.principal_id,s.csrf,s.expires_at,t.scope,t.revoked_at,t.expires_at
	 FROM console_sessions s JOIN tokens t ON t.token_hash=s.token_hash
	 WHERE s.id_hash=$1 AND t.org_id=s.org_id AND t.kind=s.kind AND t.principal_id=s.principal_id`, idHash[:]).
		Scan(&org, &kind, &principal, &csrf, &sessionExpires, &scope, &tokenRevoked, &tokenExpireAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrNoSession
	}
	if err != nil {
		return Session{}, fmt.Errorf("identity: lookup session: database error")
	}
	now := time.Now()
	if !sessionExpires.After(now) || tokenRevoked != nil || (tokenExpireAt != nil && !tokenExpireAt.After(now)) {
		return Session{}, ErrNoSession
	}
	p, err := r.livePrincipal(ctx, Kind(kind), org, principal, scope)
	if err != nil {
		return Session{}, err
	}
	return Session{Principal: p, CSRF: csrf}, nil
}

// CloseSession ends the session named by handle. Unknown handles are not an error.
func (r *Repo) CloseSession(ctx context.Context, handle string) error {
	idHash := sha256.Sum256([]byte(handle))
	if _, err := r.db.Exec(ctx, `DELETE FROM console_sessions WHERE id_hash=$1`, idHash[:]); err != nil {
		return fmt.Errorf("identity: close session: database error")
	}
	return nil
}
