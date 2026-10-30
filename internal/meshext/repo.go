// Package meshext holds the metadata of Keep's Mesh extension: which Mesh
// workspace is connected to which organisation, and which Mesh events were
// already accepted. It stores no value; credentials are sealed by the
// built-in vault. Keep's core never imports this package's callers' Mesh
// side: with the extension off, nothing here is wired and the routes 404.
package meshext

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrWorkspaceTaken is returned when a Mesh workspace is already connected to
// another organisation.
var ErrWorkspaceTaken = errors.New("meshext: workspace belongs to another organization")

// EventTypes is the closed set of events the manifest subscribes to.
var EventTypes = map[string]bool{
	"workspace.member.added":   true,
	"workspace.member.removed": true,
	"project.created":          true,
	"project.updated":          true,
	"agent.key.issued":         true,
	"agent.key.revoked":        true,
	"task.gate.decided":        true,
}

var eventIDRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// ValidEventID reports whether id fits the stored event id shape.
func ValidEventID(id string) bool { return eventIDRe.MatchString(id) }

// ValidMeshURL accepts an absolute https URL, or http for a loopback host
// (local development), with no credentials, query or fragment. Keep calls this
// URL on every hierarchy reconciliation, so the fetch itself refuses
// non-public addresses for https (see builtin.MeshVault.FetchHierarchy); the
// key fetch of a sign-in goes through a client that refuses private, loopback
// and link-local addresses (see NewVerifier). The loopback http form is the
// only way to reach a local host.
func ValidMeshURL(s string) bool {
	if len(s) > 512 {
		return false
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		h := u.Hostname()
		return h == "localhost" || h == "127.0.0.1" || h == "::1" || strings.HasSuffix(h, ".localhost")
	}
	return false
}

// Repo is the extension's PostgreSQL store.
type Repo struct {
	pool *pgxpool.Pool
	// lockSlots bounds the connections held as workspace locks to one fewer
	// than the pool has, so a holder always finds a free connection for the
	// queries it runs while locked. Without it, as many waiting installs as
	// pool connections would each hold one and wait for a second.
	lockSlots chan struct{}
}

// lockWait is how long an install may wait for a workspace lock before it
// gives up with an error instead of holding a connection indefinitely.
const lockWait = 30 * time.Second

// NewRepo returns a Repo over pool.
func NewRepo(pool *pgxpool.Pool) *Repo {
	n := 1
	if pool != nil {
		if m := int(pool.Config().MaxConns) - 1; m > n {
			n = m
		}
	}
	return &Repo{pool: pool, lockSlots: make(chan struct{}, n)}
}

// LockWorkspace serializes install attempts for one workspace across every
// server instance: it takes a PostgreSQL advisory lock on a dedicated
// connection and returns the function that releases it. If the process dies
// the connection closes and the database drops the lock.
func (r *Repo) LockWorkspace(ctx context.Context, workspace uuid.UUID) (unlock func(), err error) {
	_, unlock, err = r.lock(ctx, workspaceLock, workspace)
	return unlock, err
}

// workspaceLock names the one advisory lock of a workspace. Install,
// handshake and token delivery all write the same credential slots, and a
// reinstall rolls them back on failure, so they take this one lock: under a
// second name a delivery could seal between a reinstall's write and its
// rollback, and the rollback would put the older token back.
const workspaceLock = "mesh-install:"

// lock takes the session advisory lock named by prefix and workspace on a
// connection it holds until unlock, inside one of lockSlots: every holder,
// install or token delivery, counts against the same bound. The connection
// is returned so the holder can run its own statements on it.
func (r *Repo) lock(ctx context.Context, prefix string, workspace uuid.UUID) (*pgxpool.Conn, func(), error) {
	wctx, cancel := context.WithTimeout(ctx, lockWait)
	defer cancel()
	select {
	case r.lockSlots <- struct{}{}:
	case <-wctx.Done():
		return nil, nil, fmt.Errorf("meshext: wait for lock slot: %w", wctx.Err())
	}
	conn, err := r.pool.Acquire(wctx)
	if err != nil {
		<-r.lockSlots
		return nil, nil, fmt.Errorf("meshext: acquire lock connection: %w", err)
	}
	if _, err := conn.Exec(wctx, `SELECT pg_advisory_lock(hashtextextended($1 || $2::text, 0))`, prefix, workspace.String()); err != nil {
		// A cancelled lock wait may leave the lock request pending on the
		// server; closing the connection drops it.
		_ = conn.Conn().Close(context.Background())
		conn.Release()
		<-r.lockSlots
		return nil, nil, fmt.Errorf("meshext: lock workspace: %w", err)
	}
	return conn, func() {
		defer func() { <-r.lockSlots }()
		// A fresh context: the request's may already be cancelled. If the
		// unlock fails the connection is destroyed, which drops the lock.
		uctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := conn.Exec(uctx, `SELECT pg_advisory_unlock(hashtextextended($1 || $2::text, 0))`, prefix, workspace.String()); err != nil {
			_ = conn.Conn().Close(uctx)
		}
		conn.Release()
	}, nil
}

// Upsert records workspace as connected to org in mode. A reinstall records
// the mode it states. A workspace already held by a different organisation is
// refused.
func (r *Repo) Upsert(ctx context.Context, org, workspace, installedBy uuid.UUID, meshURL string, mode Mode) error {
	if !mode.Valid() {
		return ErrBadMode
	}
	tag, err := r.pool.Exec(ctx, `
INSERT INTO mesh_installations (workspace_id, org_id, mesh_url, installed_by, mode)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (workspace_id) DO UPDATE
   SET mesh_url = EXCLUDED.mesh_url, installed_by = EXCLUDED.installed_by, mode = EXCLUDED.mode, updated_at = now()
 WHERE mesh_installations.org_id = EXCLUDED.org_id`, workspace, org, meshURL, installedBy, string(mode))
	if err != nil {
		return fmt.Errorf("meshext: upsert installation: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrWorkspaceTaken
	}
	return nil
}

// Owner returns the organisation workspace is connected to.
func (r *Repo) Owner(ctx context.Context, workspace uuid.UUID) (uuid.UUID, bool, error) {
	var org uuid.UUID
	err := r.pool.QueryRow(ctx, `SELECT org_id FROM mesh_installations WHERE workspace_id = $1`, workspace).Scan(&org)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("meshext: lookup installation: %w", err)
	}
	return org, true, nil
}

// MeshURLs returns the distinct Mesh addresses of every workspace connected to
// org, as recorded at install. It is the only source of the origins that may
// frame Keep's screens: never a request header.
func (r *Repo) MeshURLs(ctx context.Context, org uuid.UUID) ([]string, error) {
	rows, err := r.pool.Query(ctx, `SELECT DISTINCT mesh_url FROM mesh_installations WHERE org_id = $1 ORDER BY mesh_url`, org)
	if err != nil {
		return nil, fmt.Errorf("meshext: list installations: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, fmt.Errorf("meshext: list installations: %w", err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("meshext: list installations: %w", err)
	}
	return out, nil
}

// Record stores an accepted event once. inserted is false for a repeat of an
// event id, which must have no further effect.
func (r *Repo) Record(ctx context.Context, workspace uuid.UUID, eventID, eventType string) (inserted bool, err error) {
	tag, err := r.pool.Exec(ctx, `
INSERT INTO mesh_events (workspace_id, event_id, event_type) VALUES ($1, $2, $3)
ON CONFLICT (workspace_id, event_id) DO NOTHING`, workspace, eventID, eventType)
	if err != nil {
		return false, fmt.Errorf("meshext: record event: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// Forget removes a recorded event, so that a delivery that could not be
// applied is retried instead of being taken for a repeat.
func (r *Repo) Forget(ctx context.Context, workspace uuid.UUID, eventID string) error {
	if _, err := r.pool.Exec(ctx, `DELETE FROM mesh_events WHERE workspace_id = $1 AND event_id = $2`, workspace, eventID); err != nil {
		return fmt.Errorf("meshext: forget event: %w", err)
	}
	return nil
}

// nonceRetention is how long a used nonce is kept: well over the ten minutes
// the two-sided timestamp window needs, so pruning never reopens a replay.
const nonceRetention = 15 * time.Minute

// UseNonce records the nonce of an authenticated secrets request. inserted is
// false when the workspace already used it: the request is a replay. Callers
// verify the signature first, so unsigned traffic never fills the table. Old
// rows are pruned on the way; a failed prune is not an error, a failed insert
// is.
func (r *Repo) UseNonce(ctx context.Context, workspace uuid.UUID, nonce string) (inserted bool, err error) {
	_, _ = r.pool.Exec(ctx, `DELETE FROM mesh_secret_nonces WHERE seen_at < now() - make_interval(secs => $1)`, nonceRetention.Seconds())
	tag, err := r.pool.Exec(ctx, `
INSERT INTO mesh_secret_nonces (workspace_id, nonce) VALUES ($1, $2)
ON CONFLICT (workspace_id, nonce) DO NOTHING`, workspace, nonce)
	if err != nil {
		return false, fmt.Errorf("meshext: record nonce: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// ErrWindowTaken is returned when a live install window for a workspace was
// opened by another organisation.
var ErrWindowTaken = errors.New("meshext: install window held by another organization")

// ErrNoWindow means there is no live window left to consume.
var ErrNoWindow = errors.New("meshext: no live install window")

// PendingTTL is how long an install window stays open.
const PendingTTL = 15 * time.Minute

// Pending is an install window an organisation admin opened for a workspace:
// the one Mesh install handshake that presents a signing secret with this
// SHA-256 (64 lowercase hex) may bind the workspace to the organisation.
type Pending struct {
	Org          uuid.UUID
	OpenedBy     uuid.UUID
	MeshURL      string
	SecretSHA256 string
}

// OpenPending opens (or replaces) the install window of workspace and returns
// when it closes. A workspace connected to another organisation is
// ErrWorkspaceTaken; a live window of another organisation is ErrWindowTaken.
func (r *Repo) OpenPending(ctx context.Context, workspace uuid.UUID, p Pending) (time.Time, error) {
	if err := r.DropExpiredPending(ctx); err != nil {
		return time.Time{}, err
	}
	if org, found, err := r.Owner(ctx, workspace); err != nil {
		return time.Time{}, err
	} else if found && org != p.Org {
		return time.Time{}, ErrWorkspaceTaken
	}
	var expires time.Time
	err := r.pool.QueryRow(ctx, `
INSERT INTO mesh_pending_installs (workspace_id, org_id, opened_by, mesh_url, secret_sha256, expires_at)
VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6))
ON CONFLICT (workspace_id) DO UPDATE
   SET org_id = EXCLUDED.org_id, opened_by = EXCLUDED.opened_by, mesh_url = EXCLUDED.mesh_url,
       secret_sha256 = EXCLUDED.secret_sha256, opened_at = now(), expires_at = EXCLUDED.expires_at
 WHERE mesh_pending_installs.org_id = EXCLUDED.org_id OR mesh_pending_installs.expires_at <= now()
RETURNING expires_at`, workspace, p.Org, p.OpenedBy, p.MeshURL, p.SecretSHA256, PendingTTL.Seconds()).Scan(&expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, ErrWindowTaken
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("meshext: open install window: %w", err)
	}
	return expires, nil
}

// DropExpiredPending deletes every install window past its expiry, so no
// digest outlives the window it was given for. Opening a window, looking one
// up and the periodic Mesh sync all call it.
func (r *Repo) DropExpiredPending(ctx context.Context) error {
	if _, err := r.pool.Exec(ctx, `DELETE FROM mesh_pending_installs WHERE expires_at <= now()`); err != nil {
		return fmt.Errorf("meshext: drop expired install windows: %w", err)
	}
	return nil
}

// LivePending returns the open, unexpired install window of workspace. The
// expired ones are deleted first; one that expires right after the lookup is
// refused by BindPending, which checks the expiry again.
func (r *Repo) LivePending(ctx context.Context, workspace uuid.UUID) (Pending, bool, error) {
	if err := r.DropExpiredPending(ctx); err != nil {
		return Pending{}, false, err
	}
	var p Pending
	err := r.pool.QueryRow(ctx, `
SELECT org_id, opened_by, mesh_url, secret_sha256 FROM mesh_pending_installs
 WHERE workspace_id = $1`, workspace).Scan(&p.Org, &p.OpenedBy, &p.MeshURL, &p.SecretSHA256)
	if errors.Is(err, pgx.ErrNoRows) {
		return Pending{}, false, nil
	}
	if err != nil {
		return Pending{}, false, fmt.Errorf("meshext: lookup install window: %w", err)
	}
	return p, true, nil
}

// BindPending consumes the live window p of workspace and records the
// installation it describes, in mode, in one transaction, and runs seal after both
// statements and before the commit: the window is single-use, a window that
// expired or was replaced in the meantime binds nothing and seal never runs,
// and a failing seal rolls the window and the installation back. seal works
// on its own connection, so its write is not undone if the commit fails; its
// error is returned as is.
func (r *Repo) BindPending(ctx context.Context, workspace uuid.UUID, p Pending, mode Mode, seal func(context.Context) error) error {
	if !mode.Valid() {
		return ErrBadMode
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("meshext: bind: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	tag, err := tx.Exec(ctx, `
DELETE FROM mesh_pending_installs
 WHERE workspace_id = $1 AND org_id = $2 AND opened_by = $3 AND secret_sha256 = $4 AND expires_at > now()`,
		workspace, p.Org, p.OpenedBy, p.SecretSHA256)
	if err != nil {
		return fmt.Errorf("meshext: consume install window: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrNoWindow
	}
	tag, err = tx.Exec(ctx, `
INSERT INTO mesh_installations (workspace_id, org_id, mesh_url, installed_by, mode)
VALUES ($1, $2, $3, $4, $5) ON CONFLICT (workspace_id) DO NOTHING`, workspace, p.Org, p.MeshURL, p.OpenedBy, string(mode))
	if err != nil {
		return fmt.Errorf("meshext: insert installation: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrWorkspaceTaken
	}
	if err := seal(ctx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("meshext: bind: %w", err)
	}
	return nil
}

// ErrStaleToken means the workspace is not connected to the organisation, or
// a token delivery signed at the same second or later was already accepted.
var ErrStaleToken = errors.New("meshext: no newer token delivery")

// AcceptToken records a token delivery Mesh signed at signedAt (Unix seconds)
// for workspace of org, then runs seal. A delivery not newer than the last
// accepted one is refused before seal runs, so a replay inside the signature
// window cannot put back an older token. The accepted time is committed
// before seal, which commits on its own: a sealed token never sits behind a
// time that rolled back, and a failed seal spends its time, so Mesh delivers
// again with a newer one. Deliveries for one workspace run one at a time,
// and never inside an install of it, under the workspace lock taken through
// lock, so an older seal cannot land after a newer one, a failed reinstall
// cannot roll a delivered token back, and waiting deliveries cannot exhaust
// the pool.
func (r *Repo) AcceptToken(ctx context.Context, workspace, org uuid.UUID, signedAt int64, seal func(context.Context) error) error {
	conn, unlock, err := r.lock(ctx, workspaceLock, workspace)
	if err != nil {
		return fmt.Errorf("meshext: accept token: %w", err)
	}
	defer unlock()
	// The update runs on the locked connection, so a holder needs only one
	// more connection, for seal, and never waits for the pool twice.
	tag, err := conn.Exec(ctx, `
UPDATE mesh_installations SET token_signed_at = $3, updated_at = now()
 WHERE workspace_id = $1 AND org_id = $2 AND (token_signed_at IS NULL OR token_signed_at < $3)`,
		workspace, org, signedAt)
	if err != nil {
		return fmt.Errorf("meshext: record token delivery: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrStaleToken
	}
	return seal(ctx)
}

// Uninstall removes the installation of workspace held by org; a workspace
// never installed, already removed or held by another organisation is one
// answer, ErrNotInstalled. Under the
// workspace lock, in one transaction, it locks the installation row, runs
// erase (the crypto-erasure of the workspace's sealed versions, in that same
// transaction) and only then deletes the row, which cascades to every table
// keyed by the workspace. Any failure rolls back the erasure with the rest
// and leaves the installation in place, so a repeat starts over. Install,
// token delivery and secret writes of the workspace take the same lock, so
// none of them lands between the erasure and the delete.
func (r *Repo) Uninstall(ctx context.Context, workspace, org uuid.UUID, erase func(context.Context, pgx.Tx) (int, error)) (int, error) {
	conn, unlock, err := r.lock(ctx, workspaceLock, workspace)
	if err != nil {
		return 0, fmt.Errorf("meshext: uninstall: %w", err)
	}
	defer unlock()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("meshext: uninstall: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	var one int
	err = tx.QueryRow(ctx, `SELECT 1 FROM mesh_installations WHERE workspace_id = $1 AND org_id = $2 FOR UPDATE`, workspace, org).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		// An install or handshake that failed after sealing may have left
		// credentials under the workspace with no installation to remove:
		// erase them all the same. erase reaches only this organisation's
		// store, so the answer stays that of a workspace never installed.
		if _, err := erase(ctx, tx); err != nil {
			return 0, err
		}
		if err := tx.Commit(ctx); err != nil {
			return 0, fmt.Errorf("meshext: uninstall: %w", err)
		}
		return 0, ErrNotInstalled
	}
	if err != nil {
		return 0, fmt.Errorf("meshext: uninstall: %w", err)
	}
	erased, err := erase(ctx, tx)
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM mesh_installations WHERE workspace_id = $1 AND org_id = $2`, workspace, org); err != nil {
		return 0, fmt.Errorf("meshext: delete installation: %w", err)
	}
	// An install window left open would let the next handshake connect the
	// workspace again right after its removal.
	if _, err := tx.Exec(ctx, `DELETE FROM mesh_pending_installs WHERE workspace_id = $1 AND org_id = $2`, workspace, org); err != nil {
		return 0, fmt.Errorf("meshext: delete install window: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("meshext: uninstall: %w", err)
	}
	return erased, nil
}

// WhileInstalled runs fn under the workspace lock if workspace is still
// connected to org, and returns ErrNotInstalled otherwise. A write into the
// workspace's sealed namespace goes through it, so it either lands before an
// Uninstall, which then erases it, or finds the installation gone.
func (r *Repo) WhileInstalled(ctx context.Context, workspace, org uuid.UUID, fn func(context.Context) error) error {
	conn, unlock, err := r.lock(ctx, workspaceLock, workspace)
	if err != nil {
		return fmt.Errorf("meshext: lock workspace: %w", err)
	}
	defer unlock()
	var one int
	err = conn.QueryRow(ctx, `SELECT 1 FROM mesh_installations WHERE workspace_id = $1 AND org_id = $2`, workspace, org).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotInstalled
	}
	if err != nil {
		return fmt.Errorf("meshext: lookup installation: %w", err)
	}
	return fn(ctx)
}
