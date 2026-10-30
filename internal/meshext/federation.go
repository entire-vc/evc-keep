package meshext

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Federation turns a Mesh context token into a Keep console session. Mesh is
// the identity provider: Keep trusts a signature, never an email or a claim it
// could not verify, and never calls Mesh per request.
type Federation struct {
	pool *pgxpool.Pool
	repo *Repo
	ids  *identity.Repo
	ver  *Verifier
}

// NewFederation returns a Federation over pool.
func NewFederation(pool *pgxpool.Pool, repo *Repo, ids *identity.Repo, ver *Verifier) *Federation {
	return &Federation{pool: pool, repo: repo, ids: ids, ver: ver}
}

// ExternalRef is the stable key of a Mesh person in one Keep organisation.
func ExternalRef(meshURL, userID string) string {
	return "mesh:" + strings.TrimRight(meshURL, "/") + ":" + userID
}

// ExtensionInstallation is Installation for a workspace connected as an
// extension only: a store-only installation is not found, so nothing that
// calls Mesh with the actor token is handed one for it.
func (r *Repo) ExtensionInstallation(ctx context.Context, workspace uuid.UUID) (org uuid.UUID, meshURL string, found bool, err error) {
	err = r.pool.QueryRow(ctx, `SELECT org_id, mesh_url FROM mesh_installations WHERE workspace_id = $1 AND mode = $2`, workspace, string(ModeExtension)).Scan(&org, &meshURL)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", false, nil
	}
	if err != nil {
		return uuid.Nil, "", false, fmt.Errorf("meshext: lookup installation: %w", err)
	}
	return org, meshURL, true, nil
}

// Installation returns the organisation and Mesh address of a connected workspace.
func (r *Repo) Installation(ctx context.Context, workspace uuid.UUID) (org uuid.UUID, meshURL string, found bool, err error) {
	err = r.pool.QueryRow(ctx, `SELECT org_id, mesh_url FROM mesh_installations WHERE workspace_id = $1`, workspace).Scan(&org, &meshURL)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", false, nil
	}
	if err != nil {
		return uuid.Nil, "", false, fmt.Errorf("meshext: lookup installation: %w", err)
	}
	return org, meshURL, true, nil
}

// SignIn verifies tok and opens a session for the person it names, creating
// the Keep user on first sight. Every refusal is [ErrInvalidContext]: an
// unknown workspace, a removed user and an email already held by a different
// user answer the same as a bad signature. A matching email never links an
// existing user: only the external reference does.
func (f *Federation) SignIn(ctx context.Context, tok ContextToken) (handle string, s identity.Session, err error) {
	ws, ok := PeekWorkspace(tok)
	if !ok {
		return "", identity.Session{}, ErrInvalidContext
	}
	org, meshURL, found, err := f.repo.Installation(ctx, ws)
	if err != nil {
		return "", identity.Session{}, err
	}
	if !found {
		return "", identity.Session{}, ErrInvalidContext
	}
	claims, err := f.ver.Verify(ctx, meshURL, ws, tok)
	if err != nil {
		return "", identity.Session{}, err
	}
	// The gate answers name the Mesh user by id; a subject that is not one
	// could never be linked, so it does not sign in either.
	meshUser, err := uuid.Parse(claims.Subject)
	if err != nil {
		return "", identity.Session{}, ErrInvalidContext
	}
	user, err := f.findOrCreate(ctx, org, ExternalRef(meshURL, claims.Subject), claims.Email)
	if err != nil {
		return "", identity.Session{}, err
	}
	if err := f.link(ctx, ws, meshUser, org, user); err != nil {
		return "", identity.Session{}, err
	}
	exp := time.Now().UTC().Add(identity.SessionTTL)
	res, err := f.ids.Issue(ctx, identity.IssueParams{OrgID: org, Kind: identity.KindUser, PrincipalID: user, Scope: "org:" + org.String(), ExpiresAt: &exp})
	if err != nil {
		return "", identity.Session{}, fmt.Errorf("meshext: issue session token: database error")
	}
	return f.ids.OpenSession(ctx, res.Token)
}

// link records that meshUser of workspace is user, so a gate card answered in
// Mesh names a Keep user. It grants nothing: the right to decide is the
// user's role, checked on every answer.
func (f *Federation) link(ctx context.Context, workspace, meshUser, org, user uuid.UUID) error {
	if _, err := f.pool.Exec(ctx, `INSERT INTO mesh_user_links (workspace_id,mesh_user_id,org_id,user_id) VALUES ($1,$2,$3,$4)
	 ON CONFLICT (workspace_id,mesh_user_id) DO UPDATE SET org_id=EXCLUDED.org_id, user_id=EXCLUDED.user_id, linked_at=now()`,
		workspace, meshUser, org, user); err != nil {
		return fmt.Errorf("meshext: link mesh user: database error")
	}
	return nil
}

func (f *Federation) findOrCreate(ctx context.Context, org uuid.UUID, ref, email string) (uuid.UUID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, fmt.Errorf("meshext: generate user id: %w", err)
	}
	_, err = f.pool.Exec(ctx, `INSERT INTO users (id, org_id, email, external_ref) VALUES ($1, $2, $3, $4)
		ON CONFLICT (org_id, external_ref) WHERE external_ref IS NOT NULL DO NOTHING`, id, org, email, ref)
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		return uuid.Nil, ErrInvalidContext // the email belongs to another user
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("meshext: create user: database error")
	}
	var status string
	if err = f.pool.QueryRow(ctx, `SELECT id, status FROM users WHERE org_id = $1 AND external_ref = $2`, org, ref).Scan(&id, &status); err != nil {
		return uuid.Nil, fmt.Errorf("meshext: lookup user: database error")
	}
	if status != "active" {
		return uuid.Nil, ErrInvalidContext
	}
	return id, nil
}
