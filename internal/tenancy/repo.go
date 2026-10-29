package tenancy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/metatext"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Principal kinds. Memberships belong to users only: an agent's rights are
// its sponsor's role intersected with the agent's own grants (§4), and a
// service's access is entirely its owner_scope (§1).
const (
	PrincipalUser    = "user"
	PrincipalAgent   = "agent"
	PrincipalService = "service"
)

// Repo is the tenancy hierarchy's repository: organizations, workspaces,
// projects, users, agents, services and memberships. Every method takes
// org_id explicitly and filters on it — see the package doc.
type Repo struct {
	pool *pgxpool.Pool
}

// New returns a Repo backed by pool.
func New(pool *pgxpool.Pool) *Repo { return &Repo{pool: pool} }

// Organization is an organizations row.
type Organization struct {
	ID        uuid.UUID
	Name      string
	KeyLevel  string
	CreatedAt time.Time
}

// CreateOrganization inserts a new organization. keyLevel must be one of
// "user" (the default), "project", "workspace", "organization" (§5.1); pass
// "" to take the default.
func (r *Repo) CreateOrganization(ctx context.Context, name, keyLevel string) (Organization, error) {
	return insertOrganization(ctx, r.pool, name, keyLevel)
}

// ErrOrganizationNameTaken is returned by [Repo.CreateOrganizationUniqueName]
// when an organization with that name already exists.
var ErrOrganizationNameTaken = apperr.New(apperr.ClassAlreadyExists, "an organization with this name already exists")

// CreateOrganizationUniqueName is [Repo.CreateOrganization] refusing a name
// that is already taken. organizations.name has no unique index, so the check
// and the insert run in one transaction under LOCK TABLE organizations IN
// SHARE ROW EXCLUSIVE MODE: a concurrent creation waits for this one to commit
// and then sees its row.
func (r *Repo) CreateOrganizationUniqueName(ctx context.Context, name, keyLevel string) (Organization, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Organization{}, fmt.Errorf("tenancy: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx, `LOCK TABLE organizations IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return Organization{}, fmt.Errorf("tenancy: lock organizations: %w", err)
	}
	var taken bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM organizations WHERE name = $1)`, name).Scan(&taken); err != nil {
		return Organization{}, fmt.Errorf("tenancy: check organization name: %w", err)
	}
	if taken {
		return Organization{}, ErrOrganizationNameTaken
	}
	o, err := insertOrganization(ctx, tx, name, keyLevel)
	if err != nil {
		return Organization{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Organization{}, fmt.Errorf("tenancy: commit: %w", err)
	}
	return o, nil
}

func insertOrganization(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, name, keyLevel string) (Organization, error) {
	if err := metatext.Validate("name", name, metatext.NameLimit); err != nil {
		return Organization{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Organization{}, fmt.Errorf("tenancy: generate organization id: %w", err)
	}
	if keyLevel == "" {
		keyLevel = "user"
	}
	var o Organization
	err = q.QueryRow(ctx,
		`INSERT INTO organizations (id, name, key_level) VALUES ($1, $2, $3)
		 RETURNING id, name, key_level, created_at`,
		id, name, keyLevel,
	).Scan(&o.ID, &o.Name, &o.KeyLevel, &o.CreatedAt)
	if err != nil {
		return Organization{}, fmt.Errorf("tenancy: create organization: %w", err)
	}
	return o, nil
}

// Workspace is a workspaces row.
type Workspace struct {
	ID          uuid.UUID
	OrgID       uuid.UUID
	Name        string
	ExternalRef *string
	CreatedAt   time.Time
}

// CreateWorkspace inserts a new workspace under org.
func (r *Repo) CreateWorkspace(ctx context.Context, org uuid.UUID, name string) (Workspace, error) {
	if err := metatext.Validate("name", name, metatext.NameLimit); err != nil {
		return Workspace{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Workspace{}, fmt.Errorf("tenancy: generate workspace id: %w", err)
	}
	var w Workspace
	err = r.pool.QueryRow(ctx,
		`INSERT INTO workspaces (id, org_id, name) VALUES ($1, $2, $3)
		 RETURNING id, org_id, name, external_ref, created_at`,
		id, org, name,
	).Scan(&w.ID, &w.OrgID, &w.Name, &w.ExternalRef, &w.CreatedAt)
	if err != nil {
		return Workspace{}, fmt.Errorf("tenancy: create workspace: %w", err)
	}
	return w, nil
}

// Project is a projects row.
type Project struct {
	ID          uuid.UUID
	OrgID       uuid.UUID
	WorkspaceID uuid.UUID
	Name        string
	ExternalRef *string
	CreatedAt   time.Time
}

// CreateProject inserts a new project under workspace (which must belong to
// org — enforced by the schema's composite foreign key).
func (r *Repo) CreateProject(ctx context.Context, org, workspace uuid.UUID, name string) (Project, error) {
	if err := metatext.Validate("name", name, metatext.NameLimit); err != nil {
		return Project{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Project{}, fmt.Errorf("tenancy: generate project id: %w", err)
	}
	var p Project
	err = r.pool.QueryRow(ctx,
		`INSERT INTO projects (id, org_id, workspace_id, name) VALUES ($1, $2, $3, $4)
		 RETURNING id, org_id, workspace_id, name, external_ref, created_at`,
		id, org, workspace, name,
	).Scan(&p.ID, &p.OrgID, &p.WorkspaceID, &p.Name, &p.ExternalRef, &p.CreatedAt)
	if err != nil {
		return Project{}, fmt.Errorf("tenancy: create project: %w", err)
	}
	return p, nil
}

// User is a users row.
type User struct {
	ID          uuid.UUID
	OrgID       uuid.UUID
	Email       string
	ExternalRef *string
	Status      string
	RemovedAt   *time.Time
	CreatedAt   time.Time
}

// CreateUser inserts a new active user under org.
func (r *Repo) CreateUser(ctx context.Context, org uuid.UUID, email string) (User, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return User{}, fmt.Errorf("tenancy: generate user id: %w", err)
	}
	var u User
	err = r.pool.QueryRow(ctx,
		`INSERT INTO users (id, org_id, email) VALUES ($1, $2, $3)
		 RETURNING id, org_id, email, external_ref, status, removed_at, created_at`,
		id, org, email,
	).Scan(&u.ID, &u.OrgID, &u.Email, &u.ExternalRef, &u.Status, &u.RemovedAt, &u.CreatedAt)
	if err != nil {
		return User{}, fmt.Errorf("tenancy: create user: %w", err)
	}
	return u, nil
}

// GetUser fetches a user by id, scoped to org.
func (r *Repo) GetUser(ctx context.Context, org, id uuid.UUID) (User, error) {
	var u User
	err := r.pool.QueryRow(ctx,
		`SELECT id, org_id, email, external_ref, status, removed_at, created_at
		 FROM users WHERE org_id = $1 AND id = $2`,
		org, id,
	).Scan(&u.ID, &u.OrgID, &u.Email, &u.ExternalRef, &u.Status, &u.RemovedAt, &u.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("tenancy: get user: %w", err)
	}
	return u, nil
}

// RemoveUser marks a user removed (§6) — it never deletes the row: the
// user's own scope and its secrets stay theirs, only sponsored agents lose
// access (Resolve refuses once the sponsor's status is not "active").
func (r *Repo) RemoveUser(ctx context.Context, org, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE users SET status = 'removed', removed_at = now()
		 WHERE org_id = $1 AND id = $2 AND status = 'active'`,
		org, id,
	)
	if err != nil {
		return fmt.Errorf("tenancy: remove user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Agent is an agents row.
type Agent struct {
	ID            uuid.UUID
	OrgID         uuid.UUID
	SponsorUserID uuid.UUID
	Name          string
	ExternalRef   *string
	Status        string
	CreatedAt     time.Time
}

// CreateAgent inserts a new active agent sponsored by sponsor.
func (r *Repo) CreateAgent(ctx context.Context, org, sponsor uuid.UUID, name string) (Agent, error) {
	if err := metatext.Validate("name", name, metatext.NameLimit); err != nil {
		return Agent{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Agent{}, fmt.Errorf("tenancy: generate agent id: %w", err)
	}
	var a Agent
	err = r.pool.QueryRow(ctx,
		`INSERT INTO agents (id, org_id, sponsor_user_id, name) VALUES ($1, $2, $3, $4)
		 RETURNING id, org_id, sponsor_user_id, name, external_ref, status, created_at`,
		id, org, sponsor, name,
	).Scan(&a.ID, &a.OrgID, &a.SponsorUserID, &a.Name, &a.ExternalRef, &a.Status, &a.CreatedAt)
	if err != nil {
		return Agent{}, fmt.Errorf("tenancy: create agent: %w", err)
	}
	return a, nil
}

// GetAgent fetches an agent by id, scoped to org.
func (r *Repo) GetAgent(ctx context.Context, org, id uuid.UUID) (Agent, error) {
	var a Agent
	err := r.pool.QueryRow(ctx,
		`SELECT id, org_id, sponsor_user_id, name, external_ref, status, created_at
		 FROM agents WHERE org_id = $1 AND id = $2`,
		org, id,
	).Scan(&a.ID, &a.OrgID, &a.SponsorUserID, &a.Name, &a.ExternalRef, &a.Status, &a.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Agent{}, ErrNotFound
		}
		return Agent{}, fmt.Errorf("tenancy: get agent: %w", err)
	}
	return a, nil
}

// Service is a services row.
type Service struct {
	ID         uuid.UUID
	OrgID      uuid.UUID
	Name       string
	OwnerScope Scope
	CreatedAt  time.Time
}

// CreateService inserts a new service owned by ownerScope, which must be
// "org", "ws" or "proj" — never "user" (§1: a service has no sponsor) — and
// must name an existing scope of org. The scope is stored in the TEXT column
// services.owner_scope as "level:id".
func (r *Repo) CreateService(ctx context.Context, org uuid.UUID, name string, ownerScope Scope) (Service, error) {
	if err := metatext.Validate("name", name, metatext.NameLimit); err != nil {
		return Service{}, err
	}
	if ownerScope.Level == LevelUser {
		return Service{}, invalidContextError("a service's owner scope cannot be a user")
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Service{}, fmt.Errorf("tenancy: generate service id: %w", err)
	}
	s := Service{OwnerScope: ownerScope}
	err = r.pool.QueryRow(ctx,
		`INSERT INTO services (id, org_id, name, owner_scope)
		 SELECT $1, $2, $3, $4 WHERE keep_validate_scope($2, $5, $6)
		 RETURNING id, org_id, name, created_at`,
		id, org, name, ownerScope.String(), string(ownerScope.Level), ownerScope.ID,
	).Scan(&s.ID, &s.OrgID, &s.Name, &s.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Service{}, invalidContextError("owner scope does not belong to this organization")
		}
		return Service{}, fmt.Errorf("tenancy: create service: %w", err)
	}
	return s, nil
}

// Membership is a memberships row: a user's role at one scope. The role
// vocabulary (viewer, member, admin) and the one-role-per-scope rule are the
// identity schema's; the scope is stored as "level:id" text.
type Membership struct {
	ID        uuid.UUID
	OrgID     uuid.UUID
	UserID    uuid.UUID
	Scope     Scope
	Role      string
	CreatedAt time.Time
}

// CreateMembership grants role to userID at scope, which must be an "org",
// "ws" or "proj" scope of org — a user's own scope carries no memberships.
func (r *Repo) CreateMembership(ctx context.Context, org, userID uuid.UUID, scope Scope, role string) (Membership, error) {
	if scope.Level == LevelUser {
		return Membership{}, invalidContextError("a membership cannot be at a user scope")
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Membership{}, fmt.Errorf("tenancy: generate membership id: %w", err)
	}
	m := Membership{Scope: scope}
	err = r.pool.QueryRow(ctx,
		`INSERT INTO memberships (id, org_id, user_id, scope, role)
		 SELECT $1, $2, $3, $4, $5 WHERE keep_validate_scope($2, $6, $7)
		 RETURNING id, org_id, user_id, role, created_at`,
		id, org, userID, scope.String(), role, string(scope.Level), scope.ID,
	).Scan(&m.ID, &m.OrgID, &m.UserID, &m.Role, &m.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Membership{}, invalidContextError("membership scope does not belong to this organization")
		}
		return Membership{}, fmt.Errorf("tenancy: create membership: %w", err)
	}
	return m, nil
}

// distinctScopeIDs returns the distinct scope ids of the given level at
// which userID holds a membership. Resolve uses this only for
// [LevelWorkspace] (tenancy model §7 scenario C3's ambiguous_context check)
// — see resolve.go for why the same check is not extended to projects.
// Scope texts that are not "level:uuid" are ignored.
func (r *Repo) distinctScopeIDs(ctx context.Context, org, userID uuid.UUID, level Level) ([]uuid.UUID, error) {
	prefix := string(level) + ":"
	rows, err := r.pool.Query(ctx,
		`SELECT DISTINCT scope FROM memberships
		 WHERE org_id = $1 AND user_id = $2 AND starts_with(scope, $3)`,
		org, userID, prefix,
	)
	if err != nil {
		return nil, fmt.Errorf("tenancy: list membership scopes: %w", err)
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var text string
		if err := rows.Scan(&text); err != nil {
			return nil, fmt.Errorf("tenancy: scan membership scope: %w", err)
		}
		id, err := uuid.Parse(strings.TrimPrefix(text, prefix))
		if err != nil {
			continue
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("tenancy: list membership scopes: %w", err)
	}
	return ids, nil
}

// workspaceInOrg reports whether id names a workspace of org.
func (r *Repo) workspaceInOrg(ctx context.Context, org, id uuid.UUID) (bool, error) {
	return r.exists(ctx, `SELECT 1 FROM workspaces WHERE org_id = $1 AND id = $2`, org, id)
}

// projectInWorkspace reports whether id names a project of org under workspace.
func (r *Repo) projectInWorkspace(ctx context.Context, org, workspace, id uuid.UUID) (bool, error) {
	return r.exists(ctx,
		`SELECT 1 FROM projects WHERE org_id = $1 AND workspace_id = $2 AND id = $3`,
		org, workspace, id)
}

func (r *Repo) exists(ctx context.Context, q string, args ...any) (bool, error) {
	var one int
	err := r.pool.QueryRow(ctx, q, args...).Scan(&one)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("tenancy: exists check: %w", err)
	}
	return true, nil
}

// ErrNotFound is returned by a lookup-by-id method (Get*) when no row
// matches. Unlike [NotFoundError], it carries no template and is meant for
// tenancy-management callers (tests, future admin surfaces), not for the
// oracle-sensitive Resolve/catalog path.
var ErrNotFound = errors.New("tenancy: not found")
