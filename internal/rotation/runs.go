package rotation

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RunListMax bounds one page of List and ListFailed.
const RunListMax = 200

// RunSummary is one run as a list shows it: ids, version labels, a state, a
// closed class and times. Metadata only, like the row it is read from.
type RunSummary struct {
	ID             uuid.UUID
	SecretID       uuid.UUID
	State          State
	Class          Class
	OldVersion     string
	NewVersion     string
	IncidentOpened bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// Runs reads the run history of an organization's secrets. Every query is
// bound to the organization: a run of another organization is never read.
type Runs struct{ pool *pgxpool.Pool }

func NewRuns(pool *pgxpool.Pool) *Runs { return &Runs{pool: pool} }

const runColumns = `id, secret_id, state, error_class, old_version, new_version, incident_opened, created_at, updated_at`

func scanRun(row pgx.Row) (RunSummary, error) {
	var r RunSummary
	var st, cl string
	if err := row.Scan(&r.ID, &r.SecretID, &st, &cl, &r.OldVersion, &r.NewVersion, &r.IncidentOpened, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return RunSummary{}, err
	}
	r.State, r.Class = State(st), Class(cl)
	return r, nil
}

// Latest returns the newest run of each listed secret that has one.
func (r *Runs) Latest(ctx context.Context, org uuid.UUID, secrets []uuid.UUID) (map[uuid.UUID]RunSummary, error) {
	out := make(map[uuid.UUID]RunSummary, len(secrets))
	if len(secrets) == 0 {
		return out, nil
	}
	rows, err := r.pool.Query(ctx, `SELECT DISTINCT ON (secret_id) `+runColumns+`
		FROM rotation_runs WHERE org_id=$1 AND secret_id = ANY($2)
		ORDER BY secret_id, created_at DESC, id DESC`, org, secrets)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		s, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out[s.SecretID] = s
	}
	return out, rows.Err()
}

// List returns runs of one secret, newest first, and their total.
func (r *Runs) List(ctx context.Context, org, secret uuid.UUID, limit, offset int) ([]RunSummary, int, error) {
	return r.list(ctx, org, secret, false, limit, offset)
}

// ListFailed is List narrowed to failed runs.
func (r *Runs) ListFailed(ctx context.Context, org, secret uuid.UUID, limit, offset int) ([]RunSummary, int, error) {
	return r.list(ctx, org, secret, true, limit, offset)
}

func (r *Runs) list(ctx context.Context, org, secret uuid.UUID, failed bool, limit, offset int) ([]RunSummary, int, error) {
	if limit <= 0 || limit > RunListMax {
		limit = RunListMax
	}
	if offset < 0 {
		offset = 0
	}
	var total int
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM rotation_runs
		WHERE org_id=$1 AND secret_id=$2 AND (NOT $3 OR state='failed')`, org, secret, failed).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.pool.Query(ctx, `SELECT `+runColumns+` FROM rotation_runs
		WHERE org_id=$1 AND secret_id=$2 AND (NOT $3 OR state='failed')
		ORDER BY created_at DESC, id DESC LIMIT $4 OFFSET $5`, org, secret, failed, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []RunSummary
	for rows.Next() {
		s, err := scanRun(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, s)
	}
	return out, total, rows.Err()
}

// Get returns one run of the secret; found is false for a run of another
// secret or organization, exactly as for an unknown id.
func (r *Runs) Get(ctx context.Context, org, secret, run uuid.UUID) (RunSummary, bool, error) {
	s, err := scanRun(r.pool.QueryRow(ctx, `SELECT `+runColumns+` FROM rotation_runs
		WHERE id=$1 AND org_id=$2 AND secret_id=$3`, run, org, secret))
	if errors.Is(err, pgx.ErrNoRows) {
		return RunSummary{}, false, nil
	}
	if err != nil {
		return RunSummary{}, false, err
	}
	return s, true, nil
}
