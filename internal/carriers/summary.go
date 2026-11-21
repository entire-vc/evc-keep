package carriers

import (
	"context"

	"github.com/google/uuid"
)

// Summary counts the destinations of one secret against its current version
// (the newest enabled one). InSync: registered at the current version. Stale:
// marked stale, or registered at an older version. Unknown: not verified.
// Total is their sum.
type Summary struct {
	Total, InSync, Stale, Unknown int
}

// Summary reads the carrier counts of every secret of org in one query. A
// secret with no carriers has no entry.
func (r *Repository) Summary(ctx context.Context, org uuid.UUID) (map[uuid.UUID]Summary, error) {
	if r == nil || r.pool == nil {
		return nil, ErrInternal
	}
	rows, err := r.pool.Query(ctx, `
 SELECT c.secret_id, count(*),
        count(*) FILTER (WHERE c.state='registered' AND c.version = cur.v),
        count(*) FILTER (WHERE c.state='stale' OR (c.state='registered' AND c.version IS DISTINCT FROM cur.v)),
        count(*) FILTER (WHERE c.state='unknown')
   FROM carriers c
   LEFT JOIN LATERAL (SELECT provider_version AS v FROM secret_versions v
                       WHERE v.org_id=c.org_id AND v.secret_id=c.secret_id AND NOT v.disabled
                       ORDER BY v.seal_seq DESC LIMIT 1) cur ON true
  WHERE c.org_id=$1
  GROUP BY c.secret_id`, org)
	if err != nil {
		return nil, ErrInternal // Summary query failed; never expose its error.
	}
	defer rows.Close()
	out := map[uuid.UUID]Summary{}
	for rows.Next() {
		var id uuid.UUID
		var s Summary
		if rows.Scan(&id, &s.Total, &s.InSync, &s.Stale, &s.Unknown) != nil {
			return nil, ErrInternal // Summary scan failed; never expose its error.
		}
		out[id] = s
	}
	if rows.Err() != nil {
		return nil, ErrInternal // Summary iteration failed; never expose its error.
	}
	return out, nil
}

// Summary is [Repository.Summary] for the API.
func (s *Service) Summary(ctx context.Context, org uuid.UUID) (map[uuid.UUID]Summary, error) {
	return s.repo.Summary(ctx, org)
}
