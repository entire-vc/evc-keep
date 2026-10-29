package app

import (
	"context"
	"log/slog"
	"time"

	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/config"
	"github.com/entire-vc/evc-keep/internal/meshext"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// meshSyncEvery is how often every connected workspace is reconciled against
// Mesh's export/hierarchy. With an unchanged cursor Mesh answers 304, so the
// cost of a quiet round is one request per workspace.
const meshSyncEvery = 5 * time.Minute

// meshFetcher adapts the zone vault (which holds the actor token) to
// meshext.Fetcher, so the token never crosses into meshext.
type meshFetcher struct{ v *builtin.MeshVault }

func (f meshFetcher) FetchHierarchy(ctx context.Context, org, workspace uuid.UUID, meshURL, etag string) (meshext.Fetched, error) {
	got, err := f.v.FetchHierarchy(ctx, org.String(), workspace.String(), meshURL, etag)
	if err != nil {
		return meshext.Fetched{}, err
	}
	return meshext.Fetched{NotModified: got.NotModified, ETag: got.ETag, Body: got.Body}, nil
}

// runMeshSync reconciles the Mesh hierarchy until ctx ends. It does nothing
// unless the Mesh extension is on.
func runMeshSync(ctx context.Context, cfg config.Config, pool *pgxpool.Pool, local *builtin.Local, log *slog.Logger) {
	if !cfg.MeshExtension {
		return
	}
	repo, f := meshext.NewRepo(pool), meshFetcher{local.MeshVault()}
	t := time.NewTicker(meshSyncEvery)
	defer t.Stop()
	for {
		meshSyncRound(ctx, repo, f, log)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// meshSyncRound drops the install windows that have expired since the last
// round, with their digests, and then reconciles every connected workspace.
func meshSyncRound(ctx context.Context, repo *meshext.Repo, f meshext.Fetcher, log *slog.Logger) {
	if err := repo.DropExpiredPending(ctx); err != nil {
		log.Warn("mesh install window cleanup failed", "error_class", "unavailable")
	}
	repo.ReconcileAll(ctx, f, log)
}
