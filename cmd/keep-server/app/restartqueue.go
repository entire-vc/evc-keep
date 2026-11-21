package app

import (
	"log/slog"

	"github.com/entire-vc/evc-keep/internal/restart"
	"github.com/jackc/pgx/v5/pgxpool"
)

// restartQueue is the lane restart queue over the KEEP_RESTART_LANES
// allowlist. Without one it refuses every request, and the start says so in
// one line that names the variable and no lane.
func restartQueue(pool *pgxpool.Pool, lanes []string, logger *slog.Logger) *restart.Repo {
	if len(lanes) == 0 {
		logger.Warn("restart queue has no lanes: KEEP_RESTART_LANES is unset or empty, every restart request is refused")
	}
	return restart.NewRepo(pool, lanes...)
}
