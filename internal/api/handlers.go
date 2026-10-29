package api

import (
	"net/http"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/entire-vc/evc-keep/internal/version"
	"github.com/jackc/pgx/v5/pgxpool"
)

// handleHealthz reports only that the process is alive and serving — it
// never touches the database, so it stays up even while /readyz is down.
func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// VersionResult is the body of GET /version: the commit the running binary was
// built from and when, nothing else. It is the same for every caller and
// carries no configuration, environment or host data.
type VersionResult struct {
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
}

// handleVersion serves GET /version, unauthenticated like the probes, so a
// deploy marker can read which commit is live. The answer is fixed at process
// start (build-time values only) and never touches the database.
func handleVersion(w http.ResponseWriter, r *http.Request) {
	info := version.Info()
	// no-store: the point of the endpoint is to see the commit that is live
	// now, not one a proxy cached before the last deploy.
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, VersionResult{Commit: info.Commit, BuildTime: info.BuildTime})
}

// handleReadyz reports whether the process is ready to take real traffic:
// alive, and able to reach the database.
func handleReadyz(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := pool.Ping(r.Context()); err != nil {
			// Never propagate err's text: like store.Open, a ping failure's
			// message can carry connection details pulled from
			// KEEP_DATABASE_URL. See store.Open's doc for why that bar is
			// "not even a fragment", not just "not the password".
			writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady,
				"database not reachable", reqid.FromContext(r.Context()))
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}
