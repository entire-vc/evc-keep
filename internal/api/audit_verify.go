package api

import (
	"net/http"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// auditRoutes bundles the dependency handleVerify needs. Verify takes the
// pool directly (internal/audit.Verify(ctx, pool, orgID) — see that
// function's own doc), so this route has no repo of its own to wrap it in.
type auditRoutes struct {
	pool *pgxpool.Pool
}

// handleVerify serves GET /orgs/{org_id}/audit/verify: the threat model's
// §4.8 decision to expose the CLI/keep-server "audit verify" tamper-check
// as a route callable by the thin cmd/keep client. It walks the caller's
// own organization's chain (identity.RequireOrgMatch("org_id") already
// pinned org_id to the authenticated Principal's own organization, same as
// every other route in this package) and answers with a direct projection
// of the result — never the records themselves: [audit.VerifyResult]
// carries no Record field by construction, so there is nothing here to
// leak even in outline.
func (a *auditRoutes) handleVerify(w http.ResponseWriter, r *http.Request) {
	requestID := reqid.FromContext(r.Context())
	p, _ := identity.FromContext(r.Context())

	res, err := audit.Verify(r.Context(), a.pool, p.OrgID.String())
	if err != nil {
		writeAppError(w, err, requestID)
		return
	}
	writeJSON(w, http.StatusOK, newAuditVerifyResult(res, requestID))
}
