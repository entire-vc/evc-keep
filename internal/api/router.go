// Package api is Keep Server's only external HTTP surface. Every route past
// /healthz, /readyz and /version sits behind [identity.RequireAuth] and
// [identity.RequireOrgMatch]("org_id") — except the runner registration
// routes, which authenticate by mTLS client certificate instead (see
// internal/mtls). See ADR-001 §3.1 for why api never touches a secret's
// plaintext, and this package's own closed response-field guarantee
// (closed_fields_test.go).
package api

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/enrolltoken"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/mtls"
	"github.com/entire-vc/evc-keep/internal/registry"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/jackc/pgx/v5/pgxpool"
)

// routeEntry is one registered route. Auth is false only for /healthz,
// /readyz and /version — every other route carries identity.RequireAuth +
// identity.RequireOrgMatch("org_id"). Pattern is an http.ServeMux wildcard
// path, e.g. "/orgs/{org_id}/secrets/{secret_id}" — the same syntax
// api/openapi.yaml's own path keys use, so [openapiTest]'s cross-check can
// compare the two directly with no parsing beyond splitting the YAML.
type routeEntry struct {
	Method  string
	Pattern string
	Auth    bool
	// Poller marks the only routes a restart:poll token may reach.
	Poller  bool
	Handler http.HandlerFunc
}

// routeTable is the single declared list of routes this package serves —
// consumed by [NewRouter] to build the mux, and by
// TestOpenAPIMatchesRouteTable (openapi_test.go) to guarantee
// api/openapi.yaml never drifts from what actually runs. Adding a route
// means adding one entry here; every consumer sees it at once.
//
// logger and pool are threaded through only to build the handler closures —
// this function never itself calls either, so it is safe to call with both
// nil purely to enumerate the table (see the cross-check test).
func routeTable(ir *identity.Repo, logger *slog.Logger, pool *pgxpool.Pool, input InputService, dep DeploymentService, rot RotationService, publicURL string, notifier ApprovalNotifier, carriersSvc CarrierService, restarts RestartQueue) []routeEntry {
	tr := tenancy.New(pool)
	cat := catalog.New(pool)
	aud := audit.NewJournal(pool).WithLogger(logger)

	sec := &secretRoutes{logger: logger, tr: tr, ir: ir, cat: cat, aud: aud}
	tok := &tokenRoutes{ir: ir, aud: aud, log: logger}
	avr := &auditRoutes{pool: pool}
	in := &inputRoutes{sec: sec, pool: pool}
	in.svc = input
	cr := &carrierRoutes{sec: sec, svc: carriersSvc}
	cv := &carrierVerifyRoutes{sec: sec}
	cv.svc, _ = dep.(CarrierVerifyService)
	ro := &rotateRoutes{sec: sec, svc: rot, input: input, publicURL: publicURL}
	rs := &restartRoutes{q: restarts}
	dr := &deploymentRoutes{sec: sec, svc: dep, aud: aud, publicURL: publicURL, notifier: notifier, logger: logger}

	return []routeEntry{
		{Method: "POST", Pattern: "/v1/input-links", Auth: true, Handler: in.issue},
		{Method: "GET", Pattern: "/v1/input-links/{request_id}", Auth: true, Handler: in.status},
		{Method: "POST", Pattern: "/v1/restarts/claim", Auth: true, Poller: true, Handler: rs.claim},
		{Method: "POST", Pattern: "/v1/restarts/{request_id}/ack", Auth: true, Poller: true, Handler: rs.ack},
		{Method: "POST", Pattern: "/v1/deployments", Auth: true, Handler: dr.submit},
		{Method: "GET", Pattern: "/v1/deployments/{request_id}", Auth: true, Handler: dr.status},
		{Method: "POST", Pattern: "/v1/carriers/verify", Auth: true, Handler: cv.submit},
		{Method: "GET", Pattern: "/v1/carriers/verify/{request_id}", Auth: true, Handler: cv.status},
		{Method: "GET", Pattern: "/input/assets.js", Auth: false, Handler: inputScript},
		{Method: "GET", Pattern: "/input/{token}", Auth: false, Handler: in.page},
		{Method: "POST", Pattern: "/input/{token}", Auth: false, Handler: in.complete},
		{Method: "GET", Pattern: "/healthz", Auth: false, Handler: handleHealthz},
		{Method: "GET", Pattern: "/readyz", Auth: false, Handler: handleReadyz(pool)},
		{Method: "GET", Pattern: "/version", Auth: false, Handler: handleVersion},
		{Method: "GET", Pattern: "/orgs/{org_id}/secrets", Auth: true, Handler: sec.handleListSecrets},
		{Method: "POST", Pattern: "/orgs/{org_id}/secrets", Auth: true, Handler: sec.handleCreateSecret},
		{Method: "GET", Pattern: "/orgs/{org_id}/secrets/{secret_id}", Auth: true, Handler: sec.handleSecretMeta},
		{Method: "GET", Pattern: "/orgs/{org_id}/secrets/{secret_id}/versions", Auth: true, Handler: sec.handleListVersions},
		{Method: "POST", Pattern: "/orgs/{org_id}/secrets/{secret_id}/carriers", Auth: true, Handler: cr.register},
		{Method: "GET", Pattern: "/orgs/{org_id}/secrets/{secret_id}/carriers", Auth: true, Handler: cr.list},
		{Method: "POST", Pattern: "/orgs/{org_id}/secrets/{secret_id}/rotate", Auth: true, Handler: ro.start},
		{Method: "GET", Pattern: "/orgs/{org_id}/secrets/{secret_id}/rotate/{request_id}", Auth: true, Handler: ro.status},
		{Method: "POST", Pattern: "/orgs/{org_id}/secrets/{secret_id}/carriers/verify", Auth: true, Handler: cv.submitOrg},
		{Method: "GET", Pattern: "/orgs/{org_id}/secrets/{secret_id}/carriers/verify/{request_id}", Auth: true, Handler: cv.statusOrg},
		{Method: "POST", Pattern: "/orgs/{org_id}/tokens", Auth: true, Handler: tok.handleIssueToken},
		{Method: "POST", Pattern: "/orgs/{org_id}/tokens/{token_id}/revoke", Auth: true, Handler: tok.handleRevokeToken},
		{Method: "GET", Pattern: "/orgs/{org_id}/audit/verify", Auth: true, Handler: avr.handleVerify},
	}
}

// Deps is every dependency [NewRouter] needs beyond the database pool
// itself and the logger — grouped so adding a future route's dependency
// doesn't grow NewRouter's own parameter list again. Every field is either
// a concrete repo type internal/api may import directly (enrolltoken,
// identity, registry — none of them sit inside the zone-internals
// boundary) or a small interface ([CertIssuer], [mtls.CAResolver])
// whose concrete implementation is built in cmd/keep-server/main.go, the
// one place allowed to import internal/builtin/orgpki as well as this
// package.
type Deps struct {
	Jobs RunnerJobs
	// Catalog tunes the per-principal limit on the secret catalog routes;
	// the zero value means 60 requests a minute, burst 20.
	Catalog CatalogLimit
	// Deployments serves POST /v1/deployments; nil answers not_ready.
	Deployments DeploymentService
	// Rotations serves POST .../secrets/{secret_id}/rotate; nil answers not_ready.
	Rotations RotationService
	// Restarts serves the restart poller routes; nil answers not_ready.
	Restarts RestartQueue
	// PublicURL prefixes approval links; empty yields a relative path.
	PublicURL string
	// Approvals backs the /console pages; nil falls back to Deployments when
	// it also implements ApprovalService, and otherwise the console shows
	// "unavailable" (login still works).
	Approvals ApprovalService
	// Notifier announces new approvals to a chat; nil means no channel.
	Notifier ApprovalNotifier
	Input    InputService
	// Carriers serves the carrier routes; nil answers not_ready.
	Carriers CarrierService
	// Mesh wires the optional Mesh extension (POST /mesh/install, POST
	// /mesh/events, POST /mesh/token, DELETE /orgs/{org_id}/mesh/installations/
	// {workspace_id}, ...); nil leaves its routes unregistered.
	Mesh     *MeshDeps
	Audit    audit.Journaler
	Identity *identity.Repo
	Tokens   *enrolltoken.Repo
	Runners  *registry.Repo
	Certs    CertIssuer
	CA       mtls.CAResolver
}

// NewRouter builds Keep Server's HTTP handler. logger must be one built
// from internal/obs — every log line this package writes goes through its
// allow-list, not around it. pool may be nil (see test/security's own
// skeleton test) — the repos this constructs only touch it per-request,
// never at construction time.
//
// Two families of routes exist, meant to be served from two different
// listeners in cmd/keep-server (a plain one and a TLS one — see its own
// doc): /healthz, /readyz, and the catalog routes work on either; every
// runner route is wrapped in requireTLS, so it 404s outright when reached
// over the plain listener rather than silently working somewhere it must
// not.
func NewRouter(logger *slog.Logger, pool *pgxpool.Pool, deps Deps) http.Handler {
	ir := deps.Identity
	if ir == nil {
		ir = identity.NewRepo(pool)
	}
	aud := deps.Audit
	if aud == nil {
		aud = audit.NewJournal(pool).WithLogger(logger)
	}
	mux := http.NewServeMux()
	catalogLimiter := newLimiter(deps.Catalog)

	for _, e := range routeTable(ir, logger, pool, deps.Input, deps.Deployments, deps.Rotations, deps.PublicURL, deps.Notifier, deps.Carriers, deps.Restarts) {
		h := logged(e.Pattern, logger, e.Handler)
		var handler http.Handler = h
		if e.Auth {
			if strings.Contains(e.Pattern, "{org_id}") {
				handler = identity.RequireOrgMatch("org_id")(handler)
			}
			// Inside authentication, outside the tenant check: a probe of a
			// foreign tenant or a missing id spends the budget too.
			if limitedRoute(e.Pattern) {
				handler = limitMiddleware(catalogLimiter, logger, e.Pattern)(handler)
			}
			handler = authenticate(ir, logger, e.Poller)(handler)
		}
		mux.Handle(e.Method+" "+e.Pattern, handler)
	}

	admin := chain(
		requireTLS,
		authenticate(ir, logger, false),
		requirePermission(ir, identity.PermManageRunners),
	)
	approvals := deps.Approvals
	if approvals == nil {
		approvals, _ = deps.Deployments.(ApprovalService)
	}
	approvals = withRotationApprovals(approvals, deps.Rotations)
	registerConsole(mux, logger, ir, approvals, deps.PublicURL)
	mux.Handle("POST /runners/enroll-tokens",
		logged("/runners/enroll-tokens", logger, admin(handleIssueEnrollToken(deps.Tokens, aud)).ServeHTTP))
	mux.Handle("POST /runners/{runner_id}/revoke",
		logged("/runners/{runner_id}/revoke", logger, admin(handleRevokeRunner(deps.Runners, aud)).ServeHTTP))

	mux.Handle("POST /runners/enroll",
		logged("/runners/enroll", logger, chain(requireTLS)(handleEnrollRunner(deps.Tokens, deps.Runners, deps.Certs, aud, logger)).ServeHTTP))

	runnerMTLS := chain(requireTLS, mtls.RequireMTLSWithRejection(deps.CA, deps.Runners, logger, func(ctx context.Context, p mtls.Principal, requestID string) {
		appendRunnerRenewDenial(ctx, aud, logger, p, requestID)
	}))
	mux.Handle("POST /runners/renew",
		logged("/runners/renew", logger, runnerMTLS(handleRenewRunner(deps.Runners, deps.Certs, aud, logger)).ServeHTTP))
	jobMTLS := chain(requireTLS, mtls.RequireMTLS(deps.CA, deps.Runners, logger))
	mux.Handle("GET /runners/jobs/next", logged("/runners/jobs/next", logger, jobMTLS(handleNextJob(deps.Jobs)).ServeHTTP))
	mux.Handle("POST /runners/jobs/value", logged("/runners/jobs/value", logger, jobMTLS(handleJobMaterial(deps.Jobs)).ServeHTTP))
	mux.Handle("POST /runners/jobs/{job_id}/result", logged("/runners/jobs/{job_id}/result", logger, jobMTLS(handleJobResult(deps.Jobs)).ServeHTTP))

	if deps.Mesh != nil {
		rl := deps.Mesh.ResolveLimit
		if rl.PerMinute <= 0 {
			rl.PerMinute = defaultResolvePerMinute
		}
		if rl.Burst <= 0 {
			rl.Burst = defaultResolveBurst
		}
		pl := deps.Mesh.PreauthLimit
		if pl.PerMinute <= 0 {
			pl.PerMinute = defaultPreauthPerMinute
		}
		if pl.Burst <= 0 {
			pl.Burst = defaultPreauthBurst
		}
		mr := &meshRoutes{ir: ir, aud: aud, deps: *deps.Mesh, now: time.Now, resolve: newLimiter(rl), install: newLimiter(rl),
			preauth: newLimiter(pl), logger: logger}
		// Bearer, the Mesh token and events secret in, Keep's secret out: TLS only.
		installAuth := chain(requireTLS, authenticate(ir, logger, false))
		// No Authorization header: Mesh's own handshake, authenticated by the
		// HMAC and an admin's install window; the secret is in the body, TLS only.
		mux.Handle("POST /mesh/install", logged("/mesh/install", logger,
			mr.handleMeshInstall(installAuth(http.HandlerFunc(mr.handleInstall)), requireTLS(http.HandlerFunc(mr.handleHandshake))).ServeHTTP))
		mux.Handle("POST /orgs/{org_id}/mesh/pending-installs", logged("/orgs/{org_id}/mesh/pending-installs", logger,
			chain(requireTLS, authenticate(ir, logger, false), identity.RequireOrgMatch("org_id"))(http.HandlerFunc(mr.handlePendingInstall)).ServeHTTP))
		mux.Handle("DELETE /orgs/{org_id}/mesh/installations/{workspace_id}", logged("/orgs/{org_id}/mesh/installations/{workspace_id}", logger,
			chain(requireTLS, authenticate(ir, logger, false), identity.RequireOrgMatch("org_id"))(http.HandlerFunc(mr.handleUninstall)).ServeHTTP))
		// No bearer: the HMAC over the body is the authentication.
		mux.Handle("POST /mesh/events", logged("/mesh/events", logger, mr.handleEvents))
		// No bearer: the HMAC over the body with the bound events secret is the
		// authentication; TLS only, the actor token is in the body.
		mux.Handle("POST /mesh/token", logged("/mesh/token", logger, requireTLS(http.HandlerFunc(mr.handleToken)).ServeHTTP))
		// No bearer: the HMAC over method, path and body is the authentication;
		// TLS only, the value is in the body.
		mux.Handle("PUT /orgs/{org_id}/mesh/secrets/{ref}", logged("/orgs/{org_id}/mesh/secrets/{ref}", logger, requireTLS(http.HandlerFunc(mr.handlePutSecret)).ServeHTTP))
		mux.Handle("POST /orgs/{org_id}/mesh/secrets/{ref}/resolve", logged("/orgs/{org_id}/mesh/secrets/{ref}/resolve", logger, requireTLS(http.HandlerFunc(mr.handleResolveSecret)).ServeHTTP))
		if deps.Mesh.Federation != nil {
			// No bearer: the Mesh-signed context token is the authentication.
			mux.Handle("POST /mesh/session", logged("/mesh/session", logger, requireTLS(http.HandlerFunc(mr.handleSession)).ServeHTTP))
			registerMeshUI(mux, logger, mr, catalog.New(pool))
		}
	}

	return withRequestID(pollerGate(ir, mux))
}

// limitedRoute reports whether the per-principal catalog limit applies: the
// catalog routes, and the two routes that resolve a secret by name
// (deployments and input links), which would otherwise be a way to probe
// names without a budget.
func limitedRoute(pattern string) bool {
	return strings.HasPrefix(pattern, "/orgs/{org_id}/secrets") ||
		strings.HasPrefix(pattern, "/v1/deployments") ||
		strings.HasPrefix(pattern, "/v1/input-links")
}

// chain composes middleware in application order: chain(a, b)(h) runs a
// first, then b, then h — the order each list of routes above reads in.
func chain(mw ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		for i := len(mw) - 1; i >= 0; i-- {
			h = mw[i](h)
		}
		return h
	}
}
