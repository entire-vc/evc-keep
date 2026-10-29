// Package app is the Keep Server: the catalog of secret references, tenancy,
// policy, and the audit journal. It never stores or returns a secret's
// plaintext value over its API — see CONTRIBUTING.md.
//
// It lives apart from cmd/keep-server so that a plugin binary (a separate
// module) can start the same server with its own Options; the core imports no
// plugin.
package app

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/entire-vc/evc-keep/internal/api"
	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/builtin/orgpki"
	"github.com/entire-vc/evc-keep/internal/carriers"
	"github.com/entire-vc/evc-keep/internal/config"
	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/dispatch"
	"github.com/entire-vc/evc-keep/internal/enrolltoken"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/meshext"
	"github.com/entire-vc/evc-keep/internal/meshgate"
	"github.com/entire-vc/evc-keep/internal/notify"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/registry"
	"github.com/entire-vc/evc-keep/internal/restart"
	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/pkg/gatecard"
	keepprovider "github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SelfRotateStore is what a plugin gets of the sealed service token: it can
// stage, activate and discard a new one and read the active one to authenticate
// with. *svctoken.Store is the implementation; the plugin never names it.
type SelfRotateStore interface {
	Stage(ctx context.Context, keyID string, v secret.Value) error
	Activate(ctx context.Context, keyID string) error
	Discard(ctx context.Context, keyID string) error
	Token(ctx context.Context) (string, error)
}

// SelfRotateRestarts is the restart queue as a plugin sees it, already bound to
// the organization and the lane: it asks for one restart after a rotation and
// reads whether the poller applied it. The plugin never gets a key value, an
// organization or a fingerprint; the request carries the key version and the
// fingerprint of the active key, computed here. Nil when no lane is configured.
type SelfRotateRestarts interface {
	Enqueue(ctx context.Context, keyVersion string) (uuid.UUID, error)
	Outcome(ctx context.Context, id uuid.UUID) (applied, final bool, err error)
}

// Options are what a build of keep-server may add to the core. The zero value
// is the plain server: no tracker, no confirmation cards.
type Options struct {
	// Cards builds the tracker side of the Mesh gate. The core calls it only
	// when the whole KEEP_MESH_* gate configuration is present and valid, and
	// never imports a tracker itself: a plugin binary supplies it. Nil means
	// this build has no tracker, and a gate configuration then stops the
	// start instead of being ignored. tokens is the sealed actor token of the
	// installation named by KEEP_MESH_WORKSPACE_ID, and nil when the gate is
	// given KEEP_MESH_TOKEN_FILE instead.
	Cards func(cfg config.MeshGate, tokens GateTokenSource, logger *slog.Logger) (gatecard.Cards, error)
	// SweepEvery overrides config.MeshGate.SweepEvery, for tests.
	SweepEvery time.Duration
	// SelfRotate builds one rotation of the Mesh service token over its sealed
	// store. The core calls it only when KEEP_MESH_SELF_ROTATE=1 and never
	// imports the tracker itself. Nil means this build has no tracker, and the
	// configuration then stops the start instead of being ignored.
	SelfRotate func(cfg config.MeshSelfRotate, store SelfRotateStore, restarts SelfRotateRestarts, logger *slog.Logger) (func(context.Context) error, error)
	// SelfRotateActor checks, before the rotation starts, that the
	// self-rotation account is not the actor whose token the gate holds
	// (tokens as for Cards). The core calls it only when both are on and
	// rotation is not seal-only; ErrSelfRotateSameActor stops the start, an
	// actor that cannot be learnt is the plugin's to log, not to fail. Nil
	// in a build with SelfRotate stops such a start: the check is not skipped.
	SelfRotateActor func(ctx context.Context, gate config.MeshGate, tokens GateTokenSource, account string, logger *slog.Logger) error
	// SelfRotateEvery overrides config.MeshSelfRotate.Interval, for tests.
	SelfRotateEvery time.Duration
}

// Main runs keep-server with the given command line (args[0] is the program
// name) and returns the process exit code.
func Main(args []string, opts Options) int {
	logger := obs.New(os.Stdout)
	ctx := context.Background()

	if len(args) > 1 && args[1] == "migrate" {
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: keep-server migrate up|status")
			return 2
		}
		return runMigrate(ctx, args[2])
	}

	if len(args) > 1 && args[1] == "audit" {
		if len(args) < 3 || args[2] != "verify" {
			fmt.Fprintln(os.Stderr, "usage: keep-server audit verify --org <id>")
			return 2
		}
		return runAuditVerify(ctx, args[3:])
	}

	if len(args) > 1 && args[1] == "bootstrap-org" {
		return runBootstrapOrg(ctx, args[2:])
	}

	if len(args) > 1 && args[1] == "bind-default-store" {
		return runBindDefaultStore(ctx, args[2:])
	}

	if len(args) > 1 && args[1] == "set-deploy-policy" {
		return runSetDeployPolicy(ctx, args[2:])
	}

	return runServe(ctx, logger, opts)
}

// runMigrate implements the "keep-server migrate up|status" subcommand.
// The server itself never migrates on its own — see runServe.
func runMigrate(ctx context.Context, sub string) int {
	cfg, err := config.FromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	db, err := store.OpenMigrationDB(ctx, cfg.DatabaseURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = db.Close() }()

	provider, err := store.NewProvider(db)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	switch sub {
	case "up":
		results, err := provider.Up(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "migrate up failed:", err)
			return 1
		}
		for _, r := range results {
			fmt.Printf("applied %s\n", r.Source.Path)
		}
		status, err := store.CheckSchema(ctx, provider)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("schema at version %d (target %d)\n", status.Current, status.Required)
		return 0

	case "status":
		status, err := store.CheckSchema(ctx, provider)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if status.Behind() {
			fmt.Printf("schema version %d, target %d — behind, run 'keep-server migrate up'\n", status.Current, status.Required)
			return 1
		}
		fmt.Printf("schema up to date at version %d\n", status.Current)
		return 0

	default:
		fmt.Fprintf(os.Stderr, "unknown migrate subcommand %q — usage: keep-server migrate up|status\n", sub)
		return 2
	}
}

// runAuditVerify implements "keep-server audit verify --org <id>" — the
// threat model's §4.2 CLI requirement. It walks org's R-AUD-1 chain
// (internal/audit.Verify) and prints only what the threat model allows: the
// first broken record's id and position, or that the chain is clean and how
// many records it holds — never a record's own field values, which
// audit.VerifyResult structurally cannot carry (see its doc). A clean result
// means no accidental damage and no tampering that left the chain
// self-consistent; it is not proof against a writer who can rewrite the
// whole chain (the hash is unkeyed — see audit.Verify).
func runAuditVerify(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	org := fs.String("org", "", "organization id whose chain to verify")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *org == "" {
		fmt.Fprintln(os.Stderr, "usage: keep-server audit verify --org <id>")
		return 2
	}

	cfg, err := config.FromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	pool, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer pool.Close()

	return printAuditVerify(ctx, os.Stdout, pool, *org)
}

// printAuditVerify is runAuditVerify's testable core — separated so
// main_test.go can exercise the output format against a real pool without
// spawning a process for every case store's own process-level tests
// already cover the DSN-leak angle for.
func printAuditVerify(ctx context.Context, w io.Writer, pool *pgxpool.Pool, org string) int {
	res, err := audit.Verify(ctx, pool, org)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if res.OK {
		_, _ = fmt.Fprintf(w, "chain OK: %d record(s) verified for org %s\n", res.Checked, org)
		return 0
	}
	if res.BrokenID == "" {
		_, _ = fmt.Fprintf(w, "chain BROKEN (%s): the journal head records position %d, the chain ends at %d\n", res.BreakKind, res.BrokenPosition, res.Checked)
		return 1
	}
	_, _ = fmt.Fprintf(w, "chain BROKEN (%s) at position %d: record id %s\n", res.BreakKind, res.BrokenPosition, res.BrokenID)
	return 1
}

// runServe starts the HTTP server. It checks the schema version first and
// refuses to start — a nonzero exit, before any listener opens — if the
// database is behind what this binary requires. It never applies a
// migration itself; see runMigrate.
func runServe(ctx context.Context, logger *slog.Logger, opts Options) int {
	cfg, err := config.FromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	serverCert, err := serverTLSCert(cfg, logger)
	if err != nil {
		fmt.Fprintln(os.Stderr, "runner TLS listener certificate:", err)
		return 1
	}

	mdb, err := store.OpenMigrationDB(ctx, cfg.DatabaseURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	provider, err := store.NewProvider(mdb)
	if err != nil {
		_ = mdb.Close()
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	status, err := store.CheckSchema(ctx, provider)
	_ = mdb.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, "schema check failed:", err)
		return 1
	}
	if status.Behind() {
		fmt.Fprintf(os.Stderr, "refusing to start: schema at version %d, binary requires version %d — run 'keep-server migrate up'\n", status.Current, status.Required)
		return 1
	}

	pool, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer pool.Close()

	if err := store.CheckLogSettings(ctx, pool); err != nil {
		fmt.Fprintf(os.Stderr, "refusing to start: %v — see \"Database requirements\" in README.md\n", err)
		return 1
	}

	if err := store.CheckNotSuperuser(ctx, pool); err != nil {
		fmt.Fprintf(os.Stderr, "refusing to start: %v — see \"Database requirements\" in README.md\n", err)
		return 1
	}

	if n, err := store.CheckReservedRefs(ctx, pool, keepprovider.ReservedRefPrefix); err != nil {
		var ae *apperr.Error
		class := apperr.ClassInternal
		if errors.As(err, &ae) {
			class = ae.Class
		}
		fmt.Fprintf(os.Stderr, "refusing to start: reserved provider reference in catalog (error_class=%s rows=%d)\n", class, n)
		return 1
	}

	journal := audit.NewJournal(pool).WithLogger(logger).WithClock(keyLevelClock)
	claims := newKeyLevelClaims(pool)
	defer claims.Close()
	auditor := newKeyLevelAuditor(journal, logger, claims)
	local, err := builtin.OpenLocalFile(pool, cfg.RootKeyFile, cfg.RootKeyID, logger, auditor.record)
	if err != nil {
		fmt.Fprintln(os.Stderr, "root key:", err)
		return 1
	}
	// A key-level change that died between its request and its outcome gets the
	// outcome now, before traffic. A failure is logged, not fatal: the next start retries.
	if _, err := reconcileKeyLevels(ctx, pool, journal, logger, keyLevelReconcileGrace); err != nil {
		logger.Error("key level reconcile failed", "error_class", "reconcile")
	}
	go reconcileKeyLevelsLoop(ctx, pool, journal, logger)
	orgs := orgpki.NewRepoFromLocal(pool, local)
	if err := orgs.PrimeVerificationCache(ctx, func(id uuid.UUID) {
		logger.Error("organization CA unavailable", "org_id", id.String(), "error_class", "pki_integrity")
	}); err != nil {
		fmt.Fprintln(os.Stderr, "refusing to start: organization CA catalog unavailable")
		return 1
	}
	input, err := newInputService(pool, local, cfg.PublicURL, logger)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	expiryCtx, cancelExpiry := context.WithCancel(ctx)
	defer cancelExpiry()
	go expireInputLinks(expiryCtx, input, logger)
	var inputAPI api.InputService
	if input != nil {
		inputAPI = input
	}
	deployments := deployment.NewRepo(pool, audit.NewJournal(pool).WithLogger(logger))
	carrierSvc := carriers.NewService(pool)
	rotations := newRotations(pool, local, deployments, carrierSvc, logger)
	go runPendingLayouts(expiryCtx, wireRotationInput(input, rotations, pool, logger))
	go runPendingLayouts(expiryCtx, rotationResumeSweep(rotations, logger))
	gates, err := wireMeshGate(expiryCtx, cfg, opts, pool, local.MeshVault(), deployments, rotations, logger)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := checkSelfRotateActor(expiryCtx, cfg, opts, pool, local.MeshVault(), logger); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	restarts := restart.NewRepo(pool)
	if err := wireSelfRotate(expiryCtx, cfg, opts, local, restarts, logger); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	deps := api.Deps{
		Jobs:        dispatch.New(pool, audit.NewJournal(pool).WithLogger(logger), orgs, local),
		Input:       inputAPI,
		Deployments: deployments,
		Restarts:    restarts,
		Rotations:   rotations,
		Carriers:    carrierSvc,
		PublicURL:   cfg.PublicURL,
		Notifier:    telegramNotifier(cfg.PublicURL, logger),
		Identity:    identity.NewRepo(pool),
		Catalog:     api.CatalogLimit{PerMinute: cfg.CatalogRatePerMinute, Burst: cfg.CatalogBurst},
		Tokens:      enrolltoken.NewRepo(pool),
		Runners:     registry.NewRepo(pool),
		Certs:       orgpkiCertIssuer{repo: orgs},
		CA:          orgpkiCAResolver{repo: orgs},
	}
	deps.Mesh = meshDeps(cfg, pool, local, auditor, gates, journal, logger)
	go runMeshSync(expiryCtx, cfg, pool, local, logger)
	handler := api.NewRouter(logger, pool, deps)

	srv := newHTTPServer(cfg.HTTPAddr, handler, logger)

	tlsSrv := newHTTPServer(cfg.RunnerAddr, handler, logger)
	tlsSrv.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		// Every org has its own CA, unknowable until a presented
		// certificate's own claimed org_id is read — so this listener
		// only asks for a client certificate; internal/mtls does
		// the actual chain verification at the application layer. See
		// its own doc.
		ClientAuth: tls.RequestClientCert,
	}

	// SIGTERM/SIGINT stop the listeners gracefully, then the outcome queue is
	// flushed: a key-level change that completed just before the stop must not
	// lose its journal outcome with the process.
	sigCtx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-sigCtx.Done()
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(sctx)
		_ = tlsSrv.Shutdown(sctx)
	}()
	code := serveBoth(srv, tlsSrv, logger)
	stopSignals()
	<-stopped
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), drainTimeout)
	defer cancel()
	if err := auditor.Drain(dctx); err != nil { // the count is logged by Drain itself
		logger.Error("keep-server stopping", "error_class", "audit_drain")
	}
	return code
}

// shutdownTimeout bounds the wait for in-flight requests at stop; drainTimeout
// bounds the flush of the outcome queue after that.
const (
	shutdownTimeout = 10 * time.Second
	drainTimeout    = 10 * time.Second
)

// serveBoth binds both listeners, then announces them, then serves until one
// stops. The "listening" line is a readiness signal that tests and supervisors
// act on, so it must not be logged until the sockets accept connections.
func serveBoth(srv, tlsSrv *http.Server, logger *slog.Logger) int {
	plain, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		logger.Error("keep-server stopped", "error_class", "listen_failed")
		return 1
	}
	runner, err := net.Listen("tcp", tlsSrv.Addr)
	if err != nil {
		_ = plain.Close()
		logger.Error("keep-server stopped", "error_class", "listen_failed")
		return 1
	}

	errCh := make(chan error, 2)
	go func() { errCh <- srv.Serve(plain) }()
	go func() { errCh <- tlsSrv.ServeTLS(runner, "", "") }()

	logger.Info(fmt.Sprintf("keep-server listening on %s (plain) and %s (runner mTLS)", srv.Addr, tlsSrv.Addr))
	if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("keep-server stopped", "error_class", "serve_failed")
		return 1
	}
	return 0
}

// newHTTPServer builds a Keep listener with the shared timeouts. ErrorLog is
// always set: left nil, net/http logs TLS and serve errors through the global
// log package to stderr, bypassing internal/obs. Any further listener (the
// runner mTLS one) must be built here too.
func newHTTPServer(addr string, h http.Handler, logger *slog.Logger) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ErrorLog:          obs.ServerErrorLog(logger),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

// telegramNotifier returns the approval notification channel, or nil (and no
// log noise beyond one line) when KEEP_TELEGRAM_BOT_TOKEN or the chat id is
// unset: the server works without it. Only the variable names are known here.
func telegramNotifier(publicURL string, logger *slog.Logger) api.ApprovalNotifier {
	tg := notify.NewTelegram(notify.Config{Token: os.Getenv("KEEP_TELEGRAM_BOT_TOKEN"), ChatID: os.Getenv("KEEP_TELEGRAM_CHAT_ID"), PublicURL: publicURL})
	if tg == nil {
		logger.Info("approval notifications off", "kind", "telegram")
		return nil
	}
	return tg
}

// meshDeps wires the optional Mesh extension: nil (no routes at all) unless
// KEEP_MESH_EXTENSION=1, so Keep's core runs identically without it.
func meshDeps(cfg config.Config, pool *pgxpool.Pool, local *builtin.Local, outcomes *keyLevelAuditor, gates *meshgate.Service, journal audit.Journaler, logger *slog.Logger) *api.MeshDeps {
	if !cfg.MeshExtension {
		return nil
	}
	repo := meshext.NewRepo(pool)
	keyLevels := keyLevelService{pool: pool, local: local, j: journal, log: logger, outcomes: outcomes}
	d := &api.MeshDeps{Vault: meshVault{local.MeshVault()}, Repo: repo,
		Federation: meshext.NewFederation(pool, repo, identity.NewRepo(pool), meshext.NewVerifier(meshext.ExtensionID, nil)),
		KeyLevels:  keyLevels, TrustedProxies: cfg.TrustedProxies}
	if gates != nil { // a nil *Service in the interface would not be nil
		d.Gates = gates
	}
	return d
}

// gateSource is every kind of approval a Mesh gate card may decide: a rotation
// approval first, then a deployment one, as the console does.
type gateSource struct {
	dep *deployment.Repo
	rot any // the rotation service, when there is one
}

// rotationApprovals is the rotation service's side of an approval.
type rotationApprovals interface {
	GetRotationApproval(ctx context.Context, org, id uuid.UUID) (deployment.Approval, error)
	DecideRotation(ctx context.Context, in deployment.DecideInput) (deployment.DecideResult, error)
}

func (g gateSource) GetApproval(ctx context.Context, org, id uuid.UUID) (deployment.Approval, error) {
	if ra, ok := g.rot.(rotationApprovals); ok {
		a, err := ra.GetRotationApproval(ctx, org, id)
		if !errors.Is(err, deployment.ErrNotFound) {
			return a, err
		}
	}
	return g.dep.GetApproval(ctx, org, id)
}

func (g gateSource) Decide(ctx context.Context, in deployment.DecideInput) (deployment.DecideResult, error) {
	if ra, ok := g.rot.(rotationApprovals); ok {
		res, err := ra.DecideRotation(ctx, in)
		if !errors.Is(err, deployment.ErrNotFound) {
			return res, err
		}
	}
	return g.dep.Decide(ctx, in)
}

// meshVault adapts the zone's vault to api.MeshVault: only Checkpoint needs
// it, to return the api interface rather than the concrete zone type.
type meshVault struct{ *builtin.MeshVault }

func (v meshVault) PutSecret(ctx context.Context, org, workspace, ref, value string) (api.MeshSecretMeta, error) {
	m, err := v.MeshVault.PutSecret(ctx, org, workspace, ref, value)
	return api.MeshSecretMeta(m), meshSecretErr(err)
}

func (v meshVault) PutToken(ctx context.Context, org, workspace, token string) (api.MeshSecretMeta, error) {
	m, err := v.MeshVault.PutToken(ctx, org, workspace, token)
	return api.MeshSecretMeta(m), err
}

func (v meshVault) ResolveSecret(ctx context.Context, org, workspace, ref string) ([]byte, api.MeshSecretMeta, error) {
	body, m, err := v.MeshVault.ResolveSecret(ctx, org, workspace, ref)
	return body, api.MeshSecretMeta(m), meshSecretErr(err)
}

// meshSecretErr maps the zone's two named refusals onto the api's; any other
// error stays opaque and is answered as "storage unavailable".
func meshSecretErr(err error) error {
	switch {
	case errors.Is(err, builtin.ErrMeshSecretInvalid):
		return api.ErrMeshSecretInvalid
	case errors.Is(err, builtin.ErrMeshSecretNotFound):
		return api.ErrMeshSecretNotFound
	}
	return err
}

func (v meshVault) Checkpoint(ctx context.Context, org, workspace string) (api.MeshCheckpoint, error) {
	cp, err := v.MeshVault.Checkpoint(ctx, org, workspace)
	if err != nil {
		return nil, err
	}
	return cp, nil
}
