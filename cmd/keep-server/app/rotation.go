package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/entire-vc/evc-keep/internal/api"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/carriers"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/intake"
	"github.com/entire-vc/evc-keep/internal/rotation"
	"github.com/entire-vc/evc-keep/internal/rotation/rotwire"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var errStoreUnavailable = errors.New("rotation: store unavailable")

// builtinProvider is the sealing provider of an active builtin store: the one
// place a catalog store id becomes a provider scope, shared by input links and
// rotation.
func builtinProvider(pool *pgxpool.Pool, local *builtin.Local, st catalog.Store) (*builtin.Provider, error) {
	if st.Provider != "builtin" || st.Status != "active" || local == nil {
		return nil, errStoreUnavailable
	}
	var workspace, project, user string
	switch st.OwnerScope.Level {
	case tenancy.LevelOrg:
		if st.OwnerScope.ID != st.OrgID {
			return nil, errStoreUnavailable
		}
	case tenancy.LevelWorkspace:
		workspace = st.OwnerScope.ID.String()
	case tenancy.LevelProject:
		project = st.OwnerScope.ID.String()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := pool.QueryRow(ctx, `SELECT workspace_id::text FROM projects WHERE org_id=$1 AND id=$2`, st.OrgID, st.OwnerScope.ID).Scan(&workspace); err != nil {
			return nil, errStoreUnavailable
		}
	case tenancy.LevelUser:
		user = st.OwnerScope.ID.String()
	default:
		return nil, errStoreUnavailable
	}
	return local.Provider(st.OrgID.String(), workspace, project, user), nil
}

// rotationParts are the collaborators of the engine that need the sealing
// store. The target of a secret is found on every call from the catalog, so a
// store that was disabled or moved is never rotated through a stale handle.
type rotationParts struct {
	pool     *pgxpool.Pool
	local    *builtin.Local
	cat      *catalog.Catalog
	ledger   *rotation.Ledger
	incident rotation.Incident
	entropy  io.Reader // nil: crypto/rand
}

// target resolves the secret of ref to its provider and what the generator
// issues the key for (the secret id: metadata).
func (p *rotationParts) target(ctx context.Context, ref rotation.Ref) (*builtin.Provider, rotation.Target, error) {
	var storeID uuid.UUID
	var providerRef string
	err := p.pool.QueryRow(ctx, `SELECT store_id, provider_ref FROM secrets WHERE org_id=$1 AND id=$2 AND status='active'`, ref.OrgID, ref.SecretID).Scan(&storeID, &providerRef)
	if err != nil {
		return nil, rotation.Target{}, errStoreUnavailable
	}
	st, err := p.cat.GetStore(ctx, ref.OrgID, storeID)
	if err != nil {
		return nil, rotation.Target{}, errStoreUnavailable
	}
	prov, err := builtinProvider(p.pool, p.local, st)
	if err != nil {
		return nil, rotation.Target{}, err
	}
	return prov, rotation.Target{Store: prov, Ref: provider.Ref{Path: providerRef}, Subject: ref.SecretID.String()}, nil
}

func (p *rotationParts) deps(prov *builtin.Provider, t rotation.Target) rotation.ProviderDeps {
	return rotation.ProviderDeps{
		Provider:       rotation.Generator{Entropy: p.entropy},
		Resolve:        func(context.Context, rotation.Ref) (rotation.Target, error) { return t, nil },
		Ledger:         p.ledger,
		Incident:       p.incident,
		FingerprintKey: prov.FingerprintKey,
	}
}

// rotationVersions is rotation.Versions: the generator issues the value, the
// store seals it, and the catalog gets the new version row so the deployment
// and verification jobs can name it.
type rotationVersions struct{ *rotationParts }

// ForwardOnly: a generated value leaves the old one valid until it is revoked.
func (rotationVersions) ForwardOnly() bool { return false }

func (v rotationVersions) Prepare(ctx context.Context, ref rotation.Ref, runID uuid.UUID) (rotation.Version, error) {
	prov, t, err := v.target(ctx, ref)
	if err != nil {
		return rotation.Version{}, rotation.ErrPrepare
	}
	ver, err := rotation.NewProviderVersions(v.deps(prov, t)).Prepare(ctx, ref, runID)
	if err != nil {
		return rotation.Version{}, err
	}
	if err := v.registerVersion(ctx, ref, t, ver); err != nil {
		return rotation.Version{}, rotation.ErrPrepare
	}
	return ver, nil
}

// NewerSealed reports whether a version sealed after the given one is enabled.
func (v rotationVersions) NewerSealed(ctx context.Context, ref rotation.Ref, version string) (bool, error) {
	var newer bool
	err := v.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM secret_versions n JOIN secret_versions m ON m.org_id=n.org_id AND m.secret_id=n.secret_id
 WHERE n.org_id=$1 AND n.secret_id=$2 AND m.provider_version=$3 AND NOT n.disabled AND n.seal_seq > m.seal_seq)`, ref.OrgID, ref.SecretID, version).Scan(&newer)
	return newer, err
}

// Adopt checks a version a human entered and returns the write that records it
// under the run; the catalog already holds it, intake registered it when the
// value was sealed.
func (v rotationVersions) Adopt(ctx context.Context, ref rotation.Ref, runID uuid.UUID, ver rotation.Version) (rotation.AdoptWrite, error) {
	prov, t, err := v.target(ctx, ref)
	if err != nil {
		return nil, rotation.ErrPrepare
	}
	return rotation.NewProviderVersions(v.deps(prov, t)).Adopt(ctx, ref, runID, ver)
}

// Supersede disables a version that was sealed but never laid out, in the
// provider and then in the catalog.
func (v rotationVersions) Supersede(ctx context.Context, ref rotation.Ref, version string) error {
	_, t, err := v.target(ctx, ref)
	if err != nil {
		return rotation.ErrPrepare
	}
	dis := t.Ref
	dis.Version = version
	if err := t.Store.Disable(ctx, dis); err != nil && !errors.Is(err, provider.ErrNotFound) {
		return rotation.ErrPrepare
	}
	if _, err := v.pool.Exec(ctx, `UPDATE secret_versions SET disabled=true WHERE org_id=$1 AND secret_id=$2 AND provider_version=$3`, ref.OrgID, ref.SecretID, version); err != nil {
		return rotation.ErrPrepare
	}
	return nil
}

// registerVersion records the sealed version in the catalog, once.
func (p *rotationParts) registerVersion(ctx context.Context, ref rotation.Ref, t rotation.Target, ver rotation.Version) error {
	var n int
	if err := p.pool.QueryRow(ctx, `SELECT count(*) FROM secret_versions WHERE org_id=$1 AND secret_id=$2 AND provider_version=$3`, ref.OrgID, ref.SecretID, ver.New).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	meta, err := t.Store.Version(ctx, t.Ref)
	if err != nil || meta.Version != ver.New {
		return errStoreUnavailable
	}
	_, err = p.cat.AddVersion(ctx, ref.OrgID, ref.SecretID, ver.New, ver.Fingerprint, meta.Length)
	return err
}

// rotationRevoker is rotation.Revoker: the provider disables the old version
// and the catalog row follows.
type rotationRevoker struct{ *rotationParts }

// MarkDeployed points the secret at the version every carrier confirmed. It
// only moves forward in seal order: a late or repeated call for an older
// version changes nothing.
func (r rotationRevoker) MarkDeployed(ctx context.Context, ref rotation.Ref, runID uuid.UUID, version string) error {
	if _, err := r.pool.Exec(ctx, `UPDATE secrets s SET deployed_version=$3
 WHERE s.org_id=$1 AND s.id=$2 AND EXISTS(SELECT 1 FROM secret_versions n WHERE n.org_id=$1 AND n.secret_id=$2 AND n.provider_version=$3)
   AND (s.deployed_version IS NULL OR s.deployed_version=$3
     OR (SELECT d.seal_seq FROM secret_versions d WHERE d.org_id=$1 AND d.secret_id=$2 AND d.provider_version=s.deployed_version)
        < (SELECT n.seal_seq FROM secret_versions n WHERE n.org_id=$1 AND n.secret_id=$2 AND n.provider_version=$3))`, ref.OrgID, ref.SecretID, version); err != nil {
		return rotation.ErrRevoke
	}
	return nil
}

func (r rotationRevoker) Revoke(ctx context.Context, ref rotation.Ref, runID uuid.UUID, oldVersion string) error {
	prov, t, err := r.target(ctx, ref)
	if err != nil {
		return rotation.ErrRevoke
	}
	if err := rotation.NewProviderRevoker(r.deps(prov, t)).Revoke(ctx, ref, runID, oldVersion); err != nil {
		return err
	}
	if _, err := r.pool.Exec(ctx, `UPDATE secret_versions SET disabled=true WHERE org_id=$1 AND secret_id=$2 AND provider_version=$3`, ref.OrgID, ref.SecretID, oldVersion); err != nil {
		return rotation.ErrRevoke
	}
	return r.retireOlder(ctx, ref, t, runID)
}

// retireOlder makes the end state independent of the order inputs were handled
// in and keeps "exactly one active version" true at every moment: under the
// lock of the secret's row (sealing an input holds a share lock of the same row, internal/intake) every enabled version but
// the last sealed one is disabled. A human input sealed after the run's version
// stays active and the run's version goes; the pointer deployed_version is not
// touched. It is idempotent.
func (r rotationRevoker) retireOlder(ctx context.Context, ref rotation.Ref, t rotation.Target, runID uuid.UUID) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return rotation.ErrRevoke
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, rotationLockRow, ref.OrgID, ref.SecretID); err != nil {
		return rotation.ErrRevoke
	}
	rows, err := tx.Query(ctx, `SELECT v.provider_version FROM secret_versions v
 WHERE v.org_id=$1 AND v.secret_id=$2 AND NOT v.disabled
   AND v.seal_seq < (SELECT max(m.seal_seq) FROM secret_versions m WHERE m.org_id=$1 AND m.secret_id=$2 AND NOT m.disabled)`, ref.OrgID, ref.SecretID)
	if err != nil {
		return rotation.ErrRevoke
	}
	var stale []string
	for rows.Next() {
		var v string
		if rows.Scan(&v) != nil {
			rows.Close()
			return rotation.ErrRevoke
		}
		stale = append(stale, v)
	}
	rows.Close()
	if rows.Err() != nil {
		return rotation.ErrRevoke
	}
	for _, v := range stale {
		dis := t.Ref
		dis.Version = v
		if err := t.Store.Disable(ctx, dis); err != nil && !errors.Is(err, provider.ErrNotFound) {
			return rotation.ErrRevoke
		}
		if _, err := tx.Exec(ctx, `UPDATE secret_versions SET disabled=true WHERE org_id=$1 AND secret_id=$2 AND provider_version=$3`, ref.OrgID, ref.SecretID, v); err != nil {
			return rotation.ErrRevoke
		}
	}
	if tx.Commit(ctx) != nil {
		return rotation.ErrRevoke
	}
	return nil
}

// rotationLockRow is the row lock of a secret that serialises sealing a
// version and retiring the older ones.
const rotationLockRow = `SELECT 1 FROM secrets WHERE org_id=$1 AND id=$2 FOR UPDATE`

// newRotations wires the rotation service of keep-server: a generated value,
// the carriers of the catalog, and deployment and verification through the
// signed runner jobs. Without the sealing store there is nothing to rotate and
// the routes answer not_ready.
func newRotations(pool *pgxpool.Pool, local *builtin.Local, deployments *deployment.Repo, car *carriers.Service, logger *slog.Logger) api.RotationService {
	return newRotationsWith(nil, pool, local, deployments, car, logger)
}

// newRotationsWith is newRotations with the generator's entropy source set, so
// a test knows the generated value without reading it back out of the store.
func newRotationsWith(entropy io.Reader, pool *pgxpool.Pool, local *builtin.Local, deployments *deployment.Repo, car *carriers.Service, logger *slog.Logger) api.RotationService {
	if pool == nil || local == nil || deployments == nil || car == nil {
		return nil
	}
	parts := &rotationParts{pool: pool, local: local, cat: catalog.New(pool), ledger: rotation.NewLedger(pool), incident: rotwire.Incident{Log: logger}, entropy: entropy}
	runner := &rotwire.Deployer{Pool: pool, Carriers: car, Deployments: deployments}
	svc := rotation.NewService(rotation.New(pool, rotation.Deps{
		Versions: rotationVersions{parts},
		Carriers: rotwire.Lister{Source: car},
		Deployer: runner,
		Verifier: runner,
		Revoker:  rotationRevoker{parts},
		Incident: parts.incident,
	}))
	return svc.WithJournal(audit.NewJournal(pool).WithLogger(logger))
}

// rotationResumeSweep returns the sweeper that takes back every run nothing
// drives any more: the goroutine that launched it died with a failed hook or a
// crashed process, and the run row is all that is left. The run id keys the
// engine, so relaunching one continues it (nil when there is nothing to wire).
func rotationResumeSweep(rotations api.RotationService, logger *slog.Logger) func(context.Context) {
	// The concrete type, as in wireRotationInput: a changed signature must stop
	// the build instead of leaving the sweep unwired.
	svc, ok := rotations.(*rotation.Service)
	if !ok {
		return nil
	}
	return func(ctx context.Context) {
		n, err := svc.Resume(ctx)
		if err != nil && ctx.Err() == nil {
			logger.Error("rotation resume failed", "error_class", "rotation_unavailable")
			return
		}
		if n > 0 {
			logger.Info(fmt.Sprintf("rotation runs resumed: %d", n))
		}
	}
}

// pendingLayout is a completed input link of a rotation that no run has laid
// out yet. It lives in the database from the moment the value is sealed, so a
// failed hook, a crashed process or a restart loses nothing.
type pendingLayout struct {
	org, request, secret uuid.UUID
	version, fp          string
	token                uuid.UUID // this worker's claim
}

// rotationInputs lays out the values humans entered through rotation links.
type rotationInputs struct {
	starter *rotation.Service
	pool    *pgxpool.Pool
	logger  *slog.Logger
}

// wireRotationInput starts the layout when a human finishes entering a value
// through a link a rotation issued, and returns the sweeper that finishes every
// layout the hook could not start (nil when there is nothing to wire).
func wireRotationInput(input *intake.Service, rotations api.RotationService, pool *pgxpool.Pool, logger *slog.Logger) func(context.Context) {
	// The concrete type, not an interface assertion: a changed signature must
	// stop the build instead of silently leaving the hook unwired.
	starter, ok := rotations.(*rotation.Service)
	if input == nil || !ok {
		return nil
	}
	ri := &rotationInputs{starter: starter, pool: pool, logger: logger}
	input.OnRotationInput(func(ctx context.Context, c intake.Completed) {
		// The hook is the fast path; whatever it leaves is the sweeper's.
		ri.run(context.WithoutCancel(ctx), ri.claim(ctx, c.Org, &c.Request))
	})
	return ri.sweep
}

// How often pending layouts are retried, and how long a failed one is left alone.
// Variables so a test does not wait for the real period.
var (
	rotationRetryEvery   = 5 * time.Second
	rotationRetryBackoff = 30 * time.Second
	rotationMaxAttempts  = 60 // about half an hour of a failure that stays
)

// runPendingLayouts sweeps once at start (a restart picks up what the last
// process left) and then every rotationRetryEvery until ctx ends.
func runPendingLayouts(ctx context.Context, sweep func(context.Context)) {
	if sweep == nil {
		return
	}
	t := time.NewTicker(rotationRetryEvery)
	defer t.Stop()
	for {
		sweep(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// claim takes pending layouts for this worker: one request when given, else a
// batch. The claim expires, so a worker that dies holds nothing for long.
func (ri *rotationInputs) claim(ctx context.Context, org uuid.UUID, request *uuid.UUID) []pendingLayout {
	token := uuid.New()
	var req any
	if request != nil {
		req = *request
	}
	rows, err := ri.pool.Query(ctx, `UPDATE intake_rotation_links r SET claimed_until=clock_timestamp()+interval '2 minutes', claim_token=$3
 FROM intake_links l
 WHERE r.request_id IN (SELECT r2.request_id FROM intake_rotation_links r2 JOIN intake_links l2 ON l2.org_id=r2.org_id AND l2.request_id=r2.request_id
   WHERE l2.state='completed' AND r2.started_at IS NULL AND (r2.claimed_until IS NULL OR r2.claimed_until<clock_timestamp())
     AND ($2::uuid IS NULL OR r2.request_id=$2) AND ($1::uuid IS NULL OR r2.org_id=$1) LIMIT 20 FOR UPDATE OF r2 SKIP LOCKED)
   AND l.org_id=r.org_id AND l.request_id=r.request_id
 RETURNING r.org_id, r.request_id, l.secret_id, l.version, l.fingerprint`, nilIfZero(org), req, token)
	if err != nil {
		ri.logger.Error("rotation after input not started", "error_class", "rotation_unavailable")
		return nil
	}
	defer rows.Close()
	var out []pendingLayout
	for rows.Next() {
		var p pendingLayout
		p.token = token
		if err := rows.Scan(&p.org, &p.request, &p.secret, &p.version, &p.fp); err != nil {
			ri.logger.Error("rotation after input not started", "error_class", "rotation_unavailable")
			continue
		}
		out = append(out, p)
	}
	if rows.Err() != nil {
		ri.logger.Error("rotation after input not started", "error_class", "rotation_unavailable")
	}
	return out
}

func nilIfZero(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}

func (ri *rotationInputs) sweep(ctx context.Context) {
	ri.run(ctx, ri.claim(ctx, uuid.Nil, nil))
}

func (ri *rotationInputs) run(ctx context.Context, batch []pendingLayout) {
	for _, p := range batch {
		ri.layout(ctx, p)
	}
}

// release leaves the row pending, to be tried again after wait.
func (ri *rotationInputs) release(ctx context.Context, p pendingLayout, wait time.Duration) {
	_, _ = ri.pool.Exec(ctx, `UPDATE intake_rotation_links SET claimed_until=clock_timestamp()+$3::interval WHERE org_id=$1 AND request_id=$2 AND started_at IS NULL AND claim_token=$4`, p.org, p.request, wait.String(), p.token)
}

// finish ends the pending state: the layout began, or can never begin.
func (ri *rotationInputs) finish(ctx context.Context, p pendingLayout) bool {
	_, err := ri.pool.Exec(ctx, `UPDATE intake_rotation_links SET started_at=clock_timestamp(), claimed_until=NULL, claim_token=NULL WHERE org_id=$1 AND request_id=$2`, p.org, p.request)
	return err == nil
}

// layout starts the run for one pending input. The old version is the newest
// enabled one that was actually laid out: a sealed value still waiting for its
// own layout is no predecessor, and revoking it would leave the deployed
// version active. "Newer" is the order the values were sealed in (the order
// verify reads the current version by), not the order the links were issued.
// A busy secret (another run is active) or a transient failure leaves the row
// pending; the sweeper comes back to it.
//
// Order of sealed inputs of one secret: secret_versions.seal_seq, everywhere
// (newer-input check, predecessor, retireOlder). newest = the last sealed
// input; the sequence is unique, so there is no tie. Which version is laid out
// is state, not order: secrets.deployed_version.
func (ri *rotationInputs) layout(ctx context.Context, p pendingLayout) {
	// Ownership is rechecked right before any work: a claim that expired while
	// an earlier row of the batch was slow may belong to another worker now.
	var mine bool
	if ri.pool.QueryRow(ctx, `UPDATE intake_rotation_links SET claimed_until=clock_timestamp()+interval '2 minutes', attempts=attempts WHERE org_id=$1 AND request_id=$2 AND started_at IS NULL AND claim_token=$3 RETURNING true`, p.org, p.request, p.token).Scan(&mine) != nil || !mine {
		return
	}
	fail := func(class string, wait time.Duration) {
		// A failure that does not go away is given up on, not logged forever.
		var n int
		_ = ri.pool.QueryRow(ctx, `UPDATE intake_rotation_links SET attempts=attempts+1 WHERE org_id=$1 AND request_id=$2 AND claim_token=$3 RETURNING attempts`, p.org, p.request, p.token).Scan(&n)
		if n >= rotationMaxAttempts {
			ri.logger.Error("rotation after input abandoned", "org_id", p.org.String(), "secret_id", p.secret.String(), "error_class", class)
			ri.finish(ctx, p)
			return
		}
		ri.logger.Error("rotation after input not started", "org_id", p.org.String(), "secret_id", p.secret.String(), "error_class", class)
		ri.release(ctx, p, wait)
	}
	// A busy secret waits without touching the ledger: Adopt writes a row, and
	// a retry every few seconds must not pile those up.
	var busy bool
	if err := ri.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM rotation_runs WHERE org_id=$1 AND secret_id=$2 AND state NOT IN ('done','failed'))`, p.org, p.secret).Scan(&busy); err == nil && busy {
		ri.release(ctx, p, rotationRetryEvery)
		return
	}
	// A newer sealed input of the secret, one that is pending or has a run and
	// is not disabled, replaces this one: laying this one out would fail its
	// own verify (it is not the newest) and a stale value must never be
	// deployed. It is retired. A version that already has a run is never retired.
	var newer, started, gone bool
	if err := ri.pool.QueryRow(ctx, `SELECT
 EXISTS(SELECT 1 FROM rotation_runs WHERE org_id=$1 AND secret_id=$2 AND new_version=$3),
 COALESCE((SELECT disabled FROM secret_versions WHERE org_id=$1 AND secret_id=$2 AND provider_version=$3), false),
 EXISTS(SELECT 1 FROM intake_rotation_links o
 JOIN intake_links ol ON ol.org_id=o.org_id AND ol.request_id=o.request_id
 JOIN secret_versions ov ON ov.org_id=ol.org_id AND ov.secret_id=ol.secret_id AND ov.provider_version=ol.version
 JOIN secret_versions mv ON mv.org_id=$1 AND mv.secret_id=$2 AND mv.provider_version=$3
 WHERE o.org_id=$1 AND ol.secret_id=$2 AND ol.state='completed' AND NOT ov.disabled
   AND ov.provider_version<>mv.provider_version AND ov.seal_seq > mv.seal_seq
   AND (o.started_at IS NULL OR EXISTS(SELECT 1 FROM rotation_runs r WHERE r.org_id=o.org_id AND r.secret_id=ol.secret_id AND r.new_version=ol.version)))`,
		p.org, p.secret, p.version).Scan(&started, &gone, &newer); err != nil {
		fail("rotation_unavailable", rotationRetryBackoff)
		return
	}
	if started {
		// A run already carries this version (only the mark was lost): it is
		// deployed or on its way, never to be retired.
		ri.finish(ctx, p)
		return
	}
	if gone {
		// Already retired (a later rotation of the secret disabled it): there
		// is nothing to lay out, and a disabled version is never deployed.
		ri.finish(ctx, p)
		return
	}
	if newer {
		if err := ri.starter.Supersede(ctx, rotation.Ref{OrgID: p.org, SecretID: p.secret}, p.version); err != nil {
			fail("rotation_unavailable", rotationRetryBackoff)
			return
		}
		ri.logger.Info("rotation after input superseded", "org_id", p.org.String(), "secret_id", p.secret.String())
		ri.finish(ctx, p)
		return
	}
	// The predecessor is the version that is actually laid out: the secret's
	// deployed_version pointer, kept by MarkDeployed when a run confirmed it on
	// every carrier. A secret no run has deployed yet falls back to the newest
	// earlier version that did not come from a rotation input link (a plain
	// input link or a direct write); a sealed input without a finished run is
	// never a predecessor. Order is seal_seq, never a timestamp, and
	// started_at (the sweeper's pending mark) plays no part.
	var old string
	err := ri.pool.QueryRow(ctx, `SELECT COALESCE(
 (SELECT s.deployed_version FROM secrets s
   JOIN secret_versions d ON d.org_id=s.org_id AND d.secret_id=s.id AND d.provider_version=s.deployed_version
   JOIN secret_versions cur ON cur.org_id=s.org_id AND cur.secret_id=s.id AND cur.provider_version=$3
  WHERE s.org_id=$1 AND s.id=$2 AND d.seal_seq < cur.seal_seq),
 (SELECT v.provider_version FROM secret_versions v
   JOIN secret_versions cur ON cur.org_id=v.org_id AND cur.secret_id=v.secret_id AND cur.provider_version=$3
  WHERE v.org_id=$1 AND v.secret_id=$2 AND NOT v.disabled AND v.seal_seq < cur.seal_seq
    AND NOT EXISTS(SELECT 1 FROM intake_links il JOIN intake_rotation_links rl ON rl.org_id=il.org_id AND rl.request_id=il.request_id
        WHERE il.org_id=v.org_id AND il.secret_id=v.secret_id AND il.version=v.provider_version)
  ORDER BY v.seal_seq DESC LIMIT 1), '')`, p.org, p.secret, p.version).Scan(&old)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		fail("rotation_unavailable", rotationRetryBackoff)
		return
	}
	var (
		name, class, level string
		scopeID            uuid.UUID
	)
	err = ri.pool.QueryRow(ctx, `SELECT name, class, scope_level, scope_id FROM secrets WHERE org_id=$1 AND id=$2`, p.org, p.secret).Scan(&name, &class, &level, &scopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		// The secret is gone: no layout can ever follow.
		ri.logger.Error("rotation after input abandoned", "org_id", p.org.String(), "secret_id", p.secret.String(), "error_class", "secret_gone")
		ri.finish(ctx, p)
		return
	}
	if err != nil {
		fail("rotation_unavailable", rotationRetryBackoff)
		return
	}
	ref, v := rotation.Ref{OrgID: p.org, SecretID: p.secret}, rotation.Version{Old: old, New: p.version, Fingerprint: p.fp}
	origin := rotation.Origin{Actor: audit.Actor{Type: audit.ActorSystem, ID: "human-input", Via: audit.ViaAPI},
		Scope: tenancy.Scope{Level: tenancy.Level(level), ID: scopeID}.String(), Name: name, Class: class}
	_, err = ri.starter.StartPrepared(ctx, ref, v, origin)
	switch {
	case err == nil:
		if !ri.finish(ctx, p) {
			// The run exists; only the mark failed. The claim expires and the
			// sweeper meets ErrConflict or lays the same version out again.
			ri.logger.Error("rotation after input not marked", "org_id", p.org.String(), "secret_id", p.secret.String(), "error_class", "rotation_unavailable")
		}
	case errors.Is(err, rotation.ErrConflict):
		// Another run of the secret is active: the sealed version waits for it.
		ri.release(ctx, p, rotationRetryEvery)
	case errors.Is(err, rotation.ErrPreparedProd):
		ri.logger.Error("rotation after input abandoned", "org_id", p.org.String(), "secret_id", p.secret.String(), "error_class", "prepared_prod")
		ri.finish(ctx, p)
	default:
		fail("rotation_unavailable", rotationRetryBackoff)
	}
}
