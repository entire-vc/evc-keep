package carriers

import (
	"context"
	"crypto/subtle"
	"errors"

	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Repository stores approved destinations. All org arguments must come from
// authenticated identity, never from request bodies. Database and policy
// errors are replaced with fixed errors, including their unwrap chains.
type Repository struct {
	pool   *pgxpool.Pool
	policy MetadataPolicy
}

func New(pool *pgxpool.Pool, policy MetadataPolicy) *Repository {
	return &Repository{pool: pool, policy: policy}
}

// Register is atomic and idempotent for (org, secret, host, target). A retry
// preserves id and created_at and updates only the confirmed deployment.
// The version/fingerprint must be the catalog's latest enabled version.
// Callers must set a bounded deadline and use a context-aware MetadataPolicy;
// policy approval runs under the secret/version locks until commit/rollback.
func (r *Repository) Register(ctx context.Context, org uuid.UUID, in Registration) (Carrier, error) {
	tx, err := r.begin(ctx)
	if err != nil {
		return Carrier{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	version, expected, err := current(ctx, tx, org, in.SecretID)
	if err != nil {
		return Carrier{}, err
	}
	if r.policy == nil {
		return Carrier{}, ErrMetadata
	}
	allowed, err := r.policy.Approved(ctx, org, in.SecretID, in.Metadata)
	if err != nil || !allowed {
		return Carrier{}, ErrMetadata
	}
	if in.Version != version || !validObservation(in.LastFP, expected) || !sameFingerprint(in.LastFP, expected) {
		return Carrier{}, ErrFingerprint
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Carrier{}, ErrInternal
	}
	c, err := scanCarrier(tx.QueryRow(ctx, `
 INSERT INTO carriers(org_id,id,secret_id,version,host,target_kind,target_path,target_field,consumer,healthcheck_ref,last_fp,state,last_verified_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'registered',now())
 ON CONFLICT (org_id,secret_id,host,target_kind,target_path,target_field)
 DO UPDATE SET version=EXCLUDED.version, consumer=EXCLUDED.consumer,
 healthcheck_ref=EXCLUDED.healthcheck_ref, last_fp=EXCLUDED.last_fp,
 state='registered', updated_at=now(), last_verified_at=now()
 RETURNING `+columns,
		org, id, in.SecretID, version, in.Host, in.TargetKind, in.TargetPath, in.TargetField, in.Consumer, in.HealthcheckRef, in.LastFP))
	if err != nil {
		return Carrier{}, ErrInternal // Never expose the database error.
	}
	if err = tx.Commit(ctx); err != nil {
		return Carrier{}, ErrInternal // Register commit failed; never expose its error.
	}
	return c, nil
}

const columns = `id,org_id,secret_id,version,host,target_kind,target_path,target_field,consumer,healthcheck_ref,last_fp,state,created_at,updated_at,last_verified_at`

func scanCarrier(row pgx.Row) (Carrier, error) {
	var c Carrier
	err := row.Scan(&c.ID, &c.OrgID, &c.SecretID, &c.Version, &c.Host, &c.TargetKind, &c.TargetPath, &c.TargetField, &c.Consumer, &c.HealthcheckRef, &c.LastFP, &c.State, &c.CreatedAt, &c.UpdatedAt, &c.LastVerifiedAt)
	return c, err
}

func (r *Repository) begin(ctx context.Context) (pgx.Tx, error) {
	if r == nil || r.pool == nil {
		return nil, ErrInternal
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, ErrInternal // Begin failed; never expose its error.
	}
	return tx, nil
}

// current locks the secret before reading versions. The FK's key-share
// lock on a concurrent AddVersion conflicts with this lock, so it cannot
// slip a new version between the current-version check and a carrier write.
// Version strings are opaque; recency uses catalog timestamps and UUIDs.
func current(ctx context.Context, tx pgx.Tx, org, id uuid.UUID) (string, string, error) {
	var found uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM secrets WHERE org_id=$1 AND id=$2 AND status='active' FOR UPDATE`, org, id).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrNotFound
	}
	if err != nil {
		return "", "", ErrInternal // Secret lookup failed; never expose its error.
	}
	var version, fp string
	err = tx.QueryRow(ctx, `SELECT provider_version,fingerprint FROM secret_versions WHERE org_id=$1 AND secret_id=$2 AND NOT disabled ORDER BY seal_seq DESC LIMIT 1 FOR SHARE`, org, id).Scan(&version, &fp)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrNotFound
	}
	if err != nil {
		return "", "", ErrInternal // Version lookup failed; never expose its error.
	}
	if _, err = fingerprint.Parse(fp); err != nil {
		return "", "", ErrFingerprint
	}
	return version, fp, nil
}

func sameFingerprint(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func validObservation(observed, expected string) bool {
	a, err := fingerprint.Parse(observed)
	if err != nil {
		return false
	}
	b, err := fingerprint.Parse(expected)
	return err == nil && a.KeyID == b.KeyID
}

// List conceals a foreign secret exactly like an absent secret. An owned
// secret with no destinations returns an empty slice.
func (r *Repository) List(ctx context.Context, org, id uuid.UUID) ([]Carrier, error) {
	tx, err := r.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var found uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id FROM secrets WHERE org_id=$1 AND id=$2`, org, id).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, ErrInternal // List lookup failed; never expose its error.
	}
	rows, err := tx.Query(ctx, `SELECT `+columns+` FROM carriers WHERE org_id=$1 AND secret_id=$2 ORDER BY host,target_kind,target_path,target_field,id`, org, id)
	if err != nil {
		return nil, ErrInternal // List query failed; never expose its error.
	}
	defer rows.Close()
	out := []Carrier{}
	for rows.Next() {
		c, err := scanCarrier(rows)
		if err != nil {
			return nil, ErrInternal // List scan failed; never expose its error.
		}
		out = append(out, c)
	}
	if rows.Err() != nil {
		return nil, ErrInternal // List iteration failed; never expose its error.
	}
	return out, nil
}

// MarkStale records a well-formed observation under the catalog's key.
// MarkOK additionally requires an exact match with the current catalog
// fingerprint, so an old deployment cannot mark a newer version healthy.
func (r *Repository) MarkStale(ctx context.Context, org, id uuid.UUID, fp string) error {
	return r.mark(ctx, org, id, fp, Stale)
}
func (r *Repository) MarkOK(ctx context.Context, org, id uuid.UUID, fp string) error {
	return r.mark(ctx, org, id, fp, Registered)
}
func (r *Repository) mark(ctx context.Context, org, id uuid.UUID, fp string, state State) error {
	tx, err := r.begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var secretID uuid.UUID
	// Do not lock a carrier before the secret: Register takes them in the
	// opposite order and that would allow a deadlock against MarkOK.
	err = tx.QueryRow(ctx, `SELECT secret_id FROM carriers WHERE org_id=$1 AND id=$2`, org, id).Scan(&secretID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return ErrInternal // Carrier lookup failed; never expose its error.
	}
	version, expected, err := current(ctx, tx, org, secretID)
	if err != nil {
		return err
	}
	if !validObservation(fp, expected) || (state == Registered && !sameFingerprint(fp, expected)) {
		return ErrFingerprint
	}
	query := `UPDATE carriers SET last_fp=$3,state=$4,updated_at=now(),last_verified_at=now() WHERE org_id=$1 AND id=$2`
	args := []any{org, id, fp, string(state)}
	if state == Registered {
		query = `UPDATE carriers SET last_fp=$3,state=$4,updated_at=now(),last_verified_at=now(),version=$5 WHERE org_id=$1 AND id=$2`
		args = append(args, version)
	}
	tag, err := tx.Exec(ctx, query, args...)
	if err != nil {
		return ErrInternal
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	if err = tx.Commit(ctx); err != nil {
		return ErrInternal // Mark commit failed; never expose its error.
	}
	return nil
}

// MarkUnknown records an unavailable host/check without pretending the
// destination is lost. It does not change versions or revoke anything.
func (r *Repository) MarkUnknown(ctx context.Context, org, id uuid.UUID) error {
	return r.change(ctx, `UPDATE carriers SET state='unknown',updated_at=now(),last_verified_at=NULL WHERE org_id=$1 AND id=$2`, org, id)
}
func (r *Repository) Remove(ctx context.Context, org, id uuid.UUID) error {
	return r.change(ctx, `DELETE FROM carriers WHERE org_id=$1 AND id=$2`, org, id)
}
func (r *Repository) change(ctx context.Context, query string, org, id uuid.UUID) error {
	if r == nil || r.pool == nil {
		return ErrInternal
	}
	tag, err := r.pool.Exec(ctx, query, org, id)
	if err != nil {
		return ErrInternal
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	return nil
}

// OnDeployed accepts only a successful, version-bound and fingerprint-bound
// result. Runner authentication and job authorization belong to the caller.
func (r *Repository) OnDeployed(ctx context.Context, org uuid.UUID, in Registration, result runnerproto.Result) error {
	if !result.OK || result.ErrorClass != "" || result.Version != in.Version || !sameFingerprint(result.Fingerprint, in.LastFP) {
		return ErrDeployment
	}
	if result.Healthcheck != nil && result.Healthcheck.Status != runnerproto.HealthOK && result.Healthcheck.Status != runnerproto.HealthSkipped {
		return ErrDeployment
	}
	_, err := r.Register(ctx, org, in)
	return err
}
