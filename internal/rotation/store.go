package rotation

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var errNotClaimed = errors.New("rotation: lease not claimed")

type store struct{ pool *pgxpool.Pool }

type runRow struct {
	ID             uuid.UUID
	Ref            Ref
	State          State
	OldVersion     string
	NewVersion     string
	ExpectedFP     string
	Class          Class
	IncidentOpened bool
	NewLength      int
}

type stepRow struct {
	CarrierID string
	Deploy    string
	Verify    string
}

// start creates the run row if it is new. A second active run of the same
// secret hits the partial unique index and is a conflict.
func (s *store) start(ctx context.Context, ref Ref, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO rotation_runs(id, org_id, secret_id, state)
		VALUES ($1,$2,$3,'new_version') ON CONFLICT (id) DO NOTHING`, id, ref.OrgID, ref.SecretID)
	if isActiveRunConflict(err) {
		return s.conflictAnswer(ctx, ref)
	}
	if err != nil {
		return err
	}
	var org, sec uuid.UUID
	if err := s.pool.QueryRow(ctx, `SELECT org_id, secret_id FROM rotation_runs WHERE id=$1`, id).Scan(&org, &sec); err != nil {
		return err
	}
	if org != ref.OrgID || sec != ref.SecretID {
		return ErrNotFound
	}
	return nil
}

func isActiveRunConflict(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505" && pe.ConstraintName == "rotation_runs_one_active_idx"
}

// conflictAnswer names the run in the way. It may be one whose only open step
// is revoking the old key: that is a different answer from "a run is in progress".
func (s *store) conflictAnswer(ctx context.Context, ref Ref) error {
	var pending bool
	if qe := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM rotation_runs
		WHERE org_id=$1 AND secret_id=$2 AND state='revoking_old' AND error_class=$3)`,
		ref.OrgID, ref.SecretID, string(ClassRevokeFailed)).Scan(&pending); qe == nil && pending {
		return ErrRevokePending
	}
	return ErrConflict
}

// startTx inserts a new run row inside tx; the caller commits it together with
// the request record, so a run never exists without its record.
func (s *store) startTx(ctx context.Context, tx pgx.Tx, ref Ref, id uuid.UUID) error {
	_, err := tx.Exec(ctx, `INSERT INTO rotation_runs(id, org_id, secret_id, state)
		VALUES ($1,$2,$3,'new_version')`, id, ref.OrgID, ref.SecretID)
	return err
}

// claim takes the lease and returns its epoch. The epoch is the secret's
// counter, bumped in the same statement that takes the lease: it is strictly
// above every epoch ever issued for the secret, by this run or an earlier one,
// so a carrier that accepted a lower one never refuses a later run. The run row
// is locked first, then the counter row, so two claims of a secret serialize.
func (s *store) claim(ctx context.Context, id uuid.UUID, owner string, now time.Time, ttl time.Duration) (int64, error) {
	var epoch int64
	err := s.pool.QueryRow(ctx, `WITH c AS (
			SELECT id, org_id, secret_id FROM rotation_runs
			WHERE id=$1 AND (state NOT IN ('done','failed') OR (state='failed' AND NOT incident_opened))
			  AND (lease_owner='' OR lease_until IS NULL OR lease_until < $4 OR lease_owner=$2)
			FOR UPDATE),
		e AS (
			INSERT INTO rotation_secret_epochs(org_id, secret_id, epoch)
			SELECT org_id, secret_id, 1 FROM c
			ON CONFLICT (org_id, secret_id) DO UPDATE SET epoch = rotation_secret_epochs.epoch + 1
			RETURNING epoch)
		UPDATE rotation_runs r SET lease_owner=$2, lease_until=$3, updated_at=$4, lease_epoch=(SELECT epoch FROM e)
		FROM c WHERE r.id=c.id
		RETURNING r.lease_epoch`, id, owner, now.Add(ttl), now).Scan(&epoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, errNotClaimed
	}
	return epoch, err
}

// renew extends the lease while owner still holds it. A takeover by another
// caller (different owner) makes it return errNotClaimed.
func (s *store) renew(ctx context.Context, id uuid.UUID, l *lease, now time.Time, ttl time.Duration) error {
	tag, err := s.pool.Exec(ctx, `UPDATE rotation_runs SET lease_until=$4 WHERE id=$1 AND lease_owner=$2 AND lease_epoch=$3`, id, l.owner, l.epoch, now.Add(ttl))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errNotClaimed
	}
	return nil
}

// holds reports whether the lease (owner and epoch) is the run's current one
// and unexpired.
func (s *store) holds(ctx context.Context, id uuid.UUID, l *lease, now time.Time) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM rotation_runs WHERE id=$1 AND lease_owner=$2 AND lease_epoch=$3 AND lease_until >= $4)`, id, l.owner, l.epoch, now).Scan(&ok)
	return ok, err
}

func (s *store) release(ctx context.Context, id uuid.UUID, l *lease) error {
	_, err := s.pool.Exec(ctx, `UPDATE rotation_runs SET lease_owner='', lease_until=NULL WHERE id=$1 AND lease_owner=$2 AND lease_epoch=$3`, id, l.owner, l.epoch)
	return err
}

func (s *store) load(ctx context.Context, id uuid.UUID) (runRow, error) {
	var r runRow
	var st, cl string
	err := s.pool.QueryRow(ctx, `SELECT id, org_id, secret_id, state, old_version, new_version, expected_fp, error_class, incident_opened, new_length
		FROM rotation_runs WHERE id=$1`, id).Scan(&r.ID, &r.Ref.OrgID, &r.Ref.SecretID, &st, &r.OldVersion, &r.NewVersion, &r.ExpectedFP, &cl, &r.IncidentOpened, &r.NewLength)
	r.State, r.Class = State(st), Class(cl)
	return r, err
}

// begin records the versions and the carrier steps and moves to deploying in
// one transaction.
func (s *store) begin(ctx context.Context, id uuid.UUID, v Version, carriers []string) error {
	l := leaseOf(ctx)
	if l == nil {
		return ErrLeaseLost
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, c := range carriers {
		if _, err := tx.Exec(ctx, `INSERT INTO rotation_steps(run_id, carrier_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, id, c); err != nil {
			return err
		}
	}
	tag, err := tx.Exec(ctx, `UPDATE rotation_runs SET state='deploying', old_version=$2, new_version=$3, expected_fp=$4, new_length=$7, updated_at=now()
		WHERE id=$1 AND state='new_version' AND lease_owner=$5 AND lease_epoch=$6`, id, v.Old, v.New, v.Fingerprint, l.owner, l.epoch, max(v.Length, 0))
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrLeaseLost
	}
	return tx.Commit(ctx)
}

// The writes below are fenced: they change the row only for the caller whose
// lease (owner and epoch) is the run's current one. A caller that lost its
// lease gets ErrLeaseLost and overwrites nothing of the new owner's.
func (s *store) setState(ctx context.Context, id uuid.UUID, from, to State, c Class) error {
	l := leaseOf(ctx)
	if l == nil {
		return ErrLeaseLost
	}
	tag, err := s.pool.Exec(ctx, `UPDATE rotation_runs SET state=$3, error_class=$4, updated_at=now()
		WHERE id=$1 AND state=$2 AND lease_owner=$5 AND lease_epoch=$6`, id, string(from), string(to), string(c), l.owner, l.epoch)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrLeaseLost
	}
	return nil
}

// failAbandoned ends an unfinished run whose lease is free or expired. Rotate
// releases its lease while a panic unwinds, so the run of a panicked goroutine
// qualifies; a run another caller holds does not and is left to its owner.
func (s *store) failAbandoned(ctx context.Context, id uuid.UUID, c Class, now time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE rotation_runs SET state='failed', error_class=$2, updated_at=now()
		WHERE id=$1 AND state NOT IN ('done','failed')
		  AND (lease_owner='' OR lease_until IS NULL OR lease_until < $3)`, id, string(c), now)
	return err
}

func (s *store) markIncident(ctx context.Context, id uuid.UUID) error {
	l := leaseOf(ctx)
	if l == nil {
		return ErrLeaseLost
	}
	tag, err := s.pool.Exec(ctx, `UPDATE rotation_runs SET incident_opened=true WHERE id=$1 AND lease_owner=$2 AND lease_epoch=$3`, id, l.owner, l.epoch)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrLeaseLost
	}
	return nil
}

func (s *store) steps(ctx context.Context, id uuid.UUID) ([]stepRow, error) {
	rows, err := s.pool.Query(ctx, `SELECT carrier_id, deploy_state, verify_state FROM rotation_steps WHERE run_id=$1 ORDER BY carrier_id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []stepRow
	for rows.Next() {
		var r stepRow
		if err := rows.Scan(&r.CarrierID, &r.Deploy, &r.Verify); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *store) setDeploy(ctx context.Context, id uuid.UUID, carrier, state string, c Class) error {
	l := leaseOf(ctx)
	if l == nil {
		return ErrLeaseLost
	}
	tag, err := s.pool.Exec(ctx, `UPDATE rotation_steps st SET deploy_state=$3, error_class=$4 FROM rotation_runs r
		WHERE st.run_id=$1 AND st.carrier_id=$2 AND r.id=st.run_id AND r.lease_owner=$5 AND r.lease_epoch=$6`,
		id, carrier, state, string(c), l.owner, l.epoch)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrLeaseLost
	}
	return nil
}

func (s *store) setVerify(ctx context.Context, id uuid.UUID, carrier, state, fp string, c Class) error {
	l := leaseOf(ctx)
	if l == nil {
		return ErrLeaseLost
	}
	tag, err := s.pool.Exec(ctx, `UPDATE rotation_steps st SET verify_state=$3, observed_fp=$4, error_class=$5 FROM rotation_runs r
		WHERE st.run_id=$1 AND st.carrier_id=$2 AND r.id=st.run_id AND r.lease_owner=$6 AND r.lease_epoch=$7`,
		id, carrier, state, fp, string(c), l.owner, l.epoch)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrLeaseLost
	}
	return nil
}

// allOK reports whether every step is ok in the given column (a fixed
// internal name, never caller text) and there is at least one step.
func (s *store) allOK(ctx context.Context, id uuid.UUID, col string) (bool, error) {
	if col != "deploy_state" && col != "verify_state" {
		return false, errors.New("rotation: unknown column")
	}
	var total, ok int
	err := s.pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE `+col+`='ok') FROM rotation_steps WHERE run_id=$1`, id).Scan(&total, &ok)
	return err == nil && total > 0 && total == ok, err
}

// allVerified is the last gate before the old version is revoked: every step
// deployed and verified, with the expected fingerprint on record.
func (s *store) allVerified(ctx context.Context, id uuid.UUID) (bool, error) {
	var total, good int
	err := s.pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE st.deploy_state='ok' AND st.verify_state='ok' AND st.observed_fp = r.expected_fp)
		FROM rotation_steps st JOIN rotation_runs r ON r.id=st.run_id WHERE st.run_id=$1 AND r.expected_fp <> ''`, id).Scan(&total, &good)
	return err == nil && total > 0 && total == good, err
}

func (s *store) badCarriers(ctx context.Context, id uuid.UUID) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT carrier_id FROM rotation_steps WHERE run_id=$1 AND (deploy_state='failed' OR verify_state='failed') ORDER BY carrier_id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// worstVerifyClass picks the class recorded on the run when verification
// fails: a fingerprint mismatch outranks unhealthy outranks a read error.
func (s *store) worstVerifyClass(ctx context.Context, id uuid.UUID) Class {
	var c string
	err := s.pool.QueryRow(ctx, `SELECT error_class FROM rotation_steps WHERE run_id=$1 AND verify_state='failed'
		ORDER BY CASE error_class WHEN 'fingerprint_mismatch' THEN 0 WHEN 'unhealthy' THEN 1 ELSE 2 END LIMIT 1`, id).Scan(&c)
	if err != nil {
		return ClassVerifyFailed
	}
	return Class(c)
}

// resumeBackoff is the SQL for the wait before the next resume of a run that
// was just taken: base doubled per earlier attempt, capped.
const resumeBackoff = `make_interval(secs => LEAST($5::float8, $4::float8 * power(2, r.resume_attempts)))`

// stuck is the condition of a run nothing drives: active, lease free or
// expired, untouched for $2 seconds (database clock, the one updated_at is
// written by) and past its backoff; $3 is the runs this process drives.
const stuck = `r.state NOT IN ('done','failed')
	AND (r.lease_owner='' OR r.lease_until IS NULL OR r.lease_until < $1)
	AND r.updated_at < clock_timestamp() - make_interval(secs => $2::float8)
	AND (r.resume_after IS NULL OR r.resume_after <= $1)
	AND r.id <> ALL($3::uuid[])`

// claimResumes takes up to cfg.Batch stuck runs for this caller and counts the
// attempt in the same statement. SKIP LOCKED keeps two servers sweeping at
// once off each other's rows, and the backoff written by the claim keeps the
// second sweeper off a run the first just took.
func (s *store) claimResumes(ctx context.Context, cfg ResumeConfig, now time.Time, inflight []uuid.UUID) ([]resumable, error) {
	return s.scanResumes(ctx, `WITH c AS (
			SELECT r.id FROM rotation_runs r
			WHERE r.resume_attempts < $6 AND `+stuck+`
			ORDER BY r.updated_at LIMIT $7 FOR UPDATE OF r SKIP LOCKED)
		UPDATE rotation_runs r SET resume_after=$1 + `+resumeBackoff+`, resume_attempts=r.resume_attempts+1
		FROM c WHERE r.id=c.id
		RETURNING r.id, r.org_id, r.secret_id, r.resume_attempts`,
		now, cfg.Stale.Seconds(), inflight, cfg.BackoffBase.Seconds(), cfg.BackoffMax.Seconds(), cfg.MaxAttempts, cfg.Batch)
}

// giveUpResumes fails the stuck runs that used up their attempts, with the
// fixed class internal_error. The run no longer holds the secret's one active
// slot, so the next rotation can start.
func (s *store) giveUpResumes(ctx context.Context, cfg ResumeConfig, now time.Time, inflight []uuid.UUID) ([]resumable, error) {
	return s.scanResumes(ctx, `WITH c AS (
			SELECT r.id FROM rotation_runs r
			WHERE r.resume_attempts >= $5 AND `+stuck+`
			ORDER BY r.updated_at LIMIT $6 FOR UPDATE OF r SKIP LOCKED)
		UPDATE rotation_runs r SET state='failed', error_class=$4, updated_at=now()
		FROM c WHERE r.id=c.id
		RETURNING r.id, r.org_id, r.secret_id, r.resume_attempts`,
		now, cfg.Stale.Seconds(), inflight, string(ClassInternalError), cfg.MaxAttempts, cfg.Batch)
}

func (s *store) scanResumes(ctx context.Context, q string, args ...any) ([]resumable, error) {
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []resumable
	for rows.Next() {
		var r resumable
		if err := rows.Scan(&r.id, &r.ref.OrgID, &r.ref.SecretID, &r.attempts); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
