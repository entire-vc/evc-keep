// Package dispatch delivers only authorized, immutable deployment jobs and
// ciphertext to authenticated runners. It never receives plaintext material.
package dispatch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/mtls"
	"github.com/entire-vc/evc-keep/internal/registry"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrUnavailable = errors.New("dispatch: unavailable")
var ErrNotFound = errors.New("dispatch: job unavailable")

type Snapshot struct {
	Job                                     runnerproto.Job
	SecretID, VersionID                     uuid.UUID
	OwnerScope                              tenancy.Scope
	SecretScope                             tenancy.Scope
	ProviderRef, ProviderVersion, RequestID string
}
type Signer interface {
	SignJob(context.Context, pgx.Tx, uuid.UUID, runnerproto.Job) (runnerproto.SignedJob, error)
}
type MaterialIssuer interface {
	SealMaterial(context.Context, Snapshot, []byte) (runnerproto.ValueEnvelope, error)
}
type Service struct {
	pool    *pgxpool.Pool
	journal audit.TransactionalJournaler
	signer  Signer
	issuer  MaterialIssuer
}

func New(pool *pgxpool.Pool, journal audit.TransactionalJournaler, signer Signer, issuer MaterialIssuer) *Service {
	return &Service{pool: pool, journal: journal, signer: signer, issuer: issuer}
}

// Poll waits without retaining a database transaction between attempts. The
// caller bounds the long poll with a context deadline.
func (s *Service) Poll(ctx context.Context, p mtls.Principal) (runnerproto.SignedJob, bool, error) {
	for {
		if err := ctx.Err(); err != nil {
			return runnerproto.SignedJob{}, false, err
		}
		job, ok, err := s.claimNext(ctx, p)
		if err != nil || ok {
			return job, ok, err
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return runnerproto.SignedJob{}, false, ctx.Err()
		case <-timer.C:
		}
	}
}

func (s *Service) begin(ctx context.Context, p mtls.Principal) (pgx.Tx, []byte, error) {
	if s == nil || s.pool == nil || s.journal == nil || s.signer == nil || s.issuer == nil {
		return nil, nil, ErrUnavailable
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	d, err := registry.NewRepo(s.pool).GetDeliveryTrustTx(ctx, tx, p.OrgID, p.RunnerID)
	if err != nil {
		_ = tx.Rollback(ctx)
		return nil, nil, ErrNotFound
	}
	var live bool
	err = tx.QueryRow(ctx, `SELECT cert_serial=$3 AND cert_not_after>clock_timestamp() AND revoked_at IS NULL FROM runners WHERE org_id=$1 AND id=$2`, p.OrgID, p.RunnerID, p.Serial).Scan(&live)
	if err != nil || !live {
		_ = tx.Rollback(ctx)
		return nil, nil, ErrNotFound
	}
	return tx, d.HPKEPublicKey, nil
}

const snapshotColumns = `job_payload,secret_id,version_id,store_owner_scope_level,store_owner_scope_id,secret_scope_level,secret_scope_id,provider_ref,provider_version,request_id`

func readSnapshot(row pgx.Row, p mtls.Principal, allowLateResult bool) (Snapshot, error) {
	var snap Snapshot
	var payload []byte
	err := row.Scan(&payload, &snap.SecretID, &snap.VersionID, &snap.OwnerScope.Level, &snap.OwnerScope.ID, &snap.SecretScope.Level, &snap.SecretScope.ID, &snap.ProviderRef, &snap.ProviderVersion, &snap.RequestID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Snapshot{}, ErrNotFound
	}
	if err != nil {
		return Snapshot{}, ErrUnavailable
	}
	snap.Job, err = runnerproto.DecodeJob(payload)
	if err != nil || snap.Job.OrgID != p.OrgID.String() || snap.Job.RunnerID != p.RunnerID.String() || (!allowLateResult && !time.Now().Before(snap.Job.NotAfter)) || time.Now().Before(snap.Job.IssuedAt.Add(-runnerproto.ClockSkew)) || snap.ProviderVersion != snap.Job.ExpectedVersion {
		return Snapshot{}, ErrNotFound
	}
	return snap, nil
}

func (s *Service) claimNext(ctx context.Context, p mtls.Principal) (runnerproto.SignedJob, bool, error) {
	tx, _, err := s.begin(ctx, p)
	if err != nil {
		return runnerproto.SignedJob{}, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	snap, err := readSnapshot(tx.QueryRow(ctx, `UPDATE deployment_jobs SET status='issued',issued_at=clock_timestamp()
	 WHERE id=(SELECT id FROM deployment_jobs WHERE org_id=$1 AND runner_id=$2 AND status='queued' AND expires_at>clock_timestamp() ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED)
	 RETURNING `+snapshotColumns, p.OrgID, p.RunnerID), p, false)
	if errors.Is(err, ErrNotFound) {
		return runnerproto.SignedJob{}, false, nil
	}
	if err != nil {
		return runnerproto.SignedJob{}, false, err
	}
	signed, err := s.signer.SignJob(ctx, tx, p.OrgID, snap.Job)
	if err != nil {
		return runnerproto.SignedJob{}, false, ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return runnerproto.SignedJob{}, false, ErrUnavailable
	}
	return signed, true, nil
}

// Material burns one job-bound issuance before opening any secret. A lost
// response or backend failure requires a new authorized deployment request.
func (s *Service) Material(ctx context.Context, p mtls.Principal, id string) (runnerproto.ValueEnvelope, error) {
	jobID, err := uuid.Parse(id)
	if err != nil {
		return runnerproto.ValueEnvelope{}, ErrNotFound
	}
	tx, recipient, err := s.begin(ctx, p)
	if err != nil {
		return runnerproto.ValueEnvelope{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	snap, err := readSnapshot(tx.QueryRow(ctx, `UPDATE deployment_jobs SET material_issued_at=clock_timestamp()
	 WHERE id=$1 AND org_id=$2 AND runner_id=$3 AND status='issued' AND material_issued_at IS NULL AND expires_at>clock_timestamp()
	 RETURNING `+snapshotColumns, jobID, p.OrgID, p.RunnerID), p, false)
	if err != nil {
		return runnerproto.ValueEnvelope{}, err
	}
	if snap.Job.JobID != id || (!snap.Job.NeedsValue() && !snap.Job.NeedsFingerprintKey()) {
		return runnerproto.ValueEnvelope{}, ErrNotFound
	}
	if err := tx.Commit(ctx); err != nil {
		return runnerproto.ValueEnvelope{}, ErrUnavailable
	}
	env, err := s.issuer.SealMaterial(ctx, snap, recipient)
	if err != nil {
		return runnerproto.ValueEnvelope{}, ErrUnavailable
	}
	return env, nil
}

// Result accepts late reports from a current live owner and acknowledges exact
// retries without another audit record. Success must match frozen metadata and
// follow material issuance. A terminal result can never be changed.
func (s *Service) Result(ctx context.Context, p mtls.Principal, id string, result runnerproto.Result) error {
	jobID, err := uuid.Parse(id)
	if err != nil || result.Validate() != nil {
		return ErrNotFound
	}
	tx, _, err := s.begin(ctx, p)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	encoded, err := json.Marshal(result)
	if err != nil {
		return ErrNotFound
	}
	var state string
	var stored []byte
	err = tx.QueryRow(ctx, `SELECT status,result FROM deployment_jobs
	 WHERE id=$1 AND org_id=$2 AND runner_id=$3 AND status IN ('issued','completed','failed')
	 FOR UPDATE`, jobID, p.OrgID, p.RunnerID).Scan(&state, &stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return ErrUnavailable
	}
	if state == "completed" || state == "failed" { // terminal results only acknowledge exact retries
		previous, err := runnerproto.DecodeResult(stored)
		if err != nil {
			return ErrNotFound
		}
		canonical, err := json.Marshal(previous)
		if err != nil || !bytes.Equal(canonical, encoded) {
			return ErrNotFound
		}
		return nil
	}
	snap, err := readSnapshot(tx.QueryRow(ctx, `SELECT `+snapshotColumns+` FROM deployment_jobs
	 WHERE id=$1 AND org_id=$2 AND runner_id=$3
	 AND (NOT $4 OR material_issued_at IS NOT NULL) FOR UPDATE`, jobID, p.OrgID, p.RunnerID, result.OK), p, true)
	if err != nil {
		return err
	}
	if !resultMatchesJob(result, snap.Job) {
		return ErrNotFound
	}
	status := "failed"
	auditStatus := audit.StatusFailed
	errorClass := auditFailureClass(result.ErrorClass)
	if result.OK {
		status = "completed"
		auditStatus = audit.StatusOK
		errorClass = audit.ErrClassNone
	}
	if _, err := tx.Exec(ctx, `UPDATE deployment_jobs SET status=$2,result=$3 WHERE id=$1`, jobID, status, encoded); err != nil {
		return ErrUnavailable
	}
	action, auditFingerprint := audit.ActionDeployResult, result.Fingerprint
	if snap.Job.Action == runnerproto.ActionVerify {
		// The journal keeps what the runner confirmed; an observed fingerprint
		// of a mismatching file lives only in the carrier's verification line.
		action = audit.ActionCarrierVerify
		if !result.OK {
			auditFingerprint = ""
		}
		if _, _, err := deployment.ApplyVerifyResultTx(ctx, tx, p.OrgID, snap.Job, result); err != nil {
			return ErrUnavailable
		}
	}
	record, err := s.journal.AppendTx(ctx, tx, audit.Record{RequestID: snap.RequestID, OrgID: p.OrgID.String(), Scope: snap.SecretScope.String(), Actor: audit.Actor{Type: audit.ActorRunner, ID: p.RunnerID.String(), Via: audit.ViaAPI}, Action: action, Secret: audit.SecretRef{ID: snap.SecretID.String(), Version: snap.Job.ExpectedVersion}, Target: audit.Target{RunnerID: p.RunnerID.String()}, Result: audit.Result{Status: auditStatus, ErrorClass: errorClass, Fingerprint: auditFingerprint}})
	if err != nil { // result audit must commit with the state
		return ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return ErrUnavailable
	}
	s.journal.LogCommitted(ctx, record)
	return nil
}

// Runner detail is projected onto the existing closed audit taxonomy.
func auditFailureClass(class runnerproto.ErrorClass) audit.ErrorClass {
	switch class {
	case runnerproto.ErrClassPolicyDenied, runnerproto.ErrClassRateLimited:
		return audit.ErrClassPolicyDenied
	case runnerproto.ErrClassProvider, runnerproto.ErrClassValueUnavailable:
		return audit.ErrClassProviderError
	case runnerproto.ErrClassTargetWrite, runnerproto.ErrClassHealthcheck:
		return audit.ErrClassTargetError
	case runnerproto.ErrClassSignature, runnerproto.ErrClassWrongRunner, runnerproto.ErrClassReplay:
		return audit.ErrClassPermissionDenied
	case runnerproto.ErrClassExpired, runnerproto.ErrClassInvalidJob:
		return audit.ErrClassInvalidArgument
	default:
		return audit.ErrClassInternal
	}
}

func resultMatchesJob(result runnerproto.Result, job runnerproto.Job) bool {
	// A verify job exists to find a file that does not hold the expected
	// value, so its mismatch report names the observed fingerprint, which
	// by definition is not the job's. Nothing else may differ.
	if job.Action == runnerproto.ActionVerify && !result.OK && result.ErrorClass == runnerproto.ErrClassFingerprintMismatch {
		return result.Fingerprint != job.ExpectedFingerprint && (result.Version == "" || result.Version == job.ExpectedVersion)
	}
	if result.Fingerprint != "" && result.Fingerprint != job.ExpectedFingerprint {
		return false
	}
	if result.Version != "" && result.Version != job.ExpectedVersion {
		return false
	}
	return !result.OK || (result.Fingerprint == job.ExpectedFingerprint && result.Version == job.ExpectedVersion)
}
