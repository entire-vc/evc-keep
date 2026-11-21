package carriers

import (
	"context"

	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ApplyAdoptionResultTx is the sole adoption registration path. Dispatch
// authenticates the enrolled runner, holds its trust lock, and commits the
// one-use job result and audit alongside this receipt and registry update.
// Register's completed-deployment guard is independent of this operation.
func ApplyAdoptionResultTx(ctx context.Context, tx pgx.Tx, org, runner uuid.UUID, job runnerproto.Job, result runnerproto.Result) error {
	evidence, err := deployment.ValidateAdoptionResultTx(ctx, tx, org, runner, job, result)
	if err != nil {
		return ErrDeployment
	}
	tag, err := tx.Exec(ctx, `INSERT INTO carrier_adoption_receipts(org_id,job_id,secret_id,version_id,runner_id,host,target_path,target_field,version,fingerprint)
	 SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10 FROM deployment_jobs
	 WHERE org_id=$1 AND id=$2 AND expires_at>clock_timestamp()`, org, job.JobID, evidence.SecretID, evidence.VersionID, runner, evidence.Host, job.Target.Path, job.Target.Field, job.ExpectedVersion, job.ExpectedFingerprint)
	if err != nil || tag.RowsAffected() != 1 {
		return ErrInternal
	}
	id, err := uuid.NewV7()
	if err != nil {
		return ErrInternal
	}
	_, err = tx.Exec(ctx, `INSERT INTO carriers(id,org_id,secret_id,version,host,target_kind,target_path,target_field,last_fp,state,last_verified_at,provenance,adoption_runner_id,attestation_job_id)
	 VALUES($1,$2,$3,$4,$5,'yaml-scalar',$6,$7,$8,'registered',clock_timestamp(),'adoption',$9,$10)
	 ON CONFLICT(org_id,secret_id,host,target_kind,target_path,target_field)
	 DO UPDATE SET version=EXCLUDED.version,last_fp=EXCLUDED.last_fp,state='registered',
	 updated_at=clock_timestamp(),last_verified_at=clock_timestamp(),provenance='adoption',
	 adoption_runner_id=EXCLUDED.adoption_runner_id,attestation_job_id=EXCLUDED.attestation_job_id`,
		id, org, evidence.SecretID, job.ExpectedVersion, evidence.Host, job.Target.Path, job.Target.Field, job.ExpectedFingerprint, runner, job.JobID)
	if err != nil {
		return ErrInternal
	}
	return nil
}
