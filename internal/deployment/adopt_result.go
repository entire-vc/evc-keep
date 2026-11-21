package deployment

import (
	"context"
	"encoding/json"
	"time"

	"github.com/entire-vc/evc-keep/internal/registry"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AdoptionEvidence contains only catalog and enrollment metadata. The caller
// must authenticate the runner and commit its result, receipt and carrier in
// this same transaction. There is no caller-supplied host or fingerprint.
type AdoptionEvidence struct {
	SecretID, VersionID uuid.UUID
	Host                string
}

func ValidateAdoptionResultTx(ctx context.Context, tx pgx.Tx, org, runner uuid.UUID, job runnerproto.Job, result runnerproto.Result) (AdoptionEvidence, error) {
	var out AdoptionEvidence
	if tx == nil || job.Validate() != nil || job.Action != runnerproto.ActionAdopt || job.OrgID != org.String() || job.RunnerID != runner.String() || !result.OK || result.Validate() != nil || result.Healthcheck != nil || result.Version != job.ExpectedVersion || result.Fingerprint != job.ExpectedFingerprint || !time.Now().Before(job.NotAfter) {
		return out, ErrNotFound
	}
	trust, err := registry.NewRepo(nil).GetDeliveryTrustTx(ctx, tx, org, runner)
	if err != nil {
		return out, ErrNotFound
	}
	payload, err := runnerproto.EncodeJob(job)
	if err != nil {
		return out, ErrNotFound
	}
	var target []byte
	var decision string
	var approved bool
	err = tx.QueryRow(ctx, `SELECT d.secret_id,d.version_id,d.target,d.decision,r.host,
	 EXISTS (SELECT 1 FROM approval_requests a WHERE a.org_id=d.org_id AND a.deployment_request_id=d.id
	 AND a.status='approved' AND a.binding_hash=d.request_hash)
	 FROM deployment_jobs j
	 JOIN deployment_requests d ON d.org_id=j.org_id AND d.id=j.deployment_request_id
	 JOIN runners r ON r.org_id=j.org_id AND r.id=j.runner_id
	 WHERE j.org_id=$1 AND j.runner_id=$2 AND j.id=$3 AND j.job_payload=$4
	 AND j.action='adopt' AND j.status='issued' AND j.material_issued_at IS NOT NULL AND j.expires_at>clock_timestamp()
	 AND d.adoption AND d.exec IS NULL AND d.secret_id=j.secret_id AND d.version_id=j.version_id
	 AND d.runner_id=j.runner_id AND d.request_id=j.request_id
	 AND d.secret_scope_level=j.secret_scope_level AND d.secret_scope_id=j.secret_scope_id`,
		org, runner, job.JobID, payload).Scan(&out.SecretID, &out.VersionID, &target, &decision, &out.Host, &approved)
	if err != nil || (decision != string(Queued) && (decision != string(NeedsApproval) || !approved)) {
		return AdoptionEvidence{}, ErrNotFound
	}
	var frozen runnerproto.Target
	if json.Unmarshal(target, &frozen) != nil || frozen != job.Target || !validAdoptionTarget(frozen) {
		return AdoptionEvidence{}, ErrNotFound
	}
	current, err := currentVersionID(ctx, tx, org, out.SecretID)
	if err != nil || current != out.VersionID {
		return AdoptionEvidence{}, ErrNotFound
	}
	var version, fp, class string
	err = tx.QueryRow(ctx, `SELECT v.provider_version,v.fingerprint,s.class FROM secret_versions v
	 JOIN secrets s ON s.org_id=v.org_id AND s.id=v.secret_id
	 WHERE v.org_id=$1 AND v.secret_id=$2 AND v.id=$3 AND NOT v.disabled FOR SHARE OF v`, org, out.SecretID, out.VersionID).Scan(&version, &fp, &class)
	if err != nil || version != job.ExpectedVersion || fp != job.ExpectedFingerprint || (class == "prod" && !approved) {
		return AdoptionEvidence{}, ErrNotFound
	}
	host := Host{ID: runner.String(), AttributesKnown: trust.AttrsKnown, UIDShared: trust.UIDShared, Labels: trust.HostLabels}
	if _, err = EvaluateAdoption(Policy{}, host, out.SecretID, class, job.Target); err != nil {
		return AdoptionEvidence{}, ErrNotFound
	}
	return out, nil
}
