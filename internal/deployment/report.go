package deployment

import (
	"context"
	"errors"

	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Report is the caller-visible state of one deployment request: the server
// decision, the approval reference when one is required, and the runner's
// closed Result once it has reported. It carries no value, path or host text.
type Report struct {
	Status         Status
	ApprovalID     uuid.UUID
	ApprovalStatus string
	// Scope is the secret's catalog scope, for the reader's own rights check.
	Scope tenancy.Scope
	// SecretID and VersionID are the catalog ids the request was pinned to,
	// so a retry of the same request id replays against the same version.
	SecretID, VersionID uuid.UUID
	// Done is true once the runner reported a terminal result.
	Done   bool
	Result runnerproto.Result
}

// Report reads the state of requestID inside org. A request id the
// organization never created is ErrNotFound, indistinguishable from another
// organization's.
func (r *Repo) Report(ctx context.Context, org uuid.UUID, requestID string) (Report, error) {
	if r == nil || r.pool == nil {
		return Report{}, ErrUnavailable
	}
	if org == uuid.Nil || !reqid.Valid(requestID) {
		return Report{}, ErrNotFound
	}
	var out Report
	var reqUUID uuid.UUID
	var level string
	err := r.pool.QueryRow(ctx, `SELECT id,decision,secret_scope_level,secret_scope_id,secret_id,version_id FROM deployment_requests r WHERE r.org_id=$1 AND r.request_id=$2
	 AND NOT EXISTS (SELECT 1 FROM deployment_jobs j WHERE j.org_id=r.org_id AND j.deployment_request_id=r.id AND j.action='verify')`, org, requestID).Scan(&reqUUID, &out.Status, &level, &out.Scope.ID, &out.SecretID, &out.VersionID)
	out.Scope.Level = tenancy.Level(level)
	if errors.Is(err, pgx.ErrNoRows) {
		return Report{}, ErrNotFound
	}
	if err != nil {
		return Report{}, ErrUnavailable
	}
	switch out.Status {
	case NeedsApproval:
		err = r.pool.QueryRow(ctx, `SELECT id,CASE WHEN status='requested' AND expires_at<clock_timestamp() THEN 'expired' ELSE status END FROM approval_requests WHERE org_id=$1 AND deployment_request_id=$2`, org, reqUUID).Scan(&out.ApprovalID, &out.ApprovalStatus)
		if err == nil && out.ApprovalStatus == "approved" {
			err = r.readJob(ctx, org, reqUUID, &out)
		}
	case Queued:
		err = r.readJob(ctx, org, reqUUID, &out)
	}
	if err != nil {
		return Report{}, ErrUnavailable
	}
	return out, nil
}

// readJob fills the runner's terminal result, if it has reported one, for the
// job created for request row reqUUID (directly, or after a human approval).
func (r *Repo) readJob(ctx context.Context, org, reqUUID uuid.UUID, out *Report) error {
	var state string
	var stored []byte
	err := r.pool.QueryRow(ctx, `SELECT status,result FROM deployment_jobs WHERE org_id=$1 AND deployment_request_id=$2`, org, reqUUID).Scan(&state, &stored)
	if err != nil {
		return err
	}
	switch state {
	case "completed", "failed":
		res, derr := runnerproto.DecodeResult(stored)
		if derr != nil {
			return derr
		}
		out.Done, out.Result = true, res
	case "expired":
		out.Done, out.Result = true, runnerproto.Result{ErrorClass: runnerproto.ErrClassExpired}
	}
	return nil
}
