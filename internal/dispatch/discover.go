package dispatch

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/mtls"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrInvalidBody: the report is not of the shape or size its job allows.
var ErrInvalidBody = errors.New("dispatch: invalid result body")

// MaxDiscoverBody bounds a discover report: MaxDiscoverFindings lines of
// metadata. The largest valid report (4096 findings, each with a 1 KiB path
// and a 128-character name of characters json.Marshal expands to six bytes)
// is about 29 MB, so the cap equals the runner outbox's discover entry cap and
// a report the runner stored is never one the server refuses. Every other
// result stays within MaxResultBody.
const (
	MaxResultBody   = 4096
	MaxDiscoverBody = 32 << 20
)

// discoverStored is what the discover job row keeps of a report: the verdict
// and a digest of the findings, never the findings themselves (those live in
// discovery_observations as metadata lines).
type discoverStored struct {
	OK         bool                   `json:"ok"`
	ErrorClass runnerproto.ErrorClass `json:"error_class,omitempty"`
	Digest     string                 `json:"digest,omitempty"`
}

func readDiscoverJob(row pgx.Row, p mtls.Principal, late bool) (runnerproto.Job, error) {
	var payload []byte
	if err := row.Scan(&payload); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return runnerproto.Job{}, ErrNotFound
		}
		return runnerproto.Job{}, ErrUnavailable
	}
	job, err := runnerproto.DecodeJob(payload)
	if err != nil || job.Action != runnerproto.ActionDiscover || job.OrgID != p.OrgID.String() || job.RunnerID != p.RunnerID.String() ||
		(!late && !job.NotAfter.After(time.Now())) {
		return runnerproto.Job{}, ErrNotFound
	}
	return job, nil
}

// claimDiscover hands the runner its oldest queued discover job.
func (s *Service) claimDiscover(ctx context.Context, tx pgx.Tx, p mtls.Principal) (runnerproto.SignedJob, bool, error) {
	job, err := readDiscoverJob(tx.QueryRow(ctx, `UPDATE discovery_jobs SET status='issued',issued_at=clock_timestamp()
	 WHERE id=(SELECT id FROM discovery_jobs WHERE org_id=$1 AND runner_id=$2 AND status='queued' AND expires_at>clock_timestamp() ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED)
	 RETURNING job_payload`, p.OrgID, p.RunnerID), p, false)
	if errors.Is(err, ErrNotFound) {
		return runnerproto.SignedJob{}, false, nil
	}
	if err != nil {
		return runnerproto.SignedJob{}, false, err
	}
	signed, err := s.signer.SignJob(ctx, tx, p.OrgID, job)
	if err != nil {
		return runnerproto.SignedJob{}, false, ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return runnerproto.SignedJob{}, false, ErrUnavailable
	}
	return signed, true, nil
}

// discoverMaterial burns the one key issuance of an issued discover job.
// found is false when id is not a discover job of this runner.
func (s *Service) discoverMaterial(ctx context.Context, tx pgx.Tx, p mtls.Principal, id uuid.UUID, recipient []byte) (runnerproto.ValueEnvelope, bool, error) {
	job, err := readDiscoverJob(tx.QueryRow(ctx, `UPDATE discovery_jobs SET material_issued_at=clock_timestamp()
	 WHERE id=$1 AND org_id=$2 AND runner_id=$3 AND status='issued' AND material_issued_at IS NULL AND expires_at>clock_timestamp()
	 RETURNING job_payload`, id, p.OrgID, p.RunnerID), p, false)
	if errors.Is(err, ErrNotFound) {
		return runnerproto.ValueEnvelope{}, false, nil
	}
	if err != nil {
		return runnerproto.ValueEnvelope{}, true, err
	}
	// The issuance mark is committed only after the key was sealed: a seal that
	// failed leaves the job without it, so no report of a scan that never held
	// a key can be accepted as a success.
	env, err := s.issuer.SealMaterial(ctx, Snapshot{Job: job}, recipient)
	if err != nil {
		return runnerproto.ValueEnvelope{}, true, ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return runnerproto.ValueEnvelope{}, true, ErrUnavailable
	}
	return env, true, nil
}

// ResultBody decodes a runner's report by what its job is: a discover job's
// report has its own closed shape and size, every other job's is the deploy
// result. Anything of the wrong shape for its job is ErrNotFound.
func (s *Service) ResultBody(ctx context.Context, p mtls.Principal, id string, body []byte) error {
	jobID, err := uuid.Parse(id)
	if err != nil {
		return ErrNotFound
	}
	if s == nil || s.pool == nil {
		return ErrUnavailable
	}
	var isDiscover bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM discovery_jobs WHERE id=$1 AND org_id=$2 AND runner_id=$3)`, jobID, p.OrgID, p.RunnerID).Scan(&isDiscover); err != nil {
		return ErrUnavailable
	}
	if !isDiscover {
		if len(body) > MaxResultBody {
			return ErrInvalidBody
		}
		res, err := runnerproto.DecodeResult(body)
		if err != nil {
			return ErrInvalidBody
		}
		return s.Result(ctx, p, id, res)
	}
	res, err := runnerproto.DecodeDiscoverResult(body)
	if err != nil {
		return ErrInvalidBody
	}
	return s.discoverResult(ctx, p, jobID, res)
}

func (s *Service) discoverResult(ctx context.Context, p mtls.Principal, jobID uuid.UUID, res runnerproto.DiscoverResult) error {
	tx, _, err := s.begin(ctx, p)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	stored := discoverStored{OK: res.OK, ErrorClass: res.ErrorClass}
	if res.OK {
		canonical, err := json.Marshal(res.Findings)
		if err != nil {
			return ErrNotFound
		}
		sum := sha256.Sum256(canonical)
		stored.Digest = hex.EncodeToString(sum[:])
	}
	encoded, err := json.Marshal(stored)
	if err != nil {
		return ErrNotFound
	}
	var state string
	var previous []byte
	var requestID string
	err = tx.QueryRow(ctx, `SELECT status,COALESCE(result,'null'::jsonb),request_id FROM discovery_jobs
	 WHERE id=$1 AND org_id=$2 AND runner_id=$3 AND status IN ('issued','completed','failed') FOR UPDATE`, jobID, p.OrgID, p.RunnerID).Scan(&state, &previous, &requestID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return ErrUnavailable
	}
	if state == "completed" || state == "failed" { // terminal: only an exact retry is acknowledged
		var prior discoverStored
		if json.Unmarshal(previous, &prior) != nil {
			return ErrNotFound
		}
		again, err := json.Marshal(prior)
		if err != nil || subtle.ConstantTimeCompare(again, encoded) != 1 {
			return ErrNotFound
		}
		return nil
	}
	job, err := readDiscoverJob(tx.QueryRow(ctx, `SELECT job_payload FROM discovery_jobs
	 WHERE id=$1 AND org_id=$2 AND runner_id=$3 AND (NOT $4 OR material_issued_at IS NOT NULL) FOR UPDATE`, jobID, p.OrgID, p.RunnerID, res.OK), p, true)
	if err != nil {
		return err
	}
	status, auditStatus, class := "failed", audit.StatusFailed, auditFailureClass(res.ErrorClass)
	if res.OK {
		_, err = deployment.ApplyDiscoverResultTx(ctx, tx, p.OrgID, job, res)
		switch {
		case errors.Is(err, deployment.ErrDiscoverRejected):
			// A report under a key the store never used is a broken report:
			// it is kept as a failed scan with no findings and no comparison.
			status, class = "failed", audit.ErrClassInternal
			stored = discoverStored{ErrorClass: runnerproto.ErrClassDiscoveryFailed}
			if encoded, err = json.Marshal(stored); err != nil {
				return ErrNotFound
			}
			res = runnerproto.DiscoverResult{Findings: []runnerproto.DiscoverFinding{}, ErrorClass: runnerproto.ErrClassDiscoveryFailed}
		case err != nil:
			return ErrUnavailable
		default:
			status, auditStatus, class = "completed", audit.StatusOK, audit.ErrClassNone
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE discovery_jobs SET status=$2,result=$3 WHERE id=$1`, jobID, status, encoded); err != nil {
		return ErrUnavailable
	}
	record, err := s.journal.AppendTx(ctx, tx, audit.Record{RequestID: requestID, OrgID: p.OrgID.String(), Scope: "org:" + p.OrgID.String(),
		Actor:  audit.Actor{Type: audit.ActorRunner, ID: p.RunnerID.String(), Via: audit.ViaAPI},
		Action: audit.ActionCarrierDiscover, Target: audit.Target{RunnerID: p.RunnerID.String()},
		Result: audit.Result{Status: auditStatus, ErrorClass: class}})
	if err != nil {
		return ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return ErrUnavailable
	}
	s.journal.LogCommitted(ctx, record)
	return nil
}
