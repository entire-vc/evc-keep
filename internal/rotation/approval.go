package rotation

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ClassProd is the catalog class whose rotation waits for a human: the same
// rule the deployment policy applies to a prod secret.
const ClassProd = "prod"

const maxReasonRunes = 200

// Journal is the part of the R-AUD-1 journal a rotation writes through.
// *audit.Journal implements it.
type Journal interface {
	Append(context.Context, audit.Record) (audit.Record, error)
	AppendTx(context.Context, pgx.Tx, audit.Record) (audit.Record, error)
	LogCommitted(context.Context, audit.Record)
}

// Origin is who asks for a rotation and which secret it is, as the journal
// and the approval card name them: ids, names and closed classes only.
type Origin struct {
	Actor audit.Actor
	Scope string // "org:<id>", "proj:<id>", ...
	Name  string
	Class string
}

// ApprovalRef is the approval a rotation waits for, or waited for.
type ApprovalRef struct {
	ID     uuid.UUID
	Status string // requested, approved, rejected or expired
}

// Started is the answer of Start: the id of the run (the request id), and the
// approval when the secret needs one. A run behind an approval does not exist
// until a human approves.
type Started struct {
	RunID    uuid.UUID
	Approval *ApprovalRef
}

// bind hashes length-prefixed fields, so no two field lists share a hash.
func bind(domain string, values ...string) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(domain))
	var n [8]byte
	for _, v := range values {
		binary.BigEndian.PutUint64(n[:], uint64(len(v))) //nolint:gosec // len is nonnegative
		_, _ = h.Write(n[:])
		_, _ = h.Write([]byte(v))
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func rotationBinding(org, secret, run uuid.UUID, a audit.Actor) [32]byte {
	return bind("keep/rotate/request/v1", org.String(), secret.String(), run.String(), string(a.Type), a.ID, a.SponsorID, string(a.Via))
}

func rotationTargetKey(org, secret uuid.UUID) [32]byte {
	return bind("keep/rotate/target/v1", org.String(), secret.String())
}

// auditClass maps a run's failure class onto the journal's closed taxonomy;
// a class text never reaches the journal.
func auditClass(c Class) audit.ErrorClass {
	switch c {
	case ClassNone, ClassOriginalKeyUnknown, ClassSuperseded:
		return audit.ErrClassNone
	case ClassPrepareFailed, ClassRevokeFailed, ClassRollbackUnconfirmed:
		return audit.ErrClassProviderError
	case ClassNoCarriers, ClassDeployFailed, ClassFingerprintMismatch, ClassUnhealthy, ClassVerifyFailed:
		return audit.ErrClassTargetError
	case ClassPolicyDenied:
		return audit.ErrClassPermissionDenied
	default:
		return audit.ErrClassInternal
	}
}

// requestRecord is the journal record of a rotation request. The request id
// is the run id, which is also what the API returns.
func requestRecord(ref Ref, run uuid.UUID, o Origin, decision audit.PolicyDecision, approval uuid.UUID) audit.Record {
	r := audit.Record{OrgID: ref.OrgID.String(), RequestID: run.String(), Scope: o.Scope, Actor: o.Actor,
		Action: audit.ActionSecretRotate, Secret: audit.SecretRef{ID: ref.SecretID.String(), Name: o.Name},
		Policy: audit.Policy{Decision: decision}, Result: audit.Result{Status: audit.StatusPending}}
	if approval != uuid.Nil {
		r.Approval.ID = approval.String()
	}
	return r
}

// requestApproval stores the approval of a prod rotation and journals the
// request, in one transaction. No run row exists yet; ErrConflict answers a
// rotation already running or already waiting for a human.
func (s *Service) requestApproval(ctx context.Context, ref Ref, run uuid.UUID, o Origin) (Started, error) {
	if s.journal == nil {
		return Started{}, ErrUnavailable
	}
	tx, err := s.e.store.pool.Begin(ctx)
	if err != nil {
		return Started{}, ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Organization first, the lock order of every approval writer.
	if _, err = tx.Exec(ctx, `SELECT 1 FROM organizations WHERE id=$1 FOR UPDATE`, ref.OrgID); err != nil {
		return Started{}, ErrUnavailable
	}
	var active, revokePending, waiting bool
	if err = tx.QueryRow(ctx, `SELECT
		EXISTS(SELECT 1 FROM rotation_runs WHERE org_id=$1 AND secret_id=$2 AND state NOT IN ('done','failed')),
		EXISTS(SELECT 1 FROM rotation_runs WHERE org_id=$1 AND secret_id=$2 AND state='revoking_old' AND error_class=$3),
		EXISTS(SELECT 1 FROM approval_requests WHERE org_id=$1 AND rotation_secret_id=$2 AND status='requested' AND expires_at>=clock_timestamp())`,
		ref.OrgID, ref.SecretID, string(ClassRevokeFailed)).Scan(&active, &revokePending, &waiting); err != nil {
		return Started{}, ErrUnavailable
	}
	switch {
	case revokePending:
		return Started{}, ErrRevokePending
	case active || waiting:
		return Started{}, ErrConflict
	}
	approval, err := uuid.NewV7()
	if err != nil {
		return Started{}, ErrUnavailable
	}
	hash, key := rotationBinding(ref.OrgID, ref.SecretID, run, o.Actor), rotationTargetKey(ref.OrgID, ref.SecretID)
	var expires time.Time
	if err = tx.QueryRow(ctx, `INSERT INTO approval_requests(id,org_id,rotation_secret_id,rotation_run_id,binding_hash,target_key,requester_type,requester_id,requester_sponsor_id,requester_via,requested_at,expires_at)
		SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,t,t+$11::bigint*interval '1 second' FROM (SELECT clock_timestamp() AS t) c RETURNING expires_at`,
		approval, ref.OrgID, ref.SecretID, run, hash[:], key[:], string(o.Actor.Type), o.Actor.ID, o.Actor.SponsorID, string(o.Actor.Via),
		int64(deployment.ApprovalTTL/time.Second)).Scan(&expires); err != nil {
		return Started{}, ErrUnavailable
	}
	rec := requestRecord(ref, run, o, audit.DecisionApprovalRequired, approval)
	first, err := s.journal.AppendTx(ctx, tx, rec)
	if err != nil {
		return Started{}, ErrUnavailable
	}
	rec.Action = audit.ActionApprovalRequested
	rec.Policy.RuleID = "approval-binding:" + hex.EncodeToString(hash[:])
	second, err := s.journal.AppendTx(ctx, tx, rec)
	if err != nil {
		return Started{}, ErrUnavailable
	}
	var undo func(context.Context)
	if s.confirm != nil {
		var name, class string
		if err = tx.QueryRow(ctx, `SELECT name, class FROM secrets WHERE org_id=$1 AND id=$2`, ref.OrgID, ref.SecretID).Scan(&name, &class); err != nil {
			return Started{}, ErrUnavailable
		}
		// Last before the commit: a card that cannot be made rolls everything back.
		if undo, err = s.confirm.Confirm(ctx, tx, deployment.Confirmation{OrgID: ref.OrgID, ApprovalID: approval, Kind: "rotate", SecretName: name,
			SecretClass: class, RequestID: run.String(), BindingHash: hash, ExpiresAt: expires}); err != nil {
			return Started{}, ErrUnavailable
		}
	}
	if err = tx.Commit(ctx); err != nil {
		if undo != nil {
			undo(ctx)
		}
		return Started{}, ErrUnavailable
	}
	s.journal.LogCommitted(ctx, first)
	s.journal.LogCommitted(ctx, second)
	return Started{RunID: run, Approval: &ApprovalRef{ID: approval, Status: "requested"}}, nil
}

// approvalOf reads the approval of a run id, if one exists. A requested
// approval past its time is expired.
func (s *store) approvalOf(ctx context.Context, org, secret, run uuid.UUID) (*ApprovalRef, error) {
	var a ApprovalRef
	err := s.pool.QueryRow(ctx, `SELECT id, CASE WHEN status='requested' AND expires_at<clock_timestamp() THEN 'expired' ELSE status END
		FROM approval_requests WHERE org_id=$1 AND rotation_secret_id=$2 AND rotation_run_id=$3`, org, secret, run).Scan(&a.ID, &a.Status)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

const rotationApprovalSelect = `SELECT a.id,a.status,a.requested_at,a.expires_at,a.decided_at,a.decided_by,a.decision_reason,a.binding_hash,
	a.requester_type,a.requester_id,a.requester_sponsor_id,a.requester_via,
	a.rotation_run_id,a.rotation_secret_id,s.name,s.class,s.scope_level,s.scope_id,a.expires_at < clock_timestamp()
	FROM approval_requests a JOIN secrets s ON s.org_id=a.org_id AND s.id=a.rotation_secret_id`

func scanRotationApproval(row pgx.Row) (deployment.Approval, error) {
	var a deployment.Approval
	var decidedAt *time.Time
	var decidedBy *uuid.UUID
	var hash []byte
	var level, rtype, rvia string
	var expired bool
	err := row.Scan(&a.ID, &a.Status, &a.RequestedAt, &a.ExpiresAt, &decidedAt, &decidedBy, &a.Reason, &hash,
		&rtype, &a.Requester.ID, &a.Requester.SponsorID, &rvia, &a.RequestID, &a.SecretID, &a.SecretName, &a.SecretClass, &level, &a.Scope.ID, &expired)
	if err != nil {
		return deployment.Approval{}, err
	}
	if decidedAt != nil {
		a.DecidedAt = decidedAt.UTC()
	}
	if decidedBy != nil {
		a.DecidedBy = *decidedBy
	}
	a.Requester.Type, a.Requester.Via = audit.ActorType(rtype), audit.ActorVia(rvia)
	a.Scope.Level = tenancy.Level(level)
	a.BindingHash = hex.EncodeToString(hash)
	a.RequestedAt, a.ExpiresAt = a.RequestedAt.UTC(), a.ExpiresAt.UTC()
	a.Rotate = true
	if expired && a.Status == "requested" {
		a.Status = "expired"
	}
	return a, nil
}

// GetRotationApproval reads one rotation approval of org. Any other id,
// another organization's included, is deployment.ErrNotFound.
func (s *Service) GetRotationApproval(ctx context.Context, org, id uuid.UUID) (deployment.Approval, error) {
	a, err := scanRotationApproval(s.e.store.pool.QueryRow(ctx, rotationApprovalSelect+` WHERE a.org_id=$1 AND a.id=$2`, org, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return deployment.Approval{}, deployment.ErrNotFound
	}
	if err != nil {
		return deployment.Approval{}, deployment.ErrUnavailable
	}
	return a, nil
}

// ListRotationApprovals returns the newest rotation approvals of org.
func (s *Service) ListRotationApprovals(ctx context.Context, org uuid.UUID, limit int) ([]deployment.Approval, error) {
	if limit < 1 || limit > 200 {
		limit = 200
	}
	rows, err := s.e.store.pool.Query(ctx, rotationApprovalSelect+` WHERE a.org_id=$1 ORDER BY a.requested_at DESC LIMIT $2`, org, limit)
	if err != nil {
		return nil, deployment.ErrUnavailable
	}
	defer rows.Close()
	var out []deployment.Approval
	for rows.Next() {
		a, err := scanRotationApproval(rows)
		if err != nil {
			return nil, deployment.ErrUnavailable
		}
		out = append(out, a)
	}
	if rows.Err() != nil {
		return nil, deployment.ErrUnavailable
	}
	return out, nil
}

// DecideRotation records a human decision on a rotation approval. Approving
// creates the run the approval was bound to, in the same transaction, and
// starts it; the bound hash shown to the approver, the stored one and the one
// recomputed from the stored request must agree. An id that is not a rotation
// approval of the organization is deployment.ErrNotFound.
func (s *Service) DecideRotation(ctx context.Context, in deployment.DecideInput) (deployment.DecideResult, error) {
	if !in.ApproverIsUser {
		return deployment.DecideResult{}, deployment.ErrNotHuman
	}
	if in.OrgID == uuid.Nil || in.ApprovalID == uuid.Nil || in.ApproverID == uuid.Nil || utf8.RuneCountInString(in.Reason) > maxReasonRunes || !utf8.ValidString(in.Reason) {
		return deployment.DecideResult{}, deployment.ErrInvalidArgument
	}
	shown, err := hex.DecodeString(in.BindingHash)
	if err != nil || len(shown) != 32 {
		return deployment.DecideResult{}, deployment.ErrBindingMismatch
	}
	tx, err := s.e.store.pool.Begin(ctx)
	if err != nil {
		return deployment.DecideResult{}, deployment.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, `SELECT 1 FROM organizations WHERE id=$1 FOR UPDATE`, in.OrgID); err != nil {
		return deployment.DecideResult{}, deployment.ErrUnavailable
	}
	var (
		run, secretID      uuid.UUID
		status, rtype, rid string
		rsponsor, rvia     string
		name, class, level string
		scopeID            uuid.UUID
		stored             []byte
		expired            bool
	)
	err = tx.QueryRow(ctx, `SELECT a.rotation_run_id,a.rotation_secret_id,a.status,a.binding_hash,a.requester_type,a.requester_id,a.requester_sponsor_id,a.requester_via,
		a.expires_at < clock_timestamp(),s.name,s.class,s.scope_level,s.scope_id
		FROM approval_requests a JOIN secrets s ON s.org_id=a.org_id AND s.id=a.rotation_secret_id
		WHERE a.org_id=$1 AND a.id=$2 AND a.rotation_run_id IS NOT NULL FOR UPDATE OF a`, in.OrgID, in.ApprovalID).Scan(
		&run, &secretID, &status, &stored, &rtype, &rid, &rsponsor, &rvia, &expired, &name, &class, &level, &scopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return deployment.DecideResult{}, deployment.ErrNotFound
	}
	if err != nil {
		return deployment.DecideResult{}, deployment.ErrUnavailable
	}
	if s.journal == nil {
		return deployment.DecideResult{}, deployment.ErrUnavailable
	}
	if status != "requested" {
		return deployment.DecideResult{}, deployment.ErrAlreadyDecided
	}
	if expired {
		return deployment.DecideResult{}, deployment.ErrExpired
	}
	if rtype == string(audit.ActorUser) && rid == in.ApproverID.String() {
		return deployment.DecideResult{}, deployment.ErrSelfApproval
	}
	requester := audit.Actor{Type: audit.ActorType(rtype), ID: rid, SponsorID: rsponsor, Via: audit.ActorVia(rvia)}
	recomputed := rotationBinding(in.OrgID, secretID, run, requester)
	if subtle.ConstantTimeCompare(stored, shown) != 1 || subtle.ConstantTimeCompare(stored, recomputed[:]) != 1 {
		return deployment.DecideResult{}, deployment.ErrBindingMismatch
	}
	ref := Ref{OrgID: in.OrgID, SecretID: secretID}
	scope := tenancy.Scope{Level: tenancy.Level(level), ID: scopeID}.String()
	res := deployment.DecideResult{Status: "rejected"}
	if in.Approve {
		res.Status = "approved"
		// The run the human approved. Another run of the secret, started
		// since, refuses it and creates nothing.
		if _, err = tx.Exec(ctx, `INSERT INTO rotation_runs(id, org_id, secret_id, state) VALUES ($1,$2,$3,'new_version')`, run, in.OrgID, secretID); err != nil {
			return deployment.DecideResult{}, deployment.ErrRefused
		}
	}
	var decidedAt time.Time
	if err = tx.QueryRow(ctx, `UPDATE approval_requests SET status=$3,decided_by=$4,decided_at=clock_timestamp(),decision_reason=$5
		WHERE org_id=$1 AND id=$2 RETURNING decided_at`, in.OrgID, in.ApprovalID, res.Status, in.ApproverID, in.Reason).Scan(&decidedAt); err != nil {
		return deployment.DecideResult{}, deployment.ErrUnavailable
	}
	rec := audit.Record{OrgID: in.OrgID.String(), RequestID: run.String(), Scope: scope,
		Actor:  audit.Actor{Type: audit.ActorUser, ID: in.ApproverID.String(), Via: audit.ViaConsole},
		Action: audit.ActionApprovalDecided, Secret: audit.SecretRef{ID: secretID.String(), Name: name},
		Intent:   audit.Intent{Reason: in.Reason},
		Policy:   audit.Policy{Decision: audit.DecisionAllow, RuleID: "approval-binding:" + hex.EncodeToString(stored)},
		Approval: audit.Approval{ID: in.ApprovalID.String(), ApproverID: in.ApproverID.String(), DecidedAt: decidedAt.UTC().Truncate(time.Microsecond)},
		Result:   audit.Result{Status: audit.StatusOK}}
	if !in.Approve {
		rec.Policy.Decision = audit.DecisionDeny
		rec.Result = audit.Result{Status: audit.StatusFailed, ErrorClass: audit.ErrClassPermissionDenied}
	}
	written, err := s.journal.AppendTx(ctx, tx, rec)
	if err != nil {
		return deployment.DecideResult{}, deployment.ErrUnavailable
	}
	if err = tx.Commit(ctx); err != nil {
		return deployment.DecideResult{}, deployment.ErrUnavailable
	}
	s.journal.LogCommitted(ctx, written)
	if in.Approve {
		s.launch(ctx, ref, run, Origin{Actor: requester, Scope: scope, Name: name, Class: class}, in.ApprovalID, nil)
	}
	return res, nil
}
