package deployment

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	// ErrNotHuman: only a human account decides an approval; an agent never does.
	ErrNotHuman = errors.New("deployment: approver is not a human")
	// ErrSelfApproval: a requester never approves their own request.
	ErrSelfApproval = errors.New("deployment: requester cannot approve their own request")
	// ErrExpired: the approval outlived its TTL.
	ErrExpired = errors.New("deployment: approval expired")
	// ErrAlreadyDecided: an approval is decided once.
	ErrAlreadyDecided = errors.New("deployment: approval already decided")
	// ErrBindingMismatch: the hash the approver saw is not the hash of what is stored.
	ErrBindingMismatch = errors.New("deployment: approval does not match the stored request")
	// ErrRefused: the request can no longer be run (policy, provider, rate); nothing was created.
	ErrRefused = errors.New("deployment: request can no longer be executed")
)

// maxReasonRunes mirrors the journal's bound on intent.reason.
const maxReasonRunes = 200

// Approval is what a human sees before deciding: the whole request, with
// the hash the decision is bound to. It carries references and names only.
type Approval struct {
	ID          uuid.UUID
	Status      string // requested, approved, rejected, or expired (requested past its TTL)
	RequestedAt time.Time
	ExpiresAt   time.Time
	DecidedAt   time.Time
	DecidedBy   uuid.UUID
	Reason      string
	BindingHash string // hex of the canonical request hash
	Requester   audit.Actor
	RequestID   string
	SecretID    uuid.UUID
	SecretName  string
	SecretClass string
	Scope       tenancy.Scope
	RunnerID    uuid.UUID
	Target      runnerproto.Target
	// NetAllowlist holds the destinations of a network-intent exec template.
	// Deployment targets never carry one (R-POL-3), so it is empty here.
	NetAllowlist []string
	// Exec is set for an exec_with_secret request, which has no Target.
	Exec *ApprovalExec
	// Rotate marks the approval of a two-phase rotation of SecretID: no
	// runner, no target. RequestID is the id of the run it will start.
	Rotate bool
}

// ApprovalExec is what an approver sees of an exec request besides the
// destinations: which template, in which network mode, with which parameter
// names. Parameter values are bound by the hash but never rendered.
type ApprovalExec struct {
	TemplateID string
	Digest     string
	Mode       string
	ParamNames []string
}

const approvalColumns = `a.id,a.status,a.requested_at,a.expires_at,a.decided_at,a.decided_by,a.decision_reason,a.binding_hash,
	a.requester_type,a.requester_id,a.requester_sponsor_id,a.requester_via,
	d.request_id,d.secret_id,s.name,s.class,d.secret_scope_level,d.secret_scope_id,d.runner_id,d.target,d.exec,
	a.expires_at < clock_timestamp()`

const approvalFrom = ` FROM approval_requests a
	JOIN deployment_requests d ON d.org_id=a.org_id AND d.id=a.deployment_request_id
	JOIN secrets s ON s.org_id=d.org_id AND s.id=d.secret_id`

func scanApproval(row pgx.Row) (Approval, error) {
	var a Approval
	var decidedAt *time.Time
	var decidedBy *uuid.UUID
	var hash, target, execRaw []byte
	var level, rtype, rvia string
	var expired bool
	err := row.Scan(&a.ID, &a.Status, &a.RequestedAt, &a.ExpiresAt, &decidedAt, &decidedBy, &a.Reason, &hash,
		&rtype, &a.Requester.ID, &a.Requester.SponsorID, &rvia,
		&a.RequestID, &a.SecretID, &a.SecretName, &a.SecretClass, &level, &a.Scope.ID, &a.RunnerID, &target, &execRaw, &expired)
	if err != nil {
		return Approval{}, err
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
	if err = json.Unmarshal(target, &a.Target); err != nil {
		return Approval{}, err
	}
	if execRaw != nil {
		var s execSnapshot
		if err = json.Unmarshal(execRaw, &s); err != nil {
			return Approval{}, err
		}
		a.NetAllowlist = s.Destinations
		a.Exec = &ApprovalExec{TemplateID: s.TemplateID, Digest: s.Digest, Mode: s.Mode}
		for k := range s.Params {
			a.Exec.ParamNames = append(a.Exec.ParamNames, k)
		}
		sort.Strings(a.Exec.ParamNames)
	}
	if expired && a.Status == "requested" {
		a.Status = "expired"
	}
	return a, nil
}

// GetApproval reads one approval of org. Another organization's id is
// ErrNotFound, the same as an id that never existed.
func (r *Repo) GetApproval(ctx context.Context, org, id uuid.UUID) (Approval, error) {
	if r == nil || r.pool == nil {
		return Approval{}, ErrUnavailable
	}
	a, err := scanApproval(r.pool.QueryRow(ctx, `SELECT `+approvalColumns+approvalFrom+` WHERE a.org_id=$1 AND a.id=$2`, org, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Approval{}, ErrNotFound
	}
	if err != nil {
		return Approval{}, ErrUnavailable
	}
	return a, nil
}

// ListApprovals returns the newest approvals of org, undecided first.
func (r *Repo) ListApprovals(ctx context.Context, org uuid.UUID, limit int) ([]Approval, error) {
	if r == nil || r.pool == nil {
		return nil, ErrUnavailable
	}
	if limit < 1 || limit > 200 {
		limit = 200
	}
	rows, err := r.pool.Query(ctx, `SELECT `+approvalColumns+approvalFrom+`
	 WHERE a.org_id=$1 ORDER BY (a.status='requested' AND a.expires_at>=clock_timestamp()) DESC, a.requested_at DESC LIMIT $2`, org, limit)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	var out []Approval
	for rows.Next() {
		a, err := scanApproval(rows)
		if err != nil {
			return nil, ErrUnavailable
		}
		out = append(out, a)
	}
	if rows.Err() != nil {
		return nil, ErrUnavailable
	}
	return out, nil
}

// DecideInput is one human decision. BindingHash is the hash printed on the
// card the approver looked at; the decision applies only if it still equals
// the stored one.
type DecideInput struct {
	OrgID          uuid.UUID
	ApprovalID     uuid.UUID
	ApproverID     uuid.UUID
	ApproverIsUser bool
	Approve        bool
	Reason         string
	BindingHash    string
}

type DecideResult struct {
	Status string // approved or rejected
	JobID  uuid.UUID
}

// Decide records the human decision. Approving creates exactly the job the
// stored request describes, in the same transaction; any mismatch between the
// hash shown, the hash stored and the hash recomputed from the stored fields
// refuses the decision and creates nothing.
func (r *Repo) Decide(ctx context.Context, in DecideInput) (DecideResult, error) {
	if r == nil || r.pool == nil || r.journal == nil || r.trust == nil {
		return DecideResult{}, ErrUnavailable
	}
	if !in.ApproverIsUser {
		return DecideResult{}, ErrNotHuman
	}
	if in.OrgID == uuid.Nil || in.ApprovalID == uuid.Nil || in.ApproverID == uuid.Nil || utf8.RuneCountInString(in.Reason) > maxReasonRunes || !utf8.ValidString(in.Reason) {
		return DecideResult{}, ErrInvalidArgument
	}
	shown, err := hex.DecodeString(in.BindingHash)
	if err != nil || len(shown) != 32 {
		return DecideResult{}, ErrBindingMismatch
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return DecideResult{}, ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Same lock order as Submit: organization first, so a decision, a rate
	// count and a policy edit never interleave.
	var org uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, in.OrgID).Scan(&org); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return DecideResult{}, ErrNotFound
		}
		return DecideResult{}, ErrUnavailable
	}
	var (
		reqRow, secretID, versionID, runnerID uuid.UUID
		status, rtype, rid, rsponsor, rvia    string
		requestID, level                      string
		scopeID                               uuid.UUID
		stored, targetJSON, execJSON          []byte
		expired                               bool
	)
	err = tx.QueryRow(ctx, `SELECT a.deployment_request_id,a.status,a.binding_hash,a.requester_type,a.requester_id,a.requester_sponsor_id,a.requester_via,
	 a.expires_at < clock_timestamp(),d.request_id,d.secret_id,d.version_id,d.runner_id,d.secret_scope_level,d.secret_scope_id,d.target,d.exec
	 FROM approval_requests a JOIN deployment_requests d ON d.org_id=a.org_id AND d.id=a.deployment_request_id
	 WHERE a.org_id=$1 AND a.id=$2 FOR UPDATE OF a`, in.OrgID, in.ApprovalID).Scan(&reqRow, &status, &stored, &rtype, &rid, &rsponsor, &rvia, &expired,
		&requestID, &secretID, &versionID, &runnerID, &level, &scopeID, &targetJSON, &execJSON)
	if errors.Is(err, pgx.ErrNoRows) {
		return DecideResult{}, ErrNotFound
	}
	if err != nil {
		return DecideResult{}, ErrUnavailable
	}
	if status != "requested" {
		return DecideResult{}, ErrAlreadyDecided
	}
	if expired {
		return DecideResult{}, ErrExpired
	}
	if rtype == string(audit.ActorUser) && rid == in.ApproverID.String() {
		return DecideResult{}, ErrSelfApproval
	}
	var target runnerproto.Target
	if json.Unmarshal(targetJSON, &target) != nil {
		return DecideResult{}, ErrBindingMismatch
	}
	canonical, err := json.Marshal(target)
	if err != nil {
		return DecideResult{}, ErrBindingMismatch
	}
	scope := tenancy.Scope{Level: tenancy.Level(level), ID: scopeID}
	recomputed := bindHash("keep/deploy/request/v1", in.OrgID.String(), secretID.String(), versionID.String(), runnerID.String(), scope.String(), string(canonical), rtype, rid, rsponsor, rvia)
	var snap execSnapshot
	isExec := execJSON != nil
	if isExec {
		if json.Unmarshal(execJSON, &snap) != nil {
			return DecideResult{}, ErrBindingMismatch
		}
		recomputed = execBinding(in.OrgID, secretID, versionID, runnerID, scope.String(), snap, rtype, rid, rsponsor, rvia)
	}
	if !equalHash(stored, shown) || !equalHash(stored, recomputed[:]) {
		return DecideResult{}, ErrBindingMismatch
	}

	res := DecideResult{Status: "rejected"}
	approvedAt := time.Time{}
	if in.Approve {
		res.Status = "approved"
		req := Request{OrgID: in.OrgID, Scope: scope, SecretID: secretID, VersionID: versionID, RunnerID: runnerID, RequestID: requestID, Target: target}
		secret, lerr := loadSecret(ctx, tx, req)
		if lerr != nil {
			return DecideResult{}, ErrRefused
		}
		host, terr := r.trust(ctx, tx, in.OrgID, runnerID)
		if terr != nil {
			return DecideResult{}, ErrRefused
		}
		host.ID = runnerID.String()
		// A human approval lifts the "needs approval" outcome only. Hosts that
		// policy refuses outright (production on a shared UID, unknown
		// attributes) stay refused, and so do providers the runner cannot use.
		if isExec {
			// The destinations the approver saw are the ones in the stored
			// snapshot. If the organization's template has been replaced
			// since, what the runner would hold is not what was approved.
			lt, terr := loadExecTemplate(ctx, tx, in.OrgID, snap.TemplateID)
			if terr != nil || lt.digest != snap.Digest || secret.provider != runnerproto.ProviderBuiltin ||
				(secret.class == "prod" && (!host.AttributesKnown || host.UIDShared)) {
				return DecideResult{}, ErrRefused
			}
		} else if _, perr := Evaluate(Policy{}, host, secretID, secret.class, target, true); perr != nil || secret.provider != runnerproto.ProviderBuiltin {
			return DecideResult{}, ErrRefused
		}
		limit := 10
		if qerr := tx.QueryRow(ctx, `SELECT max_deploys_per_hour FROM deployment_policies WHERE org_id=$1`, in.OrgID).Scan(&limit); qerr != nil && !errors.Is(qerr, pgx.ErrNoRows) {
			return DecideResult{}, ErrUnavailable
		}
		limited, lerr := rateLimited(ctx, tx, in.OrgID, secretID, runnerID, limit)
		if lerr != nil {
			return DecideResult{}, lerr
		}
		if limited {
			return DecideResult{}, ErrRefused
		}
		if isExec {
			res.JobID, err = insertExecJob(ctx, tx, in.OrgID, runnerID, reqRow, requestID, secretID, versionID, secret, execJob(snap))
		} else {
			res.JobID, err = insertJob(ctx, tx, in.OrgID, runnerID, reqRow, requestID, secretID, versionID, secret, target)
		}
		if err != nil {
			return DecideResult{}, err
		}
	}
	if err = tx.QueryRow(ctx, `UPDATE approval_requests SET status=$3,decided_by=$4,decided_at=clock_timestamp(),decision_reason=$5
	 WHERE org_id=$1 AND id=$2 RETURNING decided_at`, in.OrgID, in.ApprovalID, res.Status, in.ApproverID, in.Reason).Scan(&approvedAt); err != nil {
		return DecideResult{}, ErrUnavailable
	}
	rec := audit.Record{OrgID: in.OrgID.String(), RequestID: requestID, Scope: scope.String(),
		Actor:  audit.Actor{Type: audit.ActorUser, ID: in.ApproverID.String(), Via: audit.ViaConsole},
		Action: audit.ActionApprovalDecided, Secret: audit.SecretRef{ID: secretID.String(), Version: versionID.String()},
		Target: audit.Target{RunnerID: runnerID.String(), Kind: string(target.Kind)},
		Intent: audit.Intent{Reason: in.Reason},
		// The journal schema has no hash column; the binding hash travels in
		// the rule id so the record alone says which exact request was decided.
		Policy:   audit.Policy{Decision: audit.DecisionAllow, RuleID: "approval-binding:" + hex.EncodeToString(stored)},
		Approval: audit.Approval{ID: in.ApprovalID.String(), ApproverID: in.ApproverID.String(), DecidedAt: approvedAt.UTC().Truncate(time.Microsecond)},
		Result:   audit.Result{Status: audit.StatusOK}}
	if isExec {
		rec.Target.Kind = "exec"
	}
	if !in.Approve {
		rec.Policy.Decision = audit.DecisionDeny
		rec.Result = audit.Result{Status: audit.StatusFailed, ErrorClass: audit.ErrClassPermissionDenied}
	}
	written, err := r.journal.AppendTx(ctx, tx, rec)
	if err != nil {
		return DecideResult{}, ErrUnavailable
	}
	if err = tx.Commit(ctx); err != nil {
		return DecideResult{}, ErrUnavailable
	}
	r.journal.LogCommitted(ctx, written)
	return res, nil
}
