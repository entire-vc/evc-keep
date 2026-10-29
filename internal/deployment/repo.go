package deployment

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/registry"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrUnavailable         = errors.New("deployment: unavailable")
	ErrNotFound            = errors.New("deployment: reference unavailable")
	ErrConflict            = errors.New("deployment: request id conflict")
	ErrUnsupportedProvider = errors.New("deployment: provider unsupported for runner delivery")
)

// TrustLookup reads the enrolled registry under the caller's transaction.
// It must reject revoked, expired, keyless and cross-organization runners.
// A trusted host is never accepted in a deployment request.
type TrustLookup func(context.Context, pgx.Tx, uuid.UUID, uuid.UUID) (Host, error)

type Journal interface {
	AppendTx(context.Context, pgx.Tx, audit.Record) (audit.Record, error)
	LogCommitted(context.Context, audit.Record)
}

type Repo struct {
	pool    *pgxpool.Pool
	journal Journal
	trust   TrustLookup
	confirm Confirmer
}

// WithConfirmer makes every new approval wait for a person's card too: the
// card is created before the approval commits, and a card that cannot be made
// fails the request. Nil (the default) asks nobody outside Keep.
func (r *Repo) WithConfirmer(c Confirmer) *Repo {
	r.confirm = c
	return r
}

// Confirms reports whether new approvals wait for a card; startup wiring tests
// read it, nothing else does.
func (r *Repo) Confirms() bool { return r.confirm != nil }

// NewRepo always obtains host attributes and delivery eligibility from the
// enrolled registry under the same transaction as the policy decision.
func NewRepo(pool *pgxpool.Pool, journal Journal) *Repo {
	if pool == nil {
		return &Repo{journal: journal}
	}
	runners := registry.NewRepo(pool)
	trust := func(ctx context.Context, tx pgx.Tx, org, runner uuid.UUID) (Host, error) {
		d, err := runners.GetDeliveryTrustTx(ctx, tx, org, runner)
		if err != nil {
			return Host{}, err
		}
		return Host{ID: runner.String(), AttributesKnown: d.AttrsKnown, UIDShared: d.UIDShared, Labels: d.HostLabels}, nil
	}
	return &Repo{pool: pool, journal: journal, trust: trust}
}

// Request contains authenticated metadata only. Scope is the caller-resolved
// tenancy scope; it must match the selected secret. Actor is the authenticated
// principal, not an arbitrary display name from a request body.
type Request struct {
	OrgID     uuid.UUID
	Scope     tenancy.Scope
	SecretID  uuid.UUID
	VersionID uuid.UUID
	RunnerID  uuid.UUID
	RequestID string
	Target    runnerproto.Target
	Actor     audit.Actor
}

type Status string

const (
	Queued              Status = "queued"
	NeedsApproval       Status = "approval_required"
	Denied              Status = "denied"
	RateLimited         Status = "rate_limited"
	UnsupportedProvider Status = "unsupported_provider"
)

type Outcome struct {
	ID         uuid.UUID
	Status     Status
	ApprovalID uuid.UUID
	JobID      uuid.UUID
	// Created is true only for the call that stored the decision; a replay of
	// the same request id returns the first outcome with Created false, so a
	// notification is sent once per approval.
	Created bool
}

type frozenSecret struct {
	name, class, provider, providerRef, providerVersion, fingerprint string
	secretScopeLevel, storeScopeLevel                                string
	secretScopeID, storeScopeID, storeID                             uuid.UUID
}

// Submit creates exactly one durable decision for a request id. A second call
// with the same canonical metadata returns the first outcome; a changed
// payload returns ErrConflict. New policy decisions, rate accounting, jobs,
// approvals and the two audit records commit or roll back together.
func (r *Repo) Submit(ctx context.Context, in Request) (Outcome, error) {
	if r == nil || r.pool == nil || r.journal == nil || r.trust == nil {
		return Outcome{}, ErrUnavailable
	}
	if in.OrgID == uuid.Nil || in.SecretID == uuid.Nil || in.VersionID == uuid.Nil || in.RunnerID == uuid.Nil ||
		in.Scope.ID == uuid.Nil || !reqid.Valid(in.RequestID) || in.Target.Validate() != nil || networkTarget(in.Target) ||
		in.Actor.ID == "" || !knownActor(in.Actor) {
		return Outcome{}, ErrInvalidArgument
	}
	targetJSON, err := json.Marshal(in.Target)
	if err != nil {
		return Outcome{}, ErrInvalidArgument
	}
	requestHash := bindHash("keep/deploy/request/v1", in.OrgID.String(), in.SecretID.String(), in.VersionID.String(), in.RunnerID.String(), in.Scope.String(), string(targetJSON), string(in.Actor.Type), in.Actor.ID, in.Actor.SponsorID, string(in.Actor.Via))
	targetKey := bindHash("keep/deploy/target/v1", in.OrgID.String(), in.SecretID.String(), in.RunnerID.String(), string(targetJSON))
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Outcome{}, ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// This lock serializes all deployments in one organization, including
	// the rate count and policy edits. Registry locks come after this lock.
	var org uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, in.OrgID).Scan(&org); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Outcome{}, ErrNotFound
		}
		return Outcome{}, ErrUnavailable
	}
	prior, found, err := priorOutcome(ctx, tx, in.OrgID, in.RequestID, requestHash[:])
	if err != nil {
		return Outcome{}, err
	}
	if found {
		return prior, nil
	}
	host, err := r.trust(ctx, tx, in.OrgID, in.RunnerID)
	if err != nil {
		return Outcome{}, ErrNotFound
	}
	host.ID = in.RunnerID.String() // never trust an ID supplied by a lookup adapter
	secret, err := loadSecret(ctx, tx, in)
	if err != nil {
		return Outcome{}, err
	}
	var policyJSON []byte
	limit := 10
	err = tx.QueryRow(ctx, `SELECT rules,max_deploys_per_hour FROM deployment_policies WHERE org_id=$1`, in.OrgID).Scan(&policyJSON, &limit)
	if errors.Is(err, pgx.ErrNoRows) {
		policyJSON = []byte(`{"rules":[]}`)
		err = nil
	}
	if err != nil {
		return Outcome{}, ErrUnavailable
	}
	var p Policy
	if json.Unmarshal(policyJSON, &p) != nil || !validPolicy(p) || limit < 1 || limit > 1000 {
		return Outcome{}, ErrUnavailable
	}
	var registered bool
	if secret.class == "prod" {
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM approval_requests WHERE org_id=$1 AND target_key=$2 AND status='approved')`, in.OrgID, targetKey[:]).Scan(&registered)
		if err != nil {
			return Outcome{}, ErrUnavailable
		}
	}
	// loadSecret has already verified this exact ID/version against the org
	// and authenticated scope. Rules cannot authorize another catalog secret.
	decision, policyErr := Evaluate(p, host, in.SecretID, secret.class, in.Target, registered)
	status := NeedsApproval
	if errors.Is(policyErr, ErrPolicyDenied) {
		status = Denied
	} else if policyErr != nil {
		return Outcome{}, ErrUnavailable
	} else if decision == Allow {
		status = Queued
	}
	// The only production material issuer in this release resolves builtin
	// stores. Never enqueue a job that would burn its one-time material claim
	// with no available issuer. Preserve required approvals and policy denials;
	// provider capability only gates requests already allowed by policy.
	if status == Queued && secret.provider != runnerproto.ProviderBuiltin {
		status = UnsupportedProvider
	}
	if status == Queued {
		var limited bool
		if limited, err = rateLimited(ctx, tx, in.OrgID, in.SecretID, in.RunnerID, limit); err != nil {
			return Outcome{}, err
		}
		if limited {
			status = RateLimited
		}
	}
	return r.finish(ctx, tx, finishInput{in: commonRequest{OrgID: in.OrgID, Scope: in.Scope, SecretID: in.SecretID, VersionID: in.VersionID, RunnerID: in.RunnerID, RequestID: in.RequestID, Actor: in.Actor}, secret: secret, status: status, requestHash: requestHash, targetKey: targetKey, targetJSON: targetJSON,
		job: func(row uuid.UUID) (uuid.UUID, error) {
			return insertJob(ctx, tx, in.OrgID, in.RunnerID, row, in.RequestID, in.SecretID, in.VersionID, secret, in.Target)
		}})
}

// commonRequest is what every durable request carries, whatever it runs.
type commonRequest struct {
	OrgID     uuid.UUID
	Scope     tenancy.Scope
	SecretID  uuid.UUID
	VersionID uuid.UUID
	RunnerID  uuid.UUID
	RequestID string
	Actor     audit.Actor
}

type finishInput struct {
	in          commonRequest
	secret      frozenSecret
	status      Status
	requestHash [32]byte
	targetKey   [32]byte
	targetJSON  []byte
	execJSON    []byte // nil for a deployment
	job         func(requestRow uuid.UUID) (uuid.UUID, error)
}

// finish stores the decision, the approval or the job, and the audit records
// of one request, then commits. The caller holds the organization lock.
func (r *Repo) finish(ctx context.Context, tx pgx.Tx, f finishInput) (Outcome, error) {
	in, status, requestHash := f.in, f.status, f.requestHash
	id, err := uuid.NewV7()
	if err != nil {
		return Outcome{}, ErrUnavailable
	}
	out := Outcome{ID: id, Status: status, Created: true}
	var approvalExpires time.Time
	_, err = tx.Exec(ctx, `INSERT INTO deployment_requests(id,org_id,request_id,request_hash,target_key,secret_id,version_id,runner_id,secret_scope_level,secret_scope_id,target,exec,decision,created_at)
	 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,clock_timestamp())`, id, in.OrgID, in.RequestID, requestHash[:], f.targetKey[:], in.SecretID, in.VersionID, in.RunnerID, f.secret.secretScopeLevel, f.secret.secretScopeID, f.targetJSON, f.execJSON, string(status))
	if err != nil {
		return Outcome{}, ErrUnavailable
	}
	switch status {
	case NeedsApproval:
		out.ApprovalID, err = uuid.NewV7()
		if err != nil {
			return Outcome{}, ErrUnavailable
		}
		err = tx.QueryRow(ctx, `INSERT INTO approval_requests(id,org_id,deployment_request_id,binding_hash,target_key,requester_type,requester_id,requester_sponsor_id,requester_via,requested_at,expires_at)
		 SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,t,t+$10::bigint*interval '1 second' FROM (SELECT clock_timestamp() AS t) c RETURNING expires_at`, out.ApprovalID, in.OrgID, id, requestHash[:], f.targetKey[:],
			string(in.Actor.Type), in.Actor.ID, in.Actor.SponsorID, string(in.Actor.Via), int64(ApprovalTTL/time.Second)).Scan(&approvalExpires)
		if err != nil {
			return Outcome{}, ErrUnavailable
		}
	case Queued:
		out.JobID, err = f.job(id)
		if err != nil {
			return Outcome{}, err
		}
	}
	statusResult := audit.StatusPending
	policyDecision := audit.DecisionApprovalRequired
	errClass := audit.ErrClassNone
	if status == Queued {
		policyDecision = audit.DecisionAllow
	}
	if status == Denied || status == RateLimited || status == UnsupportedProvider {
		statusResult = audit.StatusFailed
		policyDecision = audit.DecisionDeny
		errClass = audit.ErrClassPolicyDenied
	}
	base := audit.Record{OrgID: in.OrgID.String(), RequestID: in.RequestID, Scope: in.Scope.String(), Actor: in.Actor,
		Secret: audit.SecretRef{ID: in.SecretID.String(), Version: in.VersionID.String()}, Target: audit.Target{RunnerID: in.RunnerID.String(), Kind: targetKind(f.execJSON)},
		Policy: audit.Policy{Decision: policyDecision}, Result: audit.Result{Status: statusResult, ErrorClass: errClass}}
	base.Action = audit.ActionDeployRequested
	first, err := r.journal.AppendTx(ctx, tx, base)
	if err != nil {
		return Outcome{}, ErrUnavailable
	}
	base.Action = audit.ActionDeployPolicyDecision
	if out.ApprovalID != uuid.Nil {
		base.Approval.ID = out.ApprovalID.String()
	}
	second, err := r.journal.AppendTx(ctx, tx, base)
	if err != nil {
		return Outcome{}, ErrUnavailable
	}
	var third audit.Record
	if out.ApprovalID != uuid.Nil {
		base.Action = audit.ActionApprovalRequested
		base.Policy.RuleID = "approval-binding:" + hex.EncodeToString(requestHash[:])
		if third, err = r.journal.AppendTx(ctx, tx, base); err != nil {
			return Outcome{}, ErrUnavailable
		}
	}
	var undo func(context.Context)
	if out.ApprovalID != uuid.Nil && r.confirm != nil {
		kind := "deploy"
		if f.execJSON != nil {
			kind = "exec"
		}
		// Last before the commit: a card that cannot be made rolls everything back.
		if undo, err = r.confirm.Confirm(ctx, tx, Confirmation{OrgID: in.OrgID, ApprovalID: out.ApprovalID, Kind: kind, SecretName: f.secret.name,
			SecretClass: f.secret.class, RequestID: in.RequestID, BindingHash: requestHash, ExpiresAt: approvalExpires}); err != nil {
			return Outcome{}, ErrUnavailable
		}
	}
	if err = tx.Commit(ctx); err != nil {
		if undo != nil {
			undo(ctx)
		}
		return Outcome{}, ErrUnavailable
	}
	r.journal.LogCommitted(ctx, first)
	r.journal.LogCommitted(ctx, second)
	if out.ApprovalID != uuid.Nil {
		r.journal.LogCommitted(ctx, third)
	}
	return out, nil
}

func knownActor(a audit.Actor) bool {
	switch a.Type {
	case audit.ActorAgent, audit.ActorUser, audit.ActorService:
	default:
		return false
	}
	switch a.Via {
	case audit.ViaAPI, audit.ViaCLI, audit.ViaMCP, audit.ViaMeshPlugin, audit.ViaConsole:
		return true
	default:
		return false
	}
}

func bindHash(domain string, values ...string) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(domain))
	var length [8]byte
	for _, v := range values {
		binary.BigEndian.PutUint64(length[:], uint64(len(v))) //nolint:gosec // len is nonnegative and fits uint64
		_, _ = h.Write(length[:])
		_, _ = h.Write([]byte(v))
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func priorOutcome(ctx context.Context, tx pgx.Tx, org uuid.UUID, requestID string, hash []byte) (Outcome, bool, error) {
	var out Outcome
	var stored []byte
	err := tx.QueryRow(ctx, `SELECT id,decision,request_hash FROM deployment_requests WHERE org_id=$1 AND request_id=$2`, org, requestID).Scan(&out.ID, &out.Status, &stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return Outcome{}, false, nil
	}
	if err != nil {
		return Outcome{}, false, ErrUnavailable
	}
	if !equalHash(stored, hash) {
		return Outcome{}, false, ErrConflict
	}
	switch out.Status {
	case NeedsApproval:
		err = tx.QueryRow(ctx, `SELECT id FROM approval_requests WHERE org_id=$1 AND deployment_request_id=$2`, org, out.ID).Scan(&out.ApprovalID)
	case Queued:
		err = tx.QueryRow(ctx, `SELECT id FROM deployment_jobs WHERE org_id=$1 AND deployment_request_id=$2`, org, out.ID).Scan(&out.JobID)
	}
	if err != nil {
		return Outcome{}, false, ErrUnavailable
	}
	return out, true, nil
}

func equalHash(a, b []byte) bool {
	if len(a) != 32 || len(b) != 32 {
		return false
	}
	var x byte
	for i := range a {
		x |= a[i] ^ b[i]
	}
	return x == 0
}

func loadSecret(ctx context.Context, tx pgx.Tx, in Request) (frozenSecret, error) {
	var s frozenSecret
	err := tx.QueryRow(ctx, `SELECT s.name,s.class,st.provider,s.provider_ref,v.provider_version,v.fingerprint,
	 s.scope_level,s.scope_id,st.owner_scope_level,st.owner_scope_id,st.id
	 FROM secrets s JOIN secret_versions v ON v.org_id=s.org_id AND v.secret_id=s.id
	 JOIN stores st ON st.org_id=s.org_id AND st.id=s.store_id
	 WHERE s.org_id=$1 AND s.id=$2 AND v.id=$3 AND s.status='active' AND v.disabled=false AND st.status='active'
	 FOR SHARE OF s,v,st`, in.OrgID, in.SecretID, in.VersionID).Scan(&s.name, &s.class, &s.provider, &s.providerRef, &s.providerVersion, &s.fingerprint,
		&s.secretScopeLevel, &s.secretScopeID, &s.storeScopeLevel, &s.storeScopeID, &s.storeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return frozenSecret{}, ErrNotFound
	}
	if err != nil {
		return frozenSecret{}, ErrUnavailable
	}
	if s.secretScopeLevel != string(in.Scope.Level) || s.secretScopeID != in.Scope.ID {
		return frozenSecret{}, ErrNotFound
	}
	return s, nil
}

// ApprovalTTL is how long a human has to decide an approval request.
const ApprovalTTL = 24 * time.Hour

// rateLimited reports whether the (secret, runner) pair already used its
// hourly allowance. The caller holds the organization lock.
func rateLimited(ctx context.Context, tx pgx.Tx, org, secretID, runner uuid.UUID, limit int) (bool, error) {
	var used int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM deployment_jobs WHERE org_id=$1 AND secret_id=$2 AND runner_id=$3 AND action<>'verify' AND created_at > clock_timestamp()-interval '1 hour'`, org, secretID, runner).Scan(&used)
	if err != nil {
		return false, ErrUnavailable
	}
	return used >= limit, nil
}

// insertJob freezes one signed-at-pull deploy job for a stored deployment
// request. With insertExecJob it is the only place a job row is written: an
// approval decides whether this runs, never what it contains.
func insertJob(ctx context.Context, tx pgx.Tx, org, runner, requestRow uuid.UUID, requestID string, secretID, versionID uuid.UUID, secret frozenSecret, target runnerproto.Target) (uuid.UUID, error) {
	return storeJob(ctx, tx, org, runner, requestRow, requestID, secretID, versionID, secret, runnerproto.ActionDeploy, target, nil)
}

func insertExecJob(ctx context.Context, tx pgx.Tx, org, runner, requestRow uuid.UUID, requestID string, secretID, versionID uuid.UUID, secret frozenSecret, ex *runnerproto.Exec) (uuid.UUID, error) {
	return storeJob(ctx, tx, org, runner, requestRow, requestID, secretID, versionID, secret, runnerproto.ActionExec, runnerproto.Target{}, ex)
}

func storeJob(ctx context.Context, tx pgx.Tx, org, runner, requestRow uuid.UUID, requestID string, secretID, versionID uuid.UUID, secret frozenSecret, action runnerproto.Action, target runnerproto.Target, ex *runnerproto.Exec) (uuid.UUID, error) {
	jobID, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, ErrUnavailable
	}
	nonce := make([]byte, runnerproto.NonceSize)
	if _, err = rand.Read(nonce); err != nil {
		return uuid.Nil, ErrUnavailable
	}
	issued := time.Now().UTC().Truncate(time.Second)
	job := runnerproto.Job{JobID: jobID.String(), OrgID: org.String(), RunnerID: runner.String(),
		Secret:          runnerproto.SecretRef{StoreID: secret.storeID.String(), Provider: secret.provider, Name: secret.name, Scope: secret.class},
		ExpectedVersion: secret.providerVersion, ExpectedFingerprint: secret.fingerprint, Action: action,
		Target: target, Exec: ex, IssuedAt: issued, NotAfter: issued.Add(runnerproto.MaxJobTTL), Nonce: nonce}
	payload, err := runnerproto.EncodeJob(job)
	if err != nil {
		return uuid.Nil, ErrInvalidArgument
	}
	_, err = tx.Exec(ctx, `INSERT INTO deployment_jobs(id,org_id,runner_id,deployment_request_id,request_id,secret_id,version_id,secret_scope_level,secret_scope_id,store_id,store_owner_scope_level,store_owner_scope_id,provider,provider_ref,provider_version,catalog_name,catalog_class,job_payload,nonce,expires_at,created_at,action)
	 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,clock_timestamp(),$21)`, jobID, org, runner, requestRow, requestID, secretID, versionID, secret.secretScopeLevel, secret.secretScopeID, secret.storeID, secret.storeScopeLevel, secret.storeScopeID, secret.provider, secret.providerRef, secret.providerVersion, secret.name, secret.class, payload, nonce, job.NotAfter, string(action))
	if err != nil {
		return uuid.Nil, ErrUnavailable
	}
	return jobID, nil
}

// targetKind is what the journal records as the kind of the thing that ran:
// "exec" for an exec request, empty for a deployment (its kind is in the job).
func targetKind(execJSON []byte) string {
	if execJSON != nil {
		return "exec"
	}
	return ""
}
