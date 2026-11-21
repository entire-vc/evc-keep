package deployment

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AdoptRequest contains authenticated references and one exact destination.
// The server chooses the current catalog version and registry host; neither
// fingerprints, versions, host names nor health assertions are caller input.
type AdoptRequest struct {
	OrgID     uuid.UUID
	Scope     tenancy.Scope
	SecretID  uuid.UUID
	RunnerID  uuid.UUID
	RequestID string
	Target    runnerproto.Target
	Actor     audit.Actor
}

// SubmitAdopt freezes an explicitly authorized read, not a deployment. The
// queue and human approvals share transport with deploy, but the action,
// request binding, policy rules, audit and eventual provenance are separate.
func (r *Repo) SubmitAdopt(ctx context.Context, in AdoptRequest) (Outcome, error) {
	if r == nil || r.pool == nil || r.journal == nil || r.trust == nil {
		return Outcome{}, ErrUnavailable
	}
	if in.OrgID == uuid.Nil || in.SecretID == uuid.Nil || in.RunnerID == uuid.Nil || in.Scope.ID == uuid.Nil || !in.Scope.Level.Valid() ||
		!reqid.Valid(in.RequestID) || in.Actor.ID == "" || !knownActor(in.Actor) || !validAdoptionTarget(in.Target) {
		return Outcome{}, ErrInvalidArgument
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Outcome{}, ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var org uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, in.OrgID).Scan(&org); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Outcome{}, ErrNotFound
		}
		return Outcome{}, ErrUnavailable
	}
	// A retry remains bound to the original version even if current changed.
	// It may acknowledge an old request, but it cannot create another job or
	// make an old attestation register against the new current version.
	var versionID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT version_id FROM deployment_requests WHERE org_id=$1 AND request_id=$2`, in.OrgID, in.RequestID).Scan(&versionID)
	if err == nil {
		hash := adoptionBinding(in, versionID)
		out, _, perr := priorOutcome(ctx, tx, in.OrgID, in.RequestID, hash[:])
		return out, perr
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Outcome{}, ErrUnavailable
	}
	host, err := r.trust(ctx, tx, in.OrgID, in.RunnerID)
	if err != nil {
		return Outcome{}, ErrNotFound
	}
	host.ID = in.RunnerID.String()
	versionID, err = currentVersionID(ctx, tx, in.OrgID, in.SecretID)
	if err != nil {
		return Outcome{}, err
	}
	secret, err := loadSecret(ctx, tx, Request{OrgID: in.OrgID, Scope: in.Scope, SecretID: in.SecretID, VersionID: versionID})
	if err != nil {
		return Outcome{}, err
	}
	p, limit, err := loadPolicy(ctx, tx, in.OrgID)
	if err != nil {
		return Outcome{}, err
	}
	decision, perr := EvaluateAdoption(p, host, in.SecretID, secret.class, in.Target)
	status := NeedsApproval
	switch {
	case errors.Is(perr, ErrPolicyDenied):
		status = Denied
	case perr != nil:
		return Outcome{}, ErrUnavailable
	case decision == Allow:
		status = Queued
	}
	if status == Queued && secret.provider != runnerproto.ProviderBuiltin {
		status = UnsupportedProvider
	}
	if status == Queued {
		limited, lerr := rateLimited(ctx, tx, in.OrgID, in.SecretID, in.RunnerID, limit)
		if lerr != nil {
			return Outcome{}, lerr
		}
		if limited {
			status = RateLimited
		}
	}
	targetJSON, _ := json.Marshal(in.Target)
	key := bindHash("keep/adopt/target/v1", in.OrgID.String(), in.SecretID.String(), in.RunnerID.String(), string(targetJSON))
	return r.finish(ctx, tx, finishInput{
		in:     commonRequest{OrgID: in.OrgID, Scope: in.Scope, SecretID: in.SecretID, VersionID: versionID, RunnerID: in.RunnerID, RequestID: in.RequestID, Actor: in.Actor},
		secret: secret, status: status, requestHash: adoptionBinding(in, versionID), targetKey: key, targetJSON: targetJSON, adoption: true,
		job: func(row uuid.UUID) (uuid.UUID, error) {
			return storeJob(ctx, tx, in.OrgID, in.RunnerID, row, in.RequestID, in.SecretID, versionID, secret, runnerproto.ActionAdopt, in.Target, nil)
		},
	})
}

func adoptionBinding(in AdoptRequest, versionID uuid.UUID) [32]byte {
	target, _ := json.Marshal(in.Target)
	return bindHash("keep/adopt/request/v1", in.OrgID.String(), in.SecretID.String(), versionID.String(), in.RunnerID.String(), in.Scope.String(), string(target),
		string(in.Actor.Type), in.Actor.ID, in.Actor.SponsorID, string(in.Actor.Via))
}

// The secret lock prevents a concurrent version insert from crossing this
// current-version decision. Result acceptance takes the same lock again.
func currentVersionID(ctx context.Context, tx pgx.Tx, org, secret uuid.UUID) (uuid.UUID, error) {
	var id uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM secrets WHERE org_id=$1 AND id=$2 AND status='active' FOR UPDATE`, org, secret).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	}
	if err != nil {
		return uuid.Nil, ErrUnavailable
	}
	err = tx.QueryRow(ctx, `SELECT id FROM secret_versions WHERE org_id=$1 AND secret_id=$2 AND NOT disabled ORDER BY seal_seq DESC LIMIT 1 FOR SHARE`, org, secret).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	}
	if err != nil {
		return uuid.Nil, ErrUnavailable
	}
	return id, nil
}

func loadPolicy(ctx context.Context, tx pgx.Tx, org uuid.UUID) (Policy, int, error) {
	var raw []byte
	limit := 10
	err := tx.QueryRow(ctx, `SELECT rules,max_deploys_per_hour FROM deployment_policies WHERE org_id=$1`, org).Scan(&raw, &limit)
	if errors.Is(err, pgx.ErrNoRows) {
		return Policy{}, limit, nil
	}
	var p Policy
	if err != nil || json.Unmarshal(raw, &p) != nil || !validPolicy(p) || limit < 1 || limit > 1000 {
		return Policy{}, 0, ErrUnavailable
	}
	return p, limit, nil
}
