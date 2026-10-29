package deployment

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/pkg/execpolicy"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrTemplateUnknown: the organization has no such exec template.
var ErrTemplateUnknown = errors.New("deployment: exec template unknown")

const (
	execRequestDomain = "keep/exec/request/v1"
	execTargetDomain  = "keep/exec/target/v1"
)

// execSnapshot is the exec part of a stored request: what the approver is
// shown and what the job will carry. Destinations are copied out of the
// template at request time, so an edit of the template afterwards cannot
// change what an existing approval covers.
type execSnapshot struct {
	TemplateID   string            `json:"template_id"`
	Digest       string            `json:"digest"`
	Mode         string            `json:"mode"`
	Destinations []string          `json:"destinations,omitempty"`
	Params       map[string]string `json:"params,omitempty"`
}

// ExecRequest is an exec_with_secret request: authenticated references, a
// template id and the values of its parameters. The template itself comes
// from the organization's policy, never from the request.
type ExecRequest struct {
	OrgID      uuid.UUID
	Scope      tenancy.Scope
	SecretID   uuid.UUID
	VersionID  uuid.UUID
	RunnerID   uuid.UUID
	RequestID  string
	Actor      audit.Actor
	TemplateID string
	Params     map[string]string
}

// PutExecTemplate registers or replaces an organization's exec template. It
// must pass the same validation the runner applies to its local copy.
func (r *Repo) PutExecTemplate(ctx context.Context, org uuid.UUID, t runnerproto.ExecTemplate) error {
	if r == nil || r.pool == nil {
		return ErrUnavailable
	}
	tpl, err := t.Template()
	if err != nil {
		return ErrInvalidArgument
	}
	if _, err = execpolicy.Validate(tpl); err != nil {
		return ErrInvalidArgument
	}
	body, err := json.Marshal(t)
	if err != nil {
		return ErrInvalidArgument
	}
	// Same organization lock as SubmitExec and Decide: a replacement waits for
	// an in-flight approval, and an approval re-reads the template afterwards.
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var lockedOrg uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, org).Scan(&lockedOrg); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidArgument
		}
		return ErrUnavailable
	}
	if _, err = tx.Exec(ctx, `INSERT INTO exec_templates(org_id,template_id,template,digest) VALUES($1,$2,$3,$4)
	 ON CONFLICT (org_id,template_id) DO UPDATE SET template=EXCLUDED.template,digest=EXCLUDED.digest`, org, t.ID, body, execpolicy.Digest(tpl)); err != nil {
		return ErrInvalidArgument
	}
	if err = tx.Commit(ctx); err != nil {
		return ErrUnavailable
	}
	return nil
}

type loadedTemplate struct {
	tpl      execpolicy.Template
	decision execpolicy.Decision
	digest   string
}

// loadExecTemplate reads and re-validates a template under the caller's
// transaction. A row that no longer validates is as good as absent.
func loadExecTemplate(ctx context.Context, tx pgx.Tx, org uuid.UUID, id string) (loadedTemplate, error) {
	var body []byte
	err := tx.QueryRow(ctx, `SELECT template FROM exec_templates WHERE org_id=$1 AND template_id=$2`, org, id).Scan(&body)
	if errors.Is(err, pgx.ErrNoRows) {
		return loadedTemplate{}, ErrTemplateUnknown
	}
	if err != nil {
		return loadedTemplate{}, ErrUnavailable
	}
	var t runnerproto.ExecTemplate
	if json.Unmarshal(body, &t) != nil || t.ID != id {
		return loadedTemplate{}, ErrTemplateUnknown
	}
	tpl, err := t.Template()
	if err != nil {
		return loadedTemplate{}, ErrTemplateUnknown
	}
	dec, err := execpolicy.Validate(tpl)
	if err != nil {
		return loadedTemplate{}, ErrTemplateUnknown
	}
	return loadedTemplate{tpl: tpl, decision: dec, digest: execpolicy.Digest(tpl)}, nil
}

func snapshotOf(id string, lt loadedTemplate, params map[string]string) execSnapshot {
	s := execSnapshot{TemplateID: id, Digest: lt.digest, Params: params}
	if lt.tpl.Network.Mode == execpolicy.NetAllowlist {
		s.Mode = "allowlist"
	} else {
		s.Mode = "none"
	}
	for _, d := range lt.decision.Destinations {
		s.Destinations = append(s.Destinations, d.String())
	}
	sort.Strings(s.Destinations)
	return s
}

// execBinding is the hash a human approves. It states the network mode and
// every destination itself instead of leaning on the template digest: the
// digest is a stored value, so only fields hashed here are checked against a
// stored row that was edited behind the console.
func execBinding(org, secretID, versionID, runnerID uuid.UUID, scope string, s execSnapshot, rtype, rid, rsponsor, rvia string) [32]byte {
	vals := []string{org.String(), secretID.String(), versionID.String(), runnerID.String(), scope, s.TemplateID, s.Digest, s.Mode, strconv.Itoa(len(s.Destinations))}
	vals = append(vals, s.Destinations...)
	keys := make([]string, 0, len(s.Params))
	for k := range s.Params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	vals = append(vals, strconv.Itoa(len(keys)))
	for _, k := range keys {
		vals = append(vals, k, s.Params[k])
	}
	vals = append(vals, rtype, rid, rsponsor, rvia)
	return bindHash(execRequestDomain, vals...)
}

func execJob(s execSnapshot) *runnerproto.Exec {
	return &runnerproto.Exec{TemplateID: s.TemplateID, Digest: s.Digest, Params: s.Params}
}

// SubmitExec creates exactly one durable decision for an exec request id. A
// template that declares network destinations always waits for a human, and
// no job row exists until the approval of exactly those destinations;
// a template with network none follows the secret's class like a deployment.
func (r *Repo) SubmitExec(ctx context.Context, in ExecRequest) (Outcome, error) {
	c := commonRequest{OrgID: in.OrgID, Scope: in.Scope, SecretID: in.SecretID, VersionID: in.VersionID, RunnerID: in.RunnerID, RequestID: in.RequestID, Actor: in.Actor}
	if r == nil || r.pool == nil || r.journal == nil || r.trust == nil {
		return Outcome{}, ErrUnavailable
	}
	if c.OrgID == uuid.Nil || c.SecretID == uuid.Nil || c.VersionID == uuid.Nil || c.RunnerID == uuid.Nil || c.Scope.ID == uuid.Nil ||
		!reqid.Valid(c.RequestID) || c.Actor.ID == "" || !knownActor(c.Actor) {
		return Outcome{}, ErrInvalidArgument
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Outcome{}, ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var org uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, c.OrgID).Scan(&org); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Outcome{}, ErrNotFound
		}
		return Outcome{}, ErrUnavailable
	}
	lt, err := loadExecTemplate(ctx, tx, c.OrgID, in.TemplateID)
	if err != nil {
		return Outcome{}, err
	}
	// Exactly the declared parameters, as the runner requires: an extra key
	// would reach the approver's card and mean nothing to the template.
	if len(in.Params) != len(lt.tpl.Params) {
		return Outcome{}, ErrInvalidArgument
	}
	// Parameter values must satisfy the template's own patterns and probes.
	if _, err = execpolicy.Expand(lt.tpl, in.Params); err != nil {
		return Outcome{}, ErrInvalidArgument
	}
	snap := snapshotOf(in.TemplateID, lt, in.Params)
	execJSON, err := json.Marshal(snap)
	if err != nil {
		return Outcome{}, ErrInvalidArgument
	}
	requestHash := execBinding(c.OrgID, c.SecretID, c.VersionID, c.RunnerID, c.Scope.String(), snap, string(c.Actor.Type), c.Actor.ID, c.Actor.SponsorID, string(c.Actor.Via))
	targetKey := bindHash(execTargetDomain, c.OrgID.String(), c.SecretID.String(), c.RunnerID.String(), string(execJSON))
	prior, found, err := priorOutcome(ctx, tx, c.OrgID, c.RequestID, requestHash[:])
	if err != nil {
		return Outcome{}, err
	}
	if found {
		return prior, nil
	}
	host, err := r.trust(ctx, tx, c.OrgID, c.RunnerID)
	if err != nil {
		return Outcome{}, ErrNotFound
	}
	host.ID = c.RunnerID.String()
	secret, err := loadSecret(ctx, tx, Request{OrgID: c.OrgID, Scope: c.Scope, SecretID: c.SecretID, VersionID: c.VersionID})
	if err != nil {
		return Outcome{}, err
	}
	status, limit, err := r.execStatus(ctx, tx, c.OrgID, host, secret, c.SecretID, lt, in.TemplateID)
	if err != nil {
		return Outcome{}, err
	}
	if status == Queued {
		limited, lerr := rateLimited(ctx, tx, c.OrgID, c.SecretID, c.RunnerID, limit)
		if lerr != nil {
			return Outcome{}, lerr
		}
		if limited {
			status = RateLimited
		}
	}
	return r.finish(ctx, tx, finishInput{in: c, secret: secret, status: status, requestHash: requestHash, targetKey: targetKey, targetJSON: []byte(`{}`), execJSON: execJSON,
		job: func(row uuid.UUID) (uuid.UUID, error) {
			return insertExecJob(ctx, tx, c.OrgID, c.RunnerID, row, c.RequestID, c.SecretID, c.VersionID, secret, execJob(snap))
		}})
}

// execStatus is the policy outcome of an exec request before rate accounting:
// a human for every network template, for a production secret and for any
// secret/template/host the organization's exec rules do not name; a refusal
// for a production secret on a host that cannot hold it; otherwise queued.
func (r *Repo) execStatus(ctx context.Context, tx pgx.Tx, org uuid.UUID, host Host, secret frozenSecret, secretID uuid.UUID, lt loadedTemplate, templateID string) (Status, int, error) {
	limit := 10
	policyJSON := []byte(`{"rules":[]}`)
	err := tx.QueryRow(ctx, `SELECT rules,max_deploys_per_hour FROM deployment_policies WHERE org_id=$1`, org).Scan(&policyJSON, &limit)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", 0, ErrUnavailable
	}
	var p Policy
	if json.Unmarshal(policyJSON, &p) != nil || !validPolicy(p) || limit < 1 || limit > 1000 {
		return "", 0, ErrUnavailable
	}
	status := Queued
	switch {
	case secret.class == "prod" && (!host.AttributesKnown || host.UIDShared):
		status = Denied
	case lt.decision.RequiresApproval || secret.class == "prod":
		status = NeedsApproval
	case !ExecAllowed(p, host, secretID, templateID):
		// Like a deployment, an exec of this secret on this host waits for a
		// human until the organization's policy names it.
		status = NeedsApproval
	case secret.provider != runnerproto.ProviderBuiltin:
		status = UnsupportedProvider
	}
	return status, limit, nil
}
