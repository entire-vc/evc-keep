// Package rotwire connects the rotation engine to the parts of Keep that
// already exist: the carrier list, the deployment jobs a runner executes and
// the carrier verification a runner answers. It moves ids, versions,
// fingerprints and closed classes; a value is sealed by the store and laid
// out by a runner, and never passes here.
package rotwire

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/carriers"
	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/rotation"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrRefused is the only error the adapters return for a carrier: why is in
// the closed state of the run, never in a message that could sit next to a value.
var ErrRefused = errors.New("rotwire: carrier step refused")

const defaultPoll = 250 * time.Millisecond

// systemActor is who the rotation acts as in the deployment records.
var systemActor = audit.Actor{Type: audit.ActorService, ID: "keep-rotation", Via: audit.ViaAPI}

// CarrierSource is what *carriers.Service offers.
type CarrierSource interface {
	List(ctx context.Context, org, secret uuid.UUID) ([]carriers.Carrier, error)
}

// Lister implements rotation.Carriers.
type Lister struct{ Source CarrierSource }

func (l Lister) List(ctx context.Context, ref rotation.Ref) ([]rotation.Carrier, error) {
	list, err := l.Source.List(ctx, ref.OrgID, ref.SecretID)
	if err != nil {
		return nil, ErrRefused
	}
	out := make([]rotation.Carrier, 0, len(list))
	for _, c := range list {
		out = append(out, rotation.Carrier{ID: c.ID.String()})
	}
	return out, nil
}

// Deployments is what *deployment.Repo offers.
type Deployments interface {
	Submit(context.Context, deployment.Request) (deployment.Outcome, error)
	Report(context.Context, uuid.UUID, string) (deployment.Report, error)
	SubmitVerify(context.Context, deployment.VerifyRequest) (deployment.VerifyReport, error)
	VerifyReport(context.Context, uuid.UUID, string) (deployment.VerifyReport, error)
}

// Deployer implements rotation.Deployer and rotation.Verifier over the signed
// runner jobs: one deploy job per carrier, one verify job per run.
type Deployer struct {
	Pool        *pgxpool.Pool
	Carriers    CarrierSource
	Deployments Deployments
	// Poll is how often a pending job is read again (default 250ms).
	Poll time.Duration
}

func (d *Deployer) poll() time.Duration {
	if d.Poll > 0 {
		return d.Poll
	}
	return defaultPoll
}

// wait calls fn until it says done or ctx ends.
func (d *Deployer) wait(ctx context.Context, fn func() (bool, error)) error {
	for {
		done, err := fn()
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		select {
		case <-ctx.Done():
			return ErrRefused
		case <-time.After(d.poll()):
		}
	}
}

type secretFacts struct {
	scope     tenancy.Scope
	versionID uuid.UUID
}

func (d *Deployer) facts(ctx context.Context, ref rotation.Ref, version string) (secretFacts, error) {
	var f secretFacts
	var level string
	err := d.Pool.QueryRow(ctx, `SELECT s.scope_level, s.scope_id, v.id FROM secrets s
		JOIN secret_versions v ON v.org_id=s.org_id AND v.secret_id=s.id
		WHERE s.org_id=$1 AND s.id=$2 AND v.provider_version=$3`, ref.OrgID, ref.SecretID, version).Scan(&level, &f.scope.ID, &f.versionID)
	f.scope.Level = tenancy.Level(level)
	if err != nil {
		return secretFacts{}, ErrRefused
	}
	return f, nil
}

func (d *Deployer) carrier(ctx context.Context, ref rotation.Ref, id string) (carriers.Carrier, error) {
	want, err := uuid.Parse(id)
	if err != nil {
		return carriers.Carrier{}, ErrRefused
	}
	list, err := d.Carriers.List(ctx, ref.OrgID, ref.SecretID)
	if err != nil {
		return carriers.Carrier{}, ErrRefused
	}
	for _, c := range list {
		if c.ID == want {
			return c, nil
		}
	}
	return carriers.Carrier{}, ErrRefused
}

// lastTarget is the target of the newest delivery of this secret to the
// carrier's destination: it carries the mode and owner the consumer needs,
// which the carrier row does not keep.
func (d *Deployer) lastTarget(ctx context.Context, c carriers.Carrier) (runnerproto.Target, error) {
	want, err := json.Marshal(struct {
		Kind     runnerproto.TargetKind
		Path     string
		Field    string
		Consumer string
	}{c.TargetKind, c.TargetPath, c.TargetField, c.Consumer})
	if err != nil {
		return runnerproto.Target{}, ErrRefused
	}
	var raw []byte
	err = d.Pool.QueryRow(ctx, `SELECT dr.target FROM deployment_jobs j
		JOIN deployment_requests dr ON dr.org_id=j.org_id AND dr.id=j.deployment_request_id
		WHERE j.org_id=$1 AND j.secret_id=$2 AND j.runner_id=$3 AND j.status='completed' AND dr.target @> $4::jsonb
		ORDER BY j.created_at DESC, j.id DESC LIMIT 1`, c.OrgID, c.SecretID, c.RunnerID, want).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) || err != nil {
		return runnerproto.Target{}, ErrRefused
	}
	var t runnerproto.Target
	if json.Unmarshal(raw, &t) != nil {
		return runnerproto.Target{}, ErrRefused
	}
	return t, nil
}

// Deploy queues the layout of version on the carrier and waits for the
// runner's closed result. Anything but a delivered, healthy result is refused.
func (d *Deployer) Deploy(ctx context.Context, ref rotation.Ref, runID uuid.UUID, c rotation.Carrier, version string) error {
	car, err := d.carrier(ctx, ref, c.ID)
	if err != nil || car.RunnerID == uuid.Nil {
		return ErrRefused
	}
	f, err := d.facts(ctx, ref, version)
	if err != nil {
		return err
	}
	target, err := d.lastTarget(ctx, car)
	if err != nil {
		return err
	}
	reqID := uuid.NewSHA1(runID, []byte("deploy/"+c.ID)).String()
	out, err := d.Deployments.Submit(ctx, deployment.Request{OrgID: ref.OrgID, Scope: f.scope, SecretID: ref.SecretID, VersionID: f.versionID,
		RunnerID: car.RunnerID, RequestID: reqID, Target: target, Actor: systemActor})
	if err != nil || out.Status != deployment.Queued {
		return ErrRefused
	}
	var rep deployment.Report
	if err := d.wait(ctx, func() (bool, error) {
		r, rerr := d.Deployments.Report(ctx, ref.OrgID, reqID)
		if rerr != nil {
			return false, ErrRefused
		}
		rep = r
		return r.Done, nil
	}); err != nil {
		return err
	}
	res := rep.Result
	healthy := res.Healthcheck == nil || res.Healthcheck.Status == runnerproto.HealthOK || res.Healthcheck.Status == runnerproto.HealthSkipped
	if !res.OK || res.ErrorClass != "" || res.Version != version || !healthy {
		return ErrRefused
	}
	return nil
}

// Verify reads the carrier back through a verify job. One verification per
// run covers every carrier; the carrier's line is its answer.
func (d *Deployer) Verify(ctx context.Context, ref rotation.Ref, c rotation.Carrier, version string) (rotation.Report, error) {
	runID, ok := rotation.RunID(ctx)
	if !ok {
		return rotation.Report{}, ErrRefused
	}
	f, err := d.facts(ctx, ref, version)
	if err != nil {
		return rotation.Report{}, err
	}
	want, err := uuid.Parse(c.ID)
	if err != nil {
		return rotation.Report{}, ErrRefused
	}
	reqID := uuid.NewSHA1(runID, []byte("verify")).String()
	if _, err := d.Deployments.SubmitVerify(ctx, deployment.VerifyRequest{OrgID: ref.OrgID, Scope: f.scope, SecretID: ref.SecretID, RequestID: reqID, Actor: systemActor}); err != nil {
		return rotation.Report{}, ErrRefused
	}
	var line deployment.VerifyItem
	var fp string
	if err := d.wait(ctx, func() (bool, error) {
		r, rerr := d.Deployments.VerifyReport(ctx, ref.OrgID, reqID)
		if rerr != nil {
			return false, ErrRefused
		}
		for _, it := range r.Items {
			if it.CarrierID == want {
				line, fp = it, r.Fingerprint
				return it.State != deployment.VerifyPending, nil
			}
		}
		return false, ErrRefused
	}); err != nil {
		return rotation.Report{}, err
	}
	switch line.State {
	case deployment.VerifyMatch:
		return rotation.Report{Fingerprint: fp, Healthy: true}, nil
	case deployment.VerifyMismatch:
		// No fingerprint: the engine records fingerprint_mismatch.
		return rotation.Report{Healthy: true}, nil
	}
	return rotation.Report{}, ErrRefused
}

// Incident implements rotation.Incident as one log line per event, ids and
// closed classes only. The run row keeps whether an incident was opened.
type Incident struct{ Log *slog.Logger }

func (i Incident) Open(ctx context.Context, r rotation.IncidentRecord) error {
	i.Log.ErrorContext(ctx, "rotation incident opened", "run_id", r.RunID.String(), "secret_id", r.Ref.SecretID.String(),
		"error_class", string(r.Class))
	return nil
}

func (i Incident) Resolve(ctx context.Context, r rotation.IncidentRecord) error {
	i.Log.InfoContext(ctx, "rotation incident resolved", "run_id", r.RunID.String(), "secret_id", r.Ref.SecretID.String(),
		"error_class", string(r.Class))
	return nil
}
