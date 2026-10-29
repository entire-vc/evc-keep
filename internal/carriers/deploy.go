package carriers

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/registry"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// evidenceTimeout bounds one policy or confirmation lookup; Register runs
// the policy while it holds the secret and version locks.
const evidenceTimeout = 5 * time.Second

// maxJobsExamined bounds how many completed deployments of one secret to one
// destination are read; the newest are read first.
const maxJobsExamined = 100

// DeployEvidence answers from server records only: the enrolled runners, the
// organization's deployment policy, and the deployment jobs the runners have
// reported on. Nothing it consults comes from a request.
type DeployEvidence struct {
	pool    *pgxpool.Pool
	runners *registry.Repo
}

func NewDeployEvidence(pool *pgxpool.Pool) *DeployEvidence {
	return &DeployEvidence{pool: pool, runners: registry.NewRepo(pool)}
}

// target is the part of a deployment target a carrier names.
func (m Metadata) target() runnerproto.Target {
	return runnerproto.Target{Kind: m.TargetKind, Path: m.TargetPath, Field: m.TargetField, Consumer: m.Consumer, Mode: 0o600}
}

func sameTarget(t runnerproto.Target, m Metadata) bool {
	return t.Kind == m.TargetKind && t.Path == m.TargetPath && t.Field == m.TargetField && t.Consumer == m.Consumer
}

// job is one completed deployment to a destination.
type job struct {
	runner   uuid.UUID
	version  string
	result   runnerproto.Result
	approved bool
}

// completedJobs reads the finished, successful deployments of the secret to
// the destination named by md, through runners of this organization that are
// not revoked and are enrolled under md.Host.
func (e *DeployEvidence) completedJobs(ctx context.Context, org, secret uuid.UUID, md Metadata) ([]job, error) {
	// The destination is chosen in SQL, before the limit: newer deployments
	// of the same secret to other destinations must not push it out.
	// Only the four fields sameTarget compares; the key names are Target's.
	want, err := json.Marshal(struct {
		Kind     runnerproto.TargetKind
		Path     string
		Field    string
		Consumer string
	}{md.TargetKind, md.TargetPath, md.TargetField, md.Consumer})
	if err != nil {
		return nil, ErrInternal
	}
	rows, err := e.pool.Query(ctx, `
 SELECT j.runner_id, j.provider_version, j.result, dr.target,
        EXISTS(SELECT 1 FROM approval_requests a WHERE a.org_id=j.org_id AND a.deployment_request_id=dr.id AND a.status='approved')
 FROM deployment_jobs j
 JOIN deployment_requests dr ON dr.org_id=j.org_id AND dr.id=j.deployment_request_id
 JOIN runners r ON r.org_id=j.org_id AND r.id=j.runner_id
 WHERE j.org_id=$1 AND j.secret_id=$2 AND j.status='completed' AND r.host=$3 AND r.revoked_at IS NULL
   AND dr.target @> $4::jsonb
 ORDER BY j.created_at DESC, j.id DESC LIMIT $5`, org, secret, md.Host, want, maxJobsExamined)
	if err != nil {
		return nil, ErrInternal // Never expose the database error.
	}
	defer rows.Close()
	var out []job
	for rows.Next() {
		var (
			j          job
			rawResult  []byte
			rawTarget  []byte
			target     runnerproto.Target
			resultSeen error
		)
		if err := rows.Scan(&j.runner, &j.version, &rawResult, &rawTarget, &j.approved); err != nil {
			return nil, ErrInternal
		}
		if json.Unmarshal(rawTarget, &target) != nil || !sameTarget(target, md) {
			continue
		}
		if j.result, resultSeen = runnerproto.DecodeResult(rawResult); resultSeen != nil || !delivered(j.result) {
			continue
		}
		out = append(out, j)
	}
	if rows.Err() != nil {
		return nil, ErrInternal
	}
	return out, nil
}

// delivered reports a result that proves the value was laid and, when a
// consumer was checked, that it came up.
func delivered(r runnerproto.Result) bool {
	if !r.OK || r.ErrorClass != "" {
		return false
	}
	return r.Healthcheck == nil || r.Healthcheck.Status == runnerproto.HealthOK || r.Healthcheck.Status == runnerproto.HealthSkipped
}

// Confirmed returns the fingerprint a runner reported after laying version
// of the secret at md. No completed, successful deployment of exactly that
// version to exactly that destination is ErrDeployment.
func (e *DeployEvidence) Confirmed(ctx context.Context, org, secret uuid.UUID, version string, md Metadata) (string, error) {
	fp, _, err := e.confirmed(ctx, org, secret, version, md)
	return fp, err
}

// confirmed also returns the kind of healthcheck the runner ran, a value of
// the closed list in runnerproto: it is the only source of a carrier's
// healthcheck, so no caller-supplied text is ever stored.
func (e *DeployEvidence) confirmed(ctx context.Context, org, secret uuid.UUID, version string, md Metadata) (fp, healthKind string, err error) {
	ctx, cancel := context.WithTimeout(ctx, evidenceTimeout)
	defer cancel()
	jobs, err := e.completedJobs(ctx, org, secret, md)
	if err != nil {
		return "", "", err
	}
	for _, j := range jobs {
		if j.version == version && j.result.Version == version {
			if j.result.Healthcheck != nil {
				healthKind = string(j.result.Healthcheck.Kind)
			}
			return j.result.Fingerprint, healthKind, nil
		}
	}
	return "", "", ErrDeployment
}

// Approved implements MetadataPolicy. The host must be the host of an
// enrolled runner of this organization that is not revoked, and the
// organization's deployment policy must admit the destination for the
// secret and that runner. A production destination counts only when the
// same destination was already laid through an approved deployment.
func (e *DeployEvidence) Approved(ctx context.Context, org, secret uuid.UUID, md Metadata) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, evidenceTimeout)
	defer cancel()
	var class string
	var rules []byte
	err := e.pool.QueryRow(ctx, `SELECT s.class, COALESCE(p.rules,'{"rules":[]}'::jsonb)
 FROM secrets s LEFT JOIN deployment_policies p ON p.org_id=s.org_id
 WHERE s.org_id=$1 AND s.id=$2 AND s.status='active'`, org, secret).Scan(&class, &rules)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, ErrInternal
	}
	var policy deployment.Policy
	if json.Unmarshal(rules, &policy) != nil {
		return false, nil
	}
	ids, err := e.runnersOf(ctx, org, md.Host)
	if err != nil {
		return false, err
	}
	jobs, err := e.completedJobs(ctx, org, secret, md)
	if err != nil {
		return false, err
	}
	for _, id := range ids {
		trust, err := e.runners.GetDeliveryTrust(ctx, org, id)
		if err != nil {
			continue // keyless, expired or revoked: this runner proves nothing.
		}
		registered := false
		for _, j := range jobs {
			registered = registered || (j.runner == id && j.approved)
		}
		host := deployment.Host{ID: id.String(), AttributesKnown: trust.AttrsKnown, UIDShared: trust.UIDShared, Labels: trust.HostLabels}
		if d, err := deployment.Evaluate(policy, host, secret, class, md.target(), registered); err == nil && d == deployment.Allow {
			return true, nil
		}
	}
	return false, nil
}

func (e *DeployEvidence) runnersOf(ctx context.Context, org uuid.UUID, host string) ([]uuid.UUID, error) {
	rows, err := e.pool.Query(ctx, `SELECT id FROM runners WHERE org_id=$1 AND host=$2 AND revoked_at IS NULL AND cert_not_after>now() ORDER BY enrolled_at, id`, org, host)
	if err != nil {
		return nil, ErrInternal
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if rows.Scan(&id) != nil {
			return nil, ErrInternal
		}
		ids = append(ids, id)
	}
	if rows.Err() != nil {
		return nil, ErrInternal
	}
	return ids, nil
}

// Service is what the API calls: it registers a destination only with proof
// of a completed deployment, and takes the fingerprint from that proof.
type Service struct {
	repo *Repository
	ev   *DeployEvidence
}

func NewService(pool *pgxpool.Pool) *Service {
	ev := NewDeployEvidence(pool)
	return &Service{repo: New(pool, ev), ev: ev}
}

// Register is idempotent for (org, secret, host, target). A destination the
// policy does not admit is ErrMetadata whether or not anything was deployed
// there; an admitted one without a completed deployment of version is
// ErrDeployment.
func (s *Service) Register(ctx context.Context, org, secret uuid.UUID, version string, md Metadata) (Carrier, error) {
	ok, err := s.ev.Approved(ctx, org, secret, md)
	if err != nil {
		return Carrier{}, ErrInternal
	}
	if !ok {
		return Carrier{}, ErrMetadata
	}
	fp, kind, err := s.ev.confirmed(ctx, org, secret, version, md)
	if err != nil {
		return Carrier{}, err
	}
	md.HealthcheckRef = kind
	c, err := s.repo.Register(ctx, org, Registration{SecretID: secret, Version: version, Metadata: md, LastFP: fp})
	if err != nil {
		return Carrier{}, err
	}
	return s.withRunner(ctx, c)
}

func (s *Service) List(ctx context.Context, org, secret uuid.UUID) ([]Carrier, error) {
	list, err := s.repo.List(ctx, org, secret)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i], err = s.withRunner(ctx, list[i]); err != nil {
			return nil, err
		}
	}
	return list, nil
}

// withRunner names the runner of the newest delivered deployment of the
// carrier's version to its destination. No record leaves RunnerID nil.
func (s *Service) withRunner(ctx context.Context, c Carrier) (Carrier, error) {
	ctx, cancel := context.WithTimeout(ctx, evidenceTimeout)
	defer cancel()
	jobs, err := s.ev.completedJobs(ctx, c.OrgID, c.SecretID, c.Metadata)
	if err != nil {
		return Carrier{}, err
	}
	for _, j := range jobs {
		if j.version == c.Version && j.result.Version == c.Version {
			c.RunnerID = j.runner
			break
		}
	}
	return c, nil
}
