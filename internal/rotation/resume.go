package rotation

import (
	"context"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/google/uuid"
)

// Resume defaults: a run untouched for a lease TTL is not being driven, the
// backoff doubles from half a minute to a quarter of an hour, and a run that
// keeps dying is given up on after ten resumes.
const (
	defaultResumeStale   = defaultLease
	defaultResumeBackoff = 30 * time.Second
	defaultResumeBackMax = 15 * time.Minute
	defaultResumeTries   = 10
	defaultResumeBatch   = 20
)

// ResumeConfig tunes Service.Resume; a zero field takes its default.
type ResumeConfig struct {
	Stale       time.Duration // a run touched more recently than this is left alone
	BackoffBase time.Duration // wait after the first resume; doubles per attempt
	BackoffMax  time.Duration
	MaxAttempts int // resumes of one run before it is failed
	Batch       int
}

func (c ResumeConfig) withDefaults() ResumeConfig {
	if c.Stale <= 0 {
		c.Stale = defaultResumeStale
	}
	if c.BackoffBase <= 0 {
		c.BackoffBase = defaultResumeBackoff
	}
	if c.BackoffMax <= 0 {
		c.BackoffMax = defaultResumeBackMax
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = defaultResumeTries
	}
	if c.Batch <= 0 {
		c.Batch = defaultResumeBatch
	}
	return c
}

// WithResume sets the resume tuning.
func (s *Service) WithResume(c ResumeConfig) *Service {
	s.resume = c
	return s
}

// resumable is a run Resume took: the claim already counted the attempt.
type resumable struct {
	ref      Ref
	id       uuid.UUID
	attempts int
}

// Resume relaunches every active run that nothing is driving: no goroutine of
// this process, no live lease, untouched for the stale threshold and past its
// backoff. The run id is the idempotency key, so the engine continues the
// run from its recorded state and the prepared version comes from the ledger,
// never from a caller. A run resumed more than MaxAttempts times is failed with
// a fixed class so it does not block the next rotation of the secret. It
// returns how many runs were relaunched; callers poll it (start and ticker).
func (s *Service) Resume(ctx context.Context) (int, error) {
	if s.journal == nil {
		return 0, ErrUnavailable
	}
	cfg := s.resume.withDefaults()
	given, err := s.e.store.giveUpResumes(ctx, cfg, s.now(), s.inflightIDs())
	if err != nil {
		return 0, ErrUnavailable
	}
	for _, r := range given {
		o, approval := s.originOf(ctx, r.ref, r.id)
		s.recordOutcome(ctx, r.ref, r.id, o, approval, ClassInternalError)
	}
	runs, err := s.e.store.claimResumes(ctx, cfg, s.now(), s.inflightIDs())
	if err != nil {
		return 0, ErrUnavailable
	}
	for _, r := range runs {
		o, approval := s.originOf(ctx, r.ref, r.id)
		s.launch(ctx, r.ref, r.id, o, approval, nil)
	}
	return len(runs), nil
}

// originOf rebuilds the requester of run id, and the approval it ran under,
// from the request record the start journaled in the same transaction as the
// run. Only closed-set names and ids are read.
func (s *Service) originOf(ctx context.Context, ref Ref, id uuid.UUID) (Origin, uuid.UUID) {
	o := Origin{Scope: "org:" + ref.OrgID.String(), Actor: audit.Actor{Type: audit.ActorSystem, ID: "keep-server", Via: audit.ViaAPI}}
	var typ, aid, sponsor, via, scope, name, appr string
	err := s.e.store.pool.QueryRow(ctx, `SELECT actor_type, actor_id, actor_sponsor_id, actor_via, scope, secret_name, approval_id
		FROM audit_records WHERE org_id=$1 AND request_id=$2 AND action=$3 ORDER BY org_seq LIMIT 1`,
		ref.OrgID.String(), id.String(), string(audit.ActionSecretRotate)).Scan(&typ, &aid, &sponsor, &via, &scope, &name, &appr)
	if err != nil {
		return o, uuid.Nil
	}
	o.Actor = audit.Actor{Type: audit.ActorType(typ), ID: aid, SponsorID: sponsor, Via: audit.ActorVia(via)}
	o.Scope, o.Name = scope, name
	approval, _ := uuid.Parse(appr)
	return o, approval
}
