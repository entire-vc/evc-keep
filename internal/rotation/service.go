package rotation

import (
	"context"
	"errors"
	"github.com/entire-vc/evc-keep/internal/deployment"
	"sync"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// runTimeout bounds one background run; the lease already ends a run whose
// owner stalls, this ends one that never finishes.
const runTimeout = 30 * time.Minute

// Phase and CarrierState name what a carrier is doing in a run.
const (
	PhaseDeploy = "deploy"
	PhaseVerify = "verify"

	CarrierPending = "pending"
	CarrierOK      = "ok"
	CarrierFailed  = "failed"
	// CarrierStale: the run failed and this carrier was not confirmed on the
	// new version; the old version stays active and the carrier is to be
	// laid out again.
	CarrierStale = "stale"
)

// CarrierStatus is one carrier's row of a report: id, phase, state.
type CarrierStatus struct {
	CarrierID string
	Phase     string
	State     string
}

// RunReport is the durable state of one run, metadata only. Version and
// Fingerprint are set only once the run is done: until then the new version
// is not the active one and a failed run activates nothing.
type RunReport struct {
	RunID       uuid.UUID
	State       State
	Class       Class
	Done        bool
	Failed      bool
	Version     string
	Fingerprint string
	Carriers    []CarrierStatus
	// Approval is the human approval the run waited for, when it needed one.
	Approval *ApprovalRef
}

// Service starts runs in the background and reports on them. A caller gets
// the run id at once and polls Report; the engine keeps its own lease, so the
// process dying mid-run leaves a run another call resumes.
type Service struct {
	e       *Engine
	wg      sync.WaitGroup
	now     func() time.Time
	journal Journal
	resume  ResumeConfig
	confirm deployment.Confirmer

	// inflight is the runs a goroutine of this process drives: Resume never
	// takes one of them, whatever the database says.
	mu       sync.Mutex
	inflight map[uuid.UUID]struct{}
}

func NewService(e *Engine) *Service {
	return &Service{e: e, now: time.Now, inflight: map[uuid.UUID]struct{}{}}
}

func (s *Service) track(id uuid.UUID, on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if on {
		s.inflight[id] = struct{}{}
	} else {
		delete(s.inflight, id)
	}
}

func (s *Service) inflightIDs() []uuid.UUID {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]uuid.UUID, 0, len(s.inflight))
	for id := range s.inflight {
		out = append(out, id)
	}
	return out
}

// WithConfirmer makes every new prod-rotation approval wait for a person's
// card as well: see deployment.Confirmer. Nil asks nobody outside Keep.
func (s *Service) WithConfirmer(c deployment.Confirmer) *Service {
	s.confirm = c
	return s
}

// WithJournal returns the service that records every rotation in the R-AUD-1
// journal: the request, and the outcome with the new version's fingerprint
// and length. Without a journal no rotation starts.
func (s *Service) WithJournal(j Journal) *Service {
	s.journal = j
	return s
}

// Start begins a rotation of ref. A prod secret waits for a human first: the
// answer carries the approval and no run exists until it is approved. Any
// other secret starts at once, with the request in the journal before the run
// begins. It returns ErrConflict while another run of the secret is active.
func (s *Service) Start(ctx context.Context, ref Ref, o Origin) (Started, error) {
	return s.start(ctx, ref, o, nil)
}

// StartPrepared begins a run that lays out v, a version that already exists:
// the second half of a human-input rotation, once the value is sealed. A prod
// secret never gets here: its human_input is refused before the link exists.
func (s *Service) StartPrepared(ctx context.Context, ref Ref, v Version, o Origin) (Started, error) {
	return s.start(ctx, ref, o, &v)
}

// Supersede retires a sealed version that a newer one replaced before it was
// laid out anywhere. No run is involved: nothing was deployed from it.
func (s *Service) Supersede(ctx context.Context, ref Ref, version string) error {
	sp, ok := s.e.versions.(Superseder)
	if !ok || !validVersion(version) {
		return ErrPrepare
	}
	return sp.Supersede(ctx, ref, version)
}

func (s *Service) start(ctx context.Context, ref Ref, o Origin, prepared *Version) (Started, error) {
	// No journal, no rotation: a rotation nobody can later account for never begins.
	if s.journal == nil {
		return Started{}, ErrUnavailable
	}
	id := uuid.New()
	if o.Class == ClassProd {
		if prepared != nil {
			return Started{}, ErrPreparedProd
		}
		return s.requestApproval(ctx, ref, id, o)
	}
	var write AdoptWrite
	if prepared != nil {
		// The version is checked here and recorded under the run, in the same
		// transaction that creates it: a run that is resumed without this
		// process's context finds it in the ledger instead of generating a value
		// over the one the human entered, and a start that does not commit leaves
		// no ledger row. Nothing is written before the transaction, and the
		// check takes its connections before the transaction holds one.
		a, ok := s.e.versions.(Adopter)
		if !ok {
			return Started{}, ErrPrepare
		}
		var err error
		if write, err = a.Adopt(ctx, ref, id, *prepared); err != nil {
			return Started{}, err
		}
	}
	// The run row and its request record commit together: a crash between them
	// cannot leave a run nobody accounted for, which would block every retry.
	tx, err := s.e.store.pool.Begin(ctx)
	if err != nil {
		return Started{}, ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// The active-run slot is taken first: a start that loses it records nothing.
	if err = s.e.store.startTx(ctx, tx, ref, id); err != nil {
		_ = tx.Rollback(ctx)
		if isActiveRunConflict(err) {
			return Started{}, s.e.store.conflictAnswer(ctx, ref)
		}
		return Started{}, err
	}
	if write != nil {
		if err = write(ctx, tx); err != nil {
			return Started{}, err
		}
	}
	rec, err := s.journal.AppendTx(ctx, tx, requestRecord(ref, id, o, audit.DecisionAllow, uuid.Nil))
	if err != nil {
		// No rotation without its record: the run row is rolled back with it.
		return Started{}, ErrUnavailable
	}
	if err = tx.Commit(ctx); err != nil {
		return Started{}, ErrUnavailable
	}
	s.journal.LogCommitted(ctx, rec)
	s.launch(ctx, ref, id, o, uuid.Nil, prepared)
	return Started{RunID: id}, nil
}

// launch drives run id in the background and journals its outcome once.
func (s *Service) launch(ctx context.Context, ref Ref, id uuid.UUID, o Origin, approval uuid.UUID, prepared *Version) {
	s.wg.Add(1)
	s.track(id, true)
	go func() {
		defer s.wg.Done()
		defer s.track(id, false)
		// A panic in a collaborator ends this run only; its text, which may sit
		// next to a value, goes nowhere. The run is failed with a fixed class,
		// so it neither stays pending nor blocks the next rotation of the secret.
		defer func() {
			if recover() != nil {
				_ = s.e.store.failAbandoned(context.WithoutCancel(ctx), id, ClassInternalError, s.now())
				s.recordOutcome(context.WithoutCancel(ctx), ref, id, o, approval, ClassInternalError)
			}
		}()
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), runTimeout)
		defer cancel()
		// The outcome is in the database; a failed run answers through Report.
		if prepared != nil {
			rctx = withPrepared(rctx, *prepared)
		}
		res, err := s.e.Rotate(rctx, ref, Options{RunID: id})
		switch {
		case err == nil && res.State == StateDone:
			s.recordOutcome(rctx, ref, id, o, approval, ClassNone)
		case errors.Is(err, ErrFailed):
			s.recordOutcome(rctx, ref, id, o, approval, res.Class)
		case errors.Is(err, ErrRevokePending):
			s.recordOutcome(rctx, ref, id, o, approval, ClassRevokeFailed)
		}
	}()
}

// recordOutcome journals the end of a run: names, the new version, its
// fingerprint and length, and a closed error class. An append failure is
// logged by the journal and swallowed: the outcome has already happened.
func (s *Service) recordOutcome(ctx context.Context, ref Ref, id uuid.UUID, o Origin, approval uuid.UUID, c Class) {
	if s.journal == nil {
		return
	}
	run, err := s.e.store.load(ctx, id)
	if err != nil {
		return
	}
	rec := requestRecord(ref, id, o, audit.DecisionAllow, approval)
	// A version is named only where it is the active one: a run that ended
	// failed activated nothing. A run whose old key could not be revoked has
	// activated the new version.
	active := run.State == StateDone || c == ClassRevokeFailed
	if active {
		rec.Secret.Version = run.NewVersion
		rec.Result = audit.Result{Status: audit.StatusOK, Fingerprint: run.ExpectedFP, Length: run.NewLength}
	}
	if run.State != StateDone || c != ClassNone {
		rec.Result.Status, rec.Result.ErrorClass = audit.StatusFailed, auditClass(c)
		if c == ClassOriginalKeyUnknown || c == ClassSuperseded {
			rec.Result.Status, rec.Result.ErrorClass = audit.StatusOK, audit.ErrClassNone
		}
	}
	_, _ = s.journal.Append(ctx, rec)
}

// Wait blocks until every run started by this service has returned.
func (s *Service) Wait() { s.wg.Wait() }

// Report answers for a run of ref; a run of another secret or organization
// is ErrNotFound.
func (s *Service) Report(ctx context.Context, ref Ref, id uuid.UUID) (RunReport, error) {
	run, err := s.e.store.load(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return s.reportApproval(ctx, ref, id)
	}
	if err != nil {
		return RunReport{}, err
	}
	if run.Ref != ref {
		return RunReport{}, ErrNotFound
	}
	steps, err := s.e.store.steps(ctx, id)
	if err != nil {
		return RunReport{}, err
	}
	rep := RunReport{RunID: id, State: run.State, Class: run.Class, Done: run.State == StateDone, Failed: run.State == StateFailed}
	if rep.Done {
		rep.Version, rep.Fingerprint = run.NewVersion, run.ExpectedFP
	}
	for _, st := range steps {
		rep.Carriers = append(rep.Carriers, carrierStatus(st, rep.Failed))
	}
	if rep.Approval, err = s.e.store.approvalOf(ctx, ref.OrgID, ref.SecretID, id); err != nil {
		return RunReport{}, err
	}
	return rep, nil
}

// reportApproval answers for a run id that has no run row: it exists only if a
// rotation approval of this secret was made for it. Waiting is pending; a
// rejected or expired approval is a failed rotation with the policy class.
func (s *Service) reportApproval(ctx context.Context, ref Ref, id uuid.UUID) (RunReport, error) {
	a, err := s.e.store.approvalOf(ctx, ref.OrgID, ref.SecretID, id)
	if err != nil {
		return RunReport{}, err
	}
	if a == nil {
		return RunReport{}, ErrNotFound
	}
	rep := RunReport{RunID: id, State: StateNewVersion, Approval: a}
	if a.Status == "rejected" || a.Status == "expired" {
		rep.State, rep.Failed, rep.Class = StateFailed, true, ClassPolicyDenied
	}
	return rep, nil
}

// carrierStatus maps a step onto phase and state. Deploy comes first: a
// carrier is in the verify phase once its layout is confirmed.
func carrierStatus(st stepRow, runFailed bool) CarrierStatus {
	cs := CarrierStatus{CarrierID: st.CarrierID, Phase: PhaseDeploy, State: st.Deploy}
	if st.Deploy == CarrierOK {
		cs.Phase, cs.State = PhaseVerify, st.Verify
	}
	if runFailed && cs.State != CarrierOK {
		cs.State = CarrierStale
	}
	return cs
}
