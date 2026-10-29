package rotation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
)

// A failed carrier leaves the run failed: the report names no version and no
// fingerprint, marks the carrier stale, and the old version is never revoked.
func TestServiceFailedCarrierActivatesNothing(t *testing.T) {
	x, f := newFx(t), newFakes(3)
	f.deployErr[cid(2)] = errors.New("boom")
	s := NewService(New(x.pool, f.deps())).WithJournal(audit.NewJournal(x.pool))
	id, err := startPlain(s, x.ctx, x.ref)
	if err != nil {
		t.Fatal(err)
	}
	s.Wait()
	rep, err := s.Report(x.ctx, x.ref, id)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Failed || rep.Done || rep.Class != ClassDeployFailed || rep.Version != "" || rep.Fingerprint != "" {
		t.Fatalf("a failed run must activate nothing: %+v", rep)
	}
	if f.revokes != 0 {
		t.Fatalf("old version revoked %d times after a failed carrier", f.revokes)
	}
	states := map[string]CarrierStatus{}
	for _, c := range rep.Carriers {
		states[c.CarrierID] = c
	}
	if len(states) != 3 || states[cid(2)].State != CarrierStale || states[cid(2)].Phase != PhaseDeploy {
		t.Fatalf("carrier 2 must be stale in deploy: %+v", rep.Carriers)
	}
	// Carrier 1 took the layout but the run stopped before it was verified:
	// nothing is confirmed on the new version, so it is stale too.
	if c1 := states[cid(1)]; c1.State != CarrierStale || c1.Phase != PhaseVerify {
		t.Fatalf("carrier 1 must be stale in verify: %+v", c1)
	}
}

func TestServiceDoneReportsVersionAndFingerprint(t *testing.T) {
	x, f := newFx(t), newFakes(2)
	s := NewService(New(x.pool, f.deps())).WithJournal(audit.NewJournal(x.pool))
	id, err := startPlain(s, x.ctx, x.ref)
	if err != nil {
		t.Fatal(err)
	}
	s.Wait()
	rep, err := s.Report(x.ctx, x.ref, id)
	if err != nil || !rep.Done || rep.Failed || rep.Version != "2" || rep.Fingerprint != fpNew || f.revokes != 1 {
		t.Fatalf("got %+v %v revokes=%d", rep, err, f.revokes)
	}
	for _, c := range rep.Carriers {
		if c.Phase != PhaseVerify || c.State != CarrierOK {
			t.Fatalf("a done run has every carrier verified: %+v", rep.Carriers)
		}
	}
}

// A run is visible only under its own secret and organization.
func TestServiceReportOfAnotherSecretIsUnavailable(t *testing.T) {
	x, f := newFx(t), newFakes(1)
	s := NewService(New(x.pool, f.deps())).WithJournal(audit.NewJournal(x.pool))
	id, err := startPlain(s, x.ctx, x.ref)
	if err != nil {
		t.Fatal(err)
	}
	s.Wait()
	for name, ref := range map[string]Ref{
		"other secret": {OrgID: x.ref.OrgID, SecretID: uuid.New()},
		"other org":    {OrgID: uuid.New(), SecretID: x.ref.SecretID},
	} {
		if _, err := s.Report(x.ctx, ref, id); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: want ErrNotFound, got %v", name, err)
		}
	}
	if _, err := s.Report(x.ctx, x.ref, uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown run: want ErrNotFound, got %v", err)
	}
}

// Start while a run of the secret is active is a conflict, not a second run.
func TestServiceStartWhileActiveConflicts(t *testing.T) {
	x, f := newFx(t), newFakes(1)
	f.gate = make(chan struct{})
	f.entered = make(chan struct{}, 1)
	s := NewService(New(x.pool, f.deps())).WithJournal(audit.NewJournal(x.pool))
	if _, err := startPlain(s, x.ctx, x.ref); err != nil {
		t.Fatal(err)
	}
	<-f.entered
	if _, err := startPlain(s, x.ctx, x.ref); !errors.Is(err, ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
	close(f.gate)
	s.Wait()
}

// The canary goes into every collaborator's error text; the report never has it.
func TestServiceReportNeverHoldsTheValue(t *testing.T) {
	c := canary.New()
	v := c.Value(1)
	if !c.In("x"+v) || !c.In(strings.ToUpper(v)) {
		t.Fatal("canary detector is blind")
	}
	for name, setup := range map[string]func(*fakes){
		"deploy": func(f *fakes) { f.deployErr[cid(2)] = errors.New("deploy of " + v) },
		"verify": func(f *fakes) { f.verifyErr[cid(2)] = errors.New("read " + v) },
		"badfp":  func(f *fakes) { f.verifyFP[cid(2)] = v },
		"revoke": func(f *fakes) { f.revokeErr = errors.New("revoke " + v) },
	} {
		t.Run(name, func(t *testing.T) {
			x, f := newFx(t), newFakes(3)
			setup(f)
			s := NewService(New(x.pool, f.deps())).WithJournal(audit.NewJournal(x.pool))
			id, err := startPlain(s, x.ctx, x.ref)
			if err != nil {
				t.Fatal(err)
			}
			s.Wait()
			rep, err := s.Report(x.ctx, x.ref, id)
			if err != nil || len(rep.Carriers) == 0 {
				t.Fatalf("interception saw nothing: %v", err)
			}
			if dump := fmt.Sprintf("%+v %#v", rep, rep); c.In(dump) {
				t.Fatalf("canary reached the report (%d bytes inspected)", len(dump))
			}
		})
	}
}

type panickingVersions struct {
	*fakes
	text string
}

func (p panickingVersions) Prepare(context.Context, Ref, uuid.UUID) (Version, error) {
	panic(p.text)
}

// A collaborator that panics with the canary takes down neither the process
// nor the report; the report holds no canary.
func TestServicePanicInACollaboratorStopsOnlyTheRun(t *testing.T) {
	c := canary.New()
	v := c.Value(1)
	x, f := newFx(t), newFakes(1)
	d := f.deps()
	d.Versions = panickingVersions{f, "prepare of " + v}
	s := NewService(New(x.pool, d)).WithJournal(audit.NewJournal(x.pool))
	id, err := startPlain(s, x.ctx, x.ref)
	if err != nil {
		t.Fatal(err)
	}
	s.Wait()
	rep, err := s.Report(x.ctx, x.ref, id)
	if err != nil || rep.Done {
		t.Fatalf("got %+v %v", rep, err)
	}
	if dump := fmt.Sprintf("%+v %#v", rep, rep); c.In(dump) {
		t.Fatalf("canary reached the report (%d bytes inspected)", len(dump))
	}
	// The run is terminal with a fixed class and the secret can be rotated again.
	if !rep.Failed || rep.Class != ClassInternalError {
		t.Fatalf("panicked run not failed with internal_error: %+v", rep)
	}
	if _, err := startPlain(s, x.ctx, x.ref); err != nil {
		t.Fatalf("next rotation blocked by the panicked run: %v", err)
	}
	s.Wait()
}

// A run another caller holds under a live lease is not failed from outside.
func TestFailAbandonedLeavesALeasedRunAlone(t *testing.T) {
	x := newFx(t)
	st := &store{pool: x.pool}
	id := uuid.New()
	if err := st.start(x.ctx, x.ref, id); err != nil {
		t.Fatal(err)
	}
	if _, err := st.claim(x.ctx, id, "owner", time.Now(), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := st.failAbandoned(x.ctx, id, ClassInternalError, time.Now()); err != nil {
		t.Fatal(err)
	}
	if run, err := st.load(x.ctx, id); err != nil || run.State != StateNewVersion {
		t.Fatalf("leased run touched: %+v %v", run, err)
	}
}

// A finished run keeps its state, and a run whose lease has expired is failed.
func TestFailAbandonedKeepsFinishedAndAppliesExpiredLease(t *testing.T) {
	x, f := newFx(t), newFakes(1)
	st := &store{pool: x.pool}
	res, err := New(x.pool, f.deps()).Rotate(x.ctx, x.ref, Options{})
	if err != nil || res.State != StateDone {
		t.Fatalf("setup: %+v %v", res, err)
	}
	run, err := st.load(x.ctx, res.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.failAbandoned(x.ctx, run.ID, ClassInternalError, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.load(x.ctx, run.ID); got.State != StateDone || got.Class != ClassNone {
		t.Fatalf("done run overwritten: %+v", got)
	}

	id := uuid.New()
	if err := st.start(x.ctx, x.ref, id); err != nil {
		t.Fatal(err)
	}
	if _, err := st.claim(x.ctx, id, "gone", time.Now(), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := st.failAbandoned(x.ctx, id, ClassInternalError, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.load(x.ctx, id); got.State != StateFailed || got.Class != ClassInternalError {
		t.Fatalf("expired lease not failed: %+v", got)
	}
}

type panickingDeployer struct {
	*fakes
	text string
}

func (p panickingDeployer) Deploy(context.Context, Ref, uuid.UUID, Carrier, string) error {
	panic(p.text)
}

type panickingVerifier struct {
	*fakes
	text string
}

func (p panickingVerifier) Verify(context.Context, Ref, Carrier, string) (Report, error) {
	panic(p.text)
}

// A collaborator that panics runs on a worker goroutine or on the run's own:
// the process survives, the run is failed with a fixed class, and the canary
// is nowhere, neither in the report nor in anything the process prints.
// The scenario runs in a child process: with a recover removed the child dies,
// and a recover that prints the panic value writes to the runtime's stderr,
// which only a separate process lets the test read.
func TestServicePanicInACollaboratorStopsOnlyTheRunAndPrintsNothing(t *testing.T) {
	if os.Getenv("KEEP_DATABASE_URL") == "" {
		t.Skip("KEEP_DATABASE_URL not set — see CONTRIBUTING.md")
	}
	for _, which := range []string{"prepare", "deploy", "verify"} {
		t.Run(which, func(t *testing.T) {
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			c := canary.New()
			cmd := exec.Command(exe, "-test.run=^TestServicePanicChild$", "-test.v", "-test.count=1") //nolint:gosec // G204: test-controlled arguments
			cmd.Env = append(os.Environ(), "KEEP_PANIC_CHILD="+which, "KEEP_PANIC_VALUE="+c.Value(1))
			out, err := cmd.CombinedOutput()
			// Never print the child's output: a leaking child prints the panic value.
			if c.In(string(out)) {
				t.Fatalf("the panic value of a %s reached the process output (%d bytes withheld)", which, len(out))
			}
			if err != nil || !strings.Contains(string(out), "--- PASS: TestServicePanicChild") {
				t.Fatalf("the process did not survive a panicking %s (err=%v, %d bytes of child output withheld)", which, err, len(out))
			}
		})
	}
}

// TestServicePanicChild is the body of the test above; it only runs as its child.
func TestServicePanicChild(t *testing.T) {
	which, v := os.Getenv("KEEP_PANIC_CHILD"), os.Getenv("KEEP_PANIC_VALUE")
	if which == "" {
		return // not a skip: it is only the child's body, and a skip would trip the no-silent-skip guards
	}
	c := canary.Of(v)
	x, f := newFx(t), newFakes(2)
	d := f.deps()
	switch which {
	case "prepare":
		d.Versions = panickingVersions{f, which + " of " + v}
	case "deploy":
		d.Deployer = panickingDeployer{f, which + " of " + v}
	default:
		d.Verifier = panickingVerifier{f, which + " of " + v}
	}
	s := NewService(New(x.pool, d)).WithJournal(audit.NewJournal(x.pool))
	id, err := startPlain(s, x.ctx, x.ref)
	if err != nil {
		t.Fatal(err)
	}
	s.Wait()
	rep, err := s.Report(x.ctx, x.ref, id)
	if err != nil || !rep.Failed || rep.Done || rep.Class != ClassInternalError || f.revokes != 0 {
		t.Fatalf("got %+v %v revokes=%d", rep, err, f.revokes)
	}
	if dump := fmt.Sprintf("%+v %#v", rep, rep); c.In(dump) {
		t.Fatalf("canary reached the report (%d bytes inspected)", len(dump))
	}
}

// startPlain starts a rotation of an ordinary (non-prod) secret and returns the run id.
func startPlain(s *Service, ctx context.Context, ref Ref) (uuid.UUID, error) {
	st, err := s.Start(ctx, ref, Origin{Actor: audit.Actor{Type: audit.ActorUser, ID: "tester", Via: audit.ViaAPI},
		Scope: "org:" + ref.OrgID.String(), Name: "db-password", Class: "credential"})
	return st.RunID, err
}
