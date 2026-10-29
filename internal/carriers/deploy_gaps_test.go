package carriers

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

func (f *deployFixture) makeProd(t *testing.T) {
	t.Helper()
	_, err := f.pool.Exec(ctx, `UPDATE secrets SET class='prod' WHERE id=$1`, f.id)
	must(t, err)
}

// addSecret creates a second secret of the org with the same store and a
// version "v1", for tests where evidence of one secret must not count for
// another.
func (f *deployFixture) addSecret(t *testing.T) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := f.pool.Exec(ctx, `INSERT INTO secrets(id,org_id,scope_level,scope_id,name,class,type,store_id,provider_ref)
	 SELECT $1,org_id,scope_level,scope_id,'OTHER',class,type,store_id,'other/ref' FROM secrets WHERE id=$2`, id, f.id)
	must(t, err)
	_, err = f.pool.Exec(ctx, `INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length) VALUES ($1,$2,$3,'v1',$4,17)`, uuid.New(), f.org, id, f.fp)
	must(t, err)
	return id
}

func (f *deployFixture) okResult() runnerproto.Result {
	return runnerproto.Result{OK: true, Fingerprint: f.fp, Version: "v1"}
}

// Only an approval that was granted counts: a pending or rejected one is no
// proof that the production destination was approved.
func TestProductionNeedsAnApprovalThatWasGranted(t *testing.T) {
	for _, status := range []string{"requested", "rejected"} {
		f := newDeployFixture(t)
		f.makeProd(t)
		f.addJob(t, jobOpts{runner: f.runner, target: f.target(), approved: true, approval: status, result: f.okResult()})
		if ok, err := f.svc.ev.Approved(ctx, f.org, f.id, f.md); err != nil || ok {
			t.Fatalf("approval in state %q admitted a production destination: %v %v", status, ok, err)
		}
	}
}

// The approval belongs to one runner: another runner of the same host with
// an approved deployment does not admit the destination for this one.
func TestProductionApprovalOfAnotherRunnerDoesNotCount(t *testing.T) {
	f := newDeployFixture(t)
	f.makeProd(t)
	other := f.addRunner(t, runnerOpts{host: f.host, org: f.org})
	f.addJob(t, jobOpts{runner: other, target: f.target(), approved: true, result: f.okResult()})
	if ok, err := f.svc.ev.Approved(ctx, f.org, f.id, f.md); err != nil || ok {
		t.Fatalf("an approval of another runner admitted the destination: %v %v", ok, err)
	}
}

// A deployment of another secret to the same destination proves nothing for
// this one, neither as a confirmation nor as an approval.
func TestDeploymentOfAnotherSecretIsNoEvidence(t *testing.T) {
	f := newDeployFixture(t)
	f.makeProd(t)
	other := f.addSecret(t)
	f.addJob(t, jobOpts{runner: f.runner, secret: other, target: f.target(), approved: true, result: f.okResult()})
	if _, err := f.svc.ev.Confirmed(ctx, f.org, f.id, "v1", f.md); !errors.Is(err, ErrDeployment) {
		t.Fatalf("a deployment of another secret confirmed this one: %v", err)
	}
	if ok, err := f.svc.ev.Approved(ctx, f.org, f.id, f.md); err != nil || ok {
		t.Fatalf("an approval of another secret admitted this one: %v %v", ok, err)
	}
}

func TestDisabledSecretIsNotApproved(t *testing.T) {
	f := newDeployFixture(t)
	if ok, err := f.svc.ev.Approved(ctx, f.org, f.id, f.md); err != nil || !ok {
		t.Fatalf("control: an active secret must be approved: %v %v", ok, err)
	}
	_, err := f.pool.Exec(ctx, `UPDATE secrets SET status='disabled' WHERE id=$1`, f.id)
	must(t, err)
	if ok, err := f.svc.ev.Approved(ctx, f.org, f.id, f.md); err != nil || ok {
		t.Fatalf("a disabled secret was approved: %v %v", ok, err)
	}
}

// A failed result is not a delivery, even when it carries the right version
// and fingerprint.
func TestAFailedResultIsNotADelivery(t *testing.T) {
	f := newDeployFixture(t)
	f.addJob(t, jobOpts{runner: f.runner, target: f.target(), result: runnerproto.Result{OK: false, ErrorClass: runnerproto.ErrClassTargetWrite, Fingerprint: f.fp, Version: "v1"}})
	if _, err := f.svc.Register(ctx, f.org, f.id, "v1", f.md); !errors.Is(err, ErrDeployment) {
		t.Fatalf("registered on a failed result: %v", err)
	}
}

// A database failure is an internal error with nothing of the driver's text
// and is never read as a refusal.
func TestDatabaseFailureIsInternalAndSilent(t *testing.T) {
	f := newDeployFixture(t)
	f.okJob(t)
	pool, err := store.Open(ctx, os.Getenv("KEEP_DATABASE_URL"))
	must(t, err)
	pool.Close()
	svc := NewService(pool)
	if _, err := svc.Register(ctx, f.org, f.id, "v1", f.md); !errors.Is(err, ErrInternal) {
		t.Fatalf("register on a closed pool: want ErrInternal, got %v", err)
	}
	ok, err := svc.ev.Approved(ctx, f.org, f.id, f.md)
	if ok || !errors.Is(err, ErrInternal) || strings.Contains(strings.ToLower(err.Error()), "closed") {
		t.Fatalf("approved on a closed pool: %v %v", ok, err)
	}
	if _, err := svc.ev.completedJobs(ctx, f.org, f.id, f.md); err != ErrInternal {
		t.Fatalf("reading the deployments on a closed pool: want exactly ErrInternal, got %v", err)
	}
}
