package app

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/intake"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/rotation"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
)

func (r *rotFixture) linkIDs() []uuid.UUID {
	r.t.Helper()
	rows, err := r.f.pool.Query(context.Background(), `SELECT request_id FROM intake_rotation_links WHERE org_id=$1 ORDER BY created_at, request_id`, r.org)
	must(r.t, err)
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		must(r.t, rows.Scan(&id))
		out = append(out, id)
	}
	return out
}

// handle runs the layout of one input through a fresh worker, as the hook does.
func (r *rotFixture) handle(id uuid.UUID) {
	ri := &rotationInputs{starter: r.svc.(*rotation.Service), pool: r.f.pool, logger: obs.New(r.logbuf)}
	ri.run(context.Background(), ri.claim(context.Background(), r.org, &id))
}

// settle sweeps until no layout is pending and no run is open.
func (r *rotFixture) settle() {
	r.t.Helper()
	ctx := context.Background()
	ri := &rotationInputs{starter: r.svc.(*rotation.Service), pool: r.f.pool, logger: obs.New(r.logbuf)}
	for end := time.Now().Add(30 * time.Second); ; time.Sleep(25 * time.Millisecond) {
		ri.sweep(ctx)
		var pending, open int
		_ = r.f.pool.QueryRow(ctx, `SELECT count(*) FROM intake_rotation_links WHERE org_id=$1 AND started_at IS NULL`, r.org).Scan(&pending)
		_ = r.f.pool.QueryRow(ctx, `SELECT count(*) FROM rotation_runs WHERE org_id=$1 AND secret_id=$2 AND state NOT IN ('done','failed')`, r.org, r.secretID).Scan(&open)
		if pending == 0 && open == 0 {
			return
		}
		if time.Now().After(end) {
			r.t.Fatalf("not settled: pending=%d open runs=%d", pending, open)
		}
	}
}

// An older input that no run laid out and that nothing supersedes (it was given
// up on) is no predecessor, and the run of the newer input still leaves exactly
// the newest version active: the end state does not depend on which version the
// run took as its predecessor.
func TestRotateE2E_GivenUpOlderInputIsDisabledByTheNextRun(t *testing.T) {
	r := newRotFixture(t, 1)
	ctx := context.Background()
	r.enterRotationInput()
	r.enterRotationInput()
	ids := r.linkIDs()
	_, err := r.f.pool.Exec(ctx, `UPDATE intake_rotation_links SET started_at=now() WHERE org_id=$1 AND request_id=$2`, r.org, ids[0])
	must(t, err)
	r.handle(ids[1])
	r.settle()
	if got := r.activeVersions(); len(got) != 1 || got[0] != "3" {
		t.Fatalf("provider active versions %v, want [3]", got)
	}
	var enabled int
	must(t, r.f.pool.QueryRow(ctx, `SELECT count(*) FROM secret_versions WHERE secret_id=$1 AND NOT disabled`, r.secretID).Scan(&enabled))
	if enabled != 1 {
		t.Fatalf("catalog has %d enabled versions, want 1", enabled)
	}
	// The key behind the predecessor is what a run revokes: it is a version that
	// was laid out, never one that only waited for its layout.
	var old string
	must(t, r.f.pool.QueryRow(ctx, `SELECT old_version FROM rotation_runs WHERE secret_id=$1 AND new_version='3'`, r.secretID).Scan(&old))
	if old != "1" {
		t.Fatalf("the run of version 3 took %q as predecessor, want the deployed 1", old)
	}
}

// A version a plain input link stored is not a rotation input: nothing else
// lays it out, so it is the deployed predecessor of the next rotation and is
// revoked with the rest.
func TestRotateE2E_PlainInputVersionIsTheRevokedPredecessor(t *testing.T) {
	r := newRotFixture(t, 1)
	rec := r.do(http.MethodPost, "/v1/input-links", map[string]string{"secret": "rot-secret"})
	var link intake.Issued
	if rec.Code != http.StatusCreated || json.Unmarshal(rec.Body.Bytes(), &link) != nil || link.URL == "" {
		t.Fatalf("input link: %d %s", rec.Code, rec.Body.String())
	}
	r.enter(link, canary.New().Value(1))
	r.enterRotationInput()
	r.settle()
	if got := r.activeVersions(); len(got) != 1 || got[0] != "3" {
		t.Fatalf("provider active versions %v, want [3]", got)
	}
	var old string
	must(t, r.f.pool.QueryRow(context.Background(), `SELECT old_version FROM rotation_runs WHERE secret_id=$1 AND new_version='3'`, r.secretID).Scan(&old))
	if old != "2" {
		t.Fatalf("the run of version 3 took %q as predecessor, want the plain input's 2", old)
	}
}

// The predecessor is the deployed_version pointer, not a guess: after a human
// input's run finished, the secret points at that version, and the next run
// revokes exactly it (a rotation input never counts as laid out by itself).
func TestRotateE2E_DeployedVersionPointerFeedsThePredecessor(t *testing.T) {
	r := newRotFixture(t, 1)
	ctx := context.Background()
	pointer := func() string {
		var v *string
		must(t, r.f.pool.QueryRow(ctx, `SELECT deployed_version FROM secrets WHERE id=$1`, r.secretID).Scan(&v))
		if v == nil {
			return ""
		}
		return *v
	}
	if got := pointer(); got != "" {
		t.Fatalf("deployed_version before any run = %q, want none", got)
	}
	r.enterRotationInput()
	r.settle()
	if got := pointer(); got != "2" {
		t.Fatalf("deployed_version after the first run = %q, want 2", got)
	}
	r.enterRotationInput()
	r.settle()
	if got := pointer(); got != "3" {
		t.Fatalf("deployed_version after the second run = %q, want 3", got)
	}
	var old string
	must(t, r.f.pool.QueryRow(ctx, `SELECT old_version FROM rotation_runs WHERE secret_id=$1 AND new_version='3'`, r.secretID).Scan(&old))
	if old != "2" {
		t.Fatalf("the second run took %q as predecessor, want the deployed 2", old)
	}
	if got := r.activeVersions(); len(got) != 1 || got[0] != "3" {
		t.Fatalf("provider active versions %v, want [3]", got)
	}
}

// skewCreatedAt turns the clock order of a secret's versions upside down: a
// version sealed later is made to look older. seal_seq is untouched, so any
// code that still orders by a timestamp picks the wrong version.
func (r *rotFixture) skewCreatedAt() {
	r.t.Helper()
	_, err := r.f.pool.Exec(context.Background(), `UPDATE secret_versions SET created_at = now() - (seal_seq || ' hours')::interval WHERE secret_id=$1`, r.secretID)
	must(r.t, err)
}

// Which of several sealed inputs is the newest is the seal order, not the
// clock: with created_at reversed, the last sealed input still wins and is the
// only version left active, whichever order they are handled in.
func TestRotateE2E_NewestIsTheLastSealedNotTheLatestTimestamp(t *testing.T) {
	r := newRotFixture(t, 1)
	r.enterRotationInput()
	r.enterRotationInput()
	r.skewCreatedAt()
	r.settle()
	if got := r.activeVersions(); len(got) != 1 || got[0] != "3" {
		t.Fatalf("provider active versions %v, want [3]", got)
	}
	var v string
	must(t, r.f.pool.QueryRow(context.Background(), `SELECT deployed_version FROM secrets WHERE id=$1`, r.secretID).Scan(&v))
	if v != "3" {
		t.Fatalf("deployed_version = %q, want 3", v)
	}
}

// With no pointer yet, the predecessor is the newest earlier version by seal
// order, even when the clock says another one is newer.
func TestRotateE2E_PredecessorFallbackFollowsSealOrder(t *testing.T) {
	r := newRotFixture(t, 1)
	rec := r.do(http.MethodPost, "/v1/input-links", map[string]string{"secret": "rot-secret"})
	var link intake.Issued
	if rec.Code != http.StatusCreated || json.Unmarshal(rec.Body.Bytes(), &link) != nil || link.URL == "" {
		t.Fatalf("input link: %d %s", rec.Code, rec.Body.String())
	}
	r.enter(link, canary.New().Value(1)) // plain version 2, sealed after version 1
	r.skewCreatedAt()                    // the clock now says 1 is newer than 2
	r.enterRotationInput()
	r.settle()
	var old string
	must(t, r.f.pool.QueryRow(context.Background(), `SELECT old_version FROM rotation_runs WHERE secret_id=$1 AND new_version='3'`, r.secretID).Scan(&old))
	if old != "2" {
		t.Fatalf("the run took %q as predecessor, want the last sealed earlier version 2", old)
	}
}

// An older sealed input handled while a newer one is still pending is retired,
// never laid out: its value must not reach a carrier, and the only run is the
// newest input's.
func TestRotateE2E_OlderInputHandledFirstGetsNoRun(t *testing.T) {
	r := newRotFixture(t, 1)
	ctx := context.Background()
	r.enterRotationInput()
	r.enterRotationInput()
	ids := r.linkIDs()
	r.handle(ids[0])
	var runs int
	must(t, r.f.pool.QueryRow(ctx, `SELECT count(*) FROM rotation_runs WHERE secret_id=$1`, r.secretID).Scan(&runs))
	if runs != 0 {
		t.Fatalf("the superseded older input got %d runs", runs)
	}
	r.handle(ids[1])
	r.settle()
	must(t, r.f.pool.QueryRow(ctx, `SELECT count(*) FROM rotation_runs WHERE secret_id=$1`, r.secretID).Scan(&runs))
	if runs != 1 {
		t.Fatalf("%d runs, want only the newest input's", runs)
	}
	if got := r.activeVersions(); len(got) != 1 || got[0] != "3" {
		t.Fatalf("provider active versions %v, want [3]", got)
	}
}

// A plain input link finished while a run of the secret is active: the value is
// newer than the run's version and no rotation issued its link. The end state
// is still one active version, the newest, in the provider and in the catalog.
func TestRotateE2E_PlainInputDuringARunEndsWithOneActiveVersion(t *testing.T) {
	every := rotationRetryEvery
	rotationRetryEvery = 50 * time.Millisecond
	t.Cleanup(func() { rotationRetryEvery = every })
	r := newRotFixture(t, 1)
	ctx := context.Background()
	var seen []string
	r.paused.Store(true)
	first := r.start(&seen)
	for end := time.Now().Add(20 * time.Second); ; time.Sleep(25 * time.Millisecond) {
		var nv string
		_ = r.f.pool.QueryRow(ctx, `SELECT new_version FROM rotation_runs WHERE id=$1`, first).Scan(&nv)
		if nv != "" {
			break
		}
		if time.Now().After(end) {
			t.Fatal("the run never made its version")
		}
	}
	rec := r.do(http.MethodPost, "/v1/input-links", map[string]string{"secret": "rot-secret"})
	var link intake.Issued
	if rec.Code != http.StatusCreated || json.Unmarshal(rec.Body.Bytes(), &link) != nil || link.URL == "" {
		t.Fatalf("input link: %d %s", rec.Code, rec.Body.String())
	}
	typed := canary.New().Value(1)
	r.typed = typed
	seen = append(seen, r.enter(link, typed))
	r.paused.Store(false)
	// Both runs end: the first one's, and the one that lays out the late value.
	for end := time.Now().Add(40 * time.Second); ; time.Sleep(25 * time.Millisecond) {
		var open, total int
		_ = r.f.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE state NOT IN ('done','failed')), count(*) FROM rotation_runs WHERE org_id=$1 AND secret_id=$2`, r.org, r.secretID).Scan(&open, &total)
		var pending int
		_ = r.f.pool.QueryRow(ctx, `SELECT count(*) FROM intake_rotation_links WHERE org_id=$1 AND started_at IS NULL`, r.org).Scan(&pending)
		if open == 0 && total >= 2 && pending == 0 {
			break
		}
		if time.Now().After(end) {
			t.Fatalf("not settled: %d runs, %d open, %d pending", total, open, pending)
		}
	}
	var enabled int
	_ = r.f.pool.QueryRow(ctx, `SELECT count(*) FROM secret_versions WHERE org_id=$1 AND secret_id=$2 AND NOT disabled`, r.org, r.secretID).Scan(&enabled)
	if got := r.activeVersions(); len(got) != 1 || enabled != 1 {
		t.Fatalf("one active version expected, provider %v, catalog %d", got, enabled)
	}
	r.checkNoLeak(seen)
	if canary.Of(typed).In(r.surfaces(seen)) {
		t.Fatal("typed value on a surface")
	}
}
