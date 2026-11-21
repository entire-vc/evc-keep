package rotation

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// seedRun writes one run row as the engine leaves it, at a chosen time.
func seedRun(t *testing.T, x fx, org, secret uuid.UUID, state State, class Class, oldV, newV string, at time.Time) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := x.pool.Exec(x.ctx, `INSERT INTO rotation_runs(id, org_id, secret_id, state, error_class, old_version, new_version, incident_opened, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)`, id, org, secret, string(state), string(class), oldV, newV, class == ClassDeployFailed, at); err != nil {
		t.Fatalf("seed run: %v", err)
	}
	return id
}

func otherOrg(t *testing.T, x fx) uuid.UUID {
	t.Helper()
	org := uuid.New()
	if _, err := x.pool.Exec(x.ctx, `INSERT INTO organizations(id,name) VALUES ($1,'other')`, org); err != nil {
		t.Fatal("insert organization")
	}
	return org
}

// Latest: the newest run of each secret of this organization; a secret
// without runs is absent, and a newer run of the same secret id in another
// organization is never read.
func TestRunsLatestNewestPerSecretOfTheOrganization(t *testing.T) {
	x := newFx(t)
	org, a, b, none := x.ref.OrgID, x.ref.SecretID, uuid.New(), uuid.New()
	t0 := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	seedRun(t, x, org, a, StateDone, ClassNone, "1", "2", t0)
	newestA := seedRun(t, x, org, a, StateFailed, ClassUnhealthy, "2", "3", t0.Add(time.Hour))
	onlyB := seedRun(t, x, org, b, StateDeploying, ClassNone, "4", "5", t0)
	seedRun(t, x, otherOrg(t, x), a, StateDone, ClassNone, "7", "8", t0.Add(2*time.Hour))

	r := NewRuns(x.pool)
	got, err := r.Latest(x.ctx, org, []uuid.UUID{a, b, none})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[a].ID != newestA || got[b].ID != onlyB {
		t.Fatalf("latest: %+v", got)
	}
	ga := got[a]
	if ga.State != StateFailed || ga.Class != ClassUnhealthy || ga.OldVersion != "2" || ga.NewVersion != "3" || ga.SecretID != a || !ga.CreatedAt.Equal(t0.Add(time.Hour)) {
		t.Fatalf("summary fields: %+v", ga)
	}
	if _, ok := got[none]; ok {
		t.Fatal("a secret without runs has a latest run")
	}
	if empty, err := r.Latest(x.ctx, org, nil); err != nil || len(empty) != 0 {
		t.Fatalf("no secrets: %v %v", empty, err)
	}
}

// List: newest first, paged by limit and offset, with the total of the
// secret's runs; ListFailed counts and pages only failed runs; Get finds a
// run only under its own organization and secret.
func TestRunsListNewestFirstPagedFilteredAndBound(t *testing.T) {
	x := newFx(t)
	org, sec := x.ref.OrgID, x.ref.SecretID
	t0 := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	var ids []uuid.UUID // oldest first
	for i, st := range []State{StateDone, StateFailed, StateDone, StateFailed, StateVerifying} {
		cl := ClassNone
		if st == StateFailed {
			cl = ClassDeployFailed
		}
		ids = append(ids, seedRun(t, x, org, sec, st, cl, "1", "2", t0.Add(time.Duration(i)*time.Minute)))
	}
	seedRun(t, x, org, uuid.New(), StateDone, ClassNone, "1", "2", t0.Add(time.Hour))
	foreign := otherOrg(t, x)
	foreignRun := seedRun(t, x, foreign, sec, StateFailed, ClassDeployFailed, "1", "2", t0.Add(time.Hour))

	r := NewRuns(x.pool)
	page, total, err := r.List(x.ctx, org, sec, 2, 0)
	if err != nil || total != 5 || len(page) != 2 || page[0].ID != ids[4] || page[1].ID != ids[3] {
		t.Fatalf("first page: %v total=%d %+v", err, total, page)
	}
	last, total, err := r.List(x.ctx, org, sec, 2, 4)
	if err != nil || total != 5 || len(last) != 1 || last[0].ID != ids[0] {
		t.Fatalf("last page: %v total=%d %+v", err, total, last)
	}
	past, total, err := r.List(x.ctx, org, sec, 2, 50)
	if err != nil || total != 5 || len(past) != 0 {
		t.Fatalf("past the end: %v total=%d %+v", err, total, past)
	}
	all, _, err := r.List(x.ctx, org, sec, 0, -3) // out-of-range bounds are clamped, not an error
	if err != nil || len(all) != 5 {
		t.Fatalf("clamped: %v %d", err, len(all))
	}
	failed, total, err := r.ListFailed(x.ctx, org, sec, 50, 0)
	if err != nil || total != 2 || len(failed) != 2 || failed[0].ID != ids[3] || failed[1].ID != ids[1] {
		t.Fatalf("failed only: %v total=%d %+v", err, total, failed)
	}
	for _, f := range failed {
		if f.State != StateFailed || f.Class != ClassDeployFailed || !f.IncidentOpened {
			t.Fatalf("failed row: %+v", f)
		}
	}

	if s, ok, err := r.Get(x.ctx, org, sec, ids[2]); err != nil || !ok || s.ID != ids[2] {
		t.Fatalf("own run: %v %v %+v", ok, err, s)
	}
	for name, c := range map[string][3]uuid.UUID{
		"other organization": {org, sec, foreignRun},
		"other secret":       {org, uuid.New(), ids[2]},
		"unknown":            {org, sec, uuid.New()},
	} {
		if _, ok, err := r.Get(x.ctx, c[0], c[1], c[2]); err != nil || ok {
			t.Fatalf("%s: found=%v err=%v", name, ok, err)
		}
	}
}
