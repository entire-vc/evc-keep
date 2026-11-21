package carriers

import (
	"testing"

	"github.com/google/uuid"
)

// insertCarrier lays a row straight into the table: Summary only reads, and
// the states it counts (stale, unknown, an older version) come from other
// writers than Register.
func insertCarrier(t *testing.T, f fixture, org, secret uuid.UUID, version, path string, state State) {
	t.Helper()
	_, err := f.pool.Exec(ctx, `INSERT INTO carriers(org_id,id,secret_id,version,host,target_kind,target_path,target_field,consumer,healthcheck_ref,last_fp,state)
 VALUES($1,$2,$3,$4,'h.example.test',$5,$6,'','','',$7,$8)`, org, uuid.New(), secret, version, f.in.TargetKind, path, f.fp, string(state))
	must(t, err)
}

func addVersion(t *testing.T, f fixture, version string, disabled bool) {
	t.Helper()
	_, err := f.pool.Exec(ctx, `INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length,disabled) VALUES ($1,$2,$3,$4,$5,17,$6)`,
		uuid.New(), f.org, f.id, version, f.fp, disabled)
	must(t, err)
}

func TestSummaryCountsCarriersAgainstTheCurrentVersion(t *testing.T) {
	f := setup(t)
	got, err := f.repo.Summary(ctx, f.org)
	must(t, err)
	if len(got) != 0 {
		t.Fatalf("a secret with no carriers has an entry: %+v", got)
	}
	register(t, f) // v1, registered: in sync
	insertCarrier(t, f, f.org, f.id, "v1", "/b", Stale)
	insertCarrier(t, f, f.org, f.id, "v1", "/c", Unknown)
	if got, err = f.repo.Summary(ctx, f.org); err != nil || got[f.id] != (Summary{Total: 3, InSync: 1, Stale: 1, Unknown: 1}) {
		t.Fatalf("at v1: %+v %v", got, err)
	}
	// A disabled newer version is not current: nothing moves.
	addVersion(t, f, "v2", true)
	if got, _ = f.repo.Summary(ctx, f.org); got[f.id] != (Summary{Total: 3, InSync: 1, Stale: 1, Unknown: 1}) {
		t.Fatalf("a disabled version became current: %+v", got)
	}
	// An enabled newer version: the registered v1 carrier is now stale.
	addVersion(t, f, "v3", false)
	if got, _ = f.repo.Summary(ctx, f.org); got[f.id] != (Summary{Total: 3, InSync: 0, Stale: 2, Unknown: 1}) {
		t.Fatalf("after v3: %+v", got)
	}
	insertCarrier(t, f, f.org, f.id, "v3", "/d", Registered)
	if got, _ = f.repo.Summary(ctx, f.org); got[f.id] != (Summary{Total: 4, InSync: 1, Stale: 2, Unknown: 1}) {
		t.Fatalf("a v3 carrier: %+v", got)
	}
	// Another organization reads none of it, and the service answers the same.
	if got, _ = f.repo.Summary(ctx, f.other); len(got) != 0 {
		t.Fatalf("foreign org sees carriers: %+v", got)
	}
	svc := &Service{repo: f.repo}
	if got, err = svc.Summary(ctx, f.org); err != nil || len(got) != 1 || got[f.id].Total != 4 {
		t.Fatalf("service: %+v %v", got, err)
	}
	if _, err = (*Repository)(nil).Summary(ctx, f.org); err != ErrInternal {
		t.Fatalf("nil repository: %v", err)
	}
}
