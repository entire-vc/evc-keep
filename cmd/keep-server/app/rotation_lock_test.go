package app

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/intake"
	"github.com/entire-vc/evc-keep/internal/rotation"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/google/uuid"
)

func (r *rotFixture) activeCatalogVersions() []string {
	r.t.Helper()
	rows, err := r.f.pool.Query(context.Background(), `SELECT provider_version FROM secret_versions WHERE org_id=$1 AND secret_id=$2 AND NOT disabled ORDER BY seal_seq`, r.org, r.secretID)
	must(r.t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		_ = rows.Scan(&v)
		out = append(out, v)
	}
	return out
}

// A version sealed while a retire is in progress must not survive next to the
// version the retire keeps: under the lock of the secret's row the retire either
// sees the new version (and keeps it) or runs after it. Every round ends with
// exactly one active version, the last sealed one.
func TestRotateE2E_ConcurrentSealDuringRetireLeavesOneActive(t *testing.T) {
	r := newRotFixture(t, 1)
	ctx := context.Background()
	parts := &rotationParts{pool: r.f.pool, local: r.local, cat: catalog.New(r.f.pool)}
	ref := rotation.Ref{OrgID: r.org, SecretID: r.secretID}
	_, tgt, err := parts.target(ctx, ref)
	must(t, err)
	rev := rotationRevoker{parts}
	prov := r.local.Provider(r.org.String(), "", "", "")
	for i := 0; i < 20; i++ {
		// Both versions exist in the store too: it refuses to disable the last
		// active one, and what the retire disables must be real.
		runMeta, err := prov.Write(ctx, provider.Ref{Path: r.path}, secret.New([]byte(canary.New().Value(10+i))))
		must(t, err)
		_, err = parts.cat.AddVersion(ctx, r.org, r.secretID, runMeta.Version, "kfp1:k:AAAAAAAAAAAAAAAA", 8)
		must(t, err)
		humanMeta, err := prov.Write(ctx, provider.Ref{Path: r.path}, secret.New([]byte(canary.New().Value(40+i))))
		must(t, err)
		human := humanMeta.Version
		tx, err := r.f.pool.Begin(ctx)
		must(t, err)
		_, err = tx.Exec(ctx, rotationLockRow, r.org, r.secretID)
		must(t, err)
		_, err = tx.Exec(ctx, `INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length) VALUES($1,$2,$3,$4,'kfp1:k:BBBBBBBBBBBBBBBB',8)`, uuid.New(), r.org, r.secretID, human)
		must(t, err)
		var wg sync.WaitGroup
		wg.Add(1)
		var rerr error
		go func() { defer wg.Done(); rerr = rev.retireOlder(ctx, ref, tgt, uuid.New()) }()
		time.Sleep(40 * time.Millisecond) // the retire is waiting for the sealing transaction
		must(t, tx.Commit(ctx))
		wg.Wait()
		must(t, rerr)
		if got := r.activeCatalogVersions(); len(got) != 1 || got[0] != human {
			t.Fatalf("round %d: want exactly the last sealed version %s active, got %v", i, human, got)
		}
	}
}

// Sealing holds a share lock of the secret's row from the moment the link is
// read (internal/intake Complete): while a retire holds the row lock, a human
// input waits, and a retire waits for an input being sealed.
func TestRotateE2E_SealWaitsForTheRetireLock(t *testing.T) {
	r := newRotFixture(t, 1)
	ctx := context.Background()
	rec := r.do(http.MethodPost, r.rotatePath(), map[string]string{"mode": "human_input"})
	var link intake.Issued
	if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &link) != nil || link.URL == "" {
		t.Fatalf("input link: %d %s", rec.Code, rec.Body.String())
	}
	tx, err := r.f.pool.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	// NO KEY UPDATE conflicts with the share lock of the input but not with the
	// foreign key check of the insert, so only that share lock can make it wait.
	_, err = tx.Exec(ctx, `SELECT 1 FROM secrets WHERE org_id=$1 AND id=$2 FOR NO KEY UPDATE`, r.org, r.secretID)
	must(t, err)
	r.typed = canary.New().Value(1)
	done := make(chan struct{})
	go func() { defer close(done); r.enter(link, r.typed) }()
	select {
	case <-done:
		t.Fatal("the input was sealed while the secret's row was locked")
	case <-time.After(400 * time.Millisecond):
	}
	must(t, tx.Commit(ctx))
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the input never completed after the lock was released")
	}
}

// A human seals a newer version while a run is laying its own out: the run
// verifies against a version that is no longer the newest and ends superseded,
// not failed; the deployed_version pointer never moves to its version, and the
// typed version gets its own run and ends as the only active one.
func TestRotateE2E_RunSupersededByNewerSealedVersion(t *testing.T) {
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
			t.Fatal("the first run never made its version")
		}
	}
	rec := r.do(http.MethodPost, r.rotatePath(), map[string]string{"mode": "human_input"})
	var link intake.Issued
	if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &link) != nil || link.URL == "" {
		t.Fatalf("input link: %d %s", rec.Code, rec.Body.String())
	}
	r.typed = canary.New().Value(1)
	seen = append(seen, r.enter(link, r.typed))
	r.paused.Store(false)
	var st, class, runVersion string
	for end := time.Now().Add(20 * time.Second); ; time.Sleep(25 * time.Millisecond) {
		_ = r.f.pool.QueryRow(ctx, `SELECT state, COALESCE(error_class,''), new_version FROM rotation_runs WHERE id=$1`, first).Scan(&st, &class, &runVersion)
		if st == "done" || st == "failed" {
			break
		}
		if time.Now().After(end) {
			t.Fatalf("first run did not end: state %q", st)
		}
	}
	if st != "failed" || class != string(rotation.ClassSuperseded) {
		t.Fatalf("first run: state %q class %q, want failed/superseded", st, class)
	}
	// An ordinary supersede is not an incident, and the API says superseded,
	// not internal.
	// The incident, if any, is opened before the run lets go of its lease.
	for end := time.Now().Add(10 * time.Second); ; time.Sleep(25 * time.Millisecond) {
		var owner string
		_ = r.f.pool.QueryRow(ctx, `SELECT lease_owner FROM rotation_runs WHERE id=$1`, first).Scan(&owner)
		if owner == "" {
			break
		}
		if time.Now().After(end) {
			t.Fatal("the superseded run never released its lease")
		}
	}
	var incident bool
	_ = r.f.pool.QueryRow(ctx, `SELECT incident_opened FROM rotation_runs WHERE id=$1`, first).Scan(&incident)
	if incident {
		t.Fatal("a superseded run opened an incident")
	}
	if got := r.poll(first, &seen); got.ErrorClass != string(rotation.ClassSuperseded) {
		t.Fatalf("API error_class %q, want superseded", got.ErrorClass)
	}
	var deployed string
	_ = r.f.pool.QueryRow(ctx, `SELECT COALESCE(deployed_version,'') FROM secrets WHERE org_id=$1 AND id=$2`, r.org, r.secretID).Scan(&deployed)
	if deployed == runVersion {
		t.Fatalf("deployed_version moved to the superseded run's version %s", runVersion)
	}
	for end := time.Now().Add(30 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		var n int
		_ = r.f.pool.QueryRow(ctx, `SELECT count(*) FROM rotation_runs WHERE org_id=$1 AND secret_id=$2 AND state='done'`, r.org, r.secretID).Scan(&n)
		if n == 1 {
			break
		}
		if time.Now().After(end) {
			t.Fatal("the typed version never got its run to done")
		}
	}
	if got := r.activeCatalogVersions(); len(got) != 1 {
		t.Fatalf("exactly one active version expected, got %v", got)
	}
	r.checkNoLeak(seen)
}
