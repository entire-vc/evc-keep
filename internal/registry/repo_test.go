package registry

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// testDB opens a pool against a real, already-migrated PostgreSQL instance —
// see CONTRIBUTING.md: the database layer is never mocked. Mirrors
// internal/enrolltoken's own testDB.
func testDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("KEEP_DATABASE_URL")
	if dsn == "" {
		t.Skip("KEEP_DATABASE_URL not set — see CONTRIBUTING.md")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func seedOrg(t *testing.T, db *pgxpool.Pool) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuid.NewV7: %v", err)
	}
	_, err = db.Exec(context.Background(), `INSERT INTO organizations (id, name) VALUES ($1, $2)`, id, "org-"+id.String())
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	return id
}

func newRepo(t *testing.T) (*Repo, *pgxpool.Pool) {
	db := testDB(t)
	return NewRepo(db), db
}

func newRunnerID(t *testing.T) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuid.NewV7: %v", err)
	}
	return id
}

func TestCreateThenCheckActiveSucceeds(t *testing.T) {
	repo, db := newRepo(t)
	ctx := context.Background()
	org := seedOrg(t, db)
	runner := newRunnerID(t)

	if err := repo.Create(ctx, org, runner, "runner-1.example.test", "serial-1", time.Now().Add(30*24*time.Hour)); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := repo.CheckActive(ctx, org, runner, "serial-1"); err != nil {
		t.Fatalf("CheckActive: %v", err)
	}
}

func TestCheckActiveRejectsUnknownRunner(t *testing.T) {
	repo, db := newRepo(t)
	ctx := context.Background()
	org := seedOrg(t, db)
	if err := repo.CheckActive(ctx, org, newRunnerID(t), "serial-1"); err != ErrRunnerRejected {
		t.Fatalf("CheckActive for unknown runner: err = %v, want ErrRunnerRejected", err)
	}
}

// TestCheckActiveRejectsCrossOrg is the spec's red-run requirement, case 2's
// registry half: a runner enrolled in org A is invisible under org B's id,
// even with the correct runner_id and serial.
func TestCheckActiveRejectsCrossOrg(t *testing.T) {
	repo, db := newRepo(t)
	ctx := context.Background()
	orgA := seedOrg(t, db)
	orgB := seedOrg(t, db)
	runner := newRunnerID(t)
	if err := repo.Create(ctx, orgA, runner, "h", "serial-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := repo.CheckActive(ctx, orgB, runner, "serial-1"); err != ErrRunnerRejected {
		t.Fatalf("CheckActive under the wrong org: err = %v, want ErrRunnerRejected", err)
	}
}

// TestCheckActiveRejectsRevoked is the spec's red-run requirement, case 3:
// a revoked runner is refused on its next request.
func TestCheckActiveRejectsRevoked(t *testing.T) {
	repo, db := newRepo(t)
	ctx := context.Background()
	org := seedOrg(t, db)
	runner := newRunnerID(t)
	if err := repo.Create(ctx, org, runner, "h", "serial-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := repo.CheckActive(ctx, org, runner, "serial-1"); err != nil {
		t.Fatalf("CheckActive before revoke: %v", err)
	}
	if err := repo.Revoke(ctx, org, runner); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := repo.CheckActive(ctx, org, runner, "serial-1"); err != ErrRunnerRejected {
		t.Fatalf("CheckActive after revoke: err = %v, want ErrRunnerRejected", err)
	}
}

func TestCheckActiveRejectsStaleSerialAfterRenewal(t *testing.T) {
	repo, db := newRepo(t)
	ctx := context.Background()
	org := seedOrg(t, db)
	runner := newRunnerID(t)
	if err := repo.Create(ctx, org, runner, "h", "serial-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdateCert(ctx, org, runner, "serial-1", "serial-2", time.Now().Add(30*24*time.Hour)); err != nil {
		t.Fatalf("UpdateCert: %v", err)
	}
	if err := repo.CheckActive(ctx, org, runner, "serial-1"); err != ErrRunnerRejected {
		t.Fatalf("CheckActive with the pre-renewal serial: err = %v, want ErrRunnerRejected", err)
	}
	if err := repo.CheckActive(ctx, org, runner, "serial-2"); err != nil {
		t.Fatalf("CheckActive with the renewed serial: %v", err)
	}
}

func TestUpdateCertRejectsRevoked(t *testing.T) {
	repo, db := newRepo(t)
	ctx := context.Background()
	org := seedOrg(t, db)
	runner := newRunnerID(t)
	if err := repo.Create(ctx, org, runner, "h", "serial-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := repo.Revoke(ctx, org, runner); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdateCert(ctx, org, runner, "serial-1", "serial-2", time.Now().Add(time.Hour)); err != ErrRunnerUnknown {
		t.Fatalf("UpdateCert on a revoked runner: err = %v, want ErrRunnerUnknown", err)
	}
}

func TestUpdateCertConcurrentSameSerial(t *testing.T) {
	repo, db := newRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	org := seedOrg(t, db)
	runner := newRunnerID(t)
	expiry := time.Now().Add(time.Hour).Truncate(time.Microsecond)
	if err := repo.Create(ctx, org, runner, "renew.example.test", "serial-old", expiry); err != nil {
		t.Fatal(err)
	}

	// Both callers authenticate the same serial before either can update it.
	// The barrier forces the stale-authentication window without relying on
	// goroutine scheduling or adding a hook to the production SQL path.
	type result struct {
		serial string
		err    error
	}
	ready := make(chan error, 2)
	release := make(chan struct{})
	results := make(chan result, 2)
	for _, serial := range []string{"serial-a", "serial-b"} {
		go func() {
			err := repo.CheckActive(ctx, org, runner, "serial-old")
			ready <- err
			if err != nil {
				return
			}
			select {
			case <-release:
			case <-ctx.Done():
				return
			}
			results <- result{serial, repo.UpdateCert(ctx, org, runner, "serial-old", serial, expiry)}
		}()
	}
	for range 2 {
		select {
		case err := <-ready:
			if err != nil {
				t.Fatal("caller could not authenticate the original serial")
			}
		case <-ctx.Done():
			t.Fatal("callers did not reach the pre-update barrier")
		}
	}
	close(release)
	winner, loser := "", ""
	successes, rejected := 0, 0
	for range 2 {
		select {
		case res := <-results:
			switch res.err {
			case nil:
				successes++
				winner = res.serial
			case ErrRunnerUnknown:
				rejected++
				loser = res.serial
			default:
				t.Fatal("renewal returned an unexpected error")
			}
		case <-ctx.Done():
			t.Fatal("concurrent updates did not finish")
		}
	}
	if successes != 1 || rejected != 1 {
		t.Fatalf("concurrent updates: successes=%d rejected=%d, want one of each", successes, rejected)
	}
	if err := repo.CheckActive(ctx, org, runner, winner); err != nil {
		t.Fatal("successful update returned an inactive serial")
	}
	for _, serial := range []string{"serial-old", loser} {
		if err := repo.CheckActive(ctx, org, runner, serial); err != ErrRunnerRejected {
			t.Fatal("original or rejected serial remained active")
		}
	}
	if err := repo.UpdateCert(ctx, org, runner, "serial-old", "serial-stale", expiry); err != ErrRunnerUnknown {
		t.Fatal("stale expected serial was accepted")
	}
	if err := repo.UpdateCert(ctx, org, runner, winner, "serial-next", expiry); err != nil {
		t.Fatal("winning serial could not renew again")
	}
}

func TestRevokeRefusesUnknownRunner(t *testing.T) {
	repo, db := newRepo(t)
	org := seedOrg(t, db)
	if err := repo.Revoke(context.Background(), org, newRunnerID(t)); err != ErrRunnerUnknown {
		t.Fatalf("Revoke unknown runner: err = %v, want ErrRunnerUnknown", err)
	}
}

func TestRevokeRefusesCrossOrg(t *testing.T) {
	repo, db := newRepo(t)
	ctx := context.Background()
	orgA := seedOrg(t, db)
	orgB := seedOrg(t, db)
	runner := newRunnerID(t)
	if err := repo.Create(ctx, orgA, runner, "h", "serial-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := repo.Revoke(ctx, orgB, runner); err != ErrRunnerUnknown {
		t.Fatalf("Revoke from the wrong org: err = %v, want ErrRunnerUnknown", err)
	}
	// Still active under its real org — the wrong-org attempt did nothing.
	if err := repo.CheckActive(ctx, orgA, runner, "serial-1"); err != nil {
		t.Fatalf("CheckActive after a wrong-org revoke attempt: %v", err)
	}
}

func TestRevokeIsIdempotent(t *testing.T) {
	repo, db := newRepo(t)
	ctx := context.Background()
	org := seedOrg(t, db)
	runner := newRunnerID(t)
	if err := repo.Create(ctx, org, runner, "h", "serial-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := repo.Revoke(ctx, org, runner); err != nil {
		t.Fatalf("first Revoke: %v", err)
	}
	if err := repo.Revoke(ctx, org, runner); err != ErrRunnerUnknown {
		t.Fatalf("second Revoke: err = %v, want ErrRunnerUnknown", err)
	}
}

func TestUpdateCertRejectsCrossOrg(t *testing.T) {
	repo, db := newRepo(t)
	ctx := context.Background()
	orgA, orgB := seedOrg(t, db), seedOrg(t, db)
	id := newRunnerID(t)
	if err := repo.Create(ctx, orgA, id, "h", "serial-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdateCert(ctx, orgB, id, "serial-1", "serial-2", time.Now().Add(time.Hour)); err != ErrRunnerUnknown {
		t.Fatal("cross-org certificate update was not rejected")
	}
	if err := repo.CheckActive(ctx, orgA, id, "serial-1"); err != nil {
		t.Fatal("cross-org attempt changed the certificate")
	}
	if err := repo.UpdateCert(ctx, orgA, id, "serial-1", "serial-2", time.Now().Add(time.Hour)); err != nil {
		t.Fatal("same-org positive control failed")
	}
}
