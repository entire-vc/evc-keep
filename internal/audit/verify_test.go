package audit

import (
	"context"
	"testing"
)

// TestVerify_DetectsInPlaceTamper is the red run for the requirement
// "editing one record directly in the database, bypassing the application
// (as a superuser) → audit verify names exactly that record." A tampering
// edit that does not also forge the
// stored hash column is the realistic case (forging a fresh, internally
// consistent hash requires reproducing this package's own canonical-JSON
// format exactly, which is not "an operator ran an ad hoc UPDATE") — see
// doc.go for why the recompute-from-stored-fields check alone already
// catches this class of tamper.
func TestVerify_DetectsInPlaceTamper(t *testing.T) {
	pool := testPool(t)
	j := NewJournal(pool)
	ctx := context.Background()
	org := "org-tamper"

	_, err := j.Append(ctx, newRecord(org, nil))
	if err != nil {
		t.Fatalf("Append #0: %v", err)
	}
	target, err := j.Append(ctx, newRecord(org, func(r *Record) { r.Intent.Reason = "before tamper" }))
	if err != nil {
		t.Fatalf("Append #1: %v", err)
	}
	if _, err := j.Append(ctx, newRecord(org, nil)); err != nil {
		t.Fatalf("Append #2: %v", err)
	}

	res, err := Verify(ctx, pool, org)
	if err != nil {
		t.Fatalf("Verify (pre-tamper): %v", err)
	}
	if !res.OK {
		t.Fatalf("chain was already broken before any tamper: %+v", res)
	}

	// Bypass the application entirely: a direct UPDATE as the pool's own
	// (superuser) login role, exactly like an operator's ad hoc fix would
	// be, never through Journal/keep_app.
	superuserExec(t, pool, `UPDATE audit_records SET actor_id = 'tampered-actor' WHERE id = $1`, target.ID)

	res, err = Verify(ctx, pool, org)
	if err != nil {
		t.Fatalf("Verify (post-tamper): %v", err)
	}
	if res.OK {
		t.Fatal("Verify did not detect an in-place tamper of a record")
	}
	if res.BrokenID != target.ID {
		t.Errorf("Verify named %q as broken, want the tampered record %q", res.BrokenID, target.ID)
	}
}

// TestVerify_DetectsDeletionFromTheMiddle is the red run for the requirement
// "deleting a record from the middle of the chain → the break is found."
// Deleting record N leaves
// record N+1's stored prev_hash pointing at a hash no longer reachable by
// walking the surviving rows in order — see doc.go's worked-through
// explanation of why this is caught by the continuity check, not the
// recompute check (record N+1 itself was never touched, so it recomputes
// clean against its OWN stored prev_hash; the mismatch is between that
// stored prev_hash and the actual previous surviving record's hash).
func TestVerify_DetectsDeletionFromTheMiddle(t *testing.T) {
	pool := testPool(t)
	j := NewJournal(pool)
	ctx := context.Background()
	org := "org-delete-middle"

	if _, err := j.Append(ctx, newRecord(org, nil)); err != nil {
		t.Fatalf("Append #0: %v", err)
	}
	toDelete, err := j.Append(ctx, newRecord(org, nil))
	if err != nil {
		t.Fatalf("Append #1: %v", err)
	}
	after, err := j.Append(ctx, newRecord(org, nil))
	if err != nil {
		t.Fatalf("Append #2: %v", err)
	}

	res, err := Verify(ctx, pool, org)
	if err != nil {
		t.Fatalf("Verify (pre-delete): %v", err)
	}
	if !res.OK {
		t.Fatalf("chain was already broken before any deletion: %+v", res)
	}

	superuserExec(t, pool, `DELETE FROM audit_records WHERE id = $1`, toDelete.ID)

	res, err = Verify(ctx, pool, org)
	if err != nil {
		t.Fatalf("Verify (post-delete): %v", err)
	}
	if res.OK {
		t.Fatal("Verify did not detect a record deleted from the middle of the chain")
	}
	if res.BrokenID != after.ID {
		t.Errorf("Verify named %q as broken, want the record after the gap %q", res.BrokenID, after.ID)
	}
}

// TestVerify_OrgFilterIsEnforced is the "org_id scope in Verify" property
// a later review round added: Verify's
// SQL filters by org_id, but nothing before this test actually proved that
// filter is load-bearing rather than incidental — TestVerify_EmptyOrgIsOK
// passes even against a database with zero organizations at all, and the
// large concurrency test (TestAppend_ConcurrentAcrossOrgsKeepsBothChainsIntact)
// is skipped in -short mode and only shows two chains staying intact side by
// side, never that one org's Verify call is actually blind to the other
// org's rows. This test interleaves two small chains and requires org A's
// Verify to see exactly org A's own records — dropping (or loosening) the
// WHERE org_id = $1 clause would pull org B's rows into org A's walk and
// break the hash-chain continuity check on the very next record, since a
// record from a different chain can't satisfy prev_hash equality.
func TestVerify_OrgFilterIsEnforced(t *testing.T) {
	pool := testPool(t)
	j := NewJournal(pool)
	ctx := context.Background()
	orgA, orgB := "org-scope-a", "org-scope-b"

	for i := 0; i < 2; i++ {
		if _, err := j.Append(ctx, newRecord(orgA, nil)); err != nil {
			t.Fatalf("Append org A #%d: %v", i, err)
		}
		if _, err := j.Append(ctx, newRecord(orgB, nil)); err != nil {
			t.Fatalf("Append org B #%d: %v", i, err)
		}
	}

	resA, err := Verify(ctx, pool, orgA)
	if err != nil {
		t.Fatalf("Verify(orgA): %v", err)
	}
	if !resA.OK {
		t.Errorf("Verify(orgA): OK=false, broken at %s/%d — org B's interleaved records leaked into org A's chain walk", resA.BrokenID, resA.BrokenPosition)
	}
	if resA.Checked != 2 {
		t.Errorf("Verify(orgA).Checked = %d, want 2 (org B's 2 records must not be counted)", resA.Checked)
	}

	resB, err := Verify(ctx, pool, orgB)
	if err != nil {
		t.Fatalf("Verify(orgB): %v", err)
	}
	if !resB.OK || resB.Checked != 2 {
		t.Errorf("Verify(orgB) = %+v, want OK=true Checked=2", resB)
	}
}

// TestVerify_EmptyOrgIsOK is the boundary case both red-run tests' baseline
// assertions rely on implicitly: an org with zero records is a clean
// (trivial) chain, not an error.
func TestVerify_EmptyOrgIsOK(t *testing.T) {
	pool := testPool(t)
	res, err := Verify(context.Background(), pool, "org-never-appended-to")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK || res.Checked != 0 {
		t.Errorf("Verify(empty org) = %+v, want OK=true Checked=0", res)
	}
}
