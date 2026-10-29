package audit

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// rechain rewrites the stored prev_hash and hash of recs (the records as
// Append returned them, in chain order) so every hash is consistent with its
// own fields, then points the chain head at the last hash. prevOverride
// replaces the prev_hash used at one index. It plays the writer who forges a
// self-consistent chain, so a Verify failure afterwards can only come from
// the check under test rather than from a stale hash.
func rechain(t *testing.T, pool *pgxpool.Pool, org string, recs []Record, firstPrev string, prevOverride map[int]string) {
	t.Helper()
	prev := firstPrev
	for i := range recs {
		if o, ok := prevOverride[i]; ok {
			prev = o
		}
		recs[i].PrevHash = prev
		h, err := computeHash(prev, recs[i])
		if err != nil {
			t.Fatalf("computeHash: %v", err)
		}
		superuserExec(t, pool, `UPDATE audit_records SET prev_hash = $2, hash = $3 WHERE id = $1`, recs[i].ID, prev, h)
		prev = h
	}
	superuserExec(t, pool, `UPDATE audit_chain_heads SET hash = $2 WHERE org_id = $1`, org, prev)
}

func appendN(t *testing.T, j *Journal, org string, n int) []Record {
	t.Helper()
	var recs []Record
	for i := 0; i < n; i++ {
		r, err := j.Append(context.Background(), newRecord(org, nil))
		if err != nil {
			t.Fatalf("Append #%d: %v", i, err)
		}
		recs = append(recs, r)
	}
	return recs
}

func mustVerifyOK(t *testing.T, pool *pgxpool.Pool, org string, wantChecked int64) {
	t.Helper()
	res, err := Verify(context.Background(), pool, org)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK || res.Checked != wantChecked {
		t.Fatalf("chain not clean before the tamper: %+v (want OK with %d checked)", res, wantChecked)
	}
}

func mustBeBroken(t *testing.T, pool *pgxpool.Pool, org string, kind BreakKind) VerifyResult {
	t.Helper()
	res, err := Verify(context.Background(), pool, org)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.OK {
		t.Fatalf("Verify reported a %s break as OK", kind)
	}
	if res.BreakKind != kind {
		t.Fatalf("Verify reported %q, want %q: %+v", res.BreakKind, kind, res)
	}
	return res
}

// Records cut off the end leave every surviving record consistent; only the
// chain head knows the chain was longer.
func TestVerify_DetectsTruncatedTail(t *testing.T) {
	pool := testPool(t)
	j := NewJournal(pool)
	org := "org-trunc"
	recs := appendN(t, j, org, 3)
	mustVerifyOK(t, pool, org, 3)

	superuserExec(t, pool, `DELETE FROM audit_records WHERE id = $1`, recs[2].ID)
	res := mustBeBroken(t, pool, org, BreakHead)
	if res.BrokenID != "" || res.BrokenPosition != 3 || res.Checked != 2 {
		t.Errorf("head break should report the head position and the walked count: %+v", res)
	}
}

func TestVerify_DetectsWipedOrganization(t *testing.T) {
	pool := testPool(t)
	j := NewJournal(pool)
	org := "org-wipe"
	appendN(t, j, org, 2)
	mustVerifyOK(t, pool, org, 2)

	superuserExec(t, pool, `DELETE FROM audit_records WHERE org_id = $1`, org)
	mustBeBroken(t, pool, org, BreakHead)
}

func TestVerify_DetectsDeletedHeadRow(t *testing.T) {
	pool := testPool(t)
	j := NewJournal(pool)
	org := "org-nohead"
	appendN(t, j, org, 2)
	mustVerifyOK(t, pool, org, 2)

	superuserExec(t, pool, `DELETE FROM audit_chain_heads WHERE org_id = $1`, org)
	mustBeBroken(t, pool, org, BreakHead)
}

// An organization that never appended has neither records nor head: clean.
func TestVerify_UnusedOrganizationIsClean(t *testing.T) {
	pool := testPool(t)
	mustVerifyOK(t, pool, "org-never-used", 0)
}

// The first record must start at GenesisHash. The chain below is otherwise
// fully self-consistent (hashes recomputed, head updated), so only the
// genesis link check can see it.
func TestVerify_DetectsFirstRecordNotChainedFromGenesis(t *testing.T) {
	pool := testPool(t)
	j := NewJournal(pool)
	org := "org-genesis-forged"
	recs := appendN(t, j, org, 3)
	rechain(t, pool, org, recs, strings.Repeat("ab", 32), nil)

	res := mustBeBroken(t, pool, org, BreakLink)
	if res.BrokenID != recs[0].ID || res.BrokenPosition != 1 {
		t.Errorf("want the first record named, got %+v", res)
	}
}

// A middle record whose prev_hash is not its predecessor's hash, with all
// hashes recomputed to match: only the link check can see it.
func TestVerify_DetectsForgedMiddleLink(t *testing.T) {
	pool := testPool(t)
	j := NewJournal(pool)
	org := "org-link-forged"
	recs := appendN(t, j, org, 3)
	rechain(t, pool, org, recs, GenesisHash, map[int]string{1: strings.Repeat("cd", 32)})

	res := mustBeBroken(t, pool, org, BreakLink)
	if res.BrokenID != recs[1].ID || res.BrokenPosition != 2 {
		t.Errorf("want the second record named, got %+v", res)
	}
}

// The first record deleted and the rest re-chained from genesis: every hash
// and link is consistent, only the org_seq gap (starts at 2) shows it.
func TestVerify_DetectsSequenceGap(t *testing.T) {
	pool := testPool(t)
	j := NewJournal(pool)
	org := "org-seq-gap"
	recs := appendN(t, j, org, 3)
	superuserExec(t, pool, `DELETE FROM audit_records WHERE id = $1`, recs[0].ID)
	rechain(t, pool, org, recs[1:], GenesisHash, nil)

	res := mustBeBroken(t, pool, org, BreakSequence)
	if res.BrokenID != recs[1].ID {
		t.Errorf("want the first surviving record named, got %+v", res)
	}
}

// fullRecord fills every optional group (target, policy, approval) — the
// ordinary newRecord leaves them empty, so a column mixed up on insert or on
// read would go unnoticed.
func fullRecord(org string) Record {
	return newRecord(org, func(r *Record) {
		r.Target = Target{RunnerID: "runner-1", Host: "host-1", Kind: "file", Path: "/srv/app/.env"}
		r.Policy = Policy{Decision: DecisionAllow, RuleID: "rule-1"}
		r.Approval = Approval{
			ID: "appr-1", ApproverID: "user-2",
			// Nanoseconds in a non-UTC zone: Append must truncate to
			// microseconds and normalize to UTC or Verify recomputes a
			// different hash.
			DecidedAt: time.Date(2026, 9, 24, 10, 30, 0, 123456789, time.FixedZone("east", 9*3600)),
		}
		r.Result.Health = HealthOK
		r.Result.ErrorClass = ErrClassNone
	})
}

// The Append -> database -> Verify round trip for every column, under a
// non-UTC local zone and a clock with nanoseconds: the CI image runs in UTC
// and macOS clocks tick in microseconds, so without both, dropping the
// normalization or the truncation would go unnoticed.
func TestVerify_RoundTripsEveryColumnUnderNonUTCLocalTime(t *testing.T) {
	prevLocal := time.Local
	time.Local = time.FixedZone("west-odd", -(5*3600 + 1800))
	t.Cleanup(func() { time.Local = prevLocal })

	pool := testPool(t)
	j := NewJournal(pool)
	j.now = func() time.Time { return time.Date(2026, 9, 24, 12, 0, 0, 987654321, time.FixedZone("far", 13*3600)) }

	org := "org-roundtrip"
	if _, err := j.Append(context.Background(), fullRecord(org)); err != nil {
		t.Fatalf("Append: %v", err)
	}
	mustVerifyOK(t, pool, org, 1)
}

// Every hashed column, edited on its own after a full record was appended,
// must break the chain at that record.
func TestVerify_DetectsTamperOfEveryColumn(t *testing.T) {
	pool := testPool(t)
	j := NewJournal(pool)
	ctx := context.Background()

	columns := [][2]string{
		{"request_id", `request_id || 'x'`},
		{"scope", `scope || 'x'`},
		{"actor_type", `'user'`},
		{"actor_id", `actor_id || 'x'`},
		{"actor_sponsor_id", `actor_sponsor_id || 'x'`},
		{"actor_via", `'cli'`},
		{"intent_task_ref", `intent_task_ref || 'x'`},
		{"intent_session_ref", `intent_session_ref || 'x'`},
		{"intent_reason", `intent_reason || 'x'`},
		// Another registered action: the CHECK refuses anything outside the registry.
		{"action", `CASE WHEN action = 'kek.purge' THEN 'exec.run' ELSE 'kek.purge' END`},
		{"secret_id", `secret_id || 'x'`},
		{"secret_name", `secret_name || 'x'`},
		{"secret_version", `secret_version || 'x'`},
		{"target_runner_id", `target_runner_id || 'x'`},
		{"target_host", `target_host || 'x'`},
		{"target_kind", `target_kind || 'x'`},
		{"target_path", `target_path || 'x'`},
		{"policy_decision", `'deny'`},
		{"policy_rule_id", `policy_rule_id || 'x'`},
		{"approval_id", `approval_id || 'x'`},
		{"approval_approver_id", `approval_approver_id || 'x'`},
		{"approval_decided_at", `approval_decided_at + interval '1 second'`},
		{"result_status", `'failed'`},
		{"result_fingerprint", `replace(result_fingerprint, 'abc', 'abd')`},
		{"result_length", `result_length + 1`},
		{"result_health", `'failed'`},
		{"result_error_class", `'internal'`},
	}
	for _, ce := range columns {
		col, expr := ce[0], ce[1]
		t.Run(col, func(t *testing.T) {
			org := "org-col-" + col
			rec, err := j.Append(ctx, fullRecord(org))
			if err != nil {
				t.Fatalf("Append: %v", err)
			}
			mustVerifyOK(t, pool, org, 1)
			superuserExec(t, pool, `UPDATE audit_records SET `+col+` = `+expr+` WHERE id = $1`, rec.ID)
			res := mustBeBroken(t, pool, org, BreakHash)
			if res.BrokenID != rec.ID {
				t.Errorf("edit of %s named %q, want %q", col, res.BrokenID, rec.ID)
			}
		})
	}
}

// The head's position can match while its hash does not (the head row
// rewritten, or the last record replaced): the hash comparison is its own
// check.
func TestVerify_DetectsStaleHeadHash(t *testing.T) {
	pool := testPool(t)
	j := NewJournal(pool)
	org := "org-headhash"
	appendN(t, j, org, 2)
	mustVerifyOK(t, pool, org, 2)

	superuserExec(t, pool, `UPDATE audit_chain_heads SET hash = $2 WHERE org_id = $1`, org, strings.Repeat("ef", 32))
	mustBeBroken(t, pool, org, BreakHead)
}

// The head's hash can match while its position does not: the two head
// comparisons are independent checks, each with its own test.
func TestVerify_DetectsStaleHeadPosition(t *testing.T) {
	pool := testPool(t)
	j := NewJournal(pool)
	org := "org-headpos"
	appendN(t, j, org, 2)
	mustVerifyOK(t, pool, org, 2)

	superuserExec(t, pool, `UPDATE audit_chain_heads SET position = position + 1 WHERE org_id = $1`, org)
	res := mustBeBroken(t, pool, org, BreakHead)
	if res.BrokenPosition != 3 {
		t.Errorf("head break should report the head's position 3, got %+v", res)
	}
}
