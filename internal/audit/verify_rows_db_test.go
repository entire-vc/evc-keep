package audit

import (
	"context"
	"database/sql"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// loadStored reads org's chain and head from the database into the in-memory
// form VerifyRows takes, normalising times to UTC as Verify does.
func loadStored(t *testing.T, ctx context.Context, pool *pgxpool.Pool, org string) ([]StoredRecord, StoredHead) {
	t.Helper()
	rows, err := pool.Query(ctx, `SELECT id, org_seq, ts, request_id, scope, actor_type, actor_id, actor_sponsor_id, actor_via,
		intent_task_ref, intent_session_ref, intent_reason, action, secret_id, secret_name, secret_version,
		target_runner_id, target_host, target_kind, target_path, policy_decision, policy_rule_id,
		approval_id, approval_approver_id, approval_decided_at, result_status, result_fingerprint, result_length,
		result_health, result_error_class, prev_hash, hash FROM audit_records WHERE org_id = $1 ORDER BY org_seq`, org)
	if err != nil {
		t.Fatal("query chain")
	}
	defer rows.Close()
	var out []StoredRecord
	for rows.Next() {
		var rec Record
		var s StoredRecord
		var dec sql.NullTime
		if err := rows.Scan(&rec.ID, &s.Seq, &rec.TS, &rec.RequestID, &rec.Scope,
			(*string)(&rec.Actor.Type), &rec.Actor.ID, &rec.Actor.SponsorID, (*string)(&rec.Actor.Via),
			&rec.Intent.TaskRef, &rec.Intent.SessionRef, &rec.Intent.Reason, (*string)(&rec.Action),
			&rec.Secret.ID, &rec.Secret.Name, &rec.Secret.Version,
			&rec.Target.RunnerID, &rec.Target.Host, &rec.Target.Kind, &rec.Target.Path,
			(*string)(&rec.Policy.Decision), &rec.Policy.RuleID,
			&rec.Approval.ID, &rec.Approval.ApproverID, &dec,
			(*string)(&rec.Result.Status), &rec.Result.Fingerprint, &rec.Result.Length,
			(*string)(&rec.Result.Health), (*string)(&rec.Result.ErrorClass), &rec.PrevHash, &s.Hash); err != nil {
			t.Fatal("scan chain")
		}
		rec.TS = rec.TS.UTC()
		if dec.Valid {
			rec.Approval.DecidedAt = dec.Time.UTC()
		}
		rec.OrgID = org
		s.Record = rec
		out = append(out, s)
	}
	var head StoredHead
	err = pool.QueryRow(ctx, `SELECT position, hash FROM audit_chain_heads WHERE org_id = $1`, org).Scan(&head.Position, &head.Hash)
	head.Present = err == nil
	return out, head
}

// VerifyRows and Verify must agree on a real chain, honest and tampered.
func TestVerifyRowsAgreesWithVerify(t *testing.T) {
	pool := testPool(t)
	j := NewJournal(pool)
	ctx := context.Background()
	org := "org-rows-agree"
	var mid Record
	for i := 0; i < 3; i++ {
		r, err := j.Append(ctx, newRecord(org, func(r *Record) { r.Intent.Reason = "row" }))
		if err != nil {
			t.Fatal("append")
		}
		if i == 1 {
			mid = r
		}
	}
	recs, head := loadStored(t, ctx, pool, org)
	got, err := VerifyRows(org, recs, head)
	want, _ := Verify(ctx, pool, org)
	if err != nil || !got.OK || !want.OK || got.Checked != want.Checked {
		t.Fatalf("honest chain: rows=%+v db=%+v", got, want)
	}
	superuserExec(t, pool, `UPDATE audit_records SET actor_id = 'tampered' WHERE id = $1`, mid.ID)
	recs, head = loadStored(t, ctx, pool, org)
	got, _ = VerifyRows(org, recs, head)
	want, _ = Verify(ctx, pool, org)
	if got.OK || want.OK || got.BreakKind != want.BreakKind || got.BrokenID != want.BrokenID {
		t.Fatalf("tampered chain: rows=%+v db=%+v", got, want)
	}
}
