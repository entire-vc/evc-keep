package audit

import (
	"context"
	"testing"
)

func TestAppendTxFollowsCallerTransaction(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	j := NewJournal(pool)
	for _, commit := range []bool{false, true} {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var before, after string
		if err = tx.QueryRow(ctx, `SELECT current_user`).Scan(&before); err != nil {
			t.Fatal(err)
		}
		if _, err = j.AppendTx(ctx, tx, newRecord("caller-transaction", nil)); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		if err = tx.QueryRow(ctx, `SELECT current_user`).Scan(&after); err != nil {
			t.Fatal(err)
		}
		if before != after {
			t.Fatal("audit changed caller role")
		}
		if commit {
			err = tx.Commit(ctx)
		} else {
			err = tx.Rollback(ctx)
		}
		if err != nil {
			t.Fatal(err)
		}
		result, err := Verify(ctx, pool, "caller-transaction")
		if err != nil {
			t.Fatal(err)
		}
		want := int64(0)
		if commit {
			want = 1
		}
		if !result.OK || result.Checked != want {
			t.Fatal("audit record did not follow caller transaction")
		}
	}
}
