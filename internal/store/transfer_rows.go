package store

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/entire-vc/evc-keep/internal/scopedtransfer"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrTransferRows is the only error the row reader and writer return. It
// carries no driver text, identifier or row content.
var ErrTransferRows = errors.New("store: cannot read or write transfer rows")

type rowPtr[T any] interface {
	*T
	scanDest() []any
}

type argRow interface{ args() []any }

// readTable selects every row of one registry table that belongs to org, with
// an explicit column list and a fixed order. The statement is built only from
// program constants and the reviewed scope rule; the organization is $1.
func readTable[T any, P rowPtr[T]](ctx context.Context, tx pgx.Tx, table string, cols []string, order string, org uuid.UUID) ([]T, error) {
	where, ok := scopeWhere(table)
	if !ok {
		return nil, ErrTransferRows
	}
	quoted := make([]string, len(cols))
	for i, c := range cols {
		quoted[i] = pgx.Identifier{c}.Sanitize()
	}
	q := "SELECT " + strings.Join(quoted, ", ") + " FROM " + pgx.Identifier{table}.Sanitize() +
		" WHERE " + where + " ORDER BY " + order
	rows, err := tx.Query(ctx, q, org)
	if err != nil {
		return nil, ErrTransferRows
	}
	defer rows.Close()
	out := []T{}
	for rows.Next() {
		if int64(len(out)) >= scopedtransfer.MaxTableRows {
			return nil, ErrTransferRows
		}
		var row T
		if err := rows.Scan(P(&row).scanDest()...); err != nil {
			return nil, ErrTransferRows
		}
		out = append(out, row)
	}
	if rows.Err() != nil {
		return nil, ErrTransferRows
	}
	return out, nil
}

// insertTable inserts rows with an explicit column list and bind parameters;
// there is no upsert, so an existing key fails the whole transaction.
func insertTable[T argRow](ctx context.Context, tx pgx.Tx, table string, cols []string, rows []T) error {
	if len(rows) == 0 {
		return nil
	}
	quoted := make([]string, len(cols))
	marks := make([]string, len(cols))
	for i, c := range cols {
		quoted[i] = pgx.Identifier{c}.Sanitize()
		marks[i] = "$" + strconv.Itoa(i+1)
	}
	q := "INSERT INTO " + pgx.Identifier{table}.Sanitize() + " (" + strings.Join(quoted, ", ") +
		") VALUES (" + strings.Join(marks, ", ") + ")"
	batch := &pgx.Batch{}
	for _, r := range rows {
		batch.Queue(q, r.args()...)
	}
	res := tx.SendBatch(ctx, batch)
	for range rows {
		if _, err := res.Exec(); err != nil {
			_ = res.Close()
			return ErrTransferRows
		}
	}
	if res.Close() != nil {
		return ErrTransferRows
	}
	return nil
}

// ReadTransferRows reads every copied table of org in one read-only
// repeatable-read transaction. It writes nothing. Whether the rows are a
// closed copy is decided by the transferverify package, not here.
func ReadTransferRows(ctx context.Context, db *pgxpool.Pool, org uuid.UUID) (*TransferRows, error) {
	tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, ErrTransferRows
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := readTransferRows(ctx, tx, org)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, ErrTransferRows
	}
	return rows, nil
}
