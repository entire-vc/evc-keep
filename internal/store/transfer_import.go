package store

import (
	"context"
	"errors"
	"sort"
	"strconv"

	"github.com/entire-vc/evc-keep/internal/scopedtransfer"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrTransferImport is the only error the import primitives return. It
// carries no driver text, identifier or row content.
var ErrTransferImport = errors.New("store: transfer import refused")

// ErrTransferTargetNotEmpty reports that the target database already holds
// application state. It is a distinct closed class so the caller can tell a
// refused target from an I/O failure.
var ErrTransferTargetNotEmpty = errors.New("store: transfer target is not empty")

// LockTransferTarget takes ACCESS EXCLUSIVE locks on every non-node-local
// registry table in name order (a deterministic order, so two importers
// cannot deadlock) and a share-row-exclusive lock on the ledger. Held until
// the transaction ends, they make the emptiness check that follows true at
// commit time: no writer can add a row in between.
func LockTransferTarget(ctx context.Context, tx pgx.Tx) error {
	ps := scopedtransfer.TablePolicies()
	sort.Slice(ps, func(i, j int) bool { return ps[i].Name < ps[j].Name })
	for _, p := range ps {
		mode := "ACCESS EXCLUSIVE"
		if p.Disposition == scopedtransfer.NodeLocal {
			mode = "SHARE ROW EXCLUSIVE"
		}
		if _, err := tx.Exec(ctx, "LOCK TABLE "+pgx.Identifier{p.Name}.Sanitize()+" IN "+mode+" MODE"); err != nil {
			return ErrTransferImport
		}
	}
	return nil
}

// RequireEmptyTransferTarget checks, inside the locked transaction, that
// every registry table except the node-local ledger has zero rows in the
// whole database (not only for the imported organization).
func RequireEmptyTransferTarget(ctx context.Context, tx pgx.Tx) error {
	for _, p := range scopedtransfer.TablePolicies() {
		if p.Disposition == scopedtransfer.NodeLocal {
			continue
		}
		var n int64
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+pgx.Identifier{p.Name}.Sanitize()).Scan(&n); err != nil {
			return ErrTransferImport
		}
		if n != 0 {
			return ErrTransferTargetNotEmpty
		}
	}
	return nil
}

// InsertTransferRows inserts the whole snapshot in foreign-key order with
// explicit columns, never upserting.
func InsertTransferRows(ctx context.Context, tx pgx.Tx, r *TransferRows) error {
	if r == nil {
		return ErrTransferImport
	}
	if err := insertTransferRows(ctx, tx, r); err != nil {
		return ErrTransferImport
	}
	return nil
}

// RestartSealSeq moves the secret_versions sequence so the next allocation
// is strictly greater than maxSeq. It runs in the import transaction: a
// rollback restores the sequence definition too, because ALTER SEQUENCE is
// transactional.
func RestartSealSeq(ctx context.Context, tx pgx.Tx, maxSeq int64) error {
	const ceiling = int64(1)<<62 - 1
	if maxSeq < 0 || maxSeq >= ceiling {
		return ErrTransferImport
	}
	if _, err := tx.Exec(ctx, "ALTER SEQUENCE secret_versions_seal_seq_seq RESTART WITH "+strconv.FormatInt(maxSeq+1, 10)); err != nil {
		return ErrTransferImport
	}
	return nil
}

// TransferLedgerEntry is the closed record of one consumed transfer.
type TransferLedgerEntry struct {
	TransferID           uuid.UUID
	RecipientFingerprint string
	OrgID                uuid.UUID
	SourceID             uuid.UUID
	SnapshotID           uuid.UUID
	CiphertextChecksum   string
	AuditHead            string
}

// InsertTransferLedger records the consumption. It is INSERT only; a repeated
// transfer or recipient hits the primary key or unique constraint and fails
// the transaction.
func InsertTransferLedger(ctx context.Context, tx pgx.Tx, e TransferLedgerEntry) error {
	_, err := tx.Exec(ctx, `INSERT INTO scoped_transfer_ledger
		(transfer_id, recipient_fingerprint, org_id, source_id, snapshot_id, ciphertext_checksum, audit_head)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		e.TransferID, e.RecipientFingerprint, e.OrgID, e.SourceID, e.SnapshotID, e.CiphertextChecksum, e.AuditHead)
	if err != nil {
		return ErrTransferImport
	}
	return nil
}

// ReadAuditHeadTx returns the organization's current audit chain head hash
// inside tx.
func ReadAuditHeadTx(ctx context.Context, tx pgx.Tx, org uuid.UUID) (string, error) {
	var h string
	if err := tx.QueryRow(ctx, `SELECT hash FROM audit_chain_heads WHERE org_id = $1`, org).Scan(&h); err != nil {
		return "", ErrTransferImport
	}
	return h, nil
}
