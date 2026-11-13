package app

// The target side of keep-server offline-transfer import. Everything that
// can be refused without touching the database is refused first (closure,
// counts); then one transaction takes the locks, proves the target empty,
// inserts the snapshot, restarts the seal sequence, records the ledger row
// and appends transfer.imported, and only after reading the result back and
// verifying it does it commit. Any failure leaves the target as it was.

import (
	"context"
	"errors"
	"log/slog"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/scopedtransfer"
	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/transferverify"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// errTransferImport is the only error class the import returns; the cause is
// a closed reason code, never a row, key or driver text.
type errTransferImport struct{ Reason string }

func (e errTransferImport) Error() string { return "offline-transfer import refused: " + e.Reason }

// IsTargetNotEmpty reports the refusal an operator most often meets.
func (e errTransferImport) IsTargetNotEmpty() bool { return e.Reason == "target_not_empty" }

// transferImportPins are the independent expectations the importer holds
// before it trusts a bundle: nothing here is read from the bundle itself.
type transferImportPins struct {
	CiphertextChecksum   string // 64 hex, of the sealed carrier
	RecipientFingerprint string // 64 hex, of the recipient public key
	SourceID             uuid.UUID
	TargetID             uuid.UUID
}

// transferReceipt is the closed result of one import: identities, counts and
// the audit head. No row value, root id or DSN.
type transferReceipt struct {
	Outcome              string
	TransferID           string
	SourceID             string
	TargetID             string
	RecipientFingerprint string
	OrgID                string
	SnapshotID           string
	Rows                 int64
	CiphertextChecksum   string
	AuditHeadBefore      string
	AuditHeadAfter       string
}

func refuse(reason string) error { return errTransferImport{Reason: reason} }

// importTransfer imports already opened and decoded rows. The caller has
// opened the bundle under the pinned context; this function owns closure,
// counts, the transaction and the read-back.
func importTransfer(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger, m scopedtransfer.Manifest, rows *store.TransferRows, pins transferImportPins) (transferReceipt, error) {
	org, err := uuid.Parse(m.OrgID)
	if err != nil || rows == nil {
		return transferReceipt{}, refuse("manifest")
	}
	transferID, err1 := uuid.Parse(m.TransferID)
	snapshotID, err2 := uuid.Parse(m.SnapshotID)
	if err1 != nil || err2 != nil || pins.SourceID == uuid.Nil {
		return transferReceipt{}, refuse("manifest")
	}
	if err := transferverify.Closure(rows, org); err != nil {
		return transferReceipt{}, refuse("closure")
	}
	// The canonical workspace must be the one the manifest pins; Closure only
	// proves the rows belong to the organization. Profile 1: the one copied
	// tenancy workspace. Profile 2: no tenancy workspace, and the workspace of
	// the one copied Mesh installation. The profile is the manifest's, never
	// guessed from the rows.
	if !workspaceMatchesProfile(m, rows) {
		return transferReceipt{}, refuse("manifest")
	}
	if !countsMatch(m, rows.CopiedCounts()) {
		return transferReceipt{}, refuse("counts")
	}
	if d, err := transferverify.ClosureDigest(rows); err != nil || d != m.ClosureDigest {
		return transferReceipt{}, refuse("digest")
	}
	headBefore := audit.GenesisHash
	if len(rows.AuditChainHeads) == 1 {
		headBefore = rows.AuditChainHeads[0].Hash
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return transferReceipt{}, refuse("database")
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	if err := store.LockTransferTarget(ctx, tx); err != nil {
		return transferReceipt{}, refuse("database")
	}
	if err := store.RequireTransferTargetSchema(ctx, tx); err != nil {
		return transferReceipt{}, refuse("profile")
	}
	if err := store.RequireEmptyTransferTarget(ctx, tx); err != nil {
		if errors.Is(err, store.ErrTransferTargetNotEmpty) {
			return transferReceipt{}, refuse("target_not_empty")
		}
		return transferReceipt{}, refuse("database")
	}
	if err := store.InsertTransferRows(ctx, tx, rows); err != nil {
		return transferReceipt{}, refuse("insert")
	}
	if err := store.RestartSealSeq(ctx, tx, rows.MaxSealSeq()); err != nil {
		return transferReceipt{}, refuse("sequence")
	}
	if _, err := audit.NewJournal(pool).WithLogger(logger).AppendTx(ctx, tx, audit.Record{
		OrgID:  m.OrgID,
		Scope:  "org:" + m.OrgID,
		Actor:  audit.Actor{Type: audit.ActorSystem, ID: "keep-server-offline-transfer", Via: audit.ViaCLI},
		Intent: audit.Intent{Reason: audit.NewReason("transfer " + m.TransferID + " " + m.ClosureDigest)},
		Action: audit.ActionTransferImported,
		Result: audit.Result{Status: audit.StatusOK},
	}); err != nil {
		return transferReceipt{}, refuse("audit")
	}

	// The ledger records the head the import leaves behind (after
	// transfer.imported), read in this transaction; the ledger is immutable.
	headAfter, err := store.ReadAuditHeadTx(ctx, tx, org)
	if err != nil {
		return transferReceipt{}, refuse("audit")
	}
	if err := store.InsertTransferLedger(ctx, tx, store.TransferLedgerEntry{
		TransferID: transferID, RecipientFingerprint: pins.RecipientFingerprint, OrgID: org,
		SourceID: pins.SourceID, SnapshotID: snapshotID,
		CiphertextChecksum: pins.CiphertextChecksum, AuditHead: headAfter,
	}); err != nil {
		return transferReceipt{}, refuse("ledger")
	}
	after, err := store.ReadTransferRowsTx(ctx, tx, org)
	if err != nil {
		return transferReceipt{}, refuse("readback")
	}
	if err := verifyReadBack(after, rows, org); err != nil {
		return transferReceipt{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return transferReceipt{}, refuse("commit")
	}
	var total int64
	for _, n := range rows.CopiedCounts() {
		total += n
	}
	return transferReceipt{
		Outcome: "imported", TransferID: m.TransferID, SourceID: pins.SourceID.String(),
		TargetID: pins.TargetID.String(), RecipientFingerprint: pins.RecipientFingerprint, OrgID: m.OrgID, SnapshotID: m.SnapshotID,
		Rows: total, CiphertextChecksum: pins.CiphertextChecksum,
		AuditHeadBefore: headBefore, AuditHeadAfter: after.AuditChainHeads[0].Hash,
	}, nil
}

// countsMatch compares the manifest with the rows: every copied table must
// match its declared count, and every other registry table must declare 0.
func countsMatch(m scopedtransfer.Manifest, got map[string]int64) bool {
	for _, t := range m.Tables {
		if got[t.Name] != t.Rows {
			return false
		}
	}
	return true
}

// verifyReadBack proves, inside the transaction and before commit, that the
// database now holds exactly the snapshot plus the one transfer.imported
// record, as a closed copy with a verifying audit chain (Closure refuses a
// missing or repeated chain head).
func verifyReadBack(after, sent *store.TransferRows, org uuid.UUID) error {
	want := sent.CopiedCounts()
	want["audit_records"]++
	for name, n := range after.CopiedCounts() {
		if want[name] != n {
			return refuse("readback")
		}
	}
	if err := transferverify.Closure(after, org); err != nil {
		return refuse("readback")
	}
	// Every copied value must read back unchanged: the digest of the target
	// rows, less the one appended import record and its chain head, must equal
	// the digest of what was sent. Counts and closure alone would miss a
	// changed value.
	if len(after.AuditRecords) != len(sent.AuditRecords)+1 {
		return refuse("readback")
	}
	base := *after
	base.AuditRecords = after.AuditRecords[:len(sent.AuditRecords)]
	base.AuditChainHeads = sent.AuditChainHeads
	got, err := transferverify.ClosureDigest(&base)
	if err != nil {
		return refuse("readback")
	}
	if want, err := transferverify.ClosureDigest(sent); err != nil || got != want {
		return refuse("readback")
	}
	return nil
}

// workspaceMatchesProfile reports whether the copied rows have the workspace
// shape the manifest's profile requires and pin the manifest's workspace.
func workspaceMatchesProfile(m scopedtransfer.Manifest, rows *store.TransferRows) bool {
	switch m.ProfileVersion {
	case scopedtransfer.ProfileVersion:
		return len(rows.Workspaces) == 1 && rows.Workspaces[0].ID.String() == m.WorkspaceID
	case scopedtransfer.ProfileVersionStoreMode:
		return len(rows.Workspaces) == 0 && len(rows.Projects) == 0 &&
			len(rows.MeshInstallations) == 1 && rows.MeshInstallations[0].Mode == "store" &&
			rows.MeshInstallations[0].WorkspaceID.String() == m.WorkspaceID
	}
	return false
}
