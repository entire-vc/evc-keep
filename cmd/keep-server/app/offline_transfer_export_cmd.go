package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/builtin/orgpki"
	"github.com/entire-vc/evc-keep/internal/scopedtransfer"
	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/transfercarrier"
	"github.com/entire-vc/evc-keep/internal/transferverify"
	"github.com/google/uuid"
)

// transferCheckpoint is the closed metadata record of one export. It holds
// identities, counts and digests only: no row, key or path. finalize compares
// it with a fresh read of the source, so any write after the export shows.
type transferCheckpoint struct {
	Version            int    `json:"version"`
	OrgID              string `json:"org_id"`
	WorkspaceID        string `json:"workspace_id"`
	TransferID         string `json:"transfer_id"`
	SnapshotID         string `json:"snapshot_id"`
	SourceID           string `json:"source_id"`
	TargetID           string `json:"target_id"`
	Schema             int64  `json:"schema"`
	ClosureDigest      string `json:"closure_digest"`
	AuditHead          string `json:"audit_head"`
	Rows               int64  `json:"rows"`
	CiphertextChecksum string `json:"ciphertext_checksum"`
}

// transferApproval is the checkpoint plus the operator's freeze assertion,
// written only after the final compare succeeded.
type transferApproval struct {
	transferCheckpoint
	Quiescence string `json:"quiescence"`
	Status     string `json:"status"`
}

const maxCheckpointBytes = 16 << 10

func parseCheckpoint(raw []byte) (transferCheckpoint, bool) {
	var c transferCheckpoint
	dec := json.NewDecoder(bytes.NewReader(raw))
	// The byte comparison with the canonical re-encoding below is what
	// rejects unknown, duplicate or reordered fields.
	if dec.Decode(&c) != nil || c.Version != 1 {
		return c, false
	}
	back, err := json.Marshal(c)
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), back) {
		return c, false
	}
	return c, validCheckpoint(c)
}

func validCheckpoint(c transferCheckpoint) bool {
	for _, id := range []string{c.OrgID, c.WorkspaceID, c.TransferID, c.SnapshotID, c.SourceID, c.TargetID} {
		if u, err := uuid.Parse(id); err != nil || u.String() != id {
			return false
		}
	}
	return c.Schema > 0 && c.Rows >= 0 && len(c.ClosureDigest) == 71 && hex64.MatchString(c.CiphertextChecksum) && c.AuditHead != ""
}

// parseApproval decodes the finalize output under the same strictness as the
// checkpoint: closed fields, canonical bytes, and only a final approval with
// the freeze asserted.
func parseApproval(raw []byte) (transferApproval, bool) {
	var a transferApproval
	if json.NewDecoder(bytes.NewReader(raw)).Decode(&a) != nil || a.Version != 1 {
		return a, false
	}
	back, err := json.Marshal(a)
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), back) {
		return a, false
	}
	return a, validCheckpoint(a.transferCheckpoint) && a.Status == "final" && a.Quiescence == "asserted"
}

// readSource reads one repeatable-read snapshot of the org and returns the
// closed rows with the metadata that identifies them. It writes nothing.
func readSource(ctx context.Context, org uuid.UUID) (scopedtransfer.Plan, scopedtransfer.Inventory, *store.TransferRows, string, bool) {
	var zeroP scopedtransfer.Plan
	dsn := os.Getenv("KEEP_DATABASE_URL")
	if dsn == "" {
		return zeroP, scopedtransfer.Inventory{}, nil, "database", false
	}
	pool, err := store.Open(ctx, dsn)
	if err != nil {
		return zeroP, scopedtransfer.Inventory{}, nil, "database", false
	}
	defer pool.Close()
	var plan scopedtransfer.Plan
	errRefused := errors.New("profile")
	inv, rows, err := store.ReadTransferSource(ctx, pool, org, func(in scopedtransfer.Inventory) error {
		p, err := scopedtransfer.PlanSnapshot(in)
		if err != nil {
			return errRefused
		}
		plan = p
		return nil
	})
	if errors.Is(err, errRefused) {
		return zeroP, inv, nil, "profile", false
	}
	if err != nil {
		return zeroP, inv, nil, "database", false
	}
	if transferverify.Closure(rows, org) != nil {
		return zeroP, inv, nil, "closure", false
	}
	return plan, inv, rows, "", true
}

func auditHeadOf(rows *store.TransferRows) string {
	if len(rows.AuditChainHeads) == 1 {
		return rows.AuditChainHeads[0].Hash
	}
	return "genesis"
}

func transferExport(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("offline-transfer export", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	s := func(n string) *string { return fs.String(n, "", "") }
	org, workspace, transfer, source, target, snapshot := s("org"), s("workspace"), s("transfer"), s("source"), s("target"), s("snapshot")
	pubF, fpPin, bundleF, cpF := s("recipient-public-file"), s("expect-recipient-fingerprint"), s("bundle"), s("checkpoint")
	schema := fs.Uint64("schema", 0, "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *schema == 0 {
		_, _ = fmt.Fprintln(stderr, offlineTransferUsage)
		return 2
	}
	for _, v := range []*string{org, workspace, transfer, source, target, snapshot, pubF, fpPin, bundleF, cpF} {
		if *v == "" {
			_, _ = fmt.Fprintln(stderr, offlineTransferUsage)
			return 2
		}
	}
	const op = "export"
	if !hex64.MatchString(*fpPin) {
		return transferFail(stderr, op, "pin")
	}
	ids := map[string]uuid.UUID{}
	for _, v := range []*string{org, workspace, transfer, source, target, snapshot} {
		id, err := uuid.Parse(*v)
		if err != nil || id.String() != *v {
			return transferFail(stderr, op, "identity")
		}
		ids[*v] = id
	}
	pub, err := transfercarrier.Read(*pubF, 1<<10)
	if err != nil {
		return transferFail(stderr, op, carrierReason(err))
	}
	fp := sha256.Sum256(pub)
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(fp[:])), []byte(*fpPin)) != 1 {
		return transferFail(stderr, op, "recipient")
	}
	keyID := os.Getenv("KEEP_ROOT_KEY_ID")
	if keyID == "" {
		keyID = "local-v1"
	}
	root, err := builtin.OpenTransferRoot(os.Getenv("KEEP_ROOT_KEY_FILE"), keyID)
	if err != nil {
		return transferFail(stderr, op, "root")
	}
	plan, inv, rows, reason, ok := readSource(ctx, ids[*org])
	if !ok {
		return transferFail(stderr, op, reason)
	}
	if inv.WorkspaceID != *workspace || uint64(inv.SchemaVersion) != *schema { //nolint:gosec // G115: SchemaVersion is a positive goose version
		return transferFail(stderr, op, "pin")
	}
	// The CA must already open under the source root: nothing unauthentic is
	// exported, and nothing is regenerated.
	if orgpki.AuthenticateTransferCA(ctx, ids[*org], rows, root) != nil {
		return transferFail(stderr, op, "pki")
	}
	digest, err := transferverify.ClosureDigest(rows)
	if err != nil {
		return transferFail(stderr, op, "closure")
	}
	m := scopedtransfer.Manifest{
		Version: scopedtransfer.ManifestVersion, ProfileVersion: plan.ProfileVersion(),
		TransferID: *transfer, OrgID: *org, WorkspaceID: *workspace, SchemaVersion: inv.SchemaVersion,
		MigrationSetID: inv.MigrationSetID, RecipientID: *target, SnapshotID: *snapshot,
		ClosureDigest: digest, Tables: plan.TableCounts(),
	}
	if !countsMatch(m, rows.CopiedCounts()) {
		return transferFail(stderr, op, "counts")
	}
	tc := builtin.TransferContext{
		Protocol: transferProtocol, Transfer: *transfer, Source: *source, Target: *target,
		Snapshot: *snapshot, Org: *org, Workspace: *workspace, Schema: *schema, RecipientPub: pub,
	}
	sealed, err := builtin.BuildTransferBundle(pub, tc, m, rows, root)
	if err != nil {
		return transferFail(stderr, op, "bundle")
	}
	sum := sha256.Sum256(sealed)
	cp := transferCheckpoint{
		Version: 1, OrgID: *org, WorkspaceID: *workspace, TransferID: *transfer, SnapshotID: *snapshot,
		SourceID: *source, TargetID: *target, Schema: inv.SchemaVersion, ClosureDigest: digest,
		AuditHead: auditHeadOf(rows), Rows: plan.RowCount(), CiphertextChecksum: hex.EncodeToString(sum[:]),
	}
	raw, err := json.Marshal(cp)
	if err != nil {
		return transferFail(stderr, op, "checkpoint")
	}
	if err := transfercarrier.Create(*bundleF, sealed); err != nil {
		return transferFail(stderr, op, carrierReason(err))
	}
	if err := transfercarrier.Create(*cpF, raw); err != nil {
		_ = os.Remove(*bundleF)
		return transferFail(stderr, op, carrierReason(err))
	}
	_, _ = fmt.Fprintf(stdout, "offline-transfer export: outcome=exported transfer=%s org=%s snapshot=%s rows=%d closure_digest=%s audit_head=%s ciphertext_checksum=%s\n",
		cp.TransferID, cp.OrgID, cp.SnapshotID, cp.Rows, cp.ClosureDigest, cp.AuditHead, cp.CiphertextChecksum)
	return 0
}

// transferFinalize is the final compare-and-set of the source side: with the
// operator's freeze asserted, it re-reads the source and writes the approval
// only if the rows are exactly those that were exported.
func transferFinalize(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("offline-transfer finalize", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	org, cpF, apF, freeze := fs.String("org", "", ""), fs.String("checkpoint", "", ""), fs.String("approval", "", ""), fs.String("quiescence-confirmed", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *org == "" || *cpF == "" || *apF == "" || *freeze == "" {
		_, _ = fmt.Fprintln(stderr, offlineTransferUsage)
		return 2
	}
	const op = "finalize"
	orgID, err := uuid.Parse(*org)
	if err != nil || orgID.String() != *org {
		return transferFail(stderr, op, "identity")
	}
	if *freeze != "true" {
		return transferFail(stderr, op, "quiescence")
	}
	raw, err := transfercarrier.Read(*cpF, maxCheckpointBytes)
	if err != nil {
		return transferFail(stderr, op, carrierReason(err))
	}
	cp, ok := parseCheckpoint(raw)
	if !ok || cp.OrgID != *org {
		return transferFail(stderr, op, "checkpoint")
	}
	_, inv, rows, reason, ok := readSource(ctx, orgID)
	if !ok {
		return transferFail(stderr, op, reason)
	}
	// The digest covers every copied row, including the audit head, the
	// workspace and the counts; the schema version is the one thing it
	// does not.
	digest, err := transferverify.ClosureDigest(rows)
	if err != nil || digest != cp.ClosureDigest || inv.SchemaVersion != cp.Schema {
		return transferFail(stderr, op, "source_changed")
	}
	out, err := json.Marshal(transferApproval{transferCheckpoint: cp, Quiescence: "asserted", Status: "final"})
	if err != nil {
		return transferFail(stderr, op, "approval")
	}
	if err := transfercarrier.Create(*apF, out); err != nil {
		return transferFail(stderr, op, carrierReason(err))
	}
	// The pin exists only once the source CAS passed and the carrier is
	// written; the operator sends it to the target over its own channel.
	pin := sha256.Sum256(out)
	_, _ = fmt.Fprintf(stdout, "offline-transfer finalize: outcome=final transfer=%s org=%s snapshot=%s rows=%d closure_digest=%s audit_head=%s ciphertext_checksum=%s approval_checksum=%s\n",
		cp.TransferID, cp.OrgID, cp.SnapshotID, cp.Rows, cp.ClosureDigest, cp.AuditHead, cp.CiphertextChecksum, hex.EncodeToString(pin[:]))
	return 0
}
