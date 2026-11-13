package app

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"

	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/builtin/orgpki"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/transfercarrier"
	"github.com/google/uuid"
)

// transferProtocol is the one wire protocol both operators pin.
const transferProtocol = "keep-offline-transfer/1"

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// transferImport opens a sealed bundle on the target and lands it in one
// transaction. Every identity and both digests are given by the operator out
// of band; nothing is trusted from the bundle. The database and the target
// root come from the environment (KEEP_DATABASE_URL, KEEP_ROOT_KEY_FILE,
// KEEP_ROOT_KEY_ID), never from arguments.
func transferImport(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("offline-transfer import", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	s := func(n string) *string { return fs.String(n, "", "") }
	bundle, privF, pubF, apF := s("bundle"), s("private-file"), s("public-file"), s("approval")
	transfer, source, target, snapshot, org, workspace := s("transfer"), s("source"), s("target"), s("snapshot"), s("org"), s("workspace")
	schema := fs.Uint64("schema", 0, "")
	sumPin, fpPin, apPin := s("expect-checksum"), s("expect-recipient-fingerprint"), s("expect-approval-checksum")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *schema == 0 {
		_, _ = fmt.Fprintln(stderr, offlineTransferUsage)
		return 2
	}
	for _, v := range []*string{bundle, privF, pubF, apF, transfer, source, target, snapshot, org, workspace, sumPin, fpPin, apPin} {
		if *v == "" {
			_, _ = fmt.Fprintln(stderr, offlineTransferUsage)
			return 2
		}
	}
	const op = "import"
	if !hex64.MatchString(*sumPin) || !hex64.MatchString(*fpPin) || !hex64.MatchString(*apPin) {
		return transferFail(stderr, op, "pin")
	}
	ids := map[string]uuid.UUID{}
	for _, v := range []*string{transfer, source, target, snapshot, org, workspace} {
		id, err := uuid.Parse(*v)
		if err != nil || id.String() != *v {
			return transferFail(stderr, op, "identity")
		}
		ids[*v] = id
	}
	sealed, err := transfercarrier.Read(*bundle, builtin.MaxTransferBundle)
	if err != nil {
		return transferFail(stderr, op, carrierReason(err))
	}
	sum := sha256.Sum256(sealed)
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(*sumPin)) != 1 {
		return transferFail(stderr, op, "checksum")
	}
	pub, err := transfercarrier.Read(*pubF, 1<<10)
	if err != nil {
		return transferFail(stderr, op, carrierReason(err))
	}
	fp := sha256.Sum256(pub)
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(fp[:])), []byte(*fpPin)) != 1 {
		return transferFail(stderr, op, "recipient")
	}
	priv, err := transfercarrier.Read(*privF, 1<<10)
	if err != nil {
		return transferFail(stderr, op, carrierReason(err))
	}
	defer clear(priv)
	keyID := os.Getenv("KEEP_ROOT_KEY_ID")
	if keyID == "" {
		keyID = "local-v1"
	}
	root, err := builtin.OpenTransferRoot(os.Getenv("KEEP_ROOT_KEY_FILE"), keyID)
	if err != nil {
		return transferFail(stderr, op, "root")
	}
	tc := builtin.TransferContext{
		Protocol: transferProtocol, Transfer: *transfer, Source: *source, Target: *target,
		Snapshot: *snapshot, Org: *org, Workspace: *workspace, Schema: *schema, RecipientPub: pub,
	}
	m, rows, err := builtin.ReadTransferBundle(priv, tc, sealed, root)
	if err != nil {
		return transferFail(stderr, op, "bundle")
	}
	// The source operator's final approval must exist and describe exactly this
	// bundle before any effect: finalize writes it only after the final
	// compare with the freeze asserted, so an import without it, or with one
	// for a different export, skips that check.
	apRaw, err := transfercarrier.Read(*apF, maxCheckpointBytes)
	if err != nil {
		return transferFail(stderr, op, carrierReason(err))
	}
	if reason := verifyApproval(apRaw, *apPin, approvalBinding{
		Transfer: *transfer, Source: *source, Target: *target, Snapshot: *snapshot, Org: *org,
		Workspace: *workspace, Schema: *schema, Checksum: *sumPin,
		ClosureDigest: m.ClosureDigest, AuditHead: auditHeadOf(rows),
	}); reason != "" {
		return transferFail(stderr, op, reason)
	}
	// The CA must open under this installation's own root before any row is
	// written; nothing is regenerated or repaired here.
	if orgpki.AuthenticateTransferCA(ctx, ids[*org], rows, root) != nil {
		return transferFail(stderr, op, "pki")
	}
	dsn := os.Getenv("KEEP_DATABASE_URL")
	if dsn == "" {
		return transferFail(stderr, op, "database")
	}
	pool, err := store.Open(ctx, dsn)
	if err != nil {
		return transferFail(stderr, op, "database")
	}
	defer pool.Close()
	rec, err := importTransfer(ctx, pool, obs.New(io.Discard), m, rows, transferImportPins{
		CiphertextChecksum: *sumPin, RecipientFingerprint: *fpPin, SourceID: ids[*source], TargetID: ids[*target],
	})
	if err != nil {
		reason := "import"
		if e, ok := err.(errTransferImport); ok {
			reason = e.Reason
		}
		return transferFail(stderr, op, reason)
	}
	// The import is committed; the recipient key and the bundle together open
	// every KEK without the target root, so the key is destroyed now.
	keyState := "destroyed"
	if transfercarrier.Destroy(*privF) != nil {
		keyState = "retained"
	}
	_, _ = fmt.Fprintf(stdout, "offline-transfer import: outcome=%s transfer=%s source=%s target=%s recipient_fingerprint=%s org=%s snapshot=%s rows=%d ciphertext_checksum=%s audit_head_before=%s audit_head_after=%s recipient_key=%s\n",
		rec.Outcome, rec.TransferID, rec.SourceID, rec.TargetID, rec.RecipientFingerprint, rec.OrgID, rec.SnapshotID, rec.Rows, rec.CiphertextChecksum, rec.AuditHeadBefore, rec.AuditHeadAfter, keyState)
	return 0
}

// approvalBinding is everything the importer already holds independently of
// the approval file: the operator's pins and what the opened bundle contains.
type approvalBinding struct {
	Transfer, Source, Target, Snapshot, Org, Workspace string
	Schema                                             uint64
	Checksum, ClosureDigest, AuditHead                 string
}

// approvalMatches reports whether raw is a final, freeze-asserted approval for
// exactly this transfer: every identity, the schema, the carrier checksum, the
// closure digest and the source audit head must equal the binding.
func approvalMatches(raw []byte, b approvalBinding) bool {
	a, ok := parseApproval(raw)
	if !ok {
		return false
	}
	return a.TransferID == b.Transfer && a.SourceID == b.Source && a.TargetID == b.Target &&
		a.SnapshotID == b.Snapshot && a.OrgID == b.Org && a.WorkspaceID == b.Workspace &&
		a.Schema > 0 && uint64(a.Schema) == b.Schema && //nolint:gosec // G115: checked positive
		a.CiphertextChecksum == b.Checksum && a.ClosureDigest == b.ClosureDigest && a.AuditHead == b.AuditHead
}

// verifyApproval is the one decision on the approval carrier: raw (read once,
// the same bytes that are then parsed) must hash to the pin the source
// operator handed over after finalize, and describe exactly this transfer.
// The pin comes only from the operator's own channel, never from a carrier. A reason is returned for a refusal, "" for acceptance.
func verifyApproval(raw []byte, pin string, b approvalBinding) string {
	sum := sha256.Sum256(raw)
	if !hex64.MatchString(pin) || subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(pin)) != 1 {
		return "approval_pin"
	}
	if !approvalMatches(raw, b) {
		return "approval"
	}
	return ""
}
