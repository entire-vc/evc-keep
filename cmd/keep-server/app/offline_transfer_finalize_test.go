package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/entire-vc/evc-keep/internal/testutil/transferfixture"
	"github.com/entire-vc/evc-keep/internal/transferverify"
	"github.com/google/uuid"
)

func newFinalizeFx(t *testing.T, mutate func(*transferCheckpoint)) (dir string, org uuid.UUID, after func(string)) {
	t.Helper()
	ctx := context.Background()
	dsn := pgscratch.New(t, nil)
	pool := scratchPoolAt(t, ctx, dsn)
	org = uuid.New()
	transferfixture.Seed(t, ctx, pool, org, strings.ToUpper(strings.ReplaceAll(uuid.NewString(), "-", ""))[:7]+"A")
	t.Setenv("KEEP_DATABASE_URL", dsn)
	plan, inv, rows, reason, ok := readSource(ctx, org)
	if !ok {
		t.Fatalf("source read: %s", reason)
	}
	digest, _ := transferverify.ClosureDigest(rows)
	cp := transferCheckpoint{
		Version: 1, OrgID: org.String(), WorkspaceID: inv.WorkspaceID, TransferID: uuid.NewString(),
		SnapshotID: uuid.NewString(), SourceID: uuid.NewString(), TargetID: uuid.NewString(),
		Schema: inv.SchemaVersion, ClosureDigest: digest, AuditHead: auditHeadOf(rows), Rows: plan.RowCount(),
		CiphertextChecksum: pinHex,
	}
	if mutate != nil {
		mutate(&cp)
	}
	raw, _ := json.Marshal(cp)
	dir = carrierDir(t)
	if err := os.WriteFile(filepath.Join(dir, "cp"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, org, func(q string) {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatal("mutate source")
		}
	}
}

func finalizeRun(d string, org uuid.UUID, freeze string) (int, string, string) {
	return runTransfer("finalize", "--org", org.String(), "--checkpoint", filepath.Join(d, "cp"),
		"--approval", filepath.Join(d, "ap"), "--quiescence-confirmed", freeze)
}

func TestTransferFinalizeApprovesAnUnchangedSource(t *testing.T) {
	d, org, _ := newFinalizeFx(t, nil)
	code, out, errs := finalizeRun(d, org, "true")
	if code != 0 || !strings.Contains(out, "outcome=final") {
		t.Fatalf("%d %q %q", code, out, errs)
	}
	raw, err := os.ReadFile(filepath.Join(d, "ap")) //nolint:gosec // G304: test path
	if err != nil || !strings.Contains(string(raw), `"status":"final"`) || !strings.Contains(string(raw), `"quiescence":"asserted"`) {
		t.Fatalf("approval: %q %v", raw, err)
	}
	if fi, _ := os.Stat(filepath.Join(d, "ap")); fi.Mode().Perm() != 0o600 {
		t.Fatal("approval is not 0600")
	}
}

func TestTransferFinalizeRefusesAChangedSource(t *testing.T) {
	d, org, change := newFinalizeFx(t, nil)
	change("UPDATE users SET email = email || '.changed'")
	code, _, errs := finalizeRun(d, org, "true")
	if code == 0 || !strings.Contains(errs, "reason=source_changed") {
		t.Fatalf("a write after export must refuse: %d %q", code, errs)
	}
	if _, err := os.Stat(filepath.Join(d, "ap")); err == nil {
		t.Fatal("refused finalize wrote an approval")
	}
}

func TestTransferFinalizeRefusesAWrongSchemaOrForeignOrg(t *testing.T) {
	d, org, _ := newFinalizeFx(t, func(c *transferCheckpoint) { c.Schema++ })
	if code, _, errs := finalizeRun(d, org, "true"); code == 0 || !strings.Contains(errs, "reason=source_changed") {
		t.Fatalf("schema: %d %q", code, errs)
	}
	d, org, _ = newFinalizeFx(t, nil)
	raw, err := os.ReadFile(filepath.Join(d, "cp")) //nolint:gosec // G304: test path
	if err != nil {
		t.Fatal(err)
	}
	extra := append(raw[:len(raw)-1:len(raw)-1], []byte(`,"extra":1}`)...)
	if err := os.WriteFile(filepath.Join(d, "cp"), extra, 0o600); err != nil { //nolint:gosec // G703: test path
		t.Fatal(err)
	}
	if code, _, errs := finalizeRun(d, org, "true"); code == 0 || !strings.Contains(errs, "reason=checkpoint") {
		t.Fatalf("unknown checkpoint field: %d %q", code, errs)
	}
	d, org, _ = newFinalizeFx(t, func(c *transferCheckpoint) { c.SourceID = strings.ToUpper(abcUID) })
	if code, _, errs := finalizeRun(d, org, "true"); code == 0 || !strings.Contains(errs, "reason=checkpoint") {
		t.Fatalf("non-canonical id in checkpoint: %d %q", code, errs)
	}
	d, _, _ = newFinalizeFx(t, nil)
	if code, _, errs := finalizeRun(d, uuid.New(), "true"); code == 0 || !strings.Contains(errs, "reason=checkpoint") {
		t.Fatalf("foreign org: %d %q", code, errs)
	}
	d, org, _ = newFinalizeFx(t, nil)
	if code, _, errs := finalizeRun(d, org, "true"); code != 0 {
		t.Fatalf("positive control: %d %q", code, errs)
	}
	if code, _, errs := finalizeRun(d, org, "true"); code == 0 || !strings.Contains(errs, "reason=carrier_exists") {
		t.Fatalf("an approval must not be overwritten: %d %q", code, errs)
	}
}
