package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/scopedtransfer"
	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/entire-vc/evc-keep/internal/testutil/transferfixture"
	"github.com/entire-vc/evc-keep/internal/transferverify"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func scratchPool(t *testing.T, ctx context.Context) *pgxpool.Pool {
	t.Helper()
	return scratchPoolAt(t, ctx, pgscratch.New(t, nil))
}

func scratchPoolAt(t *testing.T, ctx context.Context, dsn string) *pgxpool.Pool {
	t.Helper()
	mdb, err := store.OpenMigrationDB(ctx, dsn)
	if err != nil {
		t.Fatal("open migration database")
	}
	p, err := store.NewProvider(mdb)
	if err != nil {
		t.Fatal("migration provider")
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatal("migrate up")
	}
	_ = mdb.Close()
	pool, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal("open")
	}
	t.Cleanup(pool.Close)
	return pool
}

type importFx struct {
	ctx    context.Context
	org    uuid.UUID
	rows   *store.TransferRows
	m      scopedtransfer.Manifest
	pins   transferImportPins
	target *pgxpool.Pool
}

func newImportFx(t *testing.T) importFx { return newImportFxMode(t, false) }

// newImportFxMode builds the fixture for profile 1 (a tenancy workspace) or,
// with storeMode, profile 2: a native Mesh store-mode organization without
// one, whose canonical workspace is its installation's.
func newImportFxMode(t *testing.T, storeMode bool) importFx {
	t.Helper()
	ctx := context.Background()
	src := scratchPool(t, ctx)
	org := uuid.New()
	transferfixture.Seed(t, ctx, src, org, strings.ToUpper(strings.ReplaceAll(uuid.NewString(), "-", ""))[:7]+"A")
	if storeMode {
		transferfixture.DropTenancyWorkspaces(t, ctx, src, org)
	}
	rows, err := store.ReadTransferRows(ctx, src, org)
	if err != nil {
		t.Fatal("read source rows")
	}
	counts := rows.CopiedCounts()
	var tables []scopedtransfer.TableCount
	for _, p := range scopedtransfer.TablePolicies() {
		tables = append(tables, scopedtransfer.TableCount{Name: p.Name, Rows: counts[p.Name]})
	}
	digest, err := transferverify.ClosureDigest(rows)
	if err != nil {
		t.Fatal("digest")
	}
	profile, workspace := scopedtransfer.ProfileVersion, ""
	if storeMode {
		profile, workspace = scopedtransfer.ProfileVersionStoreMode, rows.MeshInstallations[0].WorkspaceID.String()
	} else {
		workspace = rows.Workspaces[0].ID.String()
	}
	m := scopedtransfer.Manifest{
		Version: scopedtransfer.ManifestVersion, ProfileVersion: profile,
		TransferID: uuid.NewString(), OrgID: org.String(), WorkspaceID: workspace,
		SchemaVersion: scopedtransfer.SchemaVersion, MigrationSetID: scopedtransfer.MigrationSetID,
		RecipientID: uuid.NewString(), SnapshotID: uuid.NewString(),
		ClosureDigest: digest, Tables: tables,
	}
	return importFx{
		ctx: ctx, org: org, rows: rows, m: m, target: scratchPool(t, ctx),
		pins: transferImportPins{
			CiphertextChecksum: strings.Repeat("c", 64), RecipientFingerprint: strings.Repeat("d", 64),
			SourceID: uuid.New(),
		},
	}
}

func (f importFx) run() (transferReceipt, error) {
	return importTransfer(f.ctx, f.target, slog.New(slog.NewJSONHandler(io.Discard, nil)), f.m, f.rows, f.pins)
}

func tableRows(t *testing.T, f importFx, table string) int64 {
	t.Helper()
	var n int64
	if err := f.target.QueryRow(f.ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil {
		t.Fatal("count")
	}
	return n
}

func TestImportTransferLandsAClosedCopy(t *testing.T) {
	f := newImportFx(t)
	rc, err := f.run()
	if err != nil || rc.Outcome != "imported" {
		t.Fatalf("positive control failed: %v", err)
	}
	if rc.AuditHeadBefore == rc.AuditHeadAfter || rc.AuditHeadAfter == "" {
		t.Fatal("transfer.imported did not advance the audit head")
	}
	if got := tableRows(t, f, "audit_records"); got != int64(len(f.rows.AuditRecords))+1 {
		t.Fatalf("audit records %d, want source+1", got)
	}
	if got := tableRows(t, f, "scoped_transfer_ledger"); got != 1 {
		t.Fatalf("ledger rows %d", got)
	}
	// The immutable ledger must carry the head AFTER transfer.imported.
	var ledgerHead string
	if err := f.target.QueryRow(f.ctx, `SELECT audit_head FROM scoped_transfer_ledger`).Scan(&ledgerHead); err != nil || ledgerHead != rc.AuditHeadAfter || ledgerHead == rc.AuditHeadBefore {
		t.Fatal("ledger audit_head is not the post-import head")
	}
	var last string
	if err := f.target.QueryRow(f.ctx, `SELECT action FROM audit_records WHERE org_id = $1 ORDER BY org_seq DESC LIMIT 1`, f.org.String()).Scan(&last); err != nil || last != string(audit.ActionTransferImported) {
		t.Fatalf("last audit action %q, want transfer.imported", last)
	}
	after, err := store.ReadTransferRows(f.ctx, f.target, f.org)
	if err != nil {
		t.Fatal("read back")
	}
	if verifyReadBack(after, f.rows, f.org) != nil {
		t.Fatal("read-back verification refused an honest import")
	}
	short := *after
	short.Users = short.Users[1:]
	if verifyReadBack(&short, f.rows, f.org) == nil {
		t.Fatal("read-back verification accepted a missing row")
	}
	if verifyReadBack(f.rows, f.rows, f.org) == nil {
		t.Fatal("read-back verification accepted a copy without the import record")
	}
	// The counts are right but the copy is not closed or has no single head:
	// each of those alone must be refused.
	noHead := *after
	noHead.AuditChainHeads = nil
	twoHeads := *after
	twoHeads.AuditChainHeads = append(append(twoHeads.AuditChainHeads[:0:0], after.AuditChainHeads...), after.AuditChainHeads...)
	foreign := *after
	foreign.Users = append(foreign.Users[:0:0], after.Users...)
	foreign.Users[0].OrgID = uuid.New()
	for name, bad := range map[string]*store.TransferRows{"no head": &noHead, "two heads": &twoHeads, "not closed": &foreign} {
		if verifyReadBack(bad, f.rows, f.org) == nil {
			t.Fatalf("read-back verification accepted a copy with %s", name)
		}
	}
	// Counts, scope, references and the chain are all intact, but a copied
	// value differs from the snapshot (what a target-side trigger could do).
	altered := *after
	altered.Users = append(altered.Users[:0:0], after.Users...)
	altered.Users[0].Email = "altered-" + altered.Users[0].Email
	if verifyReadBack(&altered, f.rows, f.org) == nil {
		t.Fatal("read-back verification accepted an altered copied value")
	}
	tamperedRecord := *after
	tamperedRecord.AuditRecords = append(tamperedRecord.AuditRecords[:0:0], after.AuditRecords...)
	tamperedRecord.AuditRecords[0].Action = tamperedRecord.AuditRecords[0].Action + "x"
	if verifyReadBack(&tamperedRecord, f.rows, f.org) == nil {
		t.Fatal("read-back verification accepted an altered source audit record")
	}
	res, err := audit.Verify(f.ctx, f.target, f.org.String())
	if err != nil || !res.OK {
		t.Fatal("audit chain does not verify after import")
	}
	// The next ordinary record continues the chain.
	if _, err := audit.NewJournal(f.target).Append(f.ctx, audit.Record{
		OrgID: f.org.String(), Scope: "org:" + f.org.String(),
		Actor:  audit.Actor{Type: audit.ActorSystem, ID: "test", Via: audit.ViaCLI},
		Action: audit.ActionOrgBootstrap, Result: audit.Result{Status: audit.StatusOK},
	}); err != nil {
		t.Fatal("append after import failed")
	}
	if res, err := audit.Verify(f.ctx, f.target, f.org.String()); err != nil || !res.OK {
		t.Fatal("chain broken by the record after import")
	}
}

func TestImportTransferRefusalsLeaveTargetEmpty(t *testing.T) {
	f := newImportFx(t)
	if _, err := f.run(); err != nil {
		t.Fatal("setup import failed")
	}
	// A second import into the now non-empty target, and a replay under the
	// same transfer: both refused, and nothing is added.
	before := tableRows(t, f, "audit_records")
	_, err := f.run()
	var e errTransferImport
	if !errors.As(err, &e) || !e.IsTargetNotEmpty() {
		t.Fatalf("second import: want target_not_empty, got %v", err)
	}
	if tableRows(t, f, "audit_records") != before {
		t.Fatal("refused import changed the target")
	}

	cases := map[string]struct {
		reason string
		mutate func(g *importFx)
	}{
		"foreign org user": {"closure", func(g *importFx) { g.rows.Users[0].OrgID = uuid.New() }},
		"count mismatch": {"counts", func(g *importFx) {
			for i := range g.m.Tables {
				if g.m.Tables[i].Name == "users" {
					g.m.Tables[i].Rows++
				}
			}
		}},
		"tampered audit hash": {"closure", func(g *importFx) { g.rows.AuditRecords[0].Hash = strings.Repeat("e", 64) }},
		"edited row":          {"digest", func(g *importFx) { g.rows.Users[0].Email = "edited@example.invalid" }},
		"unknown source":      {"manifest", func(g *importFx) { g.pins.SourceID = uuid.Nil }},
		"nil rows":            {"manifest", func(g *importFx) { g.rows = nil }},
		"other workspace":     {"manifest", func(g *importFx) { g.m.WorkspaceID = uuid.NewString() }},
		"no workspace id":     {"manifest", func(g *importFx) { g.m.WorkspaceID = "" }},
		// Same goose history and embedded migrations, but a column added by hand:
		// only the live catalog check can see it.
		"hand-altered target catalog": {"profile", func(g *importFx) {
			if _, err := g.target.Exec(g.ctx, `ALTER TABLE users ADD COLUMN hand_made_note text`); err != nil {
				t.Fatal("alter the scratch target")
			}
		}},
		"newer target schema": {"profile", func(g *importFx) {
			if _, err := g.target.Exec(g.ctx, `INSERT INTO goose_db_version (version_id, is_applied) VALUES (99999, true)`); err != nil {
				t.Fatal("drift the scratch target")
			}
		}},
	}
	for name, c := range cases {
		g := newImportFx(t)
		c.mutate(&g)
		// The reason is asserted, not just the refusal: the database would
		// refuse several of these later on its own, and the early check must
		// be the one that does.
		if _, err := g.run(); !errors.As(err, &e) || e.Reason != c.reason {
			t.Errorf("%s: want refusal %q, got %v", name, c.reason, err)
		}
		for _, table := range []string{"organizations", "users", "audit_records", "keep_kek", "scoped_transfer_ledger"} {
			if n := tableRows(t, g, table); n != 0 {
				t.Errorf("%s: %s has %d rows after a refusal", name, table, n)
			}
		}
	}
}

func TestImportTransferErrorsDoNotEchoRows(t *testing.T) {
	f := newImportFx(t)
	marker := "leak-marker-" + uuid.NewString()
	f.rows.Users[0].Email = marker
	f.rows.Users[0].OrgID = uuid.New() // forces a closure refusal that sees the row
	_, err := f.run()
	if err == nil {
		t.Fatal("want refusal")
	}
	if s := fmt.Sprintf("%v %+v %#v", err, err, err); strings.Contains(s, marker) {
		t.Fatal("refusal reflects a row value")
	}
}

func TestImportTransferStoreModeLandsAClosedCopyWithoutTenancyWorkspace(t *testing.T) {
	f := newImportFxMode(t, true)
	if len(f.rows.Workspaces) != 0 || len(f.rows.Projects) != 0 {
		t.Fatal("positive control: the store-mode fixture has tenancy rows")
	}
	if raw, err := json.Marshal(f.m); err != nil {
		t.Fatal("marshal manifest")
	} else if _, err := scopedtransfer.ParseManifest(raw); err != nil {
		t.Fatal("positive control: the store-mode manifest does not parse")
	}
	rc, err := f.run()
	if err != nil || rc.Outcome != "imported" {
		t.Fatalf("store-mode import refused: %v", err)
	}
	// No workspace or project is invented on the target.
	if tableRows(t, f, "workspaces") != 0 || tableRows(t, f, "projects") != 0 || tableRows(t, f, "mesh_installations") != 1 {
		t.Fatal("the target workspace shape differs from the source")
	}
	var ws string
	if err := f.target.QueryRow(f.ctx, `SELECT workspace_id::text FROM mesh_installations`).Scan(&ws); err != nil || ws != f.m.WorkspaceID {
		t.Fatal("the canonical workspace is not the installation's")
	}
	if res, err := audit.Verify(f.ctx, f.target, f.org.String()); err != nil || !res.OK {
		t.Fatal("audit chain does not verify after a store-mode import")
	}
}

func TestImportTransferStoreModeRefusalsLeaveTargetEmpty(t *testing.T) {
	cases := map[string]struct {
		reason string
		mutate func(g *importFx)
	}{
		"profile 1 label on store-mode rows": {"manifest", func(g *importFx) { g.m.ProfileVersion = scopedtransfer.ProfileVersion }},
		"made-up workspace":                  {"manifest", func(g *importFx) { g.m.WorkspaceID = uuid.NewString() }},
		"no workspace id":                    {"manifest", func(g *importFx) { g.m.WorkspaceID = "" }},
		"synthetic workspace row": {"manifest", func(g *importFx) {
			g.rows.Workspaces = append(g.rows.Workspaces, store.WorkspaceRow{ID: uuid.New(), OrgID: g.org, Name: "synthetic"})
		}},
		"synthetic project row": {"closure", func(g *importFx) {
			g.rows.Projects = append(g.rows.Projects, store.ProjectRow{ID: uuid.New(), OrgID: g.org, WorkspaceID: uuid.New(), Name: "synthetic"})
		}},
		"tampered workspace count": {"counts", func(g *importFx) {
			for i := range g.m.Tables {
				if g.m.Tables[i].Name == "workspaces" {
					g.m.Tables[i].Rows++
				}
			}
		}},
		"extension-mode installation": {"manifest", func(g *importFx) { g.rows.MeshInstallations[0].Mode = "extension" }},
		"foreign installation":        {"closure", func(g *importFx) { g.rows.MeshInstallations[0].OrgID = uuid.New() }},
		"second installation": {"closure", func(g *importFx) {
			g.rows.MeshInstallations = append(g.rows.MeshInstallations, g.rows.MeshInstallations[0])
		}},
		"foreign mesh row":          {"closure", func(g *importFx) { g.rows.MeshEvents[0].WorkspaceID = uuid.New() }},
		"workspace-scoped key":      {"closure", func(g *importFx) { g.rows.KEKs[0].DomainWorkspace = "foreign" }},
		"workspace-scoped envelope": {"closure", func(g *importFx) { g.rows.Envelopes[0].StoreWorkspace = "foreign" }},
		"tampered closure digest":   {"digest", func(g *importFx) { g.m.ClosureDigest = "sha256:" + strings.Repeat("0", 64) }},
		"edited row":                {"digest", func(g *importFx) { g.rows.Users[0].Email = "edited@example.invalid" }},
		"tampered audit hash":       {"closure", func(g *importFx) { g.rows.AuditRecords[0].Hash = strings.Repeat("e", 64) }},
		"hand-altered target catalog": {"profile", func(g *importFx) {
			if _, err := g.target.Exec(g.ctx, `ALTER TABLE users ADD COLUMN hand_made_note text`); err != nil {
				t.Fatal("alter the scratch target")
			}
		}},
	}
	for name, c := range cases {
		g := newImportFxMode(t, true)
		c.mutate(&g)
		var e errTransferImport
		if _, err := g.run(); !errors.As(err, &e) || e.Reason != c.reason {
			t.Errorf("%s: want refusal %q, got %v", name, c.reason, err)
		}
		for _, table := range []string{"organizations", "users", "workspaces", "mesh_installations", "audit_records", "keep_kek", "scoped_transfer_ledger"} {
			if n := tableRows(t, g, table); n != 0 {
				t.Errorf("%s: %s has %d rows after a refusal", name, table, n)
			}
		}
	}
	// Profile 2 label on a tenancy-workspace organization is refused too.
	g := newImportFx(t)
	g.m.ProfileVersion = scopedtransfer.ProfileVersionStoreMode
	g.m.WorkspaceID = g.rows.MeshInstallations[0].WorkspaceID.String()
	var e errTransferImport
	if _, err := g.run(); !errors.As(err, &e) || e.Reason != "manifest" {
		t.Errorf("profile 2 label on profile 1 rows: got %v", err)
	}
	if n := tableRows(t, g, "organizations"); n != 0 {
		t.Error("a refusal changed the target")
	}
}
