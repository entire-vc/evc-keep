package transferverify

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/testutil/transferfixture"
	"github.com/google/uuid"
)

func seededRows(t *testing.T) (*store.TransferRows, uuid.UUID) {
	t.Helper()
	dsn := os.Getenv("KEEP_DATABASE_URL")
	if dsn == "" {
		t.Skip("KEEP_DATABASE_URL not set — see CONTRIBUTING.md")
	}
	ctx := context.Background()
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal("open")
	}
	t.Cleanup(db.Close)
	org := uuid.New()
	run := strings.ToUpper(strings.ReplaceAll(uuid.NewString(), "-", ""))
	transferfixture.Seed(t, ctx, db, org, run[:7]+"A")
	transferfixture.Seed(t, ctx, db, uuid.New(), run[7:14]+"B")
	rows, err := store.ReadTransferRows(ctx, db, org)
	if err != nil {
		t.Fatal("read rows")
	}
	return rows, org
}

func class(err error) ClosureClass {
	var ce ClosureError
	if errors.As(err, &ce) {
		return ce.Class
	}
	return ""
}

func TestClosure(t *testing.T) {
	rows, org := seededRows(t)
	if err := Closure(rows, org); err != nil {
		t.Fatalf("honest snapshot rejected: %v", err)
	}
	if rows.MaxSealSeq() <= 0 {
		t.Fatal("positive control: no seal_seq in fixture")
	}
	other := uuid.New()
	cases := map[string]struct {
		mutate func(r *store.TransferRows)
		want   ClosureClass
	}{
		"foreign user":     {func(r *store.TransferRows) { r.Users[0].OrgID = other }, ClosureScope},
		"foreign secret":   {func(r *store.TransferRows) { r.Secrets[0].OrgID = other }, ClosureScope},
		"foreign kek":      {func(r *store.TransferRows) { r.KEKs[0].OrgID = other.String() }, ClosureScope},
		"foreign envelope": {func(r *store.TransferRows) { r.Envelopes[0].StoreOrg = other.String() }, ClosureScope},
		"foreign mesh":     {func(r *store.TransferRows) { r.MeshEvents[0].WorkspaceID = other }, ClosureScope},
		"foreign link org": {func(r *store.TransferRows) { r.MeshUserLinks[0].OrgID = other }, ClosureScope},
		"second workspace": {func(r *store.TransferRows) { r.Workspaces = append(r.Workspaces, r.Workspaces[0]) }, ClosureScope},
		"no org row":       {func(r *store.TransferRows) { r.Organizations = nil }, ClosureScope},
		"dangling sponsor": {func(r *store.TransferRows) { r.Agents[0].SponsorUserID = other }, ClosureReference},
		"dangling store":   {func(r *store.TransferRows) { r.Secrets[0].StoreID = other }, ClosureReference},
		"dangling secret":  {func(r *store.TransferRows) { r.SecretVersions[0].SecretID = other }, ClosureReference},
		"dangling lock": {func(r *store.TransferRows) {
			r.OverrideLocks[0].AllowedStoreIds = append(r.OverrideLocks[0].AllowedStoreIds, other)
		}, ClosureReference},
		"dangling kek":      {func(r *store.TransferRows) { r.OrgCAs[0].CAKEKID = "missing" }, ClosureReference},
		"dangling envelope": {func(r *store.TransferRows) { k := "missing"; r.Envelopes[0].KEKID = &k }, ClosureReference},
		"dangling link":     {func(r *store.TransferRows) { r.MeshUserLinks[0].UserID = other }, ClosureReference},
		"edited audit":      {func(r *store.TransferRows) { r.AuditRecords[0].ActorID = "x" }, ClosureChain},
		"cut audit":         {func(r *store.TransferRows) { r.AuditRecords = r.AuditRecords[:1] }, ClosureChain},
		"foreign head":      {func(r *store.TransferRows) { r.AuditChainHeads[0].OrgID = other.String() }, ClosureScope},
		"no audit head":     {func(r *store.TransferRows) { r.AuditChainHeads = nil }, ClosureChain},
		"duplicate seal":    {func(r *store.TransferRows) { r.SecretVersions = append(r.SecretVersions, r.SecretVersions[0]) }, ClosureShape},
	}
	for name, c := range cases {
		cp := *rows
		cp.Users = append(cp.Users[:0:0], rows.Users...)
		cp.Secrets = append(cp.Secrets[:0:0], rows.Secrets...)
		cp.KEKs = append(cp.KEKs[:0:0], rows.KEKs...)
		cp.Envelopes = append(cp.Envelopes[:0:0], rows.Envelopes...)
		cp.MeshEvents = append(cp.MeshEvents[:0:0], rows.MeshEvents...)
		cp.MeshUserLinks = append(cp.MeshUserLinks[:0:0], rows.MeshUserLinks...)
		cp.Workspaces = append(cp.Workspaces[:0:0], rows.Workspaces...)
		cp.Organizations = append(cp.Organizations[:0:0], rows.Organizations...)
		cp.Agents = append(cp.Agents[:0:0], rows.Agents...)
		cp.SecretVersions = append(cp.SecretVersions[:0:0], rows.SecretVersions...)
		cp.OverrideLocks = append(cp.OverrideLocks[:0:0], rows.OverrideLocks...)
		cp.OrgCAs = append(cp.OrgCAs[:0:0], rows.OrgCAs...)
		cp.AuditRecords = append(cp.AuditRecords[:0:0], rows.AuditRecords...)
		cp.AuditChainHeads = append(cp.AuditChainHeads[:0:0], rows.AuditChainHeads...)
		c.mutate(&cp)
		err := Closure(&cp, org)
		if got := class(err); got != c.want {
			t.Fatalf("%s: want %s, got %q (%v)", name, c.want, got, err)
		}
		if err != nil && strings.Contains(err.Error(), other.String()) {
			t.Fatalf("%s: error reflects a row value", name)
		}
	}
}

// copyRows returns a shallow copy whose slices can be edited independently.
func copyRows(r *store.TransferRows) store.TransferRows {
	cp := *r
	cp.Workspaces = append(r.Workspaces[:0:0], r.Workspaces...)
	cp.Projects = append(r.Projects[:0:0], r.Projects...)
	cp.KEKs = append(r.KEKs[:0:0], r.KEKs...)
	cp.Envelopes = append(r.Envelopes[:0:0], r.Envelopes...)
	cp.MeshInstallations = append(r.MeshInstallations[:0:0], r.MeshInstallations...)
	return cp
}

// Profile 2: a native Mesh store-mode organization has no tenancy workspace.
func TestClosureStoreModeWithoutTenancyWorkspace(t *testing.T) {
	rows, org := seededRows(t)
	sm := copyRows(rows)
	sm.Workspaces, sm.Projects = nil, nil
	if err := Closure(&sm, org); err != nil {
		t.Fatalf("store-mode snapshot rejected: %v", err)
	}
	other := uuid.New()
	for name, mutate := range map[string]func(*store.TransferRows){
		"project without workspace":   func(r *store.TransferRows) { r.Projects = rows.Projects },
		"two workspaces":              func(r *store.TransferRows) { r.Workspaces = append(rows.Workspaces[:1:1], rows.Workspaces[0]) },
		"no installation":             func(r *store.TransferRows) { r.MeshInstallations = nil },
		"foreign installation":        func(r *store.TransferRows) { r.MeshInstallations[0].OrgID = other },
		"workspace-scoped key domain": func(r *store.TransferRows) { r.KEKs[0].DomainWorkspace = "w" },
		"project-scoped key domain":   func(r *store.TransferRows) { r.KEKs[0].DomainProject = "p" },
		"workspace-scoped envelope":   func(r *store.TransferRows) { r.Envelopes[0].StoreWorkspace = "w" },
		"project-scoped envelope":     func(r *store.TransferRows) { r.Envelopes[0].StoreProject = "p" },
	} {
		cp := copyRows(&sm)
		mutate(&cp)
		if err := Closure(&cp, org); class(err) != ClosureScope && class(err) != ClosureReference {
			t.Fatalf("%s: accepted or wrong class: %v", name, err)
		}
	}
	// The same key-domain edits are not a scope fault in profile 1, where the
	// workspace exists: only the missing workspace makes them dangling.
	cp := copyRows(rows)
	cp.KEKs[0].DomainWorkspace = "w"
	if err := Closure(&cp, org); err != nil {
		t.Fatalf("profile 1 control changed: %v", err)
	}
}
