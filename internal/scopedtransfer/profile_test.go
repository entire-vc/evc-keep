package scopedtransfer

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
)

func TestProfileErrorDoesNotEchoInput(t *testing.T) {
	c := canary.New()
	if !c.In("positive control: " + c.Value(1)) {
		t.Fatal("canary detector missed the positive control")
	}
	for _, mutate := range []func(*Inventory){
		func(in *Inventory) { in.MeshMode = c.Value(1) },
		func(in *Inventory) { in.MigrationSetID = c.Value(1) },
		func(in *Inventory) { in.CatalogID = c.Value(1) },
		func(in *Inventory) { in.OrgID = c.Value(1) },
		func(in *Inventory) { in.WorkspaceID = c.Value(1) },
		func(in *Inventory) { in.Providers[0] = c.Value(1) },
		func(in *Inventory) { in.Tables[0].Name = c.Value(1) },
	} {
		in := validInventory()
		mutate(&in)
		_, err := PlanSnapshot(in)
		if err == nil {
			t.Fatal("invalid inventory was accepted")
		}
		for current := err; current != nil; current = errors.Unwrap(current) {
			encoded, marshalErr := json.Marshal(current)
			if marshalErr != nil {
				t.Fatal("cannot inspect error serialization")
			}
			for _, out := range []string{current.Error(), fmt.Sprintf("%+v", current), fmt.Sprintf("%#v", current), string(encoded)} {
				if c.In(out) {
					t.Fatal("profile error exposes input")
				}
			}
		}
	}
}

func validInventory() Inventory {
	in := Inventory{
		OrgID: uuid.NewString(), WorkspaceID: uuid.NewString(),
		Providers: []string{"builtin"}, MeshMode: "store", SchemaVersion: SchemaVersion,
		MigrationSetID: MigrationSetID, CatalogID: CatalogID,
	}
	in.WorkspaceIDs = []string{in.WorkspaceID}
	for _, policy := range TablePolicies() {
		var n int64
		if policy.Disposition == CopyRows || policy.Disposition == RewrapRows {
			n = 1
		}
		in.Tables = append(in.Tables, TableCount{Name: policy.Name, Rows: n})
	}
	return in
}

func setCount(in *Inventory, name string, rows int64) {
	for i := range in.Tables {
		if in.Tables[i].Name == name {
			in.Tables[i].Rows = rows
			return
		}
	}
	panic("test table missing from registry")
}

func TestProfileAcceptsClosedStoreInventory(t *testing.T) {
	in := validInventory()
	setCount(&in, "tokens", 3)
	setCount(&in, "console_sessions", 2)
	plan, err := PlanSnapshot(in)
	if err != nil || plan.OrgID() != in.OrgID || plan.WorkspaceID() != in.WorkspaceID {
		t.Fatal("valid profile rejected or identities changed")
	}
	var rows int64
	for _, count := range in.Tables {
		if count.Name == "tokens" || count.Name == "console_sessions" || count.Name == "scoped_transfer_ledger" {
			continue // counted for classification, never exported
		}
		rows += count.Rows
	}
	if rows == 0 || plan.RowCount() != rows {
		t.Fatal("profile lost source inventory rows")
	}
	// Mutation of either the caller's inventory or a returned copy cannot
	// change the accepted plan or the package's closed registry.
	want := plan.TableCounts()
	in.Tables[0].Rows = 99
	counts := plan.TableCounts()
	counts[0].Name = "changed"
	if !reflect.DeepEqual(plan.TableCounts(), want) {
		t.Fatal("plan aliases mutable input or output")
	}
	policies := TablePolicies()
	policies[0].Name = "changed"
	if TablePolicies()[0].Name != "organizations" {
		t.Fatal("registry aliases caller memory")
	}
}

func TestProfileRejectsUnsupportedInventory(t *testing.T) {
	for name, mutate := range map[string]func(*Inventory){
		"zero org":                 func(in *Inventory) { in.OrgID = uuid.Nil.String() },
		"short UUID":               func(in *Inventory) { in.OrgID = strings.ReplaceAll(in.OrgID, "-", "") },
		"same identities":          func(in *Inventory) { in.OrgID = in.WorkspaceID },
		"foreign workspace":        func(in *Inventory) { in.WorkspaceIDs[0] = uuid.NewString() },
		"extra workspace":          func(in *Inventory) { in.WorkspaceIDs = append(in.WorkspaceIDs, uuid.NewString()) },
		"no workspace":             func(in *Inventory) { in.WorkspaceIDs = nil },
		"external provider":        func(in *Inventory) { in.Providers = []string{"vault"} },
		"extra provider":           func(in *Inventory) { in.Providers = append(in.Providers, "vault") },
		"extension mode":           func(in *Inventory) { in.MeshMode = "extension" },
		"future schema":            func(in *Inventory) { in.SchemaVersion++ },
		"old schema":               func(in *Inventory) { in.SchemaVersion-- },
		"missing table":            func(in *Inventory) { in.Tables = in.Tables[1:] },
		"extra table":              func(in *Inventory) { in.Tables = append(in.Tables, TableCount{Name: "unknown"}) },
		"unknown instead of known": func(in *Inventory) { in.Tables[0].Name = "unknown" },
		"duplicate table":          func(in *Inventory) { in.Tables[0].Name = in.Tables[1].Name },
		"negative count":           func(in *Inventory) { setCount(in, "audit_records", -1) },
		"large count":              func(in *Inventory) { setCount(in, "audit_records", MaxTableRows+1) },
		"overflow count":           func(in *Inventory) { setCount(in, "audit_records", math.MaxInt64) },
		"no organization":          func(in *Inventory) { setCount(in, "organizations", 0) },
		"extra organizations":      func(in *Inventory) { setCount(in, "organizations", 2) },
		"extra workspace rows":     func(in *Inventory) { setCount(in, "workspaces", 2) },
		"no installation":          func(in *Inventory) { setCount(in, "mesh_installations", 0) },
		"no stores":                func(in *Inventory) { setCount(in, "stores", 0) },
		"multiple audit heads":     func(in *Inventory) { setCount(in, "audit_chain_heads", 2) },
		"multiple key levels":      func(in *Inventory) { setCount(in, "keep_org_key_level", 2) },
		"multiple org CAs":         func(in *Inventory) { setCount(in, "org_ca", 2) },
		"aggregate limit": func(in *Inventory) {
			for _, table := range []string{"users", "agents", "services", "memberships", "tokens", "audit_records"} {
				setCount(in, table, MaxTableRows)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			in := validInventory()
			mutate(&in)
			plan, err := PlanSnapshot(in)
			if err != ErrProfile || !reflect.DeepEqual(plan, Plan{}) {
				t.Fatal("unsupported input did not produce only ErrProfile and an empty plan")
			}
		})
	}
	for _, policy := range TablePolicies() {
		if policy.Disposition == RequireEmpty {
			t.Run("unsupported state/"+policy.Name, func(t *testing.T) {
				in := validInventory()
				setCount(&in, policy.Name, 1)
				if _, err := PlanSnapshot(in); err != ErrProfile {
					t.Fatal("unsupported state was silently accepted")
				}
			})
		}
	}
}

func TestProfileRegistryMatchesMigrations(t *testing.T) {
	paths, err := filepath.Glob("../store/migrations/*.sql")
	if err != nil || len(paths) == 0 {
		t.Fatal("migration positive control missing")
	}
	created := make(map[string]bool)
	createTable := regexp.MustCompile(`(?m)^CREATE TABLE ([a-z_]+) \(`)
	var latest int64
	for _, path := range paths {
		version, err := strconv.ParseInt(strings.SplitN(filepath.Base(path), "_", 2)[0], 10, 64)
		if err != nil {
			t.Fatal("unrecognized migration identity")
		}
		if version > latest {
			latest = version
		}
		raw, err := fs.ReadFile(os.DirFS("../store/migrations"), filepath.Base(path))
		if err != nil {
			t.Fatal("cannot read migration")
		}
		up := strings.SplitN(string(raw), "-- +goose Down", 2)[0]
		for _, match := range createTable.FindAllStringSubmatch(up, -1) {
			created[match[1]] = true
		}
	}
	if latest != SchemaVersion || !created["keep_kek"] || !created["mesh_secret_nonces"] {
		t.Fatal("registry version stale or schema positive control missing")
	}
	policies := TablePolicies()
	if len(created) != len(policies) {
		t.Fatal("application schema has unclassified tables")
	}
	for _, policy := range policies {
		if !created[policy.Name] {
			t.Fatal("registry table missing or duplicated")
		}
		delete(created, policy.Name)
	}
	// These dispositions are security boundaries independent of the fixture.
	for name, disposition := range map[string]Disposition{
		"tokens": OmitCredentials, "console_sessions": OmitCredentials,
		"keep_kek": RewrapRows, "keep_envelope": CopyRows,
		"mesh_events": CopyRows, "mesh_secret_nonces": CopyRows,
		"mesh_agent_keys": CopyRows, "audit_records": CopyRows,
		"org_ca": CopyRows, "runners": RequireEmpty, "enroll_tokens": RequireEmpty, "mesh_pending_installs": RequireEmpty,
		"mesh_user_links": CopyRows, "mesh_gate_requests": RequireEmpty,
		"mesh_rotator_pending_installs": RequireEmpty, "mesh_rotator_bindings": CopyRows,
	} {
		found := false
		for _, policy := range policies {
			if policy.Name == name && policy.Disposition == disposition {
				found = true
			}
		}
		if !found {
			t.Fatal("required security disposition changed")
		}
	}
}

func TestProfileRejectsUnpinnedMigrationContents(t *testing.T) {
	// The version can stay unchanged while a migration is rewritten.
	// Version equality must not authorize that different source schema.
	in := validInventory()
	in.MigrationSetID = "sha256:" + strings.Repeat("0", 64)
	if _, err := PlanSnapshot(in); err != ErrProfile {
		t.Fatal("same schema version with unpinned migration contents accepted")
	}
}

func TestProfileMigrationPinMatchesSource(t *testing.T) {
	paths, err := filepath.Glob("../store/migrations/*.sql")
	if err != nil || len(paths) != int(SchemaVersion) {
		t.Fatal("migration identity positive control missing")
	}
	sort.Strings(paths)
	h := sha256.New()
	_, _ = h.Write([]byte("keep-scoped-transfer-migrations-v1\x00"))
	for _, path := range paths {
		name := filepath.Base(path)
		raw, err := fs.ReadFile(os.DirFS("../store/migrations"), name)
		if err != nil {
			t.Fatal("cannot read migration identity")
		}
		for _, part := range [][]byte{[]byte(name), raw} {
			var size [8]byte
			binary.BigEndian.PutUint64(size[:], uint64(len(part)))
			_, _ = h.Write(size[:])
			_, _ = h.Write(part)
		}
	}
	if got := fmt.Sprintf("sha256:%x", h.Sum(nil)); got != MigrationSetID {
		t.Fatal("supported migration source identity changed; review and version the profile")
	}
}

func TestScopeRegistryMatchesMigrations(t *testing.T) {
	bodies := make(map[string]string)
	createTable := regexp.MustCompile(`(?ms)^CREATE TABLE ([a-z_]+) \((.*?)^\);`)
	paths, err := filepath.Glob("../store/migrations/*.sql")
	if err != nil || len(paths) == 0 {
		t.Fatal("migration positive control missing")
	}
	for _, path := range paths {
		raw, err := fs.ReadFile(os.DirFS("../store/migrations"), filepath.Base(path))
		if err != nil {
			t.Fatal("cannot read migration")
		}
		up := strings.SplitN(string(raw), "-- +goose Down", 2)[0]
		for _, m := range createTable.FindAllStringSubmatch(up, -1) {
			bodies[m[1]] = m[2]
		}
	}
	if len(bodies) != len(TablePolicies()) {
		t.Fatal("table parser positive control failed")
	}
	hasColumn := func(body, col string) bool {
		return regexp.MustCompile(`(?m)^\s+` + regexp.QuoteMeta(col) + `\s`).MatchString(body)
	}
	for _, policy := range TablePolicies() {
		scope, ok := TableScope(policy.Name)
		if !ok {
			t.Fatalf("table %s has no scope rule", policy.Name)
		}
		body := bodies[policy.Name]
		switch scope.Kind {
		case ScopeColumn:
			if scope.Column == "id" || !hasColumn(body, scope.Column) {
				t.Fatalf("table %s: scope column missing", policy.Name)
			}
		case ScopeSelf:
			if policy.Name != "organizations" || scope.Column != "id" || !hasColumn(body, "id") {
				t.Fatalf("table %s: invalid self scope", policy.Name)
			}
		case ScopeParent:
			fk := regexp.MustCompile(`(?m)^\s+` + scope.Column + `\s+UUID[^,\n]*REFERENCES ` + scope.Parent + `\(` + scope.ParentKey + `\)`)
			if _, parentKnown := TableScope(scope.Parent); !parentKnown ||
				scope.ParentKey == "" || !hasColumn(bodies[scope.Parent], scope.ParentKey) ||
				!hasColumn(body, scope.Column) || !fk.MatchString(body) {
				t.Fatalf("table %s: parent scope not backed by a foreign key", policy.Name)
			}
		default:
			t.Fatalf("table %s: unknown scope kind", policy.Name)
		}
	}
	if len(scopes) != len(TablePolicies()) {
		t.Fatal("scope registry has entries outside the table registry")
	}
	// A reader selecting by workspace alone would cross organizations for
	// tables that carry both; org must win wherever it exists.
	for _, name := range []string{"projects", "mesh_installations", "mesh_user_links"} {
		if s, _ := TableScope(name); s.Column != "org_id" {
			t.Fatalf("table %s must be scoped by organization", name)
		}
	}
}

func TestProfileCredentialsAreCountedButNeverTravel(t *testing.T) {
	base, err := PlanSnapshot(validInventory())
	if err != nil {
		t.Fatal("valid profile rejected")
	}
	for _, name := range []string{"tokens", "console_sessions"} {
		in := validInventory()
		setCount(&in, name, 5)
		plan, err := PlanSnapshot(in)
		if err != nil || plan.RowCount() != base.RowCount() {
			t.Fatalf("%s: existing credentials changed the snapshot row count or were refused", name)
		}
		for _, c := range plan.TableCounts() {
			if c.Name == name && c.Rows != 0 {
				t.Fatalf("%s: omitted credential rows entered the manifest", name)
			}
		}
	}
}

func TestProfileNodeLocalLedgerNeverTravels(t *testing.T) {
	in := validInventory()
	base, err := PlanSnapshot(in)
	if err != nil {
		t.Fatal("valid profile rejected")
	}
	// An imported organization carries ledger rows on its own database; they
	// are counted for classification but the plan must record none of them.
	setCount(&in, "scoped_transfer_ledger", 3)
	plan, err := PlanSnapshot(in)
	if err != nil || plan.RowCount() != base.RowCount() {
		t.Fatal("node-local ledger rows entered the snapshot row count")
	}
	for _, c := range plan.TableCounts() {
		if c.Name == "scoped_transfer_ledger" && c.Rows != 0 {
			t.Fatal("node-local ledger rows entered the manifest")
		}
	}
	// A missing ledger entry is still an unclassified table.
	in2 := validInventory()
	var kept []TableCount
	for _, c := range in2.Tables {
		if c.Name != "scoped_transfer_ledger" {
			kept = append(kept, c)
		}
	}
	in2.Tables = kept
	if _, err := PlanSnapshot(in2); err != ErrProfile {
		t.Fatal("inventory without the ledger table accepted")
	}
}

func TestProfileRejectsUnpinnedCatalog(t *testing.T) {
	// An unchanged migration history says nothing about a hand-altered
	// database: the live catalog digest must equal the pin, and an empty
	// digest (a reader that never computed one) must not pass either.
	if _, err := PlanSnapshot(validInventory()); err != nil {
		t.Fatal("positive control: pinned catalog refused")
	}
	for _, id := range []string{"", "sha256:" + strings.Repeat("0", 64)} {
		in := validInventory()
		in.CatalogID = id
		if _, err := PlanSnapshot(in); err != ErrProfile {
			t.Fatalf("catalog %q accepted", id)
		}
	}
}
