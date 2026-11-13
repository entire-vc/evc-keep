package scopedtransfer

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/google/uuid"
)

// storeModeInventory is a native Mesh store-mode organization: one Mesh
// installation, no tenancy workspace and no project. Its canonical workspace
// is the installation's.
func storeModeInventory() Inventory {
	in := validInventory()
	in.WorkspaceIDs = nil
	in.MeshWorkspaceID = in.WorkspaceID
	setCount(&in, "workspaces", 0)
	setCount(&in, "projects", 0)
	return in
}

func TestProfileAcceptsStoreModeWithoutTenancyWorkspace(t *testing.T) {
	in := storeModeInventory()
	plan, err := PlanSnapshot(in)
	if err != nil || plan.ProfileVersion() != ProfileVersionStoreMode ||
		plan.WorkspaceID() != in.MeshWorkspaceID || plan.OrgID() != in.OrgID {
		t.Fatal("store-mode profile rejected or identities changed")
	}
	for _, c := range plan.TableCounts() {
		if (c.Name == "workspaces" || c.Name == "projects") && c.Rows != 0 {
			t.Fatal("store-mode plan carries tenancy rows")
		}
	}
	// The existing profile is still profile 1.
	p1, err := PlanSnapshot(validInventory())
	if err != nil || p1.ProfileVersion() != ProfileVersion {
		t.Fatal("tenancy-workspace profile changed")
	}
}

func TestProfileRejectsUnsupportedStoreModeInventory(t *testing.T) {
	for name, mutate := range map[string]func(*Inventory){
		"canonical workspace is not the installation": func(in *Inventory) { in.MeshWorkspaceID = uuid.NewString() },
		"no installation workspace":                   func(in *Inventory) { in.MeshWorkspaceID = "" },
		"installation count is not one":               func(in *Inventory) { setCount(in, "mesh_installations", 2) },
		"no installation row":                         func(in *Inventory) { setCount(in, "mesh_installations", 0) },
		"workspace row without listed id":             func(in *Inventory) { setCount(in, "workspaces", 1) },
		"project without a workspace":                 func(in *Inventory) { setCount(in, "projects", 1) },
		"extension mode":                              func(in *Inventory) { in.MeshMode = "extension" },
		"non-builtin provider":                        func(in *Inventory) { in.Providers = []string{"vault"} },
		"installation workspace equals org":           func(in *Inventory) { in.MeshWorkspaceID = in.OrgID; in.WorkspaceID = in.OrgID },
		"non-canonical workspace":                     func(in *Inventory) { in.MeshWorkspaceID = "NOT-A-UUID"; in.WorkspaceID = in.MeshWorkspaceID },
		"two tenancy workspaces":                      func(in *Inventory) { in.WorkspaceIDs = []string{uuid.NewString(), uuid.NewString()} },
		"tenancy workspace differing from canonical":  func(in *Inventory) { in.WorkspaceIDs = []string{uuid.NewString()} },
		"unsupported state":                           func(in *Inventory) { setCount(in, "runners", 1) },
		"future schema":                               func(in *Inventory) { in.SchemaVersion++ },
		"foreign catalog":                             func(in *Inventory) { in.CatalogID = "sha256:" + string(make([]byte, 0)) },
	} {
		t.Run(name, func(t *testing.T) {
			in := storeModeInventory()
			mutate(&in)
			plan, err := PlanSnapshot(in)
			if err != ErrProfile || !reflect.DeepEqual(plan, Plan{}) {
				t.Fatal("unsupported store-mode input was accepted")
			}
		})
	}
}

func storeModeManifest() Manifest {
	m := validManifest()
	in := storeModeInventory()
	m.ProfileVersion = ProfileVersionStoreMode
	m.WorkspaceID = in.WorkspaceID
	m.Tables = in.Tables
	return m
}

func TestManifestStoreModeRoundTripAndProfileBinding(t *testing.T) {
	want := storeModeManifest()
	got, err := ParseManifest(encode(t, want))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("store-mode manifest did not round-trip")
	}
	for name, f := range map[string]func(*Manifest){
		// A profile-2 label over profile-1 counts, and the reverse, must not
		// parse: the profile version selects the shape, the counts prove it.
		"profile 2 with a workspace row": func(m *Manifest) { setManifestCount(m, "workspaces", 1) },
		"profile 2 with a project row":   func(m *Manifest) { setManifestCount(m, "projects", 1) },
		"profile 1 label on profile 2":   func(m *Manifest) { m.ProfileVersion = ProfileVersion },
		"profile 2 label on profile 1":   func(m *Manifest) { *m = validManifest(); m.ProfileVersion = ProfileVersionStoreMode },
		"profile 3":                      func(m *Manifest) { m.ProfileVersion = 3 },
		"profile 0":                      func(m *Manifest) { m.ProfileVersion = 0 },
		"no installation":                func(m *Manifest) { setManifestCount(m, "mesh_installations", 0) },
		"two installations":              func(m *Manifest) { setManifestCount(m, "mesh_installations", 2) },
		"unsupported state":              func(m *Manifest) { setManifestCount(m, "mesh_gate_requests", 1) },
		"workspace equals org":           func(m *Manifest) { m.WorkspaceID = m.OrgID },
		"unpinned migrations":            func(m *Manifest) { m.MigrationSetID = "sha256:" + string(make([]byte, 0)) },
	} {
		m := storeModeManifest()
		f(&m)
		if _, err := ParseManifest(encode(t, m)); !errors.Is(err, ErrManifest) {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// A binary that predates profile 2 knows only profile 1: its manifest check is
// reproduced here as the reference refusal, so a profile-2 bundle can never be
// half-understood by it.
func TestStoreModeManifestIsNotProfileOne(t *testing.T) {
	raw := encode(t, storeModeManifest())
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil || m["profile_version"] != float64(2) {
		t.Fatal("profile 2 must be an explicit, distinct profile_version on the wire")
	}
}
