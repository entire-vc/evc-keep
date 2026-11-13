// Package scopedtransfer defines the metadata contract for an offline transfer.
// It has no plaintext access, database connection or authority to perform one.
package scopedtransfer

import (
	"errors"

	"github.com/google/uuid"
)

// ErrProfile intentionally carries no input or underlying database error.
var ErrProfile = errors.New("scopedtransfer: unsupported snapshot profile")

// ProfileVersion identifies the closed table registry, not a schema checksum.
// A database implementation must separately verify exact column/constraint and
// migration identities; a matching migration number alone is insufficient.
//
// Two profiles exist. Profile 1 ([ProfileVersion]) is one organization with
// exactly one tenancy workspace. Profile 2 ([ProfileVersionStoreMode]) is a
// native Mesh store-mode organization: one Mesh installation and no tenancy
// workspace, which Mesh's own install never creates. A binary that knows only
// profile 1 refuses a profile-2 manifest and a profile-2 source alike.
const ProfileVersion = 1

// ProfileVersionStoreMode is the profile of an organization with a single
// store-mode Mesh installation and zero tenancy workspaces and projects. Its
// canonical workspace is the installation's workspace_id.
const ProfileVersionStoreMode = 2

// MigrationSetID pins the names and complete contents of the supported SQL
// migrations, including their order and Down sections. Its SHA-256 input is
// the domain "keep-scoped-transfer-migrations-v1\x00", followed by lexically
// ordered filename/content pairs, each prefixed by its uint64 big-endian byte
// length. This is public source metadata, never a value fingerprint.
// This pin does not prove an actual database matches the expected catalog;
// the trusted reader must still verify columns, constraints, functions,
// triggers, roles and applied migrations before constructing the inventory.
const MigrationSetID = "sha256:c576311f7ffd61ca49401c6a682c17247c331e242fdb6968adc5dcc34fdf06ea"

// CatalogID pins the live schema catalog (columns, constraints, indexes,
// triggers, functions, row-level security) that the supported migrations
// produce on PostgreSQL 17. A reader recomputes it from the database itself
// on the source and on the target; a hand-altered column or constraint under
// an unchanged migration history changes it and is refused.
const CatalogID = "sha256:4970ab77559d94fe8fd6d125eb114e401aceb2ced4a12feaff0c4420550f5ed4"

const (
	// SchemaVersion is the only migration version classified by this registry.
	SchemaVersion int64 = 51
	// MaxTableRows and MaxSnapshotRows bound the metadata plan. The transport
	// must independently bound bytes, allocations and serialized row sizes.
	MaxTableRows    int64 = 1_000_000
	MaxSnapshotRows int64 = 5_000_000
)

// Disposition is a table's treatment in the initial store-only profile.
type Disposition uint8

const (
	// CopyRows preserves selected-org rows and their original identities.
	// org_ca is copied only as an authenticated unit (0 or 1 row per org):
	// absence is never repaired by generating authority, and the reader must
	// verify both envelopes inside the builtin zone before export and import.
	CopyRows Disposition = iota + 1
	// RewrapRows preserves KEK identities and changes only their wrapping.
	RewrapRows
	// OmitCredentials never exports native tokens or console sessions. Like
	// NodeLocal, the source may hold any number of them: they are counted for
	// classification, the manifest records zero rows, and the target issues
	// its own credentials after import.
	OmitCredentials
	// RequireEmpty refuses unsupported state instead of silently dropping it.
	RequireEmpty
	// NodeLocal is state of one database that never travels: it is counted
	// by the inventory so no table escapes classification, but it is not
	// exported, and the manifest records zero rows for it. The consumption
	// ledger is the only such table.
	NodeLocal
)

// TablePolicy classifies one application table. This is not executable SQL;
// queries must use a separate closed, reviewed column/join registry.
type TablePolicy struct {
	Name        string
	Disposition Disposition
}

var tablePolicies = [...]TablePolicy{
	{"organizations", CopyRows},
	{"users", CopyRows},
	{"agents", CopyRows},
	{"services", CopyRows},
	{"memberships", CopyRows},
	{"agent_grants", CopyRows},
	{"tokens", OmitCredentials},
	{"workspaces", CopyRows},
	{"projects", CopyRows},
	{"stores", CopyRows},
	{"store_bindings", CopyRows},
	{"override_locks", CopyRows},
	{"secrets", CopyRows},
	{"secret_versions", CopyRows},
	{"audit_chain_heads", CopyRows},
	{"audit_records", CopyRows},
	{"keep_kek", RewrapRows},
	{"keep_envelope", CopyRows},
	{"keep_org_key_level", CopyRows},
	{"org_ca", CopyRows},
	{"enroll_tokens", RequireEmpty},
	{"runners", RequireEmpty},
	{"intake_links", RequireEmpty},
	{"carriers", RequireEmpty},
	{"deployment_policies", RequireEmpty},
	{"deployment_requests", RequireEmpty},
	{"approval_requests", RequireEmpty},
	{"deployment_jobs", RequireEmpty},
	{"console_sessions", OmitCredentials},
	{"exec_templates", RequireEmpty},
	{"rotation_runs", RequireEmpty},
	{"rotation_steps", RequireEmpty},
	{"rotation_secret_epochs", RequireEmpty},
	{"carrier_verifications", RequireEmpty},
	{"carrier_verification_items", RequireEmpty},
	{"rotation_keys", RequireEmpty},
	{"rotation_intents", RequireEmpty},
	{"intake_rotation_links", RequireEmpty},
	{"mesh_installations", CopyRows},
	{"mesh_events", CopyRows},
	{"mesh_user_links", CopyRows},
	{"mesh_gate_requests", RequireEmpty},
	{"mesh_members", CopyRows},
	{"mesh_projects", CopyRows},
	{"mesh_agents", CopyRows},
	{"mesh_agent_keys", CopyRows},
	{"mesh_sync_state", CopyRows},
	{"mesh_secret_nonces", CopyRows},
	{"mesh_pending_installs", RequireEmpty},
	{"mesh_rotator_pending_installs", RequireEmpty},
	{"mesh_rotator_bindings", CopyRows},
	{"restart_requests", RequireEmpty},
	{"scoped_transfer_ledger", NodeLocal},
}

// TablePolicies returns an independent copy in stable order. Future schema
// elements require an explicit profile change, including unsupported tables.
func TablePolicies() []TablePolicy {
	return append([]TablePolicy(nil), tablePolicies[:]...)
}

// TableCount contains only an application table name and scoped row count.
type TableCount struct {
	Name string `json:"name"`
	Rows int64  `json:"rows"`
}

// Inventory is metadata collected by a trusted, read-only snapshot reader.
// WorkspaceIDs and Providers must describe the entire selected organization;
// every application table must occur exactly once, including zero counts.
// Rows must be scoped by reviewed joins, including tables without org_id.
// These statements are reader obligations, not proven by this value alone.
type Inventory struct {
	OrgID       string
	WorkspaceID string
	// WorkspaceIDs are the tenancy workspaces of the organization (profile 1
	// has one, profile 2 none).
	WorkspaceIDs []string
	// MeshWorkspaceID is the workspace_id of the organization's only Mesh
	// installation, or empty when it does not have exactly one. Profile 2
	// takes its canonical workspace from it.
	MeshWorkspaceID string
	Providers       []string
	MeshMode        string
	SchemaVersion   int64
	MigrationSetID  string
	CatalogID       string
	Tables          []TableCount
}

// Plan is an immutable metadata plan, not authorization or a completed closure
// proof. The database implementation still owes exact schema verification,
// scope/FK/AAD and audit checks, fresh revocation/CAS and write quiescence.
// It must perform no import based only on a successful PlanSnapshot call.
type Plan struct {
	profile     int
	orgID       string
	workspaceID string
	tables      []TableCount
	rows        int64
}

func (p Plan) OrgID() string { return p.orgID }

// ProfileVersion is the profile the inventory matched: 1 or 2.
func (p Plan) ProfileVersion() int { return p.profile }

func (p Plan) WorkspaceID() string { return p.workspaceID }
func (p Plan) RowCount() int64     { return p.rows }

// TableCounts returns an independent copy, in registry order, including rows
// explicitly omitted as credentials. It never contains row payloads.
func (p Plan) TableCounts() []TableCount {
	return append([]TableCount(nil), p.tables...)
}

// PlanSnapshot rejects inventories outside the two supported profiles (one
// org, builtin-only Mesh store mode; one tenancy workspace or none). It
// retains no mutable caller memory.
func PlanSnapshot(in Inventory) (Plan, error) {
	profile := 0
	switch len(in.WorkspaceIDs) {
	case 1:
		if in.WorkspaceIDs[0] == in.WorkspaceID {
			profile = ProfileVersion
		}
	case 0:
		// The canonical workspace is the single Mesh installation's.
		if in.MeshWorkspaceID != "" && in.MeshWorkspaceID == in.WorkspaceID {
			profile = ProfileVersionStoreMode
		}
	}
	if profile == 0 || !canonicalID(in.OrgID) || !canonicalID(in.WorkspaceID) ||
		in.OrgID == in.WorkspaceID || in.SchemaVersion != SchemaVersion ||
		in.MigrationSetID != MigrationSetID || in.CatalogID != CatalogID ||
		in.MeshMode != "store" || len(in.Providers) != 1 ||
		in.Providers[0] != "builtin" || len(in.Tables) != len(tablePolicies) {
		return Plan{}, ErrProfile
	}
	counts := make(map[string]int64, len(tablePolicies))
	var total int64
	for _, table := range in.Tables {
		if _, exists := counts[table.Name]; exists || table.Rows < 0 ||
			table.Rows > MaxTableRows || table.Rows > MaxSnapshotRows-total {
			return Plan{}, ErrProfile
		}
		counts[table.Name] = table.Rows
		total += table.Rows
	}
	ordered := make([]TableCount, 0, len(tablePolicies))
	for _, policy := range tablePolicies {
		rows, present := counts[policy.Name]
		if !present || (policy.Disposition == RequireEmpty && rows != 0) {
			return Plan{}, ErrProfile
		}
		if policy.Disposition == NodeLocal || policy.Disposition == OmitCredentials {
			total -= rows
			rows = 0
		}
		ordered = append(ordered, TableCount{Name: policy.Name, Rows: rows})
	}
	wantWorkspaces := int64(len(in.WorkspaceIDs))
	if counts["organizations"] != 1 || counts["workspaces"] != wantWorkspaces ||
		(profile == ProfileVersionStoreMode && counts["projects"] != 0) ||
		counts["mesh_installations"] != 1 || counts["stores"] == 0 ||
		counts["audit_chain_heads"] > 1 || counts["org_ca"] > 1 || counts["keep_org_key_level"] > 1 {
		return Plan{}, ErrProfile
	}
	return Plan{profile: profile, orgID: in.OrgID, workspaceID: in.WorkspaceID, tables: ordered, rows: total}, nil
}

func canonicalID(s string) bool {
	id, err := uuid.Parse(s)
	return err == nil && id != uuid.Nil && id.String() == s
}
