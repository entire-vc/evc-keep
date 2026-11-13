package scopedtransfer

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
)

// ErrManifest intentionally carries no input and no decoder text.
var ErrManifest = errors.New("scopedtransfer: invalid manifest")

// MaxManifestBytes bounds the metadata header before any decoding.
const MaxManifestBytes = 64 << 10

// ManifestVersion is the only wire format version understood.
const ManifestVersion = 1

// Manifest is the closed, metadata-only header of a transfer bundle. It holds
// identities, counts and digests of public or ciphertext artifacts only.
type Manifest struct {
	Version        int          `json:"version"`
	ProfileVersion int          `json:"profile_version"`
	TransferID     string       `json:"transfer_id"`
	OrgID          string       `json:"org_id"`
	WorkspaceID    string       `json:"workspace_id"`
	SchemaVersion  int64        `json:"schema_version"`
	MigrationSetID string       `json:"migration_set_id"`
	RecipientID    string       `json:"recipient_id"`
	SnapshotID     string       `json:"snapshot_id"`
	ClosureDigest  string       `json:"closure_digest"`
	Tables         []TableCount `json:"tables"`
}

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ParseManifest decodes a manifest only if the input is its canonical
// encoding: unknown, duplicate or differently-cased fields, reordering,
// trailing data and decoder-dependent forms all fail the final byte
// comparison. Every identity and count is then validated against the closed
// profile. Failures return only ErrManifest.
func ParseManifest(raw []byte) (Manifest, error) {
	if len(raw) == 0 || len(raw) > MaxManifestBytes {
		return Manifest{}, ErrManifest
	}
	var compact bytes.Buffer
	if json.Compact(&compact, raw) != nil {
		return Manifest{}, ErrManifest
	}
	dec := json.NewDecoder(bytes.NewReader(compact.Bytes()))
	dec.DisallowUnknownFields()
	var m Manifest
	if dec.Decode(&m) != nil || dec.More() {
		return Manifest{}, ErrManifest
	}
	canonical, err := json.Marshal(m)
	if err != nil || !bytes.Equal(canonical, compact.Bytes()) {
		return Manifest{}, ErrManifest
	}
	if m.Version != ManifestVersion || (m.ProfileVersion != ProfileVersion && m.ProfileVersion != ProfileVersionStoreMode) ||
		!canonicalID(m.TransferID) || !canonicalID(m.RecipientID) ||
		!canonicalID(m.SnapshotID) || !digestPattern.MatchString(m.ClosureDigest) {
		return Manifest{}, ErrManifest
	}
	// A manifest implies the pinned catalog: the live catalog is checked
	// against it on the source before export and on the target before
	// import, not carried in the manifest. The profile version selects which
	// workspace shape the counts must have; PlanSnapshot then confirms the
	// counts really are that profile's.
	in := Inventory{
		CatalogID: CatalogID,
		OrgID:     m.OrgID, WorkspaceID: m.WorkspaceID,
		Providers: []string{"builtin"}, MeshMode: "store", SchemaVersion: m.SchemaVersion,
		MigrationSetID: m.MigrationSetID, Tables: m.Tables,
	}
	if m.ProfileVersion == ProfileVersion {
		in.WorkspaceIDs = []string{m.WorkspaceID}
	} else {
		in.MeshWorkspaceID = m.WorkspaceID
	}
	if _, err := PlanSnapshot(in); err != nil {
		return Manifest{}, ErrManifest
	}
	return m, nil
}
