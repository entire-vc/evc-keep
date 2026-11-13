package audit

import "testing"

// The metadata probe's action is registered, spelled as the database
// registry (migration 00049) spells it, and a lookalike is not.
func TestMeshSecretMetadataActionRegistered(t *testing.T) {
	if ActionMeshSecretMetadata != "mesh.secret.metadata" {
		t.Fatalf("action spelled %q", ActionMeshSecretMetadata)
	}
	if !ActionMeshSecretMetadata.Known() {
		t.Fatal("mesh.secret.metadata is not a registered action")
	}
	if Action("mesh.secret.metadata.x").Known() || Action("mesh.secret.meta").Known() {
		t.Fatal("a lookalike action is registered")
	}
}
