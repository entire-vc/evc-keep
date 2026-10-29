package builtin

import (
	"encoding/hex"
	"testing"
)

// The vector was produced by Sign() of evc-mesh (commit 202f6c65,
// internal/extensions/external/handshake.go), run unchanged on these inputs.
// It pins Mesh's install signature independently of Keep's reading of it.
const (
	meshVectorSigner = "kav-signing-secret-0123456789abcdef0123456789abcdef" // pragma: allowlist secret
	meshVectorTS     = "1793000000"
	meshVectorBody   = `{"extension_id":"keep","version":"1.0.0","workspace_id":"6f1c2a4e-9b3d-4c7a-8e21-5d0f3b9a7c64","signing_secret":"` +
		meshVectorSigner + `","events":["project.created"],"events_path":"/mesh/events"}`
	meshVectorSig = "d8d46c88b39d9319071f327d813c138c013c5490084b57a403e532990b600e8d"
)

func TestVerifyInstallAcceptsMeshSignVector(t *testing.T) {
	tag, err := hex.DecodeString(meshVectorSig)
	if err != nil {
		t.Fatal(err)
	}
	var m MeshVault
	msg := []byte(meshVectorTS + "." + meshVectorBody)
	if !m.VerifyInstall(meshVectorSigner, msg, tag) {
		t.Fatal("the signature Mesh computes for this handshake is refused")
	}
	for name, bad := range map[string][]byte{
		"no separator": []byte(meshVectorTS + meshVectorBody),
		"body only":    []byte(meshVectorBody),
		"other ts":     []byte("1793000001." + meshVectorBody),
	} {
		if m.VerifyInstall(meshVectorSigner, bad, tag) {
			t.Fatalf("%s: accepted a message Mesh did not sign", name)
		}
	}
	if m.VerifyInstall(meshVectorSigner+"x", msg, tag) {
		t.Fatal("accepted the vector under another secret")
	}
}
