package builtin

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/google/uuid"
)

// meshValue reads back the sealed value of kind, for comparison only.
func meshValue(t *testing.T, m *MeshVault, org, ws, kind string) string {
	t.Helper()
	path, err := meshPath(ws, kind)
	if err != nil {
		t.Fatal("path")
	}
	v, _, err := m.local.Provider(org, "", "", "").Resolve(context.Background(), provider.Ref{Path: path})
	if err != nil {
		t.Fatalf("resolve %s: %v", kind, err)
	}
	defer v.Wipe()
	var out string
	secret.Expose(v, func(b []byte) { out = string(b) })
	return out
}

// Restore must bring back every credential kind the workspace held, not only
// the one a caller happens to observe, and leave the workspace that held
// nothing untouched by a restore.
func TestMeshCheckpointRestoresEveryKind(t *testing.T) {
	ctx := context.Background()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal("root")
	}
	local, err := NewLocal(testPool(t), "mesh-checkpoint-root", raw, nil, nopAudit)
	if err != nil {
		t.Fatal("local backend")
	}
	m := local.MeshVault()
	org, ws := uuid.NewString(), uuid.NewString()
	old := map[string]string{MeshExtensionToken: "old-token-aaaa", MeshEventsSecret: "old-events-bbbb", MeshKeepSecret: "old-keep-cccc"}
	for k, v := range old {
		if err := m.Put(ctx, org, ws, k, v); err != nil {
			t.Fatalf("seed %s: %v", k, err)
		}
	}
	cp, err := m.Checkpoint(ctx, org, ws)
	if err != nil {
		t.Fatal("checkpoint")
	}
	defer cp.Wipe()
	for k := range old {
		if err := m.Put(ctx, org, ws, k, "new-"+k); err != nil {
			t.Fatalf("overwrite %s: %v", k, err)
		}
	}
	if err := cp.Restore(ctx); err != nil {
		t.Fatalf("restore: %v", err)
	}
	for k, want := range old {
		if got := meshValue(t, m, org, ws, k); got != want {
			t.Errorf("%s after restore is not the previous value", k)
		}
	}

	// A workspace that held nothing: checkpoint is empty and Restore is a no-op.
	fresh := uuid.NewString()
	empty, err := m.Checkpoint(ctx, org, fresh)
	if err != nil {
		t.Fatal("checkpoint of unknown workspace")
	}
	defer empty.Wipe()
	if err := empty.Restore(ctx); err != nil {
		t.Fatalf("restore of empty checkpoint: %v", err)
	}
	if _, _, err := m.local.Provider(org, "", "", "").Resolve(ctx, provider.Ref{Path: "mesh/" + fresh + "/" + MeshKeepSecret}); err == nil {
		t.Error("restore invented a credential for a workspace that had none")
	}
}

// A previous credential that cannot be opened cannot be read back; that must not
// block a reinstall, and the readable kinds are still restored.
func TestMeshCheckpointSkipsUnreadableKinds(t *testing.T) {
	ctx := context.Background()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal("root")
	}
	local, err := NewLocal(testPool(t), "mesh-checkpoint-root", raw, nil, nopAudit)
	if err != nil {
		t.Fatal("local backend")
	}
	m := local.MeshVault()
	org, ws := uuid.NewString(), uuid.NewString()
	for k, v := range map[string]string{MeshExtensionToken: "old-token-aaaa", MeshEventsSecret: "old-events-bbbb"} {
		if err := m.Put(ctx, org, ws, k, v); err != nil {
			t.Fatalf("seed %s: %v", k, err)
		}
	}
	// Corrupt the sealed token so it cannot be opened (a stand-in for a key
	// that was purged or changed level).
	if _, err := local.pool.Exec(ctx, `UPDATE keep_envelope SET ciphertext = '\x00' WHERE store_org=$1 AND name=$2`, org, "mesh/"+ws+"/"+MeshExtensionToken); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	cp, err := m.Checkpoint(ctx, org, ws)
	if err != nil {
		t.Fatalf("checkpoint over an unreadable kind: %v", err)
	}
	defer cp.Wipe()
	if err := m.Put(ctx, org, ws, MeshEventsSecret, "new-events-zzzz"); err != nil {
		t.Fatal("overwrite")
	}
	if err := cp.Restore(ctx); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got := meshValue(t, m, org, ws, MeshEventsSecret); got != "old-events-bbbb" {
		t.Error("readable kind was not restored")
	}
}
