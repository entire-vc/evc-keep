package builtin

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
)

func meshTokenVault(t *testing.T) *MeshVault {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal("root")
	}
	local, err := NewLocal(testPool(t), "mesh-token-root", raw, nil, nopAudit)
	if err != nil {
		t.Fatal("local backend")
	}
	return local.MeshVault()
}

// ExtensionToken reads the sealed actor token anew on every call: a token put
// by a later install or rotation is the one returned next, with no restart.
func TestMeshExtensionTokenIsReadAnewOnEachCall(t *testing.T) {
	ctx := context.Background()
	m := meshTokenVault(t)
	org, ws := uuid.NewString(), uuid.NewString()
	c := canary.New()
	for i := range 2 {
		if err := m.Put(ctx, org, ws, MeshExtensionToken, c.Value(i)); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
		tok, err := m.ExtensionToken(ctx, org, ws)
		if err != nil {
			t.Fatalf("token %d: %v", i, err)
		}
		if tok != c.Value(i) {
			t.Fatalf("call %d returned a token other than the one sealed last", i)
		}
	}
}

// Nothing sealed, another organisation, a malformed workspace, or another
// kind's value: the call fails, and its text names neither a value nor the
// vault path.
func TestMeshExtensionTokenRefusalsNameNothing(t *testing.T) {
	ctx := context.Background()
	m := meshTokenVault(t)
	org, ws := uuid.NewString(), uuid.NewString()
	c := canary.New()
	if err := m.Put(ctx, org, ws, MeshExtensionToken, c.Value(0)); err != nil {
		t.Fatal("seed")
	}
	other := uuid.NewString()
	if err := m.Put(ctx, org, other, MeshEventsSecret, c.Value(1)); err != nil {
		t.Fatal("seed events")
	}
	for name, call := range map[string][2]string{
		"no installation token": {org, uuid.NewString()},
		"other organisation":    {uuid.NewString(), ws},
		"malformed workspace":   {org, "../" + ws},
		"only another kind":     {org, other},
	} {
		tok, err := m.ExtensionToken(ctx, call[0], call[1])
		if err == nil || tok != "" {
			t.Fatalf("%s: returned a token", name)
		}
		if c.In(err.Error()) || strings.Contains(err.Error(), "mesh/") || strings.Contains(err.Error(), ws) {
			t.Fatalf("%s: error names a value or the path: %v", name, err)
		}
	}
}
