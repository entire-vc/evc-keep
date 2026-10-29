package api

import (
	"strings"
	"testing"
)

// matchVault records what the handler asks the zone to compare.
type matchVault struct {
	MeshVault
	calls int
	want  [32]byte
}

func (v *matchVault) MatchInstallSecret(_ string, want [32]byte) bool {
	v.calls++
	v.want = want
	return true
}

// A stored window digest that is not 64 lowercase hex never reaches the
// zone comparison and matches nothing; a well-formed one reaches it whole.
func TestMeshSecretMatchTakesOnlyAFullDigest(t *testing.T) {
	v := &matchVault{}
	m := &meshRoutes{deps: MeshDeps{Vault: v}}
	full := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	for name, d := range map[string]string{
		"empty": "", "mesh label": full[:8], "63": full[:63], "65": full + "0",
		"upper": strings.ToUpper(full), "not hex": strings.Repeat("g", 64),
	} {
		if m.meshSecretMatch(d, "s") || v.calls != 0 {
			t.Fatalf("%s: a malformed digest matched or reached the zone", name)
		}
	}
	if !m.meshSecretMatch(full, "s") || v.calls != 1 || v.want[0] != 0x00 || v.want[1] != 0x11 || v.want[31] != 0xff {
		t.Fatalf("a full digest did not reach the zone intact: calls %d, % x", v.calls, v.want)
	}
}
