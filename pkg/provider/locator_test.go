package provider

import "testing"

func TestValidRef(t *testing.T) {
	valid := []string{
		"builtin://5f2b6b6e-7b1a-4d2f-9a3d-4f6b8b6b6b6b",
		"op://vault/item/field",
		"sops://path/to/file.enc.yaml#/db/password",
		"vault://secret/data/prod#password",
	}
	for _, s := range valid {
		if !ValidRef(s) {
			t.Errorf("ValidRef(%q) = false, want true", s)
		}
	}

	invalid := []string{
		"",
		"just a plain string",
		"http://example.com/secret",
		"builtin://",
		"builtin:/missing-slash",
		"BUILTIN://uppercase-scheme",
		"op://has space",
		"unknownscheme://x",
	}
	for _, s := range invalid {
		if ValidRef(s) {
			t.Errorf("ValidRef(%q) = true, want false", s)
		}
	}
}

// Keep's own service credential lives in the builtin store that tenant refs
// point at: no caller-supplied ref may name it or one of its companions.
func TestValidRefRefusesTheServiceTokenName(t *testing.T) {
	for _, s := range []string{
		"builtin://mesh-service-token",
		"builtin://mesh-service-token-staged-5d1c0f43-4e0b-4f43-8a2b-2f4d9a0f77c2",
		"builtin://mesh-service-token-dropped-5d1c0f43-4e0b-4f43-8a2b-2f4d9a0f77c2",
		"builtin://mesh-service-token/x",
	} {
		if ValidRef(s) {
			t.Errorf("ValidRef(%q) = true, want false", s)
		}
	}
	if !ValidRef("builtin://mesh/ws/extension") || !ValidRef("builtin://prod/mesh-service") {
		t.Error("an unrelated builtin ref was refused")
	}
}
