package config

import "testing"

// The Mesh extension is off unless KEEP_MESH_EXTENSION is exactly "1".
func TestMeshExtensionIsOffByDefault(t *testing.T) {
	t.Setenv("KEEP_DATABASE_URL", "postgres://synthetic-test-only@127.0.0.1:1/keep")
	for value, want := range map[string]bool{"": false, "0": false, "true": false, "yes": false, "1": true} {
		t.Setenv("KEEP_MESH_EXTENSION", value)
		cfg, err := FromEnv()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.MeshExtension != want {
			t.Errorf("KEEP_MESH_EXTENSION=%q: MeshExtension = %v, want %v", value, cfg.MeshExtension, want)
		}
	}
}
