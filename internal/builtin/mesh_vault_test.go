package builtin

import "testing"

func TestMeshPathIsClosed(t *testing.T) {
	const ws = "0b7a1c52-6f0e-4a54-9d0c-1b3f2f1a9c11"
	for _, kind := range []string{MeshExtensionToken, MeshEventsSecret, MeshKeepSecret} {
		p, err := meshPath(ws, kind)
		if err != nil || p != "mesh/"+ws+"/"+kind {
			t.Errorf("meshPath(%q) = %q, %v", kind, p, err)
		}
	}
	for _, c := range [][2]string{
		{ws, "other"}, {ws, ""}, {"../" + ws, MeshKeepSecret}, {ws + "/x", MeshKeepSecret},
		{"", MeshKeepSecret}, {"0B7A1C52-6F0E-4A54-9D0C-1B3F2F1A9C11", MeshKeepSecret},
	} {
		if p, err := meshPath(c[0], c[1]); err == nil {
			t.Errorf("meshPath(%q, %q) = %q, want error", c[0], c[1], p)
		}
	}
}
