package app

import (
	"encoding/json"
	"os"
	"slices"
	"sort"
	"testing"
)

const (
	keepManifestPath    = "../../../mesh-extension.json"
	rotatorManifestPath = "../../../mesh-extension.keep-rotator.json"
)

// meshManifestPaths are the manifests TestMeshManifestValidAgainstMeshSchema
// validates; TestMeshManifestsSplitRotationRights requires both to be listed.
var meshManifestPaths = []string{keepManifestPath, rotatorManifestPath}

// rotationRights are the Mesh rights that issue or revoke credentials. Mesh
// keeps one extension actor per (workspace, provider), so the actor that rotates
// is a second extension, keep-rotator, and Keep itself holds none of them.
var rotationRights = []string{"agent_key:rotate", "ext_token:self_rotate", "agent_keys:write"}

type manifestCaps struct {
	ID           string `json:"id"`
	Version      string `json:"version"`
	Capabilities struct {
		API     []string        `json:"api"`
		Events  []string        `json:"events"`
		UI      []string        `json:"ui"`
		Network json.RawMessage `json:"network"`
		Secrets []string        `json:"secrets"`
	} `json:"capabilities"`
	External struct {
		UI        map[string]json.RawMessage `json:"ui"`
		TokenPath string                     `json:"token_path"`
	} `json:"external"`
}

func readManifestCaps(t *testing.T, path string) manifestCaps {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // G304: one of the two manifest paths fixed in this file
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	var m manifestCaps
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("%s is not JSON: %v", path, err)
	}
	return m
}

// sharedRotationRights returns the rotation rights both lists hold.
func sharedRotationRights(a, b []string) []string {
	var out []string
	for _, r := range rotationRights {
		if slices.Contains(a, r) && slices.Contains(b, r) {
			out = append(out, r)
		}
	}
	return out
}

func TestMeshManifestsSplitRotationRights(t *testing.T) {
	// Positive control: the check sees an overlap when there is one.
	if got := sharedRotationRights([]string{"tasks:write", "agent_key:rotate"}, []string{"agent_key:rotate"}); len(got) != 1 {
		t.Fatalf("overlap check is blind: %v", got)
	}
	for _, p := range []string{keepManifestPath, rotatorManifestPath} {
		if !slices.Contains(meshManifestPaths, p) {
			t.Errorf("%s is not validated against the Mesh schema", p)
		}
	}
	keep := readManifestCaps(t, keepManifestPath)
	rot := readManifestCaps(t, rotatorManifestPath)
	if keep.ID != "keep" || rot.ID != "keep-rotator" {
		t.Fatalf("manifest ids %q and %q, want keep and keep-rotator", keep.ID, rot.ID)
	}
	if shared := sharedRotationRights(keep.Capabilities.API, rot.Capabilities.API); len(shared) != 0 {
		t.Errorf("rotation rights %v are held by both keep and keep-rotator", shared)
	}
	for _, r := range rotationRights {
		if slices.Contains(keep.Capabilities.API, r) {
			t.Errorf("keep manifest holds rotation right %q; it belongs to keep-rotator", r)
		}
	}
	// The rotator still needs the two rights its routes are mapped to in Mesh.
	for _, r := range []string{"agent_key:rotate", "ext_token:self_rotate"} {
		if !slices.Contains(rot.Capabilities.API, r) {
			t.Errorf("keep-rotator manifest lacks %q", r)
		}
	}
}

func TestMeshRotatorManifestIsNarrow(t *testing.T) {
	m := readManifestCaps(t, rotatorManifestPath)
	if m.Version != "0.1.0" {
		t.Errorf("keep-rotator version %q, want 0.1.0", m.Version)
	}
	api := slices.Clone(m.Capabilities.API)
	sort.Strings(api)
	want := []string{"agent_key:rotate", "agent_keys:read", "ext_token:self_rotate"}
	if !slices.Equal(api, want) {
		t.Errorf("keep-rotator api %v, want exactly %v", m.Capabilities.API, want)
	}
	if len(m.Capabilities.Events) != 0 {
		t.Errorf("keep-rotator subscribes to events %v", m.Capabilities.Events)
	}
	if len(m.Capabilities.UI) != 0 || len(m.External.UI) != 0 {
		t.Errorf("keep-rotator declares screens: %v %v", m.Capabilities.UI, m.External.UI)
	}
	if len(m.Capabilities.Network) != 0 {
		t.Errorf("keep-rotator declares network domains: %s", m.Capabilities.Network)
	}
	if len(m.Capabilities.Secrets) != 0 {
		t.Errorf("keep-rotator declares secrets %v", m.Capabilities.Secrets)
	}
	// keep-rotator takes its token by self-rotation: with a token_path Mesh
	// would deliver it to /mesh/token, which refuses any id but keep.
	if m.External.TokenPath != "" {
		t.Errorf("keep-rotator declares token_path %q", m.External.TokenPath)
	}
}
