package app

import (
	"encoding/json"
	"os"
	"slices"
	"sort"
	"strings"
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

// TestReadmeDescribesEveryManifestPermission holds the catalog rule that the
// README says what Keep does with each right it asks for: every API right,
// event and UI slot of the keep manifest has its own row in the Permissions
// section, and every network domain is named there.
func TestReadmeDescribesEveryManifestPermission(t *testing.T) {
	m := readManifestCaps(t, keepManifestPath)
	raw, err := os.ReadFile("../../../README.md")
	if err != nil {
		t.Fatalf("README: %v", err)
	}
	section := readmeSection(string(raw), "## Permissions")
	if section == "" {
		t.Fatal("README has no ## Permissions section")
	}
	var net struct {
		AllowedDomains []string `json:"allowed_domains"`
	}
	if err := json.Unmarshal(m.Capabilities.Network, &net); err != nil {
		t.Fatalf("manifest network: %v", err)
	}
	if len(m.Capabilities.API) == 0 || len(m.Capabilities.Events) == 0 || len(m.Capabilities.UI) == 0 || len(net.AllowedDomains) == 0 {
		t.Fatal("manifest declares an empty api, events, ui or network list: nothing to check")
	}
	for _, list := range [][]string{m.Capabilities.API, m.Capabilities.Events, m.Capabilities.UI} {
		for _, name := range list {
			if !readmeHasRow(section, name) {
				t.Errorf("README Permissions has no row for %s that says what Keep does", name)
			}
		}
	}
	for _, d := range net.AllowedDomains {
		if !strings.Contains(section, "`"+d+"`") {
			t.Errorf("README Permissions does not name the domain %s", d)
		}
	}
	// handleResolveSecret answers a Mesh workspace with a stored value, so the
	// section may not claim that no value ever reaches Mesh.
	if strings.Contains(section, "No secret value is sent to Mesh") {
		t.Error("README Permissions claims no value reaches Mesh, but resolve returns one")
	}
	if !strings.Contains(section, "/mesh/secrets/{ref}/resolve") || !strings.Contains(section, "no-store") {
		t.Error("README Permissions does not name the resolve exception and its no-store answer")
	}
}

// readmeSection returns the text from the heading line to the next heading of
// the same level, or "" when the heading is absent.
func readmeSection(doc, heading string) string {
	start := strings.Index(doc, "\n"+heading+"\n")
	if start < 0 {
		return ""
	}
	rest := doc[start+1+len(heading):]
	if end := strings.Index(rest, "\n## "); end >= 0 {
		rest = rest[:end]
	}
	return rest
}

// readmeHasRow reports whether section has a table row for name whose next
// cell, what Keep does with it, is not empty.
func readmeHasRow(section, name string) bool {
	for _, line := range strings.Split(section, "\n") {
		cells := strings.Split(line, "|")
		if len(cells) > 3 && strings.TrimSpace(cells[1]) == "`"+name+"`" && strings.TrimSpace(cells[2]) != "" {
			return true
		}
	}
	return false
}

func TestReadmeSectionStopsAtNextHeading(t *testing.T) {
	doc := "# T\n\n## Permissions\n\n| `a:read` | reads |\n\n## Accounts\n\n| `b:read` | reads |\n"
	section := readmeSection(doc, "## Permissions")
	if !readmeHasRow(section, "a:read") {
		t.Error("row inside the section not found")
	}
	if readmeHasRow(section, "b:read") {
		t.Error("row after the next ## heading counted as inside the section")
	}
	if readmeSection(doc, "## Rights") != "" {
		t.Error("absent heading returned text")
	}
	if readmeHasRow("| `a:read` | | |", "a:read") {
		t.Error("row with an empty description counted")
	}
}
