package api

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// themeHarness drives the screen script's theme handling with a fake root
// element: every style property the script sets is recorded. It prints one
// JSON object with what each scenario left on the root.
const themeHarness = `
const { create } = require(process.argv[2]);
const MESH = 'https://mesh.example.test', EVIL = 'https://evil.example.test';
const parent = { postMessage() {} };
function mk() {
  const props = {};
  const root = { style: { setProperty(n, v) { props[n] = String(v); } } };
  const api = create({ origins: [MESH], parent, needLogin: false, root,
    workspace() {}, login() { return Promise.resolve(false); }, reload() {} });
  return { api, props };
}
const good = { '--background': '180 29% 6%', '--foreground': '180 67% 94%', '--primary': '172 66% 50%', '--radius': '0.75rem', 'card': '180 35% 9%' };
const bad = {
  '--muted': 'red;background:url(x)',
  '--accent': 'expression(alert(1))',
  '--border': '1'.repeat(33),
  '--ring': '1 2% 3%; color: red',
  '--input': 12,
  '--radius-evil': '1rem',
  '--font-sans': '"Comic Sans MS"',
  '--sidebar-background': '1 2% 3%',
  'background-image': '1 2% 3%',
  '__proto__': '1 2% 3%',
  '----secondary': '1 2% 3%',
  '--warning': '',
};
const badRadius = [{ '--radius': '1px' }, { '--radius': '1234567rem' }, { '--radius': '1rem;x' }, { '--radius': 'calc(1rem)' }];
const out = {};
let s;
s = mk(); s.api.onMessage({ source: parent, origin: MESH, data: { type: 'mesh.context', version: 1, theme: { mode: 'dark', tokens: good } } }); out.v1 = s.props;
s = mk(); s.api.onMessage({ source: parent, origin: MESH, data: { type: 'mesh.context', version: 2, slot: 'sidebar.item', theme: { mode: 'dark', tokens: good } } }); out.v2 = s.props;
s = mk(); s.api.onMessage({ source: parent, origin: MESH, data: { type: 'mesh.theme', version: 2, mode: 'light', tokens: good } }); out.themeMsg = s.props;
s = mk(); s.api.onMessage({ source: parent, origin: MESH, data: { type: 'mesh.context', version: 1, theme: { mode: 'dark', tokens: bad } } }); out.badCtx = s.props;
s = mk(); s.api.onMessage({ source: parent, origin: MESH, data: { type: 'mesh.theme', version: 2, mode: 'purple', tokens: bad } }); out.badTheme = s.props;
out.badRadius = badRadius.map(t => { const m = mk(); m.api.onMessage({ source: parent, origin: MESH, data: { type: 'mesh.theme', version: 2, mode: 'light', tokens: t } }); return m.props; });
s = mk(); s.api.onMessage({ source: parent, origin: EVIL, data: { type: 'mesh.theme', version: 2, mode: 'dark', tokens: good } }); out.foreign = s.props;
s = mk(); s.api.onMessage({ source: {}, origin: MESH, data: { type: 'mesh.theme', version: 2, mode: 'dark', tokens: good } }); out.otherWindow = s.props;
s = mk(); s.api.onMessage({ source: parent, origin: MESH, data: { type: 'mesh.context', version: 3, theme: { mode: 'dark', tokens: good } } }); out.v3 = s.props;
s = mk(); for (const t of [null, 'dark', 5, { mode: 'dark', tokens: 'x' }, { mode: 'dark', tokens: null }]) { s.api.onMessage({ source: parent, origin: MESH, data: { type: 'mesh.context', version: 1, theme: t } }); } out.malformed = s.props;
console.log(JSON.stringify(out));
`

func runThemeHarness(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI to run the screen script test")
		}
		t.Skip("node not installed")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "app.js")
	if err := os.WriteFile(script, []byte(meshUIScript), 0o600); err != nil {
		t.Fatal(err)
	}
	harness := filepath.Join(dir, "harness.js")
	if err := os.WriteFile(harness, []byte(themeHarness), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, harness, script) //nolint:gosec // G204: node found by LookPath, harness is a file this test writes
	cmd.Dir = dir
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("node: %v %s", err, raw)
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("harness output: %v %s", err, raw)
	}
	return out
}

// The theme arrives from Mesh in mesh.context (protocol 1 and 2) and in
// mesh.theme. Only the listed token names with values of the listed shape
// reach the root style; anything else is dropped without a trace.
func TestMeshUIScriptAppliesOnlyValidThemeTokens(t *testing.T) {
	out := runThemeHarness(t)
	props := func(k string) map[string]string {
		var m map[string]string
		if err := json.Unmarshal(out[k], &m); err != nil {
			t.Fatalf("%s: %v %s", k, err, out[k])
		}
		return m
	}
	applied := map[string]string{"--background": "180 29% 6%", "--foreground": "180 67% 94%", "--primary": "172 66% 50%", "--radius": "0.75rem", "--card": "180 35% 9%"}
	for k, mode := range map[string]string{"v1": "dark", "v2": "dark", "themeMsg": "light"} {
		got := props(k)
		for name, v := range applied {
			if got[name] != v {
				t.Errorf("%s: %s = %q, want %q (all: %v)", k, name, got[name], v, got)
			}
		}
		if got["color-scheme"] != mode {
			t.Errorf("%s: color-scheme = %q, want %q", k, got["color-scheme"], mode)
		}
		if len(got) != len(applied)+1 {
			t.Errorf("%s: unexpected properties set: %v", k, got)
		}
	}
	if got := props("badCtx"); len(got) != 1 || got["color-scheme"] != "dark" {
		t.Errorf("an invalid token name or value reached the root style: %v", got)
	}
	if got := props("badTheme"); len(got) != 0 {
		t.Errorf("an invalid token or mode reached the root style: %v", got)
	}
	var radius []map[string]string
	if err := json.Unmarshal(out["badRadius"], &radius); err != nil {
		t.Fatal(err)
	}
	for i, got := range radius {
		if _, ok := got["--radius"]; ok {
			t.Errorf("invalid radius %d reached the root style: %v", i, got)
		}
	}
	for _, k := range []string{"foreign", "otherWindow", "v3", "malformed"} {
		if got := props(k); len(got) != 0 {
			t.Errorf("%s: a theme from a foreign origin, another window, an unknown version or a malformed payload was applied: %v", k, got)
		}
	}
}

// The style is painted with the Mesh theme tokens: no palette of its own, no
// system font, no dark-mode guess of its own, and every token the CSS reads
// has a fallback (the Mesh light theme) on :root.
func TestMeshUIStyleUsesOnlyMeshTokens(t *testing.T) {
	for _, banned := range []string{"system-ui", "#2457d6", "prefers-color-scheme", "@import", "url(http", "url(//", "data:"} {
		if strings.Contains(meshUIStyle, banned) {
			t.Errorf("style carries %q", banned)
		}
	}
	allowed := map[string]bool{"radius": true, "font-sans": true, "font-mono": true}
	for _, n := range meshThemeColorTokens {
		allowed[n] = true
	}
	root := regexp.MustCompile(`(?s):root\{(.*?)\}`).FindStringSubmatch(meshUIStyle)
	if root == nil {
		t.Fatal("style has no :root block")
	}
	for n := range allowed {
		if !strings.Contains(root[1], "--"+n+":") {
			t.Errorf(":root has no fallback for --%s", n)
		}
	}
	for _, m := range regexp.MustCompile(`var\(--([a-z0-9-]+)\)`).FindAllStringSubmatch(meshUIStyle, -1) {
		if !allowed[m[1]] {
			t.Errorf("style reads --%s, which is not a Mesh theme token", m[1])
		}
	}
	if regexp.MustCompile(`#[0-9a-fA-F]{3,8}\b`).MatchString(meshUIStyle) {
		t.Error("style has a hex colour of its own")
	}
	// The script's list of names is exactly the list the style falls back on.
	list := regexp.MustCompile(`var THEME = \[([^\]]*)\];`).FindStringSubmatch(meshUIScript)
	if list == nil {
		t.Fatal("the script has no THEME list")
	}
	var script []string
	for _, m := range regexp.MustCompile(`'([^']*)'`).FindAllStringSubmatch(list[1], -1) {
		script = append(script, m[1])
	}
	if strings.Join(script, ",") != strings.Join(meshThemeColorTokens, ",") {
		t.Errorf("the script accepts %v, the style falls back on %v", script, meshThemeColorTokens)
	}
}
