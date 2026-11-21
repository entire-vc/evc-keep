package api

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// jsHarness drives the screen's script with fake window/parent objects. It
// prints one JSON object: what the script posted to the parent and what it did.
const jsHarness = `
const { create } = require(process.argv[2]);
const MESH = 'https://mesh.example.test', EVIL = 'https://evil.example.test';
const parent = { sent: [], postMessage(m, o) { this.sent.push([m, o]); } };
const other = {};
const log = { workspace: [], login: [], reload: 0 };
function mk(origins, needLogin) {
  parent.sent.length = 0; log.workspace.length = 0; log.login.length = 0; log.reload = 0;
  return create({ origins, parent, needLogin, workspace: s => log.workspace.push(s),
    login: t => { log.login.push(t); return Promise.resolve(true); }, reload: () => { log.reload++; } });
}
const ctxMsg = (extra) => Object.assign({ type: 'mesh.context', version: 1, token: 'T', workspace_slug: 'acme' }, extra || {});
const out = {};
(async () => {
  let a = mk([MESH], true);
  a.onMessage({ source: parent, origin: EVIL, data: ctxMsg() });               // foreign origin
  for (const near of [MESH + '.evil.example.test', MESH + ':8443', 'https://MESH.example.test', MESH + '/', 'null', '', undefined]) {
    a.onMessage({ source: parent, origin: near, data: ctxMsg() });             // near-miss origins
  }
  a.onMessage({ source: other, origin: MESH, data: ctxMsg() });                // not the parent window
  a.onMessage({ source: parent, origin: MESH, data: { type: 'mesh.context', version: 3, token: 'T' } });    // unknown protocol version
  a.onMessage({ source: parent, origin: MESH, data: { type: 'mesh.theme', version: 2, token: 'T', workspace_slug: 'acme' } }); // a theme message never signs in
  a.onMessage({ source: parent, origin: MESH, data: ctxMsg({ type: 'mesh.toast' }) });   // right shape, wrong type
  a.onMessage({ source: parent, origin: MESH, data: 'mesh.context' });
  a.onMessage({ source: parent, origin: MESH, data: null });
  a.onMessage(null);
  await new Promise(r => setTimeout(r, 5));
  out.ignored = { login: log.login.length, ws: log.workspace.length, ctx: a.context() };
  a.onMessage({ source: parent, origin: MESH, data: ctxMsg() });
  await new Promise(r => setTimeout(r, 5));
  out.accepted = { login: log.login.slice(), ws: log.workspace.slice(), reload: log.reload, hasCtx: a.context() !== null };
  parent.sent.length = 0;
  a.ready(); a.resize(480.2); a.resize(-1); a.resize('x'); a.toast('success', 'x'.repeat(400));
  a.navigate('/w/acme/dashboard'); a.navigate('//evil.example.test'); a.navigate('https://evil.example.test'); a.navigate('/\\evil'); a.navigate(5);
  out.sent = parent.sent.slice();
  // Two installed Meshes: nothing is sent until the first accepted context names the target.
  let b = mk([MESH, 'https://mesh2.example.test'], false);
  b.ready(); out.beforeContext = parent.sent.length;
  b.onMessage({ source: parent, origin: EVIL, data: ctxMsg() }); b.ready(); out.afterForeign = parent.sent.length;
  b.onMessage({ source: parent, origin: 'https://mesh2.example.test', data: ctxMsg() }); b.ready();
  out.afterOwn = parent.sent.slice();
  // A page that already has a session never posts the token anywhere.
  let c = mk([MESH], false);
  c.onMessage({ source: parent, origin: MESH, data: ctxMsg() });
  await new Promise(r => setTimeout(r, 5));
  out.noLogin = log.login.length;
  // Protocol 2 (Mesh with the theme) signs in the same way, once.
  let d = mk([MESH], true);
  d.onMessage({ source: parent, origin: MESH, data: ctxMsg({ version: 2, slot: 'sidebar.item', theme: { mode: 'dark', tokens: {} } }) });
  await new Promise(r => setTimeout(r, 5));
  out.v2 = { login: log.login.slice(), ws: log.workspace.slice(), reload: log.reload };
  console.log(JSON.stringify(out));
})();
`

func TestMeshUIScriptPostMessageProtocol(t *testing.T) {
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
	if err := os.WriteFile(harness, []byte(jsHarness), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, harness, script) //nolint:gosec // G204: node found by LookPath, harness is a file this test writes
	cmd.Dir = dir
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("node: %v %s", err, raw)
	}
	var out struct {
		Ignored struct {
			Login, WS int
			Ctx       any
		}
		Accepted struct {
			Login  []string
			WS     []string
			Reload int
			HasCtx bool
		}
		Sent          [][]any
		BeforeContext int
		AfterForeign  int
		AfterOwn      [][]any
		NoLogin       int
		V2            struct {
			Login, WS []string
			Reload    int
		}
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("harness output: %v %s", err, raw)
	}
	if out.Ignored.Login != 0 || out.Ignored.WS != 0 || out.Ignored.Ctx != nil {
		t.Errorf("a foreign origin, a non-parent source or a malformed message was acted on: %+v", out.Ignored)
	}
	if len(out.Accepted.Login) != 1 || out.Accepted.Login[0] != "T" || out.Accepted.Reload != 1 || !out.Accepted.HasCtx || len(out.Accepted.WS) != 1 || out.Accepted.WS[0] != "acme" {
		t.Errorf("the genuine context was not applied: %+v", out.Accepted)
	}
	// ready, resize(480), toast, navigate(/w/acme/dashboard): nothing else.
	want := []string{`{"type":"mesh.ready"}`, `{"height":481,"type":"mesh.resize"}`, "toast", `{"path":"/w/acme/dashboard","type":"mesh.navigate"}`}
	if len(out.Sent) != len(want) {
		t.Fatalf("sent %d messages, want %d: %v", len(out.Sent), len(want), out.Sent)
	}
	for i, s := range out.Sent {
		if s[1] != "https://mesh.example.test" {
			t.Errorf("message %d went to %v, not the Mesh origin", i, s[1])
		}
		b, _ := json.Marshal(s[0])
		if want[i] == "toast" {
			var m struct{ Type, Level, Message string }
			_ = json.Unmarshal(b, &m)
			if m.Type != "mesh.toast" || m.Level != "success" || len(m.Message) != 300 {
				t.Errorf("toast: %s", b)
			}
		} else if string(b) != want[i] {
			t.Errorf("message %d = %s, want %s", i, b, want[i])
		}
	}
	if out.BeforeContext != 0 || out.AfterForeign != 0 || len(out.AfterOwn) != 1 || out.AfterOwn[0][1] != "https://mesh2.example.test" {
		t.Errorf("with two Meshes the target must be the one that spoke: %d %d %v", out.BeforeContext, out.AfterForeign, out.AfterOwn)
	}
	if len(out.V2.Login) != 1 || out.V2.Login[0] != "T" || out.V2.Reload != 1 || len(out.V2.WS) != 1 || out.V2.WS[0] != "acme" {
		t.Errorf("a protocol 2 context did not sign in exactly once: %+v", out.V2)
	}
	if out.NoLogin != 0 {
		t.Error("a page with a session posted the token to the server")
	}
	if strings.Contains(meshUIScript, "innerHTML") || strings.Contains(meshUIScript, "eval(") {
		t.Error("the script writes markup or evaluates code")
	}
}

// copyHarness drives copy() through every branch of the fallback chain with
// fake clipboard and selection objects.
const copyHarness = `
const { copy, copyMessage } = require(process.argv[2]);
const LINK = 'https://keep.example.test/input/TOKEN#signing=SIG&request=1';
function env(clip, canSelect, execOK) {
  const log = { selected: 0, exec: 0, wrote: [] };
  return { log, e: {
    clipboard: clip === 'ok' ? { writeText: t => { log.wrote.push(t); return Promise.resolve(); } }
      : clip === 'reject' ? { writeText: () => Promise.reject(new Error('NotAllowedError')) }
      : clip === 'throw' ? { writeText: () => { throw new Error('sync'); } } : null,
    select: () => { log.selected++; return canSelect; },
    exec: () => { log.exec++; if (execOK === 'throw') { throw new Error('x'); } return execOK; } } };
}
(async () => {
  const out = {};
  for (const [name, clip, sel, ex] of [['api', 'ok', true, true], ['reject', 'reject', true, true], ['throw', 'throw', true, true],
    ['none', null, true, true], ['execFalse', 'reject', true, false], ['execThrows', null, true, 'throw'], ['nothing', null, false, true]]) {
    const { log, e } = env(clip, sel, ex);
    const how = await copy(e, LINK);
    out[name] = { how, selected: log.selected, exec: log.exec, wrote: log.wrote };
  }
  out.msgs = ['link', 'command', 'fingerprint', 'other'].flatMap(k => ['clipboard', 'exec', 'manual'].map(h => copyMessage(k, h)));
  console.log(JSON.stringify(out));
})();
`

func TestMeshUIScriptCopyNeverSilent(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI to run the screen script test")
		}
		t.Skip("node not installed")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "app.js")
	harness := filepath.Join(dir, "copy.js")
	if os.WriteFile(script, []byte(meshUIScript), 0o600) != nil || os.WriteFile(harness, []byte(copyHarness), 0o600) != nil {
		t.Fatal("write harness")
	}
	cmd := exec.Command(node, harness, script) //nolint:gosec // G204: node found by LookPath, harness is a file this test writes
	cmd.Dir = dir
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("node: %v %s", err, raw)
	}
	type run struct {
		How      string
		Selected int
		Exec     int
		Wrote    []string
	}
	var out struct {
		API, Reject, Throw, None, ExecFalse, ExecThrows, Nothing run
		Msgs                                                     []struct{ Level, Text string }
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("harness output: %v %s", err, raw)
	}
	if out.API.How != "clipboard" || out.API.Exec != 0 || len(out.API.Wrote) != 1 {
		t.Errorf("clipboard API path: %+v", out.API)
	}
	for name, r := range map[string]run{"reject": out.Reject, "throw": out.Throw, "none": out.None} {
		if r.How != "exec" || r.Selected != 1 || r.Exec != 1 {
			t.Errorf("%s: no select+execCommand fallback: %+v", name, r)
		}
	}
	for name, r := range map[string]run{"execFalse": out.ExecFalse, "execThrows": out.ExecThrows} {
		if r.How != "manual" || r.Selected != 2 {
			t.Errorf("%s: the field is not left selected for Ctrl/Cmd+C: %+v", name, r)
		}
	}
	if out.Nothing.How != "manual" || out.Nothing.Exec != 0 {
		t.Errorf("nothing to select: %+v", out.Nothing)
	}
	if len(out.Msgs) != 12 {
		t.Fatalf("messages: %+v", out.Msgs)
	}
	for i, m := range out.Msgs {
		manual := i%3 == 2
		switch {
		case m.Text == "":
			t.Errorf("message %d is empty: copy would fail silently", i)
		case strings.Contains(m.Text, "keep.example.test") || strings.Contains(m.Text, "TOKEN") || strings.Contains(m.Text, "input-link"):
			t.Errorf("message %d carries the copied text: %q", i, m.Text)
		case manual && (m.Level != "info" || !strings.Contains(m.Text, "+C")):
			t.Errorf("manual message %d: %+v", i, m)
		case !manual && m.Level != "success":
			t.Errorf("success message %d: %+v", i, m)
		}
	}
	if out.Msgs[0].Text != "Link copied" || out.Msgs[3].Text != "Command copied" || out.Msgs[6].Text != "Fingerprint copied" {
		t.Errorf("kind texts: %+v", out.Msgs)
	}
}
