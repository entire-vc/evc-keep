//go:build mesh_ui_browser

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// meshParentJS is the Mesh side of the protocol: it frames the screen, answers
// mesh.ready with mesh.context and acts on resize, navigate and toast. With
// data-theme it puts the Mesh theme into mesh.context and window.__theme(mode)
// sends mesh.theme, as Mesh does when the person switches light and dark. The
// browser script reads window.__log and the DOM; nothing here is Keep code.
const meshParentJS = `(function () {
  var b = document.body, k = document.getElementById('keep'), keep = b.dataset.keep, sendContext = b.dataset.context !== '0';
  var THEMES = {
    light: { '--background': '0 0% 100%', '--foreground': '180 23% 8%', '--card': '0 0% 100%', '--card-foreground': '180 23% 8%',
      '--primary': '180 100% 21%', '--primary-foreground': '0 0% 100%', '--muted': '180 20% 96%', '--muted-foreground': '180 10% 40%',
      '--border': '180 28% 90%', '--input': '180 28% 90%', '--ring': '180 100% 21%', '--radius': '0.5rem' },
    dark: { '--background': '180 29% 6%', '--foreground': '180 67% 94%', '--card': '180 35% 9%', '--card-foreground': '180 67% 94%',
      '--primary': '172 66% 50%', '--primary-foreground': '180 45% 4%', '--secondary': '180 32% 17%', '--secondary-foreground': '180 67% 94%',
      '--muted': '180 36% 12%', '--muted-foreground': '180 10% 55%', '--accent': '172 66% 50%', '--accent-foreground': '180 45% 4%',
      '--destructive': '0 91% 71%', '--success': '142 71% 45%', '--border': '180 30% 20%', '--input': '180 30% 20%', '--ring': '172 66% 50%',
      '--radius': '0.5rem', '--font-sans': '"Comic Sans MS"', '--warning': 'red;background:url(/x)' }
  };
  var mode = b.dataset.theme || '';
  window.__log = [];
  window.__theme = function (m) { mode = m; k.contentWindow.postMessage({ type: 'mesh.theme', version: 2, mode: m, tokens: THEMES[m] }, keep); };
  document.getElementById('secrets-nav').addEventListener('click', function () { k.src = b.dataset.src; });
  addEventListener('message', function (e) {
    if (e.source !== k.contentWindow || e.origin !== keep) { window.__log.push({ type: 'foreign' }); return; }
    var d = e.data || {};
    window.__log.push({ type: d.type, height: d.height, path: d.path, level: d.level, message: d.message });
    if (d.type === 'mesh.ready' && sendContext) {
      var c = { type: 'mesh.context', version: 1, workspace_slug: 'acme', token: b.dataset.fresh };
      if (mode) { c.theme = { mode: mode, tokens: THEMES[mode] }; }
      k.contentWindow.postMessage(c, keep);
    }
    if (d.type === 'mesh.resize') { k.style.height = d.height + 'px'; }
    if (d.type === 'mesh.navigate') { document.getElementById('where').textContent = d.path; }
    if (d.type === 'mesh.toast') { var t = document.getElementById('toast'); t.textContent = d.message; t.dataset.level = d.level; }
  });
})();`

const meshParentCSS = `body{margin:0;font:15px system-ui;display:flex;min-height:100vh}
#side{width:200px;flex:none;background:#20232a;color:#ddd;padding:12px}#side a{display:block;padding:8px;color:#ddd;cursor:pointer}
#side a[aria-current]{background:#3a3f4b}#main{flex:1;min-width:0;padding:0}#bar{padding:8px 12px;border-bottom:1px solid #ccc}
iframe{border:0;width:100%;height:300px;display:block}
@media (max-width:600px){body{display:block}#side{width:auto;display:flex;gap:8px}}`

// meshFrameSandbox is the sandbox and permissions Mesh gives an extension
// screen (evc-mesh external-frame.tsx): popups that escape the sandbox, so
// an input link opens in a new tab, and clipboard writes, no top navigation.
const meshFrameSandbox = `sandbox="allow-scripts allow-forms allow-same-origin allow-popups allow-popups-to-escape-sandbox" allow="clipboard-write"`

func TestMeshUIBrowserScenario(t *testing.T) {
	// The server starts before the router: input links carry its origin.
	var router atomic.Value
	keep := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { router.Load().(http.Handler).ServeHTTP(w, r) }))
	keep.StartTLS()
	t.Cleanup(keep.Close)
	f := newUIFixtureInput(t, keep.URL)
	router.Store(f.router)
	cn := canary.New()
	token, tokenV := f.seedSecret("deploy-token", cn.Value(1))
	f.seedCarrier(token, tokenV, "web-1.example.test", "/etc/app/token", "registered")
	f.seedCarrier(token, tokenV, "a-host-with-a-long-name-that-must-wrap.example.test", "/srv/a/very/deep/path/that/must/wrap/in/a/narrow/frame/token", "stale")
	f.seedSecret("db-password", cn.Value(2))
	f.seedSecret("a-very-long-secret-name-that-must-wrap-in-a-narrow-frame-without-overflow", cn.Value(3))
	for sub, role := range map[string]identity.Role{"viewer": identity.RoleViewer, "boss": identity.RoleAdmin} {
		f.login(sub, sub+"@example.test") // creates the user; the browser never sees this cookie
		f.grant(sub, role)
	}
	// A member with no grant yet: the list is empty, the screen shows how a
	// secret gets added (the empty state at 393 px, light and dark).
	f.login("newcomer", "newcomer@example.test")
	// Adds a secret from the screen: name → one-time link → new tab, copy.
	f.login("adder", "adder@example.test")

	mesh := f.mesh.URL()
	mux := http.NewServeMux()
	mux.HandleFunc("/parent.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		_, _ = w.Write([]byte(meshParentJS))
	})
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	// A valid context token for the evil-page control, which must fail to use it.
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(f.token(r.URL.Query().Get("sub"), r.URL.Query().Get("sub")+"@example.test"))) //nolint:gosec // G705: test fake, a signed token as plain text for the browser harness
	})
	// A Mesh-origin page that is not the screen's parent: opens the screen as a
	// popup. Its messages carry an allowed origin but not the parent window.
	mux.HandleFunc("/pop", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, "<!doctype html><script>window.__w = null; function openIt() { window.__w = window.open(%q, 'k'); }</script>", r.URL.Query().Get("u")) //nolint:gosec // G705: test fake page, its inputs are the harness's own URLs and tokens
	})
	mux.HandleFunc("/parent.css", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		_, _ = w.Write([]byte(meshParentCSS))
	})
	// The sidebar entry is drawn from the manifest, as Mesh draws it from the
	// manifest it stored at install.
	side := manifestSidebarItem(t)
	mux.HandleFunc("/parent", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		sub := q.Get("sub")
		src := keep.URL + side.Path
		fresh := f.token(sub, sub+"@example.test")
		first := fresh
		if q.Get("expired") == "1" { // the URL token has lapsed; the screen must sign in through mesh.context
			c := f.mesh.Valid(f.ws.String(), meshSub(sub), sub+"@example.test")
			c["iat"], c["nbf"], c["exp"] = time.Now().Add(-20*time.Minute).Unix(), time.Now().Add(-20*time.Minute).Unix(), time.Now().Add(-10*time.Minute).Unix()
			first = sign(f.mesh.Key0(0), nil, c)
		}
		auto := ""
		if q.Get("autoload") == "1" {
			auto = fmt.Sprintf(" src=%q", src+"?token="+first)
		}
		w.Header().Set("Content-Type", "text/html")
		page := fmt.Sprintf(`<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><link rel=stylesheet href=/parent.css></head>
<body data-keep=%q data-context=%q data-theme=%q data-src=%q data-fresh=%q><nav id=side><strong>Mesh</strong><a>Projects</a><a id=secrets-nav aria-current=page>%s</a></nav>
<div id=main><div id=bar>workspace: <span id=where></span> <span id=toast></span></div><iframe id=keep title=%q %s%s></iframe></div><script src=/parent.js></script></body></html>`,
			keep.URL, map[bool]string{true: "0", false: "1"}[q.Get("context") == "0"], map[bool]string{true: "dark", false: ""}[q.Get("theme") == "dark"], src+"?token="+first, fresh, html.EscapeString(side.Title), side.Title, meshFrameSandbox, auto)
		_, _ = io.WriteString(w, page) //nolint:gosec // G705: test fake page, its inputs are the harness's own URLs and tokens
	})
	f.mesh.SetPages(mux)

	domDump := filepath.Join(t.TempDir(), "dom.txt")
	linkDump := filepath.Join(t.TempDir(), "links.txt")
	in, _ := json.Marshal(map[string]any{"keep": keep.URL, "mesh": mesh, "domDump": domDump, "linkDump": linkDump,
		"shots": os.Getenv("KEEP_MESH_UI_SHOTS"), "names": []string{"deploy-token", "db-password"}})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", "../../../scripts/check-mesh-ui-browser.mjs")
	cmd.Stdin = bytes.NewReader(in)
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	err := cmd.Run()
	// Nothing the browser run prints may carry a secret value.
	for name, s := range map[string]string{"stdout": out.String(), "stderr": stderr.String()} {
		if cn.In(s) {
			t.Fatalf("canary in the browser script %s", name)
		}
	}
	if err != nil {
		t.Fatalf("browser scenario failed: %v\n%s", err, strings.TrimSpace(stderr.String()))
	}
	t.Logf("browser scenario: %s", strings.TrimSpace(out.String()))
	// What the browser really rendered (markup and text of the list, the page
	// of one secret and the settings frames, after the screen script ran) must
	// not carry a value. The dump must hold all three, each by a marker only
	// that screen draws (the list: its summary; the secret: its carriers head;
	// settings: its level), or the scan proves nothing.
	dom, err := os.ReadFile(domDump) //nolint:gosec // G304: a file in t.TempDir()
	if err != nil || !strings.Contains(string(dom), "Need attention") || !strings.Contains(string(dom), "Checked by fingerprint") || !strings.Contains(string(dom), "Current level") {
		t.Fatal("the DOM dump is missing or does not hold the screens it must scan")
	}
	if cn.In(string(dom)) {
		t.Fatal("canary in the browser DOM")
	}
	if cn.In(f.logbuf.String()) {
		t.Fatal("canary in the server log")
	}
	// The input links the screen issued: real, and none in the server log
	// (positive control: the log is not empty).
	links, err := os.ReadFile(linkDump) //nolint:gosec // G304: a file in t.TempDir()
	if err != nil {
		t.Fatal("no input links were recorded by the browser run")
	}
	tokens := 0
	for _, l := range strings.Fields(string(links)) {
		tok, _, _ := strings.Cut(strings.TrimPrefix(l, keep.URL+"/input/"), "#")
		if tok == "" || tok == l || strings.Contains(f.logbuf.String(), tok) || f.logbuf.Len() == 0 {
			t.Fatal("an input link is malformed or its token reached the server log")
		}
		tokens++
	}
	if tokens < 2 {
		t.Fatalf("input links recorded: %d, want the 1440 and 393 runs", tokens)
	}
}

func manifestSidebarItem(t *testing.T) struct{ Path, Title string } {
	t.Helper()
	raw, err := os.ReadFile("../../../mesh-extension.json")
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	var m struct {
		External struct {
			UI map[string]struct {
				Path  string `json:"path"`
				Title string `json:"title"`
			} `json:"ui"`
		} `json:"external"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("manifest is not JSON: %v", err)
	}
	side, ok := m.External.UI["sidebar.item"]
	if !ok || side.Path == "" || side.Title == "" {
		t.Fatalf("manifest has no sidebar item: %+v", m.External.UI)
	}
	return struct{ Path, Title string }{side.Path, side.Title}
}
