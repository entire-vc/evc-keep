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
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// meshParentJS is the Mesh side of the protocol: it frames the screen, answers
// mesh.ready with mesh.context and acts on resize, navigate and toast. The
// browser script reads window.__log and the DOM; nothing here is Keep code.
const meshParentJS = `(function () {
  var b = document.body, k = document.getElementById('keep'), keep = b.dataset.keep, sendContext = b.dataset.context !== '0';
  window.__log = [];
  document.getElementById('secrets-nav').addEventListener('click', function () { k.src = b.dataset.src; });
  addEventListener('message', function (e) {
    if (e.source !== k.contentWindow || e.origin !== keep) { window.__log.push({ type: 'foreign' }); return; }
    var d = e.data || {};
    window.__log.push({ type: d.type, height: d.height, path: d.path, level: d.level, message: d.message });
    if (d.type === 'mesh.ready' && sendContext) {
      k.contentWindow.postMessage({ type: 'mesh.context', version: 1, workspace_slug: 'acme', token: b.dataset.fresh }, keep);
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

func TestMeshUIBrowserScenario(t *testing.T) {
	f := newUIFixture(t)
	cn := canary.New()
	f.seedSecret("deploy-token", cn.Value(1))
	f.seedSecret("db-password", cn.Value(2))
	f.seedSecret("a-very-long-secret-name-that-must-wrap-in-a-narrow-frame-without-overflow", cn.Value(3))
	for sub, role := range map[string]identity.Role{"viewer": identity.RoleViewer, "boss": identity.RoleAdmin} {
		f.login(sub, sub+"@example.test") // creates the user; the browser never sees this cookie
		f.grant(sub, role)
	}

	keep := httptest.NewTLSServer(f.router)
	t.Cleanup(keep.Close)
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
<body data-keep=%q data-context=%q data-src=%q data-fresh=%q><nav id=side><strong>Mesh</strong><a>Projects</a><a id=secrets-nav aria-current=page>%s</a></nav>
<div id=main><div id=bar>workspace: <span id=where></span> <span id=toast></span></div><iframe id=keep title=%q%s></iframe></div><script src=/parent.js></script></body></html>`,
			keep.URL, map[bool]string{true: "0", false: "1"}[q.Get("context") == "0"], src+"?token="+first, fresh, html.EscapeString(side.Title), side.Title, auto)
		_, _ = io.WriteString(w, page) //nolint:gosec // G705: test fake page, its inputs are the harness's own URLs and tokens
	})
	f.mesh.SetPages(mux)

	domDump := filepath.Join(t.TempDir(), "dom.txt")
	in, _ := json.Marshal(map[string]any{"keep": keep.URL, "mesh": mesh, "domDump": domDump,
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
	// What the browser really rendered (markup and text of the list and the
	// settings frames, after the screen script ran) must not carry a value. The
	// dump must hold the rows, or the scan proves nothing.
	dom, err := os.ReadFile(domDump) //nolint:gosec // G304: a file in t.TempDir()
	if err != nil || !strings.Contains(string(dom), "deploy-token") || !strings.Contains(string(dom), "Organization key level") {
		t.Fatal("the DOM dump is missing or does not hold the screens it must scan")
	}
	if cn.In(string(dom)) {
		t.Fatal("canary in the browser DOM")
	}
	if cn.In(f.logbuf.String()) {
		t.Fatal("canary in the server log")
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
