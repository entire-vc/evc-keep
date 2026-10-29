package api

// meshUIHTML is the whole markup of the Mesh screen. html/template escapes
// every field by context; there is no inline script, no inline style and no
// foreign URL (the policy would block them anyway).
const meshUIHTML = `
{{define "head"}}<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Keep — secrets</title>
<link rel="stylesheet" href="/mesh/ui/app.css"><script src="/mesh/ui/app.js" defer></script></head>
<body data-origins="{{.OriginList}}"{{if .NeedLogin}} data-login="1"{{end}}{{if .Toast}} data-toast="{{.Toast}}" data-toast-level="{{.ToastLvl}}"{{end}}>
{{if .Active}}<header><nav aria-label="Keep">
<a href="/mesh/ui/secrets"{{if eq .Active "secrets"}} aria-current="page"{{end}}>Secrets</a>
<a href="/mesh/ui/settings"{{if eq .Active "settings"}} aria-current="page"{{end}}>Key level</a>
</nav><button type="button" class="link" data-mesh-workspace hidden>Open workspace</button></header>{{end}}
<main>{{end}}
{{define "foot"}}</main></body></html>{{end}}

{{define "signedout"}}{{template "head" .}}<h1>Keep</h1>
<p class="note" role="status">{{if .NeedLogin}}Signing in through Mesh…{{else}}Open this screen from Mesh to sign in.{{end}}</p>{{template "foot" .}}{{end}}

{{define "unavailable"}}{{template "head" .}}<h1>Unavailable</h1>
<p class="err" role="alert">The service is temporarily unavailable or the request was refused. Reload the screen from Mesh.</p>{{template "foot" .}}{{end}}

{{define "secrets"}}{{template "head" .}}<h1>Secrets</h1>
<form method="get" action="/mesh/ui/secrets" class="filters" role="search">
<label>Name <input type="search" name="q" value="{{.Q}}" maxlength="128" placeholder="Filter by name"></label>
<label>Class <select name="class"><option value="">All</option>
<option value="api_token"{{if eq .Class "api_token"}} selected{{end}}>api_token</option>
<option value="password"{{if eq .Class "password"}} selected{{end}}>password</option>
<option value="key"{{if eq .Class "key"}} selected{{end}}>key</option>
<option value="certificate"{{if eq .Class "certificate"}} selected{{end}}>certificate</option></select></label>
<button type="submit">Filter</button></form>
{{if .Rows}}<div class="scroll"><table><thead><tr><th>Name</th><th>Scope</th><th>Class</th><th>Version</th><th>Fingerprint</th><th>Length</th><th>Status</th></tr></thead><tbody>
{{range .Rows}}<tr><td data-label="Name"><strong>{{.Name}}</strong></td><td data-label="Scope">{{.Scope}}</td><td data-label="Class">{{.Class}}</td>
{{if .HasVersion}}<td data-label="Version">{{.Version}}</td><td data-label="Fingerprint"><code>{{.Fingerprint}}</code></td><td data-label="Length">{{.Length}}</td><td data-label="Status" class="st-{{.Status}}">{{.Status}}</td>
{{else}}<td data-label="Version" colspan="4" class="muted">no value yet</td>{{end}}</tr>
{{end}}</tbody></table></div>
{{if .Truncated}}<p class="muted">Showing the first 200. Narrow the filter to see the rest.</p>{{end}}
{{else}}<p class="empty">{{if or .Q .Class}}No secret matches this filter.{{else}}No secrets yet. Values are never shown here, only names, versions and fingerprints.{{end}}</p>{{end}}
{{template "foot" .}}{{end}}

{{define "settings"}}{{template "head" .}}<h1>Organization key level</h1>
{{if .Error}}<p class="err" role="alert">{{.Error}}</p>{{end}}
{{if .Available}}<dl><dt>Current level</dt><dd><strong>{{.Level}}</strong></dd>
{{if .ChangedAt}}<dt>Changed</dt><dd>{{.ChangedAt}} by {{.ChangedBy}}</dd>{{end}}</dl>
{{if .Result}}<p class="note" role="status">Re-wrapped {{.Result.Rewrapped}}, unchanged {{.Result.Unchanged}}, retired {{.Result.Retired}}.</p>{{end}}
<p class="muted">The level decides how many stores share one key: <em>user</em> separates each user's secrets cryptographically; <em>organization</em> shares one key across the organization. Values are never re-encrypted; only their keys are re-wrapped.</p>
{{if .CanChange}}<form method="post" action="/mesh/ui/settings/key-level" class="stack"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label>New level <select name="level">{{range .Levels}}<option value="{{.}}"{{if eq . $.Level}} selected{{end}}>{{.}}</option>{{end}}</select></label>
<label class="check"><input type="checkbox" name="confirm_weakening" value="yes"> I understand that a coarser level lets more stores share a key</label>
<button type="submit">Change level</button></form>
{{else if .IsAdmin}}<p class="note">Changing the level is not available on this server.</p>
{{else}}<p class="note">Only an organization admin can change the level.</p>{{end}}
{{else}}<p class="note">The key level is not available on this server.</p>{{end}}
{{template "foot" .}}{{end}}
`

const meshUIStyle = `*{box-sizing:border-box}
:root{color-scheme:light dark;--fg:#1b1f24;--bg:#f6f7f9;--card:#fff;--line:#d8dce2;--muted:#5b6470;--accent:#2457d6;--err:#b3261e;--ok:#1a7f37}
@media (prefers-color-scheme:dark){:root{--fg:#e6e8eb;--bg:#16181c;--card:#1e2126;--line:#33373e;--muted:#9aa3ae;--accent:#7aa2ff;--err:#ff8a80;--ok:#56d364}}
body{margin:0;font:15px/1.5 system-ui,sans-serif;color:var(--fg);background:var(--bg)}
header{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:10px 16px;border-bottom:1px solid var(--line);background:var(--card)}
nav{display:flex;gap:4px}nav a{padding:6px 12px;border-radius:6px;color:var(--muted);text-decoration:none}
nav a[aria-current=page]{background:var(--bg);color:var(--fg);font-weight:600}
main{padding:16px;max-width:1100px;margin:0 auto}h1{font-size:20px;margin:4px 0 14px}
.filters{display:flex;flex-wrap:wrap;gap:12px;align-items:flex-end;margin-bottom:14px}
label{display:flex;flex-direction:column;gap:4px;font-size:13px;color:var(--muted)}
input,select,button{font:inherit;padding:7px 10px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg)}
button{background:var(--accent);color:#fff;border-color:var(--accent);cursor:pointer}
button.link{background:none;border:0;color:var(--accent);padding:0}
.scroll{overflow-x:auto}table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px}
th,td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
code{font:13px ui-monospace,monospace;word-break:break-all}
.muted{color:var(--muted)}.err{color:var(--err)}.note{padding:10px 12px;border:1px solid var(--line);border-radius:6px;background:var(--card)}
.empty{padding:28px 12px;text-align:center;color:var(--muted)}.st-current{color:var(--ok)}.st-disabled{color:var(--err)}
dl{display:grid;grid-template-columns:max-content 1fr;gap:6px 16px}dt{color:var(--muted)}dd{margin:0}
.stack{display:flex;flex-direction:column;gap:12px;max-width:420px}.check{flex-direction:row;align-items:flex-start;gap:8px;font-size:14px}
@media (max-width:600px){
main{padding:12px}.filters label,.filters input,.filters select{width:100%}
table,thead,tbody,tr,td{display:block;border:0}thead{position:absolute;left:-9999px}
tr{background:var(--card);border:1px solid var(--line);border-radius:8px;margin-bottom:10px;padding:6px 0}
td{display:flex;justify-content:space-between;gap:12px;border:0;padding:4px 12px;min-width:0;text-align:right;overflow-wrap:anywhere}
td::before{content:attr(data-label);color:var(--muted);font-size:12px;text-transform:uppercase;flex:none;text-align:left}
.scroll{overflow-x:visible}table{table-layout:fixed}label{min-width:0}
td[colspan]{display:block}td[colspan]::before{content:none}
}
`

// meshUIScript speaks the postMessage protocol of docs/extensions/ui-iframe.md
// on the Mesh side: it acts on a message only from the parent window and only
// from an origin recorded at install; everything else is ignored silently.
const meshUIScript = `(function (root) {
  'use strict';
  function create(env) {
    var origins = env.origins, target = origins.length === 1 ? origins[0] : null, ctx = null;
    function allowed(o) { return origins.indexOf(o) !== -1; }
    function send(msg) { if (target) { env.parent.postMessage(msg, target); } }
    function path(p) { return typeof p === 'string' && p.charAt(0) === '/' && p.charAt(1) !== '/' && p.indexOf('\\') === -1; }
    function onMessage(ev) {
      if (!ev || ev.source !== env.parent || !allowed(ev.origin)) { return; }
      var d = ev.data;
      if (!d || typeof d !== 'object' || d.type !== 'mesh.context' || d.version !== 1) { return; }
      target = ev.origin;
      ctx = d;
      if (typeof d.workspace_slug === 'string' && /^[a-z0-9-]{1,64}$/.test(d.workspace_slug)) { env.workspace(d.workspace_slug); }
      if (env.needLogin && typeof d.token === 'string') {
        env.login(d.token).then(function (ok) { if (ok) { env.reload(); } }, function () {});
      }
    }
    return {
      onMessage: onMessage,
      ready: function () { send({ type: 'mesh.ready' }); },
      resize: function (h) { if (typeof h === 'number' && h > 0) { send({ type: 'mesh.resize', height: Math.ceil(h) }); } },
      navigate: function (p) { if (path(p)) { send({ type: 'mesh.navigate', path: p }); } },
      toast: function (level, message) { send({ type: 'mesh.toast', level: level, message: String(message).slice(0, 300) }); },
      context: function () { return ctx; }
    };
  }
  function start() {
    var b = document.body, origins = (b.dataset.origins || '').split(' ').filter(Boolean);
    var slug = null;
    var api = create({
      origins: origins, parent: window.parent, needLogin: b.dataset.login === '1',
      workspace: function (s) { slug = s; var el = document.querySelector('[data-mesh-workspace]'); if (el) { el.hidden = false; } },
      login: function (token) {
        return fetch('/mesh/ui/session', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin', body: JSON.stringify({ token: token }) })
          .then(function (r) { return r.ok; });
      },
      reload: function () { location.replace('/mesh/ui/secrets'); }
    });
    window.addEventListener('message', api.onMessage);
    document.addEventListener('click', function (e) {
      var el = e.target.closest && e.target.closest('[data-mesh-workspace]');
      if (el && slug) { api.navigate('/w/' + slug); }
    });
    if (window.ResizeObserver) { new ResizeObserver(function () { api.resize(document.documentElement.scrollHeight); }).observe(document.documentElement); }
    if (b.dataset.toast) { api.toast(b.dataset.toastLevel || 'info', b.dataset.toast); }
    api.ready();
  }
  if (typeof module !== 'undefined' && module.exports) { module.exports = { create: create }; } else { start(); }
})(this);
`
