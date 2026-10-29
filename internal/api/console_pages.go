package api

import "html/template"

// consoleTemplates is the whole UI. html/template escapes every field by
// context; there is no script, no inline style and no foreign URL.
var consoleTemplates = template.Must(template.New("console").Parse(`
{{define "head"}}<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Keep — approvals</title>
<link rel="stylesheet" href="/console/console.css"></head><body>
<header><strong>Keep</strong>{{if .CSRF}}<nav><a href="/console/approvals">Requests</a>
<form method="post" action="/console/logout" class="inline"><input type="hidden" name="csrf" value="{{.CSRF}}"><button type="submit" class="link">Sign out</button></form></nav>{{end}}</header><main>{{end}}
{{define "foot"}}</main></body></html>{{end}}

{{define "login"}}{{template "head" .}}<h1>Sign in</h1>
{{if .Error}}<p class="err" role="alert">{{.Error}}</p>{{end}}
<form method="post" action="/console/login"><label>Human token
<input type="password" name="token" autocomplete="off" required></label>
<button type="submit">Sign in</button></form>{{template "foot" .}}{{end}}

{{define "error"}}{{template "head" .}}<h1>Something went wrong</h1><p class="err" role="alert">{{.Message}}</p>
{{if .RequestID}}<p class="muted">request_id: {{.RequestID}}</p>{{end}}
<p><a href="/console/approvals">Back to requests</a></p>{{template "foot" .}}{{end}}

{{define "list"}}{{template "head" .}}<h1>Approval requests</h1>
{{if .Rows}}<div class="scroll"><table><thead><tr><th>Secret</th><th>Class</th><th>Target</th><th>Requested by</th><th>Status</th><th>Expires</th></tr></thead><tbody>
{{range .Rows}}<tr><td><a href="/console/approvals/{{.ID}}">{{.Secret}}</a></td><td>{{.Class}}</td><td>{{.Target}}</td><td>{{.Requester}}</td><td class="st-{{.Status}}">{{.StatusText}}</td><td>{{.Expires}}</td></tr>
{{end}}</tbody></table></div>{{else}}<p>No requests.</p>{{end}}{{template "foot" .}}{{end}}

{{define "card"}}{{template "head" .}}<h1>Request: {{.Secret}}</h1>
<p class="st-{{.Status}}">Status: <strong>{{.StatusText}}</strong></p>
{{if .Note}}<p class="note">{{.Note}}</p>{{end}}
<dl>
<dt>Requested by</dt><dd>{{.Requester}}</dd>
{{if .Sponsor}}<dt>Agent's sponsor</dt><dd>{{.Sponsor}}</dd>{{end}}
<dt>Secret</dt><dd>{{.Secret}} ({{.Class}})</dd>
<dt>Scope</dt><dd>{{.Scope}}</dd>
<dt>Host (runner)</dt><dd>{{.Runner}}</dd>
{{range .Target}}<dt>{{.Name}}</dt><dd>{{.Value}}</dd>
{{end}}
<dt>Requested</dt><dd>{{.Requested}}</dd>
<dt>Valid until</dt><dd>{{.Expires}}</dd>
{{if .Decided}}<dt>Decided at</dt><dd>{{.Decided}}</dd>{{end}}
{{if .Reason}}<dt>Reason</dt><dd>{{.Reason}}</dd>{{end}}
<dt>Content hash</dt><dd class="mono">{{.Hash}}</dd>
<dt>request_id</dt><dd class="mono">{{.RequestID}}</dd>
</dl>
{{if .NetAllowlist}}<section class="warn"><h2>Network destinations</h2><ul>{{range .NetAllowlist}}<li>{{.}}</li>{{end}}</ul><p>{{.NetWarning}}</p></section>{{end}}
<p class="muted">The secret value is never shown here.</p>
{{if .CanDecide}}<form method="post" action="/console/approvals/{{.ID}}/decision">
<input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="binding" value="{{.Hash}}">
<label>Reason (required to reject)<input type="text" name="reason" maxlength="200"></label>
<div class="actions"><button type="submit" name="decision" value="approve">Approve</button>
<button type="submit" name="decision" value="reject" class="danger">Reject</button></div></form>{{end}}
{{template "foot" .}}{{end}}
`))

const consoleStyle = `*{box-sizing:border-box}body{margin:0;font:16px/1.5 system-ui,sans-serif;color:#1b1f24;background:#f6f7f9}
header{display:flex;flex-wrap:wrap;gap:8px;justify-content:space-between;align-items:center;padding:12px 16px;background:#1b1f24;color:#fff}
header a,.link{color:#fff;background:none;border:0;padding:0;font:inherit;cursor:pointer;text-decoration:underline;margin-left:12px}
.inline{display:inline}main{max-width:960px;margin:0 auto;padding:16px}
h1{font-size:1.4rem}dl{display:grid;grid-template-columns:max-content 1fr;gap:6px 16px;background:#fff;padding:16px;border:1px solid #d8dce2;border-radius:6px}
dt{color:#57606a}dd{margin:0;overflow-wrap:anywhere}.mono{font-family:ui-monospace,monospace;font-size:.85rem}
.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;background:#fff}th,td{text-align:left;padding:8px;border-bottom:1px solid #e3e6ea}
input[type=text],input[type=password]{display:block;width:100%;padding:8px;margin:4px 0 12px;font:inherit}
button{padding:10px 18px;font:inherit;border:0;border-radius:4px;background:#1a7f37;color:#fff;cursor:pointer}button.danger{background:#cf222e}
.actions{display:flex;gap:12px;flex-wrap:wrap}.warn{background:#fff8c5;border:1px solid #d4a72c;padding:12px 16px;border-radius:6px;margin:16px 0}
.err{color:#cf222e}.muted{color:#57606a;font-size:.9rem}.note{background:#ddf4ff;padding:8px 12px;border-radius:6px}
.st-approved{color:#1a7f37}.st-rejected,.st-expired{color:#cf222e}
@media (max-width:600px){dl{grid-template-columns:1fr}dt{margin-top:8px}button{width:100%}}
`
