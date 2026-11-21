package api

// meshUIPagesHTML is the markup of the Secrets list and of the page of one
// secret, on the component classes of the Mesh brief (§4). Same rules as
// meshUIHTML: html/template escapes every field, no inline script or style.
// The shared icons (search, key, alert, back) come from meshUIHTML; icon-copy
// is local and carries its own size.
const meshUIPagesHTML = `
{{define "icon-copy"}}<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>{{end}}
{{define "wrap"}}{{range $i, $p := .Parts}}{{if $i}}<wbr>{{end}}{{$p}}{{end}}{{end}}
{{define "badge"}}<span class="badge badge-{{.Badge}}">{{.Label}}</span>{{end}}

{{define "add-button"}}{{if .Add.Enabled}}<a class="btn btn-sm" href="/mesh/ui/secrets/new">{{template "icon-plus"}}Add secret</a>{{else}}<span class="add-off"><button class="btn btn-sm" type="button" disabled aria-describedby="add-why">Add secret</button> <span class="muted" id="add-why">{{.Add.Reason}}</span></span>{{end}}{{end}}
{{define "icon-plus"}}<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 5v14M5 12h14"/></svg>{{end}}
{{define "add-form"}}<form class="add-form" method="post" action="/mesh/ui/secrets/new" autocomplete="off"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label class="field"><span>Name</span><input class="input" type="text" name="name" value="{{.Add.Name}}" required maxlength="128" spellcheck="false" autocapitalize="off" placeholder="stripe-api-key"></label>
<label class="field"><span>Who can use it</span><select class="select" name="scope">{{range .Add.Scopes}}<option value="{{.Value}}"{{if .Selected}} selected{{end}}>{{.Label}}</option>{{end}}</select></label>
<label class="field"><span>Class</span><input class="input" type="text" name="class" value="{{.Add.Class}}" maxlength="64" spellcheck="false" autocapitalize="off"></label>
<button class="btn" type="submit">Create input link</button></form>{{end}}
{{define "copy-row"}}<div class="copy-row"><input class="input mono" id="{{.ID}}" type="text" value="{{.Value}}" readonly spellcheck="false" aria-label="{{.Label}}"><button class="btn btn-outline" type="button" data-copy-from="{{.ID}}" data-copy-kind="{{.Kind}}">{{template "icon-copy"}}{{.Button}}</button></div>{{end}}

{{define "secrets"}}{{template "head" .}}<div class="page-head"><div><h1>Secrets</h1><p class="muted">Names, versions and fingerprints only. Values never reach this page.</p></div>{{if .Total}}{{template "add-button" .}}{{end}}</div>
{{if .Total}}<div class="summary">
<a class="card stat" href="{{.AllHref}}"><div class="n">{{.Total}}</div><div class="l">Secrets</div></a>
{{if .ShowCarriers}}<div class="card stat"><div class="n">{{.CarrierTotal}}</div><div class="l">Carriers</div></div>{{end}}
<a class="card stat{{if .Attention}} warn{{end}}" href="{{.AttentionHref}}"><div class="n">{{.Attention}}</div><div class="l">Need attention</div></a>
{{if .ShowRotating}}<a class="card stat" href="{{.RotatingHref}}"><div class="n">{{.Rotating}}</div><div class="l">Rotating now</div></a>{{end}}
</div>
<form class="toolbar" method="get" action="/mesh/ui/secrets" role="search" data-autosubmit>
<label class="search"><span class="sr-only">Name</span>{{template "icon-search"}}<input class="input" type="search" name="q" value="{{.Q}}" maxlength="128" placeholder="Search by name"></label>
<label><span class="sr-only">Class</span><select class="select" name="class">{{range .Classes}}<option value="{{.Value}}"{{if .Selected}} selected{{end}}>{{.Label}}</option>{{end}}</select></label>
<label><span class="sr-only">Scope</span><select class="select" name="scope">{{range .Scopes}}<option value="{{.Value}}"{{if .Selected}} selected{{end}}>{{.Label}}</option>{{end}}</select></label>
{{if .StateQ}}<input type="hidden" name="state" value="{{.StateQ}}">{{end}}
<span class="spacer"></span>
<nav class="seg" aria-label="State">{{range .States}}<a href="{{.Href}}"{{if .Current}} aria-current="true"{{end}}>{{.Label}}{{if .Count}} <span class="count">{{.Count}}</span>{{end}}</a>{{end}}</nav>
<label><span class="sr-only">Sort</span><select class="select" name="sort">{{range .Sorts}}<option value="{{.Value}}"{{if .Selected}} selected{{end}}>{{.Label}}</option>{{end}}</select></label>
<button class="btn btn-outline btn-sm" type="submit" data-apply>Apply</button></form>
{{if .Rows}}<div class="card"><table class="table"><thead><tr><th>Name</th><th>Class · scope</th><th>Current version</th>{{if .ShowCarriers}}<th class="num">Carriers in sync</th>{{end}}<th>Last rotated</th><th>State</th></tr></thead><tbody>
{{range .Rows}}<tr><td class="first"><span><a class="row-link" href="{{.Href}}">{{.Name}}</a>{{if .Description}} <span class="sub">{{.Description}}</span>{{end}}</span> <span class="sm-only">{{template "badge" .State}}</span></td>
<td class="nowrap" data-k="Class"><span class="badge badge-outline">{{.Class}}</span> <span class="muted">· {{.Scope}}</span></td>
<td class="nowrap" data-k="Version">{{if .HasVersion}}{{.Version}} <span class="mono">{{.Fingerprint}}</span>{{else}}— <span class="muted">no value yet</span>{{end}}</td>
{{if $.ShowCarriers}}<td class="num" data-k="Carriers">{{.Carriers}}</td>{{end}}<td class="nowrap" data-k="Rotated">{{.Rotated}}</td><td class="hide-sm">{{template "badge" .State}}</td></tr>
{{end}}</tbody></table>
<div class="foot"><span>{{.From}}–{{.To}} of {{.Matched}}</span><span>{{if .PrevHref}}<a class="btn btn-outline btn-sm" href="{{.PrevHref}}" rel="prev">Previous</a>{{end}} {{if .NextHref}}<a class="btn btn-outline btn-sm" href="{{.NextHref}}" rel="next">Next</a>{{end}}</span></div></div>
{{if .Truncated}}<p class="muted">Only the first 1000 secrets are listed. Narrow the filter to find the rest.</p>{{end}}
{{else}}<div class="section"><div class="card"><div class="empty">{{template "icon-search"}}<p>{{if .Q}}No secret matches “{{.Q}}”{{else}}No secret matches these filters{{end}}</p><a class="btn btn-ghost btn-sm" href="/mesh/ui/secrets">Reset filters</a></div></div></div>{{end}}
{{else}}<div class="card"><div class="empty">{{template "icon-key"}}<p>No secrets yet</p><small>Name a secret and Keep makes a one-time input link for whoever holds the value. The value goes straight to Keep, never through Mesh or chat.</small>{{if .Add.Enabled}}{{template "add-form" .}}{{else}}<div class="add-slot">{{template "add-button" .}}</div>{{end}}</div></div>{{end}}
{{template "foot" .}}{{end}}

{{define "secret"}}{{template "head" .}}<a class="crumb" href="/mesh/ui/secrets">{{template "icon-back"}}Secrets</a>
<div class="page-head"><div><h1>{{template "wrap" .Heading}}</h1>
<div class="meta"><span class="badge badge-outline">{{.Class}}</span> <span>Scope <b>{{.Scope}}</b></span> <span>Store <b>{{.StoreName}}</b> <span class="muted">{{.StoreProvider}}</span></span> <span>Created <b>{{.Created}}</b></span></div>
{{if .Description}}<p class="muted">{{.Description}}</p>{{end}}</div></div>
{{with .Banner}}<div class="banner banner-{{.Level}}" role="status">{{template "icon-alert"}}<div><b>{{.Title}}</b> {{if .Where}}{{template "wrap" .Where}} {{end}}{{.Text}}{{if .Command}} <code>{{.Command}}</code>{{end}}</div></div>{{end}}
{{if .ShowCarriers}}<div class="section"><div class="section-head"><h2>Carriers{{if .Carriers}} <span class="muted">· {{.InSync}} of {{len .Carriers}} in sync</span>{{end}}</h2><span class="muted">Checked by fingerprint, never by value</span></div>
<div class="card">{{if .Carriers}}<table class="table"><thead><tr><th>Host</th><th>Target</th><th>Consumer · health check</th><th>State</th><th>Last verified</th></tr></thead><tbody>
{{range .Carriers}}<tr><td class="first"><span><b>{{template "wrap" .Host}}</b> <span class="sub">{{.Kind}}</span></span> <span class="sm-only">{{template "badge" .State}}</span></td>
<td data-k="Target"><span class="mono">{{template "wrap" .Path}}</span>{{if .Field}} <span class="sub">{{.Field}}</span>{{end}}</td>
<td data-k="Consumer">{{if .Consumer}}{{.Consumer}}{{else}}—{{end}} <span class="sub">{{if .Health}}{{.Health}}{{else}}—{{end}}</span></td>
<td class="hide-sm">{{template "badge" .State}}</td><td class="nowrap" data-k="Verified">{{.Verified}}</td></tr>
{{end}}</tbody></table>{{else}}<div class="empty">{{template "icon-key"}}<p>Not laid out anywhere yet</p><small>A runner lays the current version out to a file or a service: <code>{{.DeployCommand}}</code></small></div>{{end}}</div></div>{{end}}
<div class="section"><div class="section-head"><h2>Versions</h2></div>
<div class="card">{{if .Versions}}<table class="table"><thead><tr><th>Version</th><th>Fingerprint</th><th class="num">Length</th><th>Created</th><th>Status</th></tr></thead><tbody>
{{range .Versions}}<tr><td class="first"><b>{{.Version}}</b> <span class="sm-only">{{template "badge" .State}}</span></td>
<td data-k="Fingerprint"><span class="copy"><span class="mono">{{.Fingerprint}}</span><button type="button" title="Copy fingerprint" aria-label="Copy fingerprint" data-copy="{{.Fingerprint}}">{{template "icon-copy"}}</button></span></td>
<td class="num" data-k="Length">{{.Length}}</td><td class="nowrap" data-k="Created">{{.Created}}</td><td class="hide-sm">{{template "badge" .State}}</td></tr>
{{end}}</tbody></table>{{else}}<div class="empty">{{template "icon-key"}}<p>No value yet</p><small>Send a one-time input link to whoever holds the value. The value goes straight to Keep.</small>
<div class="link-block">{{template "copy-row" .InputCopy}}
{{if .CanLink}}<form method="post" action="/mesh/ui/secrets/{{.ID}}/input-link"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="btn" type="submit">Create input link</button></form>{{else}}<span class="add-off"><button class="btn btn-sm" type="button" disabled aria-describedby="link-why">Create input link</button> <span class="muted" id="link-why">{{.LinkReason}}</span></span>{{end}}
<p class="copy-status muted" role="status" data-copy-status></p></div></div>{{end}}</div></div>
{{if .ShowRotations}}<div class="section"><div class="section-head"><h2>Rotations</h2>{{if .Runs}}<a class="muted" href="{{.RunsHref}}">All rotations{{if gt .RunsTotal (len .Runs)}} ({{.RunsTotal}}){{end}}</a>{{end}}</div>
<div class="card">{{if .Runs}}<table class="table"><thead><tr><th>Started</th><th>Versions</th><th>Result</th></tr></thead><tbody>
{{range .Runs}}<tr><td class="first"><span><a class="row-link" href="{{.Href}}">{{.Started}}</a> <span class="sub">{{.By}}</span></span> <span class="sm-only">{{template "badge" .State}}</span></td>
<td data-k="Versions">{{.Versions}}</td><td class="hide-sm">{{template "badge" .State}}</td></tr>
{{end}}</tbody></table>{{else}}<div class="empty"><p>No rotations yet</p></div>{{end}}</div></div>{{end}}
{{template "foot" .}}{{end}}

{{define "secret-missing"}}{{template "head" .}}<a class="crumb" href="/mesh/ui/secrets">{{template "icon-back"}}Secrets</a>
<div class="card"><div class="empty">{{template "icon-search"}}<p>Secret not found</p><small>It does not exist, or this account cannot see it.</small><a class="btn btn-ghost btn-sm" href="/mesh/ui/secrets">Back to Secrets</a></div></div>
{{template "foot" .}}{{end}}

{{define "secret-new"}}{{template "head" .}}<a class="crumb" href="/mesh/ui/secrets">{{template "icon-back"}}Secrets</a>
<div class="page-head"><div><h1>Add secret</h1><p class="muted">Keep creates the record and a one-time input link. Whoever holds the value opens the link and types it into Keep directly.</p></div></div>
{{if .Add.Error}}<div class="banner banner-danger" role="alert">{{template "icon-alert"}}<div>{{.Add.Error}}{{if .Exists}} <a href="{{.Exists}}">Open the secret</a>{{end}}</div></div>{{end}}
<div class="card pad">{{if .Add.Enabled}}{{template "add-form" .}}{{else}}{{template "add-button" .}}{{end}}</div>
{{template "foot" .}}{{end}}

{{define "secret-issued"}}{{template "head" .}}<a class="crumb" href="/mesh/ui/secrets">{{template "icon-back"}}Secrets</a>
<div class="page-head"><div><h1>{{template "wrap" .Heading}}</h1>
<div class="meta"><span class="badge badge-outline">One-time link</span> <span>Scope <b>{{.Scope}}</b></span>{{if .ExpiresIn}} <span>Expires in <b>{{.ExpiresIn}}</b> <span class="muted">· {{.Expires}}</span></span>{{end}}</div></div></div>
<div class="banner banner-ok" role="status">{{template "icon-alert"}}<div><b>Input link ready.</b> Send it to whoever holds the value, or open it yourself. The value is typed on Keep’s input page and never passes through Mesh.</div></div>
<div class="card pad link-block"><h2>Input link</h2>
{{template "copy-row" .LinkCopy}}
<div class="actions"><a class="btn" href="{{.URL}}" target="_blank" rel="noopener noreferrer">Open input page</a></div>
<p class="muted">One-time link: it works once{{if .ExpiresIn}} and expires in {{.ExpiresIn}}{{end}}. Anyone who has it can set the value, so send it only to the person who holds it.</p>
<h2>Or from a terminal</h2>
{{template "copy-row" .CommandCopy}}
<p class="muted">Issues another one-time link for the same secret.</p>
<p class="copy-status muted" role="status" data-copy-status></p></div>
<div class="actions"><a class="btn btn-outline btn-sm" href="{{.SecretHref}}">Open the secret</a> <a class="btn btn-ghost btn-sm" href="/mesh/ui/secrets/new">Add another</a></div>
{{template "foot" .}}{{end}}
`
