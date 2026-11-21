package api

// meshUIRotationHTML is the markup of the rotation screens, on the classes of
// the screen's shell. No inline script or style: the policy blocks both.
// The run page's live part is the one [data-live] node; data-live-active on it
// tells the screen's live script to fetch the page again in 3 s.
const meshUIRotationHTML = `
{{define "rotation-notfound"}}{{template "head" .}}<div class="empty" role="status">
<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>
<p>Not found</p><small>This secret or rotation does not exist, or you cannot see it.</small>
<a class="btn btn-outline btn-sm" href="/mesh/ui/secrets">Back to secrets</a></div>{{template "foot" .}}{{end}}

{{define "rotations"}}{{template "head" .}}
<a class="crumb" href="/mesh/ui/secrets/{{.SecretID}}">← {{.SecretName}}</a>
<div class="page-head"><div><h1>Rotations</h1><p class="muted">Every rotation run of {{.SecretName}}, newest first.</p></div></div>
{{if .CanFilter}}<div class="toolbar"><nav class="seg" aria-label="Result">
<a href="/mesh/ui/secrets/{{.SecretID}}/rotations"{{if not .Failed}} aria-current="true"{{end}}>All</a>
<a href="/mesh/ui/secrets/{{.SecretID}}/rotations?result=failed"{{if .Failed}} aria-current="true"{{end}}>Failed</a></nav></div>{{end}}
{{if .Rows}}<div class="card"><table class="table"><thead><tr><th>Started</th><th>Versions</th><th class="hide-sm">Result</th></tr></thead><tbody>
{{range .Rows}}<tr><td class="first"><span><a class="row-link" href="/mesh/ui/secrets/{{$.SecretID}}/rotations/{{.ID}}">{{if .Started}}{{.Started}}{{else}}Run{{end}}</a>{{if .By}}<span class="sub">{{.By}}</span>{{end}}</span>
<span class="sm-only"><span class="badge badge-{{.Tone}}">{{.Result}}</span></span></td>
<td data-k="Versions">{{.Versions}}</td><td class="hide-sm"><span class="badge badge-{{.Tone}}">{{.Result}}</span></td></tr>
{{end}}</tbody></table>
<div class="foot"><span>{{.From}}–{{.To}} of {{.Total}}</span><span>{{if .PrevHref}}<a class="btn btn-outline btn-sm" href="{{.PrevHref}}">Previous</a>{{end}}
{{if .NextHref}}<a class="btn btn-outline btn-sm" href="{{.NextHref}}">Next</a>{{end}}</span></div></div>
{{else}}<div class="card"><div class="empty" role="status">
<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M21 12a9 9 0 1 1-3-6.7L21 8"/><path d="M21 3v5h-5"/></svg>
{{if .Failed}}<p>No failed rotations</p><small>Every rotation of this secret that ended is either done or still running.</small>
<a class="btn btn-outline btn-sm" href="/mesh/ui/secrets/{{.SecretID}}/rotations">Show all</a>
{{else if .Total}}<p>No rotations on this page</p><a class="btn btn-outline btn-sm" href="/mesh/ui/secrets/{{.SecretID}}/rotations">First page</a>
{{else}}<p>No rotations yet</p><small>A rotation starts from the API or the <code>rotate</code> MCP tool; its progress shows up here.</small>{{end}}
</div></div>{{end}}
{{template "foot" .}}{{end}}

{{define "rotation-run"}}{{template "head" .}}
<a class="crumb" href="/mesh/ui/secrets/{{.SecretID}}/rotations">← {{.SecretName}} · rotations</a>
<div data-live{{if .Live}} data-live-active{{end}}>
<div class="page-head"><div><h1>{{.Title}}</h1><div class="meta"><span class="badge badge-{{.StatusTone}}">{{.Status}}</span>
{{if .Started}}<span>Started <b>{{.Started}}</b></span>{{end}}{{if .By}}<span>By <b>{{.By}}</b></span>{{end}}
<span>Request <b class="mono">{{.RunID}}</b></span>{{if .Approval}}<span>Approval <b>{{.Approval}}</b></span>{{end}}</div></div></div>
<div class="banner{{if .Banner.Tone}} banner-{{.Banner.Tone}}{{end}}" role="status"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M12 8v4m0 4h.01"/></svg>
<div><b>{{.Banner.Head}}</b>{{if .Banner.Body}} {{.Banner.Body}}{{end}}{{if .Banner.Class}} Cause: <span class="mono">{{.Banner.Class}}</span>.{{end}}</div></div>
<ol class="steps">{{range .Steps}}<li{{if .State}} class="{{.State}}"{{end}}><b>{{.Name}}</b><span>{{.Note}}</span></li>{{end}}</ol>
<div class="section"><div class="section-head"><h2>Carriers</h2>{{if .Live}}<span class="muted">Updates every 3 s while the run is active</span>{{end}}</div>
{{if .Carriers}}<div class="card"><table class="table"><thead><tr><th>Carrier</th><th class="hide-sm">Phase</th><th class="hide-sm">State</th><th>Detail</th></tr></thead><tbody>
{{range .Carriers}}<tr><td class="first"><span><b>{{.Host}}</b>{{if .Target}}<span class="sub mono">{{.Target}}</span>{{end}}</span>
<span class="sm-only"><span class="badge badge-{{.Tone}}">{{.Phase}} · {{.State}}</span></span></td>
<td class="hide-sm">{{.Phase}}</td><td class="hide-sm"><span class="badge badge-{{.Tone}}">{{.State}}</span></td>
<td data-k="Detail">{{if .Class}}<span class="mono">{{.Class}}</span>{{else}}—{{end}}</td></tr>
{{end}}</tbody></table></div>
{{else}}<div class="card"><div class="empty" role="status"><p>No carriers in this run yet</p><small>Carriers appear once the new version is laid out.</small></div></div>{{end}}
</div></div>
<script src="/mesh/ui/live.js" defer></script>
{{template "foot" .}}{{end}}
`

// meshUILiveScript keeps the run page current without a JSON API: while the
// page's [data-live] node carries data-live-active it fetches the same page
// (same origin, the session cookie only), parses it with DOMParser and puts
// the new [data-live] node in place of the old one. It stops for good once a
// fetched page has no data-live-active, or on any answer that is not the page.
const meshUILiveScript = `(function (root) {
  'use strict';
  var PERIOD = 3000;
  function create(env) {
    var stopped = false, timer = null;
    function active(node) { return !!node && node.hasAttribute('data-live-active'); }
    function stop() { stopped = true; if (timer !== null) { env.clear(timer); timer = null; } }
    function schedule() { if (!stopped) { timer = env.later(tick, PERIOD); } }
    function tick() {
      timer = null;
      if (stopped) { return; }
      env.fetch().then(function (html) {
        if (stopped) { return; }
        if (typeof html !== 'string') { stop(); return; }
        var next = env.parse(html).querySelector('[data-live]');
        var cur = env.current();
        if (!next || !cur) { stop(); return; }
        env.replace(cur, next);
        if (active(next)) { schedule(); } else { stop(); }
      }, function () { stop(); });
    }
    return {
      start: function () { if (active(env.current())) { schedule(); } else { stop(); } },
      stop: stop,
      stopped: function () { return stopped; }
    };
  }
  function start() {
    var live = create({
      current: function () { return document.querySelector('[data-live]'); },
      fetch: function () {
        return fetch(location.href, { credentials: 'same-origin', cache: 'no-store', redirect: 'error', headers: { 'Accept': 'text/html' } })
          .then(function (r) {
            // The media type itself, case-insensitively, without parameters: text/htmlx is not text/html.
            var t = (r.headers.get('Content-Type') || '').split(';')[0].trim().toLowerCase();
            return r.ok && t === 'text/html' ? r.text() : null;
          });
      },
      parse: function (html) { return new DOMParser().parseFromString(html, 'text/html'); },
      replace: function (cur, next) { cur.replaceWith(document.importNode(next, true)); },
      later: function (fn, ms) { return setTimeout(fn, ms); },
      clear: function (t) { clearTimeout(t); }
    });
    live.start();
  }
  if (typeof module !== 'undefined' && module.exports) { module.exports = { create: create }; } else { start(); }
})(this);
`
