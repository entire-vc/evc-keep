package api

// meshUIHTML is the whole markup of the Mesh screen. html/template escapes
// every field by context; there is no inline script, no inline style and no
// foreign URL (the policy would block them anyway).
//
// The shell (head, foot, page-head) and the CSS classes of meshUIStyle are a
// contract for every page of the screen: pages are written on these classes
// and do not add styles of their own.
const meshUIHTML = `
{{define "head"}}<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{{if .Title}}{{.Title}} — {{end}}Keep</title>
<link rel="stylesheet" href="/mesh/ui/app.css"><script src="/mesh/ui/app.js" defer></script></head>
<body data-origins="{{.OriginList}}"{{if .NeedLogin}} data-login="1"{{end}}{{if .Toast}} data-toast="{{.Toast}}" data-toast-level="{{.ToastLvl}}"{{end}}>
{{if .Active}}<div class="topbar"><nav class="tabs" aria-label="Keep">
<a href="/mesh/ui/secrets"{{if eq .Active "secrets"}} aria-current="page"{{end}}>Secrets</a>
<a href="/mesh/ui/settings"{{if eq .Active "settings"}} aria-current="page"{{end}}>Key level</a>
</nav><div class="side"><button type="button" class="btn btn-ghost btn-sm" data-mesh-workspace hidden>Open workspace</button></div></div>{{end}}
<main class="page">{{end}}
{{define "foot"}}</main></body></html>{{end}}

{{define "page-head"}}<div class="page-head"><div>{{if .Back.Href}}<a class="crumb" href="{{.Back.Href}}">{{template "icon-back"}}{{.Back.Label}}</a>{{end}}
<h1>{{.Title}}</h1>{{if .Subtitle}}<p class="muted">{{.Subtitle}}</p>{{end}}</div></div>{{end}}

{{define "icon-back"}}<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="m15 18-6-6 6-6"/></svg>{{end}}
{{define "icon-key"}}<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6M15.5 7.5l3 3L22 7l-3-3"/></svg>{{end}}
{{define "icon-search"}}<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>{{end}}
{{define "icon-off"}}<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg>{{end}}
{{define "icon-ok"}}<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>{{end}}
{{define "icon-alert"}}<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="m21.7 18-8-14a2 2 0 0 0-3.4 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.7-3Z"/><path d="M12 9v4M12 17h.01"/></svg>{{end}}

{{define "signedout"}}{{template "head" .}}{{template "page-head" .}}
<div class="card"><div class="empty" role="status">{{template "icon-key"}}<p>{{if .NeedLogin}}Signing in through Mesh…{{else}}Open this screen from Mesh{{end}}</p>
<small>{{if .NeedLogin}}The screen signs you in with your Mesh session; there is no second login.{{else}}Keep opens from the Mesh sidebar, signed in with your Mesh session.{{end}}</small></div></div>{{template "foot" .}}{{end}}

{{define "unavailable"}}{{template "head" .}}{{template "page-head" .}}
<div class="card"><div class="empty" role="alert">{{template "icon-off"}}<p>Keep is unavailable</p>
<small>The service is temporarily unavailable or the request was refused. Reload the screen from Mesh.</small></div></div>{{template "foot" .}}{{end}}

{{define "settings"}}{{template "head" .}}{{template "page-head" .}}
{{if .Error}}<div class="banner banner-danger" role="alert">{{template "icon-alert"}}<div>{{.Error}}</div></div>{{end}}
{{if .Result}}<div class="banner banner-ok" role="status">{{template "icon-ok"}}<div>Re-wrapped {{.Result.Rewrapped}}, unchanged {{.Result.Unchanged}}, retired {{.Result.Retired}}.</div></div>{{end}}
{{if .Available}}<div class="card pad"><h2>Current level: <strong>{{.Level}}</strong></h2>
{{if .ChangedAt}}<p class="muted">Changed {{.ChangedAt}} by {{.ChangedBy}}</p>{{end}}
{{if .CanChange}}<form method="post" action="/mesh/ui/settings/key-level"><input type="hidden" name="csrf" value="{{.CSRF}}">
<fieldset class="levels"><legend class="sr-only">New level</legend>
{{range .Levels}}<label class="level{{if eq .Name $.Level}} on{{end}}"><input type="radio" name="level" value="{{.Name}}"{{if eq .Name $.Level}} checked{{end}}><span><b>{{.Name}}</b><span>{{.Meaning}}</span></span></label>
{{end}}</fieldset>
<label class="check"><input type="checkbox" name="confirm_weakening" value="yes"> I understand that a coarser level lets more stores share a key</label>
<button class="btn" type="submit">Change level</button></form>
{{else}}<div class="levels">{{range .Levels}}<label class="level{{if eq .Name $.Level}} on{{end}}"><input type="radio" disabled{{if eq .Name $.Level}} checked{{end}}><span><b>{{.Name}}</b><span>{{.Meaning}}</span></span></label>
{{end}}</div>
<div class="banner">{{template "icon-ok"}}<div>{{if .IsAdmin}}Changing the level is not available on this server.{{else}}Only an organization admin can change the level. Others see it read-only.{{end}}</div></div>{{end}}
</div>
{{else}}<div class="card"><div class="empty">{{template "icon-off"}}<p>The key level is not available on this server.</p></div></div>{{end}}
{{template "foot" .}}{{end}}
`

// meshUIStyle paints the screen with the Mesh theme: every colour is a Mesh
// token (hsl(var(--x))); the values on :root are the Mesh light theme, used
// until Mesh sends its theme (mesh.context, mesh.theme). There is no palette
// and no dark mode of its own: Mesh decides. Components follow Mesh (shadcn).
const meshUIStyle = `@font-face{font-family:"Inter";font-style:normal;font-weight:400;font-display:swap;src:url(/mesh/ui/fonts/inter-cyrillic-400-normal.woff2) format("woff2");unicode-range:U+0301,U+0400-045F,U+0490-0491,U+04B0-04B1,U+2116}
@font-face{font-family:"Inter";font-style:normal;font-weight:400;font-display:swap;src:url(/mesh/ui/fonts/inter-latin-ext-400-normal.woff2) format("woff2");unicode-range:U+0100-02BA,U+02BD-02C5,U+02C7-02CC,U+02CE-02D7,U+02DD-02FF,U+0304,U+0308,U+0329,U+1D00-1DBF,U+1E00-1E9F,U+1EF2-1EFF,U+2020,U+20A0-20AB,U+20AD-20C0,U+2113,U+2C60-2C7F,U+A720-A7FF}
@font-face{font-family:"Inter";font-style:normal;font-weight:400;font-display:swap;src:url(/mesh/ui/fonts/inter-latin-400-normal.woff2) format("woff2");unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD}
@font-face{font-family:"Inter";font-style:normal;font-weight:500;font-display:swap;src:url(/mesh/ui/fonts/inter-cyrillic-500-normal.woff2) format("woff2");unicode-range:U+0301,U+0400-045F,U+0490-0491,U+04B0-04B1,U+2116}
@font-face{font-family:"Inter";font-style:normal;font-weight:500;font-display:swap;src:url(/mesh/ui/fonts/inter-latin-ext-500-normal.woff2) format("woff2");unicode-range:U+0100-02BA,U+02BD-02C5,U+02C7-02CC,U+02CE-02D7,U+02DD-02FF,U+0304,U+0308,U+0329,U+1D00-1DBF,U+1E00-1E9F,U+1EF2-1EFF,U+2020,U+20A0-20AB,U+20AD-20C0,U+2113,U+2C60-2C7F,U+A720-A7FF}
@font-face{font-family:"Inter";font-style:normal;font-weight:500;font-display:swap;src:url(/mesh/ui/fonts/inter-latin-500-normal.woff2) format("woff2");unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD}
@font-face{font-family:"Inter";font-style:normal;font-weight:600;font-display:swap;src:url(/mesh/ui/fonts/inter-cyrillic-600-normal.woff2) format("woff2");unicode-range:U+0301,U+0400-045F,U+0490-0491,U+04B0-04B1,U+2116}
@font-face{font-family:"Inter";font-style:normal;font-weight:600;font-display:swap;src:url(/mesh/ui/fonts/inter-latin-ext-600-normal.woff2) format("woff2");unicode-range:U+0100-02BA,U+02BD-02C5,U+02C7-02CC,U+02CE-02D7,U+02DD-02FF,U+0304,U+0308,U+0329,U+1D00-1DBF,U+1E00-1E9F,U+1EF2-1EFF,U+2020,U+20A0-20AB,U+20AD-20C0,U+2113,U+2C60-2C7F,U+A720-A7FF}
@font-face{font-family:"Inter";font-style:normal;font-weight:600;font-display:swap;src:url(/mesh/ui/fonts/inter-latin-600-normal.woff2) format("woff2");unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD}
@font-face{font-family:"Inter";font-style:normal;font-weight:700;font-display:swap;src:url(/mesh/ui/fonts/inter-cyrillic-700-normal.woff2) format("woff2");unicode-range:U+0301,U+0400-045F,U+0490-0491,U+04B0-04B1,U+2116}
@font-face{font-family:"Inter";font-style:normal;font-weight:700;font-display:swap;src:url(/mesh/ui/fonts/inter-latin-ext-700-normal.woff2) format("woff2");unicode-range:U+0100-02BA,U+02BD-02C5,U+02C7-02CC,U+02CE-02D7,U+02DD-02FF,U+0304,U+0308,U+0329,U+1D00-1DBF,U+1E00-1E9F,U+1EF2-1EFF,U+2020,U+20A0-20AB,U+20AD-20C0,U+2113,U+2C60-2C7F,U+A720-A7FF}
@font-face{font-family:"Inter";font-style:normal;font-weight:700;font-display:swap;src:url(/mesh/ui/fonts/inter-latin-700-normal.woff2) format("woff2");unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD}
@font-face{font-family:"JetBrains Mono";font-style:normal;font-weight:400;font-display:swap;src:url(/mesh/ui/fonts/jetbrains-mono-cyrillic-400-normal.woff2) format("woff2");unicode-range:U+0301,U+0400-045F,U+0490-0491,U+04B0-04B1,U+2116}
@font-face{font-family:"JetBrains Mono";font-style:normal;font-weight:400;font-display:swap;src:url(/mesh/ui/fonts/jetbrains-mono-latin-ext-400-normal.woff2) format("woff2");unicode-range:U+0100-02BA,U+02BD-02C5,U+02C7-02CC,U+02CE-02D7,U+02DD-02FF,U+0304,U+0308,U+0329,U+1D00-1DBF,U+1E00-1E9F,U+1EF2-1EFF,U+2020,U+20A0-20AB,U+20AD-20C0,U+2113,U+2C60-2C7F,U+A720-A7FF}
@font-face{font-family:"JetBrains Mono";font-style:normal;font-weight:400;font-display:swap;src:url(/mesh/ui/fonts/jetbrains-mono-latin-400-normal.woff2) format("woff2");unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD}
:root{
--background:0 0% 100%;--foreground:180 23% 8%;--card:0 0% 100%;--card-foreground:180 23% 8%;
--primary:180 100% 21%;--primary-foreground:0 0% 100%;--secondary:180 30% 95%;--secondary-foreground:180 23% 8%;
--muted:180 20% 96%;--muted-foreground:180 10% 40%;--accent:180 100% 21%;--accent-foreground:0 0% 100%;
--destructive:0 84% 60%;--destructive-foreground:0 0% 100%;--success:142 76% 36%;--success-foreground:0 0% 100%;
--warning:38 92% 50%;--warning-foreground:0 0% 100%;--border:180 28% 90%;--input:180 28% 90%;--ring:180 100% 21%;
--radius:0.5rem;--font-sans:"Inter",ui-sans-serif,sans-serif;--font-mono:"JetBrains Mono",ui-monospace,monospace;
color-scheme:light}
*{box-sizing:border-box}
html,body{margin:0}
[hidden]{display:none!important}
body{font:400 14px/20px var(--font-sans);color:hsl(var(--foreground));background:hsl(var(--background));-webkit-font-smoothing:antialiased}
a{color:inherit}
.mono{font-family:var(--font-mono);font-size:12px;line-height:16px;overflow-wrap:anywhere}
.muted{color:hsl(var(--muted-foreground))}
.sr-only{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
code{font-family:var(--font-mono);font-size:12px}

.topbar{display:flex;align-items:flex-end;justify-content:space-between;gap:12px;padding:0 24px;border-bottom:1px solid hsl(var(--border))}
.tabs{display:flex;gap:4px;overflow-x:auto;scrollbar-width:none}
.tabs a{padding:8px 12px;font-size:14px;font-weight:500;text-decoration:none;color:hsl(var(--muted-foreground));border-bottom:2px solid transparent;margin-bottom:-1px;white-space:nowrap}
.tabs a:hover{color:hsl(var(--foreground))}
.tabs a[aria-current=page]{color:hsl(var(--foreground));border-bottom-color:hsl(var(--primary))}
.topbar .side{padding:6px 0}
.page{max-width:1080px;margin:0 auto;padding:24px}
.page-head{display:flex;flex-wrap:wrap;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:20px}
.page-head h1{margin:0;font-size:24px;line-height:32px;font-weight:700;letter-spacing:-.025em}
.page-head p{margin:4px 0 0}
.crumb{display:inline-flex;align-items:center;gap:4px;font-size:13px;color:hsl(var(--muted-foreground));text-decoration:none;margin-bottom:8px}
.crumb:hover{color:hsl(var(--foreground))}
.meta{display:flex;flex-wrap:wrap;gap:6px 16px;margin-top:8px;font-size:13px;color:hsl(var(--muted-foreground))}
.meta b{font-weight:500;color:hsl(var(--foreground))}

.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;height:36px;padding:0 16px;border-radius:var(--radius);border:1px solid transparent;font:500 14px/1 var(--font-sans);white-space:nowrap;cursor:pointer;text-decoration:none;background:hsl(var(--primary));color:hsl(var(--primary-foreground))}
.btn:hover{background:hsl(var(--primary)/.9)}
.btn-outline{background:hsl(var(--background));color:hsl(var(--foreground));border-color:hsl(var(--border))}
.btn-outline:hover{background:hsl(var(--accent));color:hsl(var(--accent-foreground))}
.btn-ghost{background:transparent;color:hsl(var(--foreground))}
.btn-ghost:hover{background:hsl(var(--accent));color:hsl(var(--accent-foreground))}
.btn-destructive{background:hsl(var(--destructive));color:hsl(var(--destructive-foreground))}
.btn-destructive:hover{background:hsl(var(--destructive)/.9)}
.btn-sm{height:32px;padding:0 12px;font-size:12px}
.btn:focus-visible,.input:focus-visible,.select:focus-visible,.tabs a:focus-visible,.row-link:focus-visible,.crumb:focus-visible,.seg a:focus-visible,.level input:focus-visible,.check input:focus-visible{outline:none;box-shadow:0 0 0 2px hsl(var(--background)),0 0 0 4px hsl(var(--ring))}
.input,.select{height:36px;padding:0 12px;border:1px solid hsl(var(--input));border-radius:var(--radius);background:hsl(var(--background));color:hsl(var(--foreground));font:400 14px var(--font-sans);box-shadow:0 1px 2px rgb(0 0 0/.05);min-width:0}
.select{appearance:none;padding-right:32px;background-image:linear-gradient(45deg,transparent 50%,hsl(var(--muted-foreground)) 50%),linear-gradient(135deg,hsl(var(--muted-foreground)) 50%,transparent 50%);background-position:calc(100% - 15px) 16px,calc(100% - 10px) 16px;background-size:5px 5px;background-repeat:no-repeat}
.input::placeholder{color:hsl(var(--muted-foreground))}
.search{position:relative;flex:1 1 260px;max-width:360px}
.search .input{width:100%;padding-left:34px}
.search svg{position:absolute;left:11px;top:10px;width:16px;height:16px;color:hsl(var(--muted-foreground))}

.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:12px}
.toolbar .spacer{flex:1}
.seg{display:inline-flex;padding:3px;border-radius:var(--radius);background:hsl(var(--muted));gap:2px}
.seg a{padding:5px 10px;border-radius:calc(var(--radius) - 2px);font-size:13px;font-weight:500;text-decoration:none;color:hsl(var(--muted-foreground));display:inline-flex;gap:6px;align-items:center}
.seg a[aria-current=true]{background:hsl(var(--background));color:hsl(var(--foreground));box-shadow:0 1px 2px rgb(0 0 0/.08)}
.count{font-size:11px;font-weight:600;padding:0 6px;border-radius:999px;background:hsl(var(--warning));color:hsl(var(--warning-foreground));line-height:16px}

.badge{display:inline-flex;align-items:center;gap:6px;border-radius:calc(var(--radius) - 2px);padding:2px 8px;font-size:12px;line-height:16px;font-weight:500;white-space:nowrap}
.badge-outline{border:1px solid hsl(var(--border));color:hsl(var(--foreground))}
.badge-muted{background:hsl(var(--secondary));color:hsl(var(--secondary-foreground))}
.badge-ok{border:1px solid hsl(var(--border));color:hsl(var(--foreground))}
.badge-ok::before,.badge-run::before{content:"";width:6px;height:6px;border-radius:50%;background:hsl(var(--success))}
.badge-run::before{background:hsl(var(--primary))}
.badge-run{border:1px solid hsl(var(--primary)/.4);color:hsl(var(--foreground))}
.badge-warn{background:hsl(var(--warning));color:hsl(var(--warning-foreground))}
.badge-danger{background:hsl(var(--destructive));color:hsl(var(--destructive-foreground))}

.card{border:1px solid hsl(var(--border));border-radius:calc(var(--radius) + 4px);background:hsl(var(--card));color:hsl(var(--card-foreground));box-shadow:0 1px 2px rgb(0 0 0/.05)}
.section{margin-top:24px}
.section-head{display:flex;align-items:baseline;justify-content:space-between;gap:12px;margin-bottom:8px}
.section-head h2{margin:0;font-size:16px;line-height:24px;font-weight:600}
.summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:20px}
.stat{padding:12px 16px;text-decoration:none}
.stat .n{font-size:24px;line-height:32px;font-weight:600;letter-spacing:-.02em}
.stat .l{font-size:12px;color:hsl(var(--muted-foreground))}
.stat.warn .n{color:hsl(var(--warning))}
.stat.danger .n{color:hsl(var(--destructive))}

.table{width:100%;border-collapse:collapse;font-size:14px}
.table th{padding:10px 16px;text-align:left;font-size:12px;font-weight:500;color:hsl(var(--muted-foreground));border-bottom:1px solid hsl(var(--border));white-space:nowrap}
.table td{padding:12px 16px;border-bottom:1px solid hsl(var(--border));vertical-align:middle}
.table tr:last-child td{border-bottom:0}
.table tbody tr:hover{background:hsl(var(--muted)/.6)}
.row-link{font-weight:500;text-decoration:none;color:hsl(var(--foreground));overflow-wrap:anywhere}
.row-link:hover{text-decoration:underline;text-underline-offset:4px}
.sub{display:block;font-size:12px;line-height:16px;color:hsl(var(--muted-foreground));margin-top:2px}
.num{text-align:right;white-space:nowrap}
.foot{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:12px 16px;border-top:1px solid hsl(var(--border));font-size:13px;color:hsl(var(--muted-foreground))}
.copy{display:inline-flex;align-items:center;gap:6px}
.copy button{border:0;background:none;padding:2px;color:hsl(var(--muted-foreground));cursor:pointer;border-radius:4px}
.copy button:hover{color:hsl(var(--foreground));background:hsl(var(--muted))}

.banner{display:flex;gap:12px;align-items:flex-start;padding:12px 16px;border-radius:var(--radius);border:1px solid hsl(var(--border));background:hsl(var(--muted));font-size:14px;margin-bottom:16px}
.banner svg{flex:none;width:18px;height:18px;margin-top:1px}
.banner b{font-weight:600}
.banner-warn{border-color:hsl(var(--warning)/.5);background:hsl(var(--warning)/.08)}
.banner-warn svg{color:hsl(var(--warning))}
.banner-danger{border-color:hsl(var(--destructive)/.5);background:hsl(var(--destructive)/.08)}
.banner-danger svg{color:hsl(var(--destructive))}
.banner-ok{border-color:hsl(var(--success)/.45);background:hsl(var(--success)/.08)}
.banner-ok svg{color:hsl(var(--success))}

.steps{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin:0 0 16px;padding:0;list-style:none}
.steps li{padding:10px 12px;border-radius:var(--radius);border:1px solid hsl(var(--border));font-size:13px}
.steps li b{display:block;font-weight:600;font-size:13px}
.steps li span{color:hsl(var(--muted-foreground));font-size:12px}
.steps li.done{border-color:hsl(var(--success)/.5)}
.steps li.done b::before{content:"\2713  ";color:hsl(var(--success))}
.steps li.now{border-color:hsl(var(--primary));box-shadow:inset 0 0 0 1px hsl(var(--primary))}
.steps li.fail{border-color:hsl(var(--destructive));box-shadow:inset 0 0 0 1px hsl(var(--destructive))}
.steps li.skip{opacity:.55}

.empty{display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:80px 16px}
.empty svg{width:40px;height:40px;color:hsl(var(--muted-foreground)/.4);margin-bottom:12px}
.empty p{margin:0;font-size:14px;font-weight:500;color:hsl(var(--muted-foreground))}
.empty small{display:block;margin-top:4px;font-size:12px;color:hsl(var(--muted-foreground)/.75);max-width:44ch}
.empty code{display:inline-block;max-width:100%;overflow-x:auto;vertical-align:bottom;white-space:nowrap;padding:2px 6px;border-radius:4px;background:hsl(var(--muted));color:hsl(var(--foreground))}
.empty .btn{margin-top:12px}
.btn:disabled{opacity:.5;cursor:not-allowed}
.btn:disabled:hover{background:hsl(var(--primary))}
.pad{padding:20px}
.pad h2{margin:16px 0 8px;font-size:14px;line-height:20px;font-weight:600}
.pad h2:first-child{margin-top:0}
.add-off{display:inline-flex;flex-wrap:wrap;align-items:center;gap:6px 10px;font-size:13px}
.add-slot{margin-top:12px}
.add-form{display:flex;flex-wrap:wrap;align-items:flex-end;gap:12px;margin-top:16px;text-align:left;max-width:640px}
.empty .add-form{justify-content:center}
.field{display:flex;flex-direction:column;gap:6px;font-size:13px;font-weight:500;flex:1 1 160px;min-width:0}
.field .input,.field .select{width:100%;box-sizing:border-box}
.add-form .btn,.empty .add-form .btn{margin-top:0}
.copy-row{display:flex;gap:8px;align-items:center;width:100%;max-width:720px}
.copy-row .input{flex:1 1 auto;min-width:0;height:36px;box-sizing:border-box;background:hsl(var(--muted)/.5)}
.link-block{display:flex;flex-direction:column;align-items:stretch;gap:10px;width:100%;max-width:720px;margin:16px auto 0;text-align:left}
.pad.link-block{margin:0 0 16px;max-width:none}
.link-block form{margin:0}
.link-block p{margin:0}
.actions{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.copy-status:empty{display:none}
@media (max-width:480px){.copy-row{flex-direction:column;align-items:stretch}.add-form .btn{width:100%}}

.levels{display:grid;gap:8px;margin:12px 0 16px;padding:0;border:0;min-width:0}
.level{display:flex;gap:12px;align-items:flex-start;padding:12px 14px;border:1px solid hsl(var(--border));border-radius:var(--radius);cursor:pointer}
.level input{margin-top:3px;accent-color:hsl(var(--primary))}
.level b{font-weight:600}
.level span{display:block;font-size:13px;color:hsl(var(--muted-foreground))}
.level b,.level>span{color:hsl(var(--foreground))}
.level.on,.level:has(input:checked){border-color:hsl(var(--primary));box-shadow:inset 0 0 0 1px hsl(var(--primary))}
.level:has(input:disabled){cursor:default}
.pad{padding:20px 24px}
.pad h2{margin:0 0 4px;font-size:16px;font-weight:600}
.pad>p{margin:0}
.pad .banner{margin:0}
.check{display:flex;gap:8px;align-items:flex-start;font-size:13px;margin:0 0 16px}
.check input{margin-top:2px;accent-color:hsl(var(--primary))}

@media (max-width:640px){
  .topbar{padding:0 12px}.page{padding:16px 12px}
  .page-head h1{font-size:20px;line-height:28px}
  .summary{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}
  .search{max-width:none;flex-basis:100%}
  .toolbar .select{flex:1 1 40%}
  .toolbar .spacer{display:none}
  .table thead{display:none}
  .table,.table tbody,.table tr,.table td{display:block;width:100%}
  .table tr{padding:12px 16px;border-bottom:1px solid hsl(var(--border))}
  .table tr:last-child{border-bottom:0}
  .table td{padding:2px 0;border:0}
  .table td[data-k]::before{content:attr(data-k) " ";color:hsl(var(--muted-foreground));font-size:12px}
  .table td.first{display:flex;justify-content:space-between;gap:8px;align-items:flex-start;padding-bottom:4px}
  .table td.hide-sm{display:none}
  .num{text-align:left}
  .steps{grid-template-columns:repeat(2,minmax(0,1fr))}
  .foot{flex-direction:column;align-items:flex-start}
  .pad{padding:16px}
}
.sm-only{display:none}
@media (max-width:640px){.sm-only{display:inline-flex}}
.nowrap{white-space:nowrap}@media (max-width:640px){.nowrap{white-space:normal}}
`

// meshUIScript speaks the postMessage protocol of docs/extensions/ui-iframe.md
// on the Mesh side: it acts on a message only from the parent window and only
// from an origin recorded at install; everything else is ignored silently.
// The Mesh theme (theme in mesh.context, mesh.theme) is applied token by token:
// only a listed name with a value of the token's shape reaches the root style.
const meshUIScript = `(function (root) {
  'use strict';
  var THEME = ['background', 'foreground', 'card', 'card-foreground', 'primary', 'primary-foreground',
    'secondary', 'secondary-foreground', 'muted', 'muted-foreground', 'accent', 'accent-foreground', 'destructive',
    'destructive-foreground', 'success', 'success-foreground', 'warning', 'warning-foreground', 'border', 'input', 'ring'];
  function tokenOK(n, v) {
    if (typeof v !== 'string') { return false; }
    if (n === 'radius') { return /^[0-9.]{1,6}rem$/.test(v); }
    return THEME.indexOf(n) !== -1 && /^[0-9. %]{1,32}$/.test(v);
  }
  // Copy feedback is fixed text per kind: the copied text (an input link is a
  // bearer credential for one value) never reaches a toast, which goes to Mesh.
  var COPIED = { link: 'Link copied', command: 'Command copied', fingerprint: 'Fingerprint copied' };
  var MANUAL = 'Press Ctrl/\u2318+C to copy';
  // copy never fails silently: the clipboard API, then select the field and
  // execCommand('copy'), then leave the field selected for the keyboard.
  // env: clipboard (navigator.clipboard or null), select() (true when there is
  // something to select), exec() (document.execCommand('copy')).
  // Resolves to 'clipboard', 'exec' or 'manual'.
  function copy(env, text) {
    function fallback() {
      var sel = false, ok = false;
      try { sel = env.select() === true; } catch (e) { sel = false; }
      if (sel) { try { ok = env.exec() === true; } catch (e) { ok = false; } }
      if (ok) { return 'exec'; }
      if (sel) { try { env.select(); } catch (e) { /* the field stays as it is */ } }
      return 'manual';
    }
    var cb = env.clipboard;
    if (!cb || typeof cb.writeText !== 'function') { return Promise.resolve(fallback()); }
    var p;
    try { p = cb.writeText(text); } catch (e) { return Promise.resolve(fallback()); }
    return Promise.resolve(p).then(function () { return 'clipboard'; }, function () { return fallback(); });
  }
  function copyMessage(kind, how) {
    if (how === 'manual') { return { level: 'info', text: MANUAL }; }
    return { level: 'success', text: COPIED[kind] || 'Copied' };
  }
  function create(env) {
    var origins = env.origins, target = origins.length === 1 ? origins[0] : null, ctx = null;
    function allowed(o) { return origins.indexOf(o) !== -1; }
    function send(msg) { if (target) { env.parent.postMessage(msg, target); } }
    function path(p) { return typeof p === 'string' && p.charAt(0) === '/' && p.charAt(1) !== '/' && p.indexOf('\\') === -1; }
    function applyMeshTheme(t) {
      if (!t || typeof t !== 'object' || !t.tokens || typeof t.tokens !== 'object' || !env.root) { return; }
      var st = env.root.style, tokens = t.tokens;
      Object.keys(tokens).forEach(function (k) {
        var n = k.slice(0, 2) === '--' ? k.slice(2) : k;
        if (tokenOK(n, tokens[k])) { st.setProperty('--' + n, tokens[k]); }
      });
      if (t.mode === 'light' || t.mode === 'dark') { st.setProperty('color-scheme', t.mode); }
    }
    function onMessage(ev) {
      if (!ev || ev.source !== env.parent || !allowed(ev.origin)) { return; }
      var d = ev.data;
      if (!d || typeof d !== 'object' || (d.version !== 1 && d.version !== 2)) { return; }
      if (d.type === 'mesh.theme') { applyMeshTheme(d); return; }
      if (d.type !== 'mesh.context') { return; }
      target = ev.origin;
      ctx = d;
      applyMeshTheme(d.theme);
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
      origins: origins, parent: window.parent, needLogin: b.dataset.login === '1', root: document.documentElement,
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
      var cp = e.target.closest && e.target.closest('[data-copy],[data-copy-from]');
      if (cp) { copyFrom(cp); }
    });
    function copyFrom(btn) {
      var field = btn.hasAttribute('data-copy-from') ? document.getElementById(btn.getAttribute('data-copy-from')) : null;
      var shown = field || (btn.parentNode && btn.parentNode.querySelector('.mono'));
      var text = field ? field.value : btn.getAttribute('data-copy');
      var kind = btn.getAttribute('data-copy-kind') || 'fingerprint';
      copy({
        clipboard: navigator.clipboard || null,
        select: function () {
          if (field) { field.focus(); field.select(); field.setSelectionRange(0, field.value.length); return true; }
          if (!shown || !window.getSelection) { return false; }
          var r = document.createRange(); r.selectNodeContents(shown);
          var s = window.getSelection(); s.removeAllRanges(); s.addRange(r); return true;
        },
        exec: function () { return document.execCommand('copy'); }
      }, text).then(function (how) {
        var m = copyMessage(kind, how), st = document.querySelector('[data-copy-status]');
        if (st) { st.textContent = m.text; }
        api.toast(m.level, m.text);
      });
    }
    Array.prototype.forEach.call(document.querySelectorAll('form[data-autosubmit]'), function (f) {
      Array.prototype.forEach.call(f.querySelectorAll('[data-apply]'), function (b) { b.hidden = true; });
      f.addEventListener('change', function (e) { if (e.target && e.target.tagName === 'SELECT') { f.submit(); } });
    });
    if (window.ResizeObserver) { new ResizeObserver(function () { api.resize(document.documentElement.scrollHeight); }).observe(document.documentElement); }
    if (b.dataset.toast) { api.toast(b.dataset.toastLevel || 'info', b.dataset.toast); }
    api.ready();
  }
  if (typeof module !== 'undefined' && module.exports) { module.exports = { create: create, copy: copy, copyMessage: copyMessage }; } else { start(); }
})(this);
`

// meshThemeColorTokens are the colour tokens of the Mesh theme the screen
// takes from Mesh (mesh.context theme, mesh.theme); --radius is the only other.
var meshThemeColorTokens = []string{"background", "foreground", "card", "card-foreground", "primary", "primary-foreground",
	"secondary", "secondary-foreground", "muted", "muted-foreground", "accent", "accent-foreground", "destructive",
	"destructive-foreground", "success", "success-foreground", "warning", "warning-foreground", "border", "input", "ring"}
