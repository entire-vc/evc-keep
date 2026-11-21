package api

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// liveHarness drives the run page's live script with a fake page: a page is
// "active" (the [data-live] node carries data-live-active), "done" (the node
// without it), "none" (no [data-live] node) or null (not the page). Timers
// run only when the harness fires them, so it sees exactly what is scheduled.
const liveHarness = `
const { create } = require(process.argv[2]);
const node = (active, n) => ({ n, hasAttribute: a => a === 'data-live-active' && active });
function page(spec) {
  return { querySelector: q => (q === '[data-live]' && spec !== 'none') ? node(spec.startsWith('active'), spec) : null };
}
function mk(first, answers) {
  const st = { cur: node(first === 'active', 'first'), fetched: 0, replaced: [], timers: [], cleared: 0, periods: [] };
  st.live = create({
    current: () => st.cur,
    fetch: () => { st.fetched++; const a = answers.shift();
      return a instanceof Error ? Promise.reject(a) : Promise.resolve(a === undefined ? 'done' : a); },
    parse: html => page(html),
    replace: (cur, next) => { st.replaced.push(next.n); st.cur = next; },
    later: (fn, ms) => { st.periods.push(ms); st.timers.push(fn); return st.timers.length; },
    clear: () => { st.cleared++; },
  });
  return st;
}
async function fire(st) {           // run the pending timer, if any, and let its fetch settle
  const fn = st.timers.shift(); if (!fn) return false;
  fn(); await new Promise(r => setTimeout(r, 1)); return true;
}
async function drain(st) {          // fire timers until none is pending, at most 10: a script that never stops fails, not hangs
  for (let i = 0; i < 10 && await fire(st); i++) {}
}
function sum(st) {
  return { fetched: st.fetched, replaced: st.replaced, pending: st.timers.length, stopped: st.live.stopped(), periods: st.periods };
}
const out = {};
(async () => {
  // Active page: polls while the answers stay active, stops on the first page without the marker.
  let a = mk('active', ['active-1', 'active-2', 'done']);
  a.live.start();
  await drain(a);
  out.untilDone = sum(a);
  // A finished page never polls.
  let b = mk('done', []); b.live.start(); out.finished = sum(b);
  // Not the page (an error page, a login page, a redirect): stop, replace nothing.
  let c = mk('active', [null]); c.live.start(); await drain(c); out.notPage = sum(c);
  let d = mk('active', ['none']); d.live.start(); await drain(d); out.noNode = sum(d);
  let e = mk('active', [new Error('offline')]); e.live.start(); await drain(e); out.failed = sum(e);
  // Stopped by hand while a timer is pending: the timer is cleared, nothing is fetched.
  let f = mk('active', ['active-1']); f.live.start(); f.live.stop(); out.stoppedByHand = Object.assign(sum(f), { cleared: f.cleared });
  console.log(JSON.stringify(out));
})();
`

type liveRun struct {
	Fetched  int
	Replaced []string
	Pending  int
	Stopped  bool
	Periods  []int
	Cleared  int
}

// The live script asks again every 3 s only while the fetched page says the
// run is active, and stops for good on a page without data-live-active, on
// anything that is not the page, or on a failed fetch.
func TestMeshUIRotationLiveScriptStopsWithoutActiveMarker(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI to run the live script test")
		}
		t.Skip("node not installed")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "live.js")
	if err := os.WriteFile(script, []byte(meshUILiveScript), 0o600); err != nil {
		t.Fatal(err)
	}
	harness := filepath.Join(dir, "harness.js")
	if err := os.WriteFile(harness, []byte(liveHarness), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, harness, script) //nolint:gosec // G204: node found by LookPath, harness is a file this test writes
	cmd.Dir = dir
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("node: %v %s", err, raw)
	}
	var out struct {
		UntilDone, Finished, NotPage, NoNode, Failed, StoppedByHand liveRun
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("harness output: %v %s", err, raw)
	}
	u := out.UntilDone
	if u.Fetched != 3 || strings.Join(u.Replaced, ",") != "active-1,active-2,done" || u.Pending != 0 || !u.Stopped {
		t.Errorf("an active run must be polled until a page without data-live-active, then stop: %+v", u)
	}
	for i, p := range u.Periods {
		if p != 3000 {
			t.Errorf("poll %d scheduled after %d ms, want 3000", i, p)
		}
	}
	if f := out.Finished; f.Fetched != 0 || f.Pending != 0 || !f.Stopped {
		t.Errorf("a finished run's page must not poll: %+v", f)
	}
	for name, r := range map[string]liveRun{"not the page": out.NotPage, "no live node": out.NoNode, "fetch failed": out.Failed} {
		if r.Fetched != 1 || len(r.Replaced) != 0 || r.Pending != 0 || !r.Stopped {
			t.Errorf("%s: the script must stop and replace nothing: %+v", name, r)
		}
	}
	if s := out.StoppedByHand; s.Cleared != 1 || s.Fetched != 0 || !s.Stopped {
		t.Errorf("stop must clear the pending timer: %+v", s)
	}
	// The script writes no markup and runs no strings; it fetches only its own page.
	for _, bad := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "Function(", "setTimeout('", "postMessage"} {
		if strings.Contains(meshUILiveScript, bad) {
			t.Errorf("live script uses %s", bad)
		}
	}
	for _, want := range []string{"fetch(location.href", "credentials: 'same-origin'", "redirect: 'error'", "DOMParser", "importNode"} {
		if !strings.Contains(meshUILiveScript, want) {
			t.Errorf("live script lacks %q", want)
		}
	}
}

// Execute the browser entry point too: injecting create(env) alone would
// bypass the actual HTTP status, content type and same-origin options.
func TestMeshUIRotationLiveScriptRejectsNonHTMLResponses(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI")
		}
		t.Skip("node not installed")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "live.js")
	if err := os.WriteFile(script, []byte(meshUILiveScript), 0o600); err != nil {
		t.Fatal(err)
	}
	harness := filepath.Join(dir, "browser.cjs")
	const source = `
const fs = require('fs'), vm = require('vm'), assert = require('assert/strict');
const source = fs.readFileSync(process.argv[2], 'utf8');
(async () => {
  for (const [name, ok, type, rejects, accepts] of [
    ['html', true, 'text/html; charset=utf-8', false, true],
    ['http-error', false, 'text/html', false, false],
    ['json', true, 'application/json', false, false],
    ['html-upper', true, 'Text/HTML; charset=utf-8', false, true],
    ['html-spaced', true, ' text/html ;charset=utf-8', false, true],
    ['html-suffix', true, 'text/htmlx', false, false],
    ['html-subtype', true, 'text/html-fragment; charset=utf-8', false, false],
    ['xhtml', true, 'application/xhtml+xml', false, false],
    ['missing-type', true, null, false, false],
    ['offline', false, null, true, false],
  ]) {
    const timers = [], calls = [];
    let reads = 0, parses = 0, replacements = 0;
    const next = { hasAttribute: () => false };
    const current = { hasAttribute: () => true, replaceWith: n => { assert.equal(n, next); replacements++; } };
    // mock: external boundary — the browser's network and DOM, running the real script entry point.
    vm.runInNewContext(source, {
      document: { querySelector: () => current, importNode: (n, deep) => { assert.equal(deep, true); return n; } },
      location: { href: 'https://keep.example.test/mesh/ui/secrets/s/rotations/r' },
      fetch: async (url, options) => {
        calls.push({ url, options });
        if (rejects) throw new Error('offline');
        return { ok, headers: { get: name => { assert.equal(name, 'Content-Type'); return type; } },
          text: async () => { reads++; return 'finished'; } };
      },
      DOMParser: class { parseFromString(html, type) {
        assert.equal(html, 'finished'); assert.equal(type, 'text/html'); parses++;
        return { querySelector: q => { assert.equal(q, '[data-live]'); return next; } };
      } },
      setTimeout: (fn, ms) => { assert.equal(ms, 3000); timers.push(fn); return timers.length; },
      clearTimeout: () => {},
    });
    assert.equal(timers.length, 1, name + ': active page must schedule');
    timers.shift()();
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(calls.length, 1, name);
    assert.equal(calls[0].url, 'https://keep.example.test/mesh/ui/secrets/s/rotations/r', name);
    const o = calls[0].options;
    assert.equal(o.credentials, 'same-origin', name); assert.equal(o.cache, 'no-store', name);
    assert.equal(o.redirect, 'error', name); assert.equal(o.headers.Accept, 'text/html', name);
    assert.equal(reads, Number(accepts), name + ': response body read');
    assert.equal(parses, Number(accepts), name + ': response parsed');
    assert.equal(replacements, Number(accepts), name + ': DOM replaced');
    assert.equal(timers.length, 0, name + ': polling must stop');
  }
  console.log('HTTP response guards: PASS');
})().catch(err => { console.error(err); process.exitCode = 1; });
`
	if err := os.WriteFile(harness, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, node, harness, script).CombinedOutput() //nolint:gosec // G204: test-owned script and harness
	if err != nil || !strings.Contains(string(out), "HTTP response guards: PASS") {
		t.Fatalf("browser entry point: %v\n%s", err, out)
	}
}
