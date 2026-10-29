//go:build intake_browser

package builtin

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/api"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/intake"
	"github.com/entire-vc/evc-keep/internal/intake/descriptor"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/google/uuid"
)

type pageLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *pageLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}
func (b *pageLogBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.buf.String() }

// This test runs the actual page, router, single-use service, PostgreSQL,
// receiver and catalog. The browser prints only completion metadata; any
// diagnostic containing the generated canary is a failure, never echoed.
func TestIntakePageBrowserLifecycle(t *testing.T) {
	f := newIntakeFixture(t)
	f.actor.Type = audit.ActorAgent
	f.actor.SponsorID = uuid.NewString()
	prior := secret.New([]byte(canary.New().Value(1)))
	defer prior.Wipe()
	meta, err := f.provider.Write(f.ctx, provider.Ref{Path: f.ref.ProviderRef}, prior)
	if err != nil {
		t.Fatal("initial provider version")
	}
	fk, err := f.provider.FingerprintKey(f.ctx)
	if err != nil {
		t.Fatal("fingerprint key")
	}
	defer fk.Wipe()
	priorFP, err := fingerprint.Compute(fk, prior)
	if err != nil {
		t.Fatal("initial fingerprint")
	}
	pool := f.provider.db.pool
	_, err = pool.Exec(f.ctx, `INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length) VALUES($1,$2,$3,$4,$5,$6)`, uuid.New(), f.ref.OrgID, f.ref.ID, meta.Version, priorFP, prior.Len())
	if err != nil {
		t.Fatal("initial catalog version")
	}
	cat := catalog.New(pool)
	before, err := cat.ListVersions(f.ctx, f.ref.OrgID, f.ref.ID)
	if err != nil || len(before) != 1 {
		t.Fatal("initial catalog assertion")
	}
	// Exercise UTF-8 byte lengths and HTML entity decoding in the actual DOM.
	// The issued signature must use current catalog text, not the stale ref.
	if _, err = pool.Exec(f.ctx, `UPDATE secrets SET name=$2 WHERE id=$1`, f.ref.ID, "sample<&\u00e9\r\nnext"); err != nil {
		t.Fatal("set visible metadata fixture")
	}
	if _, err = pool.Exec(f.ctx, `UPDATE stores SET name=$2 WHERE id=$1`, f.store.ID, "sample-store\rnext"); err != nil {
		t.Fatal("set storage metadata fixture")
	}
	link, token, view := f.issue(t)
	probe := canary.New()
	plain := []byte(probe.Value(1))
	defer clear(plain)
	if !probe.In(base64.StdEncoding.EncodeToString(append([]byte("xx"), plain...))) {
		t.Fatal("page canary positive control")
	}
	var logs pageLogBuffer
	f.provider.log = obs.New(&logs)
	h := api.NewRouter(obs.New(&logs), pool, api.Deps{Input: f.svc})
	var mu sync.Mutex
	var surfaceLeak, badMutation bool
	var posts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer clear(body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		output := rec.Body.String()
		if r.Method == http.MethodGet && rec.Code == http.StatusOK && r.URL.Query().Get("case") != "" {
			replaceAttribute := func(name, from, to string) {
				re := regexp.MustCompile(`(` + name + `=")([^"]*)(")`)
				matches := re.FindAllStringSubmatch(output, -1)
				if len(matches) != 1 || html.UnescapeString(matches[0][2]) != from {
					mu.Lock()
					badMutation = true
					mu.Unlock()
					return
				}
				output = re.ReplaceAllStringFunc(output, func(string) string { return name + `="` + html.EscapeString(to) + `"` })
			}
			// Mutate the visible text, never a second metadata copy in attributes.
			visible := map[string]string{"secret-name": view.SecretName, "scope": view.Scope, "store": view.StoreName, "class": view.Class, "requester": view.RequestedBy, "sponsor": view.Sponsor}
			if value, ok := visible[r.URL.Query().Get("case")]; ok {
				shown := ">" + strings.ReplaceAll(html.EscapeString(value), "\r", "&#13;") + "<"
				if value == "" || strings.Count(output, shown) != 1 {
					mu.Lock()
					badMutation = true
					mu.Unlock()
				}
				output = strings.Replace(output, shown, ">different<", 1)
			}
			if name, ok := strings.CutPrefix(r.URL.Query().Get("case"), "hidden-field-"); ok {
				re := regexp.MustCompile(`<([^>]+ id="metadata-` + regexp.QuoteMeta(name) + `")>`)
				if len(re.FindAllString(output, -1)) != 1 {
					mu.Lock()
					badMutation = true
					mu.Unlock()
				}
				output = re.ReplaceAllString(output, `<$1 hidden>`)
			}
			var attr, from, to string
			switch r.URL.Query().Get("case") {
			case "hidden-name":
				output = strings.Replace(output, `<h2 id="metadata-SecretName">`, `<h2 hidden id="metadata-SecretName">`, 1)
				output = strings.Replace(output, `</h2>`, `</h2><h2>different</h2>`, 1)
			case "hidden-ancestor":
				output = strings.Replace(output, `<dl>`, `<dl hidden>`, 1)
			case "extra-name":
				output = strings.Replace(output, `</h2>`, `</h2><h2>different</h2>`, 1)
			case "duplicate-name":
				output = strings.Replace(output, `</h2>`, `</h2><h2 id="metadata-SecretName">different</h2>`, 1)
			case "nested-name":
				output = strings.Replace(output, `<h2 id="metadata-SecretName">`, `<h2 id="metadata-SecretName"><span>`, 1)
				output = strings.Replace(output, `</h2>`, `</span></h2>`, 1)
			case "metadata-label":
				output = strings.Replace(output, `<dt>Requested by</dt>`, `<dt>Storage</dt>`, 1)
			case "raw-row-text":
				output = strings.Replace(output, `<dt>Requested by</dt>`, `<dt>Requested by</dt>different`, 1)
			case "raw-card-text":
				output = strings.Replace(output, `<dl>`, `different<dl>`, 1)
			case "noncanonical-public":
				attr, from, to = "data-public", base64.StdEncoding.EncodeToString(view.PublicKey), base64.StdEncoding.EncodeToString(view.PublicKey)+"\n"
			case "noncanonical-signature":
				attr, from, to = "data-signature", base64.StdEncoding.EncodeToString(view.Signature), base64.StdEncoding.EncodeToString(view.Signature)+"\n"
			case "public":
				attr = "data-public"
				from = base64.StdEncoding.EncodeToString(view.PublicKey)
				swapped := append([]byte(nil), view.PublicKey...)
				swapped[0] ^= 1
				to = base64.StdEncoding.EncodeToString(swapped)
			case "request":
				attr = "data-request"
				from = view.RequestID
				to = uuid.Must(uuid.NewV7()).String()
			case "signed-request", "foreign-descriptor":
				otherID := uuid.Must(uuid.NewV7()).String()
				_, _, signature, e := f.provider.IntakeDescriptor(f.ctx, otherID, descriptor.Metadata{SecretName: view.SecretName, Scope: view.Scope, StoreName: view.StoreName, Class: view.Class, RequestedBy: view.RequestedBy, Sponsor: view.Sponsor})
				if e != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				replaceAttribute("data-request", view.RequestID, otherID)
				replaceAttribute("data-signature", base64.StdEncoding.EncodeToString(view.Signature), base64.StdEncoding.EncodeToString(signature))
				if r.URL.Query().Get("case") == "foreign-descriptor" {
					output = strings.Replace(output, ">"+strings.ReplaceAll(html.EscapeString(view.SecretName), "\r", "&#13;")+"<", ">different<", 1)
				}
			case "legacy-v1":
				key, e := f.provider.intakeKeys(f.ctx)
				if e != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				var signature []byte
				secret.Expose(key, func(raw []byte) {
					signature = ed25519.Sign(ed25519.PrivateKey(raw[32:]), []byte("keep/intake-key/v1\x00"+view.RequestID+"\x00"+base64.StdEncoding.EncodeToString(view.PublicKey)))
				})
				key.Wipe()
				replaceAttribute("data-signature", base64.StdEncoding.EncodeToString(view.Signature), base64.StdEncoding.EncodeToString(signature))
			case "signature":
				attr = "data-signature"
				from = base64.StdEncoding.EncodeToString(view.Signature)
				swapped := append([]byte(nil), view.Signature...)
				swapped[0] ^= 1
				to = base64.StdEncoding.EncodeToString(swapped)
			case "signer":
				attr = "data-signing"
				public, private, e := ed25519.GenerateKey(nil)
				if e != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				signature := ed25519.Sign(private, descriptor.Message(view.RequestID, view.PublicKey, descriptor.Metadata{SecretName: view.SecretName, Scope: view.Scope, StoreName: view.StoreName, Class: view.Class, RequestedBy: view.RequestedBy, Sponsor: view.Sponsor}))
				clear(private)
				replaceAttribute("data-signature", base64.StdEncoding.EncodeToString(view.Signature), base64.StdEncoding.EncodeToString(signature))
				from = base64.StdEncoding.EncodeToString(view.SigningKey)
				to = base64.StdEncoding.EncodeToString(public)
			}
			if from != "" {
				replaceAttribute(attr, from, to)
			}
		}
		leaked := probe.In(string(body)) || probe.In(output)
		for _, headers := range []http.Header{r.Header, rec.Header()} {
			for _, values := range headers {
				for _, value := range values {
					leaked = leaked || probe.In(value)
				}
			}
		}
		mu.Lock()
		surfaceLeak = surfaceLeak || leaked
		if r.Method == http.MethodPost {
			posts++
		}
		mu.Unlock()
		for k, values := range rec.Header() {
			w.Header()[k] = values
		}
		w.WriteHeader(rec.Code)
		_, _ = io.WriteString(w, output)
	}))
	defer server.Close()
	u, err := url.Parse(link.URL)
	if err != nil {
		t.Fatal("parse input link")
	}
	browserURL := server.URL + u.RequestURI() + "#" + u.Fragment
	input, err := json.Marshal(struct {
		URL       string   `json:"url"`
		Plaintext string   `json:"plaintext"`
		Metadata  []string `json:"metadata"`
	}{browserURL, string(plain), []string{view.SecretName, view.Scope, view.StoreName, view.Class, view.RequestedBy, view.Sponsor}})
	if err != nil {
		t.Fatal("encode page fixture")
	}
	defer clear(input)
	// A whole run takes 10-15 s on a quiet host and was seen at 62 s on a loaded
	// runner, where a 60 s limit turned a slow run into a failure. Callers keep
	// the go test -timeout above this, or the test binary dies first.
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", "../../scripts/check-intake-page.mjs")
	cmd.Stdin = bytes.NewReader(input)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	if probe.In(out.String()) || probe.In(stderr.String()) {
		t.Fatal("page browser leaked canary in diagnostics")
	}
	for _, snapshot := range pageStartupSnapshots(stderr.String()) {
		t.Log("page-startup-snapshot " + snapshot)
	}
	if runErr != nil {
		if ctx.Err() != nil {
			t.Log("page-browser-process deadline")
		} else {
			t.Log("page-browser-process nonzero")
		}
		for _, failure := range pageBrowserFailures(stderr.String()) {
			t.Log("page-browser-failed " + failure)
		}
		// Fixed assertion messages only; never forward a JS stack, source line,
		// observed value, URL, console argument or whole subprocess output.
		reason := "page browser failed"
		if failures := pageBrowserFailures(stderr.String()); len(failures) > 0 {
			reason += " " + strings.Join(failures, " ")
		}
		if assertion := pageFixedAssertion(stderr.String()); assertion != "" {
			reason = assertion
		}
		t.Fatal(reason)
	}
	var result intake.Result
	if json.Unmarshal(out.Bytes(), &result) != nil || result.Version == "" || result.Fingerprint == "" {
		t.Fatal("page completion metadata")
	}
	mu.Lock()
	leaked, mutationFailed, postCount := surfaceLeak, badMutation, posts
	mu.Unlock()
	if leaked || probe.In(logs.String()) || logs.String() == "" {
		t.Fatal("page canary escaped to HTTP or log, or capture empty")
	}
	if mutationFailed || postCount != 1 {
		t.Fatal("page probes did not exercise exact mutation or single submission")
	}
	value, resolved, err := f.provider.Resolve(f.ctx, provider.Ref{Path: f.ref.ProviderRef})
	if err != nil {
		t.Fatal("resolve browser input")
	}
	defer value.Wipe()
	control := secret.New(plain)
	defer control.Wipe()
	expected, err := fingerprint.Compute(fk, control)
	if err != nil || expected != result.Fingerprint || !value.Equal(control) || resolved.Version != result.Version || result.Version == meta.Version {
		t.Fatal("page browser receipt differs from entered value and resolved new version")
	}
	after, err := cat.ListVersions(f.ctx, f.ref.OrgID, f.ref.ID)
	if err != nil || len(after) != 2 {
		t.Fatal("page catalog did not gain exactly one version")
	}
	found := false
	for _, version := range after {
		if version.ProviderVersion == result.Version && version.Fingerprint == expected {
			found = true
		}
	}
	if !found {
		t.Fatal("page catalog version or fingerprint mismatch")
	}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, "/input/"+token, strings.NewReader(`{"enc":"","ciphertext":""}`)))
		if rec.Code != http.StatusGone {
			t.Fatal("page capability remained usable after submission")
		}
	}
	for _, table := range []string{"intake_links", "secret_versions", "secrets", "audit_records"} {
		rows, e := pool.Query(f.ctx, "SELECT row_to_json(x)::text FROM "+table+" x WHERE org_id::text=$1", f.ref.OrgID.String())
		if e != nil {
			t.Fatal("page persistence capture")
		}
		for rows.Next() {
			var row string
			if rows.Scan(&row) != nil {
				rows.Close()
				t.Fatal("page persistence row")
			}
			if probe.In(row) {
				rows.Close()
				t.Fatal("page canary persisted outside zone")
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			t.Fatal("page persistence iteration")
		}
	}
	verified, err := audit.Verify(f.ctx, pool, f.ref.OrgID.String())
	if err != nil || !verified.OK {
		t.Fatal("page audit chain invalid")
	}
	t.Log("PASS page v2 signature + signer/request pins before encrypt/send; 20 tamper probes rejected; external-script execution control and CSP block; ciphertext-only single submission; cleared field; cookie write/sent-cookie/307 redirect controls; no browser storage/URL/title/console/exception side effects")
	t.Log("PASS live Chromium -> HTTP -> sealed store -> Resolve -> catalog 1 to 2 versions, input HMAC matches receipt/catalog; GET and POST replay 410; no canary in HTTP/log/audit/outside-zone DB")
}

// Re-allowlist the Node snapshot before forwarding it to the CI baseline log.
func pageStartupSnapshots(stderr string) []string {
	var result []string
	numeric := func(raw json.RawMessage, keys []string) map[string]int64 {
		var values map[string]json.RawMessage
		_ = json.Unmarshal(raw, &values)
		safe := map[string]int64{}
		for _, key := range keys {
			var n int64
			if value, ok := values[key]; ok && string(value) != "null" && json.Unmarshal(value, &n) == nil && n >= 0 {
				safe[key] = n
			}
		}
		return safe
	}
	for _, line := range strings.Split(stderr, "\n") {
		var row struct {
			Event   string                     `json:"event"`
			Samples map[string]json.RawMessage `json:"startup_snapshots"`
		}
		if json.Unmarshal([]byte(line), &row) != nil || row.Event != "chromium-startup-failed" {
			continue
		}
		for _, phase := range []string{"before", "failure"} {
			var sample struct {
				Budget      int                        `json:"budget_ms"`
				Timeout     int                        `json:"timed_out"`
				Unavailable int                        `json:"unavailable"`
				Snapshot    map[string]json.RawMessage `json:"snapshot"`
			}
			if json.Unmarshal(row.Samples[phase], &sample) != nil || sample.Budget != 50 {
				continue
			}
			safe := map[string]any{"phase": phase, "budget_ms": 50, "timed_out": sample.Timeout == 1, "unavailable": sample.Unavailable == 1}
			for _, key := range []string{"temporary", "profile", "shared_memory"} {
				safe[key] = numeric(sample.Snapshot[key], []string{"type", "block_bytes", "blocks", "available_blocks"})
			}
			safe["cpu"] = numeric(sample.Snapshot["cpu"], []string{"nr_periods", "nr_throttled", "throttled_usec"})
			safe["memory"] = numeric(sample.Snapshot["memory"], []string{"oom", "oom_kill", "high", "max"})
			var processes []struct {
				Kind  string `json:"kind"`
				State string `json:"state"`
			}
			_ = json.Unmarshal(sample.Snapshot["processes"], &processes)
			if len(processes) > 64 {
				processes = processes[:64]
			}
			for i := range processes {
				switch processes[i].Kind {
				case "chrome", "chromium", "chrome_crashpad_handler":
				default:
					processes[i].Kind = "other"
				}
				switch processes[i].State {
				case "R", "S", "D", "Z", "T", "t", "I", "X":
				default:
					processes[i].State = "other"
				}
			}
			safe["processes"] = processes
			encoded, _ := json.Marshal(safe)
			result = append(result, string(encoded))
		}
		break
	}
	return result
}

func TestPageStartupSnapshotAllowlist(t *testing.T) {
	raw := `{"event":"chromium-startup-failed","startup_snapshots":{"before":{"budget_ms":50,"snapshot":{"cpu":{"nr_throttled":9,"private":"PRIVATE_SENTINEL"},"memory":{"oom":2},"processes":[{"kind":"PRIVATE_SENTINEL","state":"D","path":"PRIVATE_SENTINEL"}]}},"failure":{"budget_ms":50,"timed_out":1,"private":"PRIVATE_SENTINEL"}}}`
	rows := pageStartupSnapshots(raw)
	if len(rows) != 2 || strings.Contains(strings.Join(rows, ""), "PRIVATE_SENTINEL") {
		t.Fatal("startup evidence allowlist")
	}
	var before, failure map[string]any
	_ = json.Unmarshal([]byte(rows[0]), &before)
	_ = json.Unmarshal([]byte(rows[1]), &failure)
	if before["cpu"].(map[string]any)["nr_throttled"] != float64(9) || before["memory"].(map[string]any)["oom"] != float64(2) || failure["timed_out"] != true {
		t.Fatal("startup numeric evidence lost")
	}
	if len(pageStartupSnapshots(`{"event":"untrusted","startup_snapshots":{}}`)) != 0 {
		t.Fatal("startup event allowlist")
	}
}

// Only fixed Node failure metadata crosses the subprocess boundary.
func pageBrowserFailures(stderr string) []string {
	var rows []string
	for _, line := range strings.Split(stderr, "\n") {
		var row struct {
			Event string `json:"event"`
			Stage string `json:"stage"`
			Class string `json:"error_class"`
			Code  string `json:"code"`
		}
		if json.Unmarshal([]byte(line), &row) != nil || row.Event != "page-browser-failed" {
			continue
		}
		switch row.Stage {
		case "setup", "readiness", "discovery", "socket", "page", "cleanup":
		default:
			row.Stage = "other"
		}
		switch row.Class {
		case "Error", "TypeError", "SyntaxError", "AssertionError":
		default:
			row.Class = "other"
		}
		switch row.Code {
		case "ERR_ASSERTION", "ECONNREFUSED", "ECONNRESET", "ENOENT", "EACCES", "CDP_COMMAND_FAILED", "CLEANUP_SOCKET", "CLEANUP_BROWSER", "CLEANUP_SERVER", "CLEANUP_PROFILE":
		default:
			row.Code = "other"
		}
		safe, _ := json.Marshal(map[string]string{"stage": row.Stage, "error_class": row.Class, "code": row.Code})
		rows = append(rows, string(safe))
		if len(rows) == 2 {
			break
		}
	}
	return rows
}

func TestPageBrowserFailureAllowlist(t *testing.T) {
	for _, code := range []string{"CDP_COMMAND_FAILED", "ENOENT", "ERR_ASSERTION", "CLEANUP_SOCKET", "CLEANUP_BROWSER", "CLEANUP_SERVER", "CLEANUP_PROFILE"} {
		raw := `{"event":"page-browser-failed","stage":"page","error_class":"Error","code":"` + code + `","message":"PRIVATE_SENTINEL"}`
		rows := pageBrowserFailures(raw)
		if len(rows) != 1 || !strings.Contains(rows[0], code) || strings.Contains(rows[0], "PRIVATE_SENTINEL") {
			t.Fatal("failure evidence boundary")
		}
	}
	rows := pageBrowserFailures(`{"event":"page-browser-failed","stage":"PRIVATE_SENTINEL","error_class":"PRIVATE_SENTINEL","code":"PRIVATE_SENTINEL"}`)
	if len(rows) != 1 || strings.Contains(rows[0], "PRIVATE_SENTINEL") {
		t.Fatal("unknown failure metadata leaked")
	}
}

func TestPageBrowserFailureNodeBoundary(t *testing.T) {
	cmd := exec.Command("node", "--input-type=module", "-e", `
 import {emitPageFailure,pageCleanup} from '../../scripts/lib/page-failure.mjs';
 const primary=Object.assign(new TypeError('PRIVATE_SENTINEL'),{code:'CDP_COMMAND_FAILED'});
 try { try { throw primary; } finally { await pageCleanup(primary,async()=>{throw new Error('PRIVATE_SENTINEL')}); } }
 catch(error) { emitPageFailure('page',error); process.exitCode=1; }
 `)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if cmd.Run() == nil {
		t.Fatal("Node failure verdict lost")
	}
	rows := pageBrowserFailures(stderr.String())
	if len(rows) != 2 || !strings.Contains(rows[0], `"stage":"cleanup"`) || !strings.Contains(rows[1], "CDP_COMMAND_FAILED") || !strings.Contains(rows[1], "TypeError") || strings.Contains(stderr.String(), "PRIVATE_SENTINEL") {
		t.Fatal("Node to Go failure boundary")
	}
	for _, row := range rows {
		t.Log("page-browser-failed " + row)
	}
}

func pageFixedAssertion(stderr string) string {
	for _, line := range strings.Split(stderr, "\n") {
		switch line {
		case "AssertionError [ERR_ASSERTION]: page browser: expected UI state was not reached (duplicate-pin)",
			"AssertionError [ERR_ASSERTION]: page browser: expected UI state was not reached (extra-name)",
			"AssertionError [ERR_ASSERTION]: page browser: expected UI state was not reached (hidden-field-SecretName)",
			"AssertionError [ERR_ASSERTION]: page browser: expected UI state was not reached (nested-name)",
			"AssertionError [ERR_ASSERTION]: page browser: expected UI state was not reached (noncanonical-public)",
			"AssertionError [ERR_ASSERTION]: page browser: expected UI state was not reached (raw-card-text)",
			"AssertionError [ERR_ASSERTION]: page browser: expected UI state was not reached (raw-row-text)",
			"AssertionError [ERR_ASSERTION]: page browser: expected UI state was not reached (secret-name)",
			"AssertionError [ERR_ASSERTION]: page browser: expected UI state was not reached (signed-request)",
			"AssertionError [ERR_ASSERTION]: page browser: expected UI state was not reached (signer)",
			"AssertionError [ERR_ASSERTION]: page browser: expected UI state was not reached (unknown-fragment)",
			"AssertionError [ERR_ASSERTION]: page browser: textarea privacy attribute autocomplete",
			"AssertionError [ERR_ASSERTION]: page browser: textarea privacy attribute autocapitalize",
			"AssertionError [ERR_ASSERTION]: page browser: textarea privacy attribute autocorrect",
			"AssertionError [ERR_ASSERTION]: page browser: textarea privacy attribute spellcheck":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: expected redirect probe and one ciphertext submission":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: plaintext field not cleared after submission":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: encryption before descriptor verification":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: external script control did not execute":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: external script was not blocked by CSP":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: expected UI state was not reached":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: external script CSP event missing":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: valid descriptor did not verify":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: canary detector control failed":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: unexpected network side effect":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: cookie control is not visible":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: cookie control was not seeded":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: redirect control did not run":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: tampered descriptor accepted":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: tampered descriptor was sent":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: unexpected diagnostic output":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: wrong ciphertext destination":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: browser storage side effect":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: credential or referrer sent":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: invalid completion metadata":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: browser cookie side effect":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: input in URL, title or DOM":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: requester metadata missing":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: script integrity violation":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: textarea privacy attribute":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: Cache Storage side effect":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: unexpected CSP diagnostic":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: window.name side effect":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: CSS import side effect":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: Chromium did not start":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: unexpected browser log":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: unexpected input field":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: IndexedDB side effect":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: Chromium is required":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: input in browser log":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: non-envelope request":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: console side effect":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: horizontal overflow":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: interception failed":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: unhandled exception":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: CDP command failed":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: navigation timeout":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: evaluation failed":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: redirect followed":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: OPFS side effect":
			return line
		case "AssertionError [ERR_ASSERTION]: page browser: input in request":
			return line
		}
	}
	return ""
}

func TestPageBrowserFixedAssertionNodeBoundary(t *testing.T) {
	cmd := exec.Command("node", "--input-type=module", "-e", `
 import assert from "node:assert/strict";
 import {emitFixedAssertion} from "../../scripts/lib/page-failure.mjs";
 try { assert(false,"page browser: valid descriptor did not verify"); } catch(error) { emitFixedAssertion(error); process.exitCode=1; }
 `)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if cmd.Run() == nil || pageFixedAssertion(stderr.String()) != "AssertionError [ERR_ASSERTION]: page browser: valid descriptor did not verify" {
		t.Fatal("fixed assertion identity lost")
	}
	if pageFixedAssertion("AssertionError [ERR_ASSERTION]: page browser: PRIVATE_SENTINEL") != "" {
		t.Fatal("unknown assertion leaked")
	}
}

func TestPageBrowserMutationWitnessNodeBoundary(t *testing.T) {
	for _, reason := range []string{"page browser: expected UI state was not reached (secret-name)", "page browser: textarea privacy attribute autocomplete"} {
		cmd := exec.Command("node", "--input-type=module", "-e", `
 import {emitFixedAssertion} from "../../scripts/lib/page-failure.mjs";
 emitFixedAssertion({name:"AssertionError",message:process.argv[1]+"; PRIVATE_SENTINEL"});
 process.exitCode=1;`, reason)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if cmd.Run() == nil || pageFixedAssertion(stderr.String()) != "AssertionError [ERR_ASSERTION]: "+reason {
			t.Fatal("exact existing mutation witness lost at Node to Go boundary")
		}
		if strings.Contains(stderr.String(), "PRIVATE_SENTINEL") {
			t.Fatal("private assertion suffix leaked")
		}
	}
	for _, raw := range []string{"AssertionError [ERR_ASSERTION]: page browser: expected UI state was not reached (PRIVATE_SENTINEL)", "AssertionError [ERR_ASSERTION]: page browser: textarea privacy attribute PRIVATE_SENTINEL"} {
		if pageFixedAssertion(raw) != "" {
			t.Fatal("unknown witness was forwarded")
		}
	}
}
