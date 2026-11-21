package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

func discoverServer(t *testing.T, post, get string, polls *atomic.Int32, seen *map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		base := "/orgs/test-org/carriers/discover"
		switch {
		case r.Method == http.MethodPost && r.URL.Path == base:
			if seen != nil {
				_ = json.NewDecoder(r.Body).Decode(seen)
			}
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(post))
		case r.Method == http.MethodGet && r.URL.Path == base+"/dr-1":
			if polls != nil && polls.Add(1) < 2 {
				w.WriteHeader(http.StatusAccepted)
				_, _ = w.Write([]byte(post))
				return
			}
			_, _ = w.Write([]byte(get))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

const discoverPending = `{"ok":false,"request_id":"dr-1","runner_id":"r","store_id":"s","host":"host-a","state":"pending","findings":[]}`

func discoverArgs(extra ...string) []string {
	return append([]string{"carriers", "discover", "--runner", "r-1", "--store", "s-1", "--wait", "5s"}, extra...)
}

func TestDiscoverCLIWaitsAndPrintsFindingsWithoutAnythingElse(t *testing.T) {
	discoverPollEvery = 10 * time.Millisecond
	c := canary.New()
	done := `{"ok":false,"request_id":"dr-1","runner_id":"r","store_id":"s","host":"host-a","state":"completed","value":"` + c.Value(0) + `","offset":0,"total":3,"findings":[` +
		`{"verdict":"match","path":"/srv/a/.env","name":"DB_PASSWORD","fingerprint":"kfp1:k1:abcdefghijklmnop","incident":false},` +
		`{"verdict":"sprawl","path":"/tmp/x/.env","name":"DB_PASSWORD","fingerprint":"kfp1:k1:abcdefghijklmnop","incident":true},` +
		`{"verdict":"\u001b[31mevil","path":"/p","incident":false}]}`
	var polls atomic.Int32
	var seen map[string]any
	srv := discoverServer(t, discoverPending, done, &polls, &seen)
	var out, errout bytes.Buffer
	code := run(discoverArgs("--debug"), nil, &out, &errout, deployEnv(srv.URL))
	if code != 1 {
		t.Fatalf("exit %d, want 1 (findings): %s %s", code, out.String(), errout.String())
	}
	for _, want := range []string{"sprawl", "true", "DB_PASSWORD", "/tmp/x/.env", "kfp1:k1:abcdefghijklmnop", "(unexpected value)"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output lacks %q: %s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "\x1b") || c.In(out.String()) || c.In(errout.String()) || strings.Contains(errout.String(), "test-credential") {
		t.Fatalf("unsafe output: %q %q", out.String(), errout.String())
	}
	if polls.Load() < 2 || seen["runner_id"] != "r-1" || seen["store_id"] != "s-1" || len(seen) != 3 {
		t.Fatalf("polls %d, request %v", polls.Load(), seen)
	}
}

func TestDiscoverCLIExitCodes(t *testing.T) {
	discoverPollEvery = 10 * time.Millisecond
	clean := `{"ok":true,"request_id":"dr-1","runner_id":"r","store_id":"s","host":"h","state":"completed","total":1,"findings":[{"verdict":"match","path":"/a","incident":false}]}`
	srv := discoverServer(t, discoverPending, clean, nil, nil)
	var out, errout bytes.Buffer
	if code := run(discoverArgs(), nil, &out, &errout, deployEnv(srv.URL)); code != 0 {
		t.Fatalf("clean = %d: %s %s", code, out.String(), errout.String())
	}
	out.Reset()
	if code := run(discoverArgs("--wait", "0s"), nil, &out, &errout, deployEnv(srv.URL)); code != 4 || !strings.Contains(out.String(), "pending") {
		t.Fatalf("pending = %d: %s", code, out.String())
	}
	if code := run([]string{"carriers", "discover", "--runner", "r-1"}, nil, &out, &errout, deployEnv(srv.URL)); code != 2 {
		t.Fatalf("missing --store = %d, want 2", code)
	}
	if code := run([]string{"carriers", "other"}, nil, &out, &errout, deployEnv(srv.URL)); code != 2 {
		t.Fatalf("unknown subcommand = %d, want 2", code)
	}
}

// Every string the server sends is held to the terminal-safe form, not only
// the verdict; the JSON mode prints the same normalized result.
func TestDiscoverCLINeutralizesControlSequencesInEveryField(t *testing.T) {
	discoverPollEvery = 10 * time.Millisecond
	esc := `\u001b[31m`
	done := `{"ok":false,"request_id":"dr-1","runner_id":"r","store_id":"s","host":"` + esc + `host","state":"completed","error_class":"` + esc + `cls","total":1,"findings":[` +
		`{"verdict":"sprawl","path":"` + esc + `p","name":"` + esc + `n","fingerprint":"` + esc + `f","incident":true}]}`
	// A state outside the closed set is a report with no lines.
	badState := `{"ok":false,"request_id":"dr-1","runner_id":"r","store_id":"s","host":"h","state":"` + esc + `bad","total":0,"findings":[]}`
	for _, body := range []string{done, badState} {
		srv := discoverServer(t, discoverPending, body, nil, nil)
		for _, extra := range [][]string{nil, {"--json"}} {
			var out, errout bytes.Buffer
			code := run(discoverArgs(extra...), nil, &out, &errout, deployEnv(srv.URL))
			if code != 1 || strings.Contains(out.String(), "\x1b") || !strings.Contains(out.String(), "dr-1") {
				t.Fatalf("%v: exit %d, output %q %q", extra, code, out.String(), errout.String())
			}
			if body == done && extra != nil && !strings.Contains(out.String(), `"verdict": "sprawl"`) && !strings.Contains(out.String(), `"verdict":"sprawl"`) {
				t.Fatalf("--json lacks the finding: %q", out.String())
			}
		}
	}
}

// A full report of ASCII findings (~4.6 MB) is larger than the shared 1 MiB
// cap; the discover call has its own bound and a body past
// that bound is still refused with the static error and no findings.
func TestDiscoverCLIReadsFullReportButStaysBounded(t *testing.T) {
	path := "/" + strings.Repeat("p", 1000) + "/.env"
	f := `{"verdict":"match","path":"` + path + `","name":"DB_PASSWORD","fingerprint":"kfp1:k1:abcdefghijklmnop","incident":false}`
	report := func(n int) string {
		return `{"ok":true,"request_id":"dr-1","runner_id":"r","store_id":"s","host":"host-a","state":"completed","total":` + fmt.Sprint(n) + `,"findings":[` +
			strings.TrimSuffix(strings.Repeat(f+",", n), ",") + `]}`
	}
	// The discover read stays near the worst valid answer (~54 MB): no
	// more than 64 MiB, so it cannot quietly grow into an unbounded read.
	if maxDiscoverResponseBytes > 64<<20 {
		t.Fatalf("discover cap %d exceeds 64 MiB", maxDiscoverResponseBytes)
	}
	full := report(4096)
	if len(full) <= maxResponseBytes || len(full) > maxDiscoverResponseBytes {
		t.Fatalf("fixture %d bytes must sit between the shared cap and the discover cap", len(full))
	}
	cases := []struct {
		name     string
		body     string
		wantCode int
		wantErr  string
	}{
		{"positive control: one finding", report(1), 0, ""},
		{"full valid report", full, 0, ""},
		// Trailing whitespace is valid JSON, so these two differ only in size.
		{"exactly the discover cap", padTo(full, maxDiscoverResponseBytes), 0, ""},
		{"one byte past the discover cap", padTo(full, maxDiscoverResponseBytes+1), 1, "too large"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := discoverServer(t, tc.body, tc.body, nil, nil)
			var out, errout bytes.Buffer
			code := run(discoverArgs(), nil, &out, &errout, deployEnv(srv.URL))
			if code != tc.wantCode || !strings.Contains(errout.String(), tc.wantErr) {
				t.Fatalf("exit %d (want %d), stderr %q", code, tc.wantCode, errout.String())
			}
			if tc.wantErr != "" && out.Len() != 0 {
				t.Fatalf("a refused read printed findings: %d bytes", out.Len())
			}
		})
	}
}

func padTo(body string, n int) string { return body + strings.Repeat(" ", n-len(body)) }

// worstDiscoverPage is the largest page the server can give, encoded the
// way internal/api encodes it (encoding/json, HTML escaping on): a page is
// at most deployment.DiscoverPageSize (4096) lines, of which at most
// deployment.MaxDiscoverCarriers (1024) are unknown_find lines with a path
// and field as long as registration allows (4096 and 256 characters); the
// rest are runner findings with a 1024-byte path and a 128-character name.
// Paths are '&', '<' and '>' (six bytes each on the wire).
func worstDiscoverPage(t *testing.T, offset, total int) discoverResult {
	t.Helper()
	esc := func(n int) string { return strings.Repeat("&<>", n/3+1)[:n] }
	r := discoverResult{OK: false, RequestID: "dr-1", RunnerID: strings.Repeat("r", 36),
		StoreID: strings.Repeat("s", 36), Host: esc(253), State: "completed", Offset: offset, Total: total}
	fp := "kfp1:" + strings.Repeat("k", 16) + ":abcdefghijklmnop"
	for i := 0; i < 4096-1024; i++ {
		r.Findings = append(r.Findings, discoverFound{Verdict: "sprawl", CarrierID: strings.Repeat("c", 36),
			Path: "/" + esc(1023), Name: fmt.Sprintf("N%04d", i) + strings.Repeat("A", 123), Fingerprint: fp, Incident: true})
	}
	for i := 0; i < 1024; i++ {
		r.Findings = append(r.Findings, discoverFound{Verdict: "unknown_find", CarrierID: strings.Repeat("c", 36),
			Path: "/" + esc(4095), Name: esc(256), Fingerprint: fp, Incident: true})
	}
	return r
}

func encodePage(t *testing.T, r discoverResult) string {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// pagedServer answers POST with page 0 and GET ?offset=N with pages[N]; it
// counts every GET per offset, and a second GET of one offset is refused, so
// a client that loops on a page shows as a count, never as a hang.
func pagedServer(t *testing.T, pages map[int]string, gets map[int]int) *httptest.Server {
	t.Helper()
	return pagedServerStatus(t, pages, gets, nil)
}

// pagedServerStatus is pagedServer answering GET ?offset=N with HTTP
// status[N] where one is given.
func pagedServerStatus(t *testing.T, pages map[int]string, gets map[int]int, status map[int]int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		base := "/orgs/test-org/carriers/discover"
		switch {
		case r.Method == http.MethodPost && r.URL.Path == base:
			_, _ = w.Write([]byte(pages[0]))
		case r.Method == http.MethodGet && r.URL.Path == base+"/dr-1":
			var offset int
			if _, err := fmt.Sscan(r.URL.Query().Get("offset"), &offset); err != nil {
				t.Errorf("GET without an offset: %s", r.URL.RawQuery)
			}
			gets[offset]++
			body, ok := pages[offset]
			if !ok || gets[offset] > 1 {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error_class":"invalid_argument","message":"carrier discovery request invalid","request_id":"x"}`))
				return
			}
			if code, ok := status[offset]; ok {
				w.WriteHeader(code)
			}
			_, _ = w.Write([]byte(body))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A report of three pages, the first the worst page the server can give, is
// read page by page, each under the bound, and printed whole as one JSON
// document; its exit is the whole report's ok, not the last page's.
func TestDiscoverCLIReadsThreePagesWithTheWorstPage(t *testing.T) {
	const total = 4096 + 4096 + 1
	worst := encodePage(t, worstDiscoverPage(t, 0, total))
	if len(worst) <= 32<<20 || len(worst) > maxDiscoverResponseBytes || !strings.Contains(worst, `\u0026\u003c\u003e`) {
		t.Fatalf("worst page is %d bytes: must be escaped, above 32 MiB and within the cap", len(worst))
	}
	second := discoverResult{RequestID: "dr-1", State: "completed", Offset: 4096, Total: total}
	for i := 0; i < 4096; i++ {
		second.Findings = append(second.Findings, discoverFound{Verdict: "match", Path: fmt.Sprintf("/m/%d", i), Name: "M"})
	}
	last := discoverResult{RequestID: "dr-1", State: "completed", Offset: 8192, Total: total,
		Findings: []discoverFound{{Verdict: "match", Path: "/z", Name: "Z"}}}
	gets := map[int]int{}
	srv := pagedServer(t, map[int]string{0: worst, 4096: encodePage(t, second), 8192: encodePage(t, last)}, gets)
	var out, errout bytes.Buffer
	code := run(discoverArgs("--json"), nil, &out, &errout, deployEnv(srv.URL))
	if code != 1 || strings.Contains(errout.String(), "keep:") {
		t.Fatalf("exit %d (want 1: the report is not clean), stderr %q", code, errout.String())
	}
	if gets[4096] != 1 || gets[8192] != 1 || len(gets) != 2 {
		t.Fatalf("pages read: %v", gets)
	}
	var doc struct {
		OK       bool              `json:"ok"`
		Total    int               `json:"total"`
		Findings []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil || doc.OK || doc.Total != total || len(doc.Findings) != total {
		t.Fatalf("printed report: ok %v total %d findings %d (%v)", doc.OK, doc.Total, len(doc.Findings), err)
	}
	if strings.Count(out.String(), `"unknown_find"`) != 1024 || strings.Count(out.String(), `"sprawl"`) != 3072 || strings.Contains(out.String(), `"length"`) {
		t.Fatal("printed lines do not match the pages")
	}
}

// Pages that do not add up to one report end the run with an error and a
// non-zero exit, after exactly the one page that broke it: an empty page
// before the total, a total that changed, a page that starts elsewhere than
// asked, one with more lines than are left, one of a report that is no
// longer completed, of another request, answered 202, with another ok, one
// whose findings are missing, or a report calling itself ok that holds a
// line other than a match. The positive control is the same report served
// right.
func TestDiscoverCLIRefusesPagesThatDoNotAddUp(t *testing.T) {
	pageWith := func(offset, total, lines int, state string, edit func(*discoverResult)) string {
		r := discoverResult{OK: true, RequestID: "dr-1", State: state, Offset: offset, Total: total, Findings: []discoverFound{}}
		for i := 0; i < lines; i++ {
			r.Findings = append(r.Findings, discoverFound{Verdict: "match", Path: fmt.Sprintf("/p/%d-%d", offset, i)})
		}
		if edit != nil {
			edit(&r)
		}
		return encodePage(t, r)
	}
	page := func(offset, total, lines int, state string) string { return pageWith(offset, total, lines, state, nil) }
	first := page(0, 4, 2, "completed")
	for _, tc := range []struct {
		name   string
		second string
		status int
		code   int
	}{
		{"positive control", page(2, 4, 2, "completed"), 0, 0},
		{"empty page before the total", page(2, 4, 0, "completed"), 0, 1},
		{"total changed", page(2, 5, 2, "completed"), 0, 1},
		{"offset not the one asked", page(1, 4, 2, "completed"), 0, 1},
		{"more lines than are left", page(2, 4, 3, "completed"), 0, 1},
		{"report no longer completed", page(2, 4, 2, "failed"), 0, 1},
		{"page of another request", pageWith(2, 4, 2, "completed", func(r *discoverResult) { r.RequestID = "dr-2" }), 0, 1},
		{"page answered 202", page(2, 4, 2, "completed"), http.StatusAccepted, 1},
		{"ok changed", pageWith(2, 4, 2, "completed", func(r *discoverResult) { r.OK = false }), 0, 1},
		{"findings missing", `{"ok":true,"request_id":"dr-1","state":"completed","offset":2,"total":4}`, 0, 1},
		{"ok report with a sprawl line", pageWith(2, 4, 2, "completed", func(r *discoverResult) { r.Findings[1].Verdict = "sprawl" }), 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gets := map[int]int{}
			status := map[int]int{}
			if tc.status != 0 {
				status[2] = tc.status
			}
			srv := pagedServerStatus(t, map[int]string{0: first, 2: tc.second}, gets, status)
			for _, extra := range [][]string{nil, {"--json"}} {
				clear(gets)
				var out, errout bytes.Buffer
				code := run(discoverArgs(extra...), nil, &out, &errout, deployEnv(srv.URL))
				if code != tc.code || gets[2] != 1 || len(gets) != 1 {
					t.Fatalf("%v: exit %d (want %d), pages read %v, stderr %q", extra, code, tc.code, gets, errout.String())
				}
				if tc.code != 0 && !strings.Contains(errout.String(), "pages do not add up") {
					t.Fatalf("%v: stderr %q", extra, errout.String())
				}
			}
		})
	}
	// A first page that does not start the report, or holds more than it.
	for name, body := range map[string]string{"first page elsewhere": page(2, 4, 2, "completed"), "first page past total": page(0, 1, 2, "completed"),
		"lines on a pending report": page(0, 0, 1, "pending"), "total on a pending report": page(0, 4, 0, "pending"), "whole report on a pending page": page(0, 2, 2, "pending"),
		"more pages of an invalid request": pageWith(0, 4, 2, "completed", func(r *discoverResult) { r.RequestID = "dr 1" }),
		"ok report with a sprawl line":     pageWith(0, 1, 1, "completed", func(r *discoverResult) { r.Findings[0].Verdict = "sprawl" })} {
		srv := pagedServer(t, map[int]string{0: body}, map[int]int{})
		var out, errout bytes.Buffer
		if code := run(discoverArgs(), nil, &out, &errout, deployEnv(srv.URL)); code != 1 || !strings.Contains(errout.String(), "pages do not add up") {
			t.Fatalf("%s: exit %d stderr %q", name, code, errout.String())
		}
	}
}

// The first answer's HTTP status must agree with its state: 202 only while
// pending, 200 otherwise; a clean completed body under any other status is
// a contract break, never a clean exit. The positive control is the same
// body under 200.
func TestDiscoverCLIRefusesAFirstAnswerWhoseStatusDisagrees(t *testing.T) {
	clean := `{"ok":true,"request_id":"dr-1","runner_id":"r","store_id":"s","host":"h","state":"completed","offset":0,"total":1,"findings":[{"verdict":"match","path":"/a","name":"N","incident":false}]}`
	for _, tc := range []struct {
		name   string
		status int
		body   string
		code   int
	}{
		{"positive control", http.StatusOK, clean, 0},
		{"completed under 201", http.StatusCreated, clean, 1},
		{"completed under 202", http.StatusAccepted, clean, 1},
		{"pending under 200", http.StatusOK, discoverPending, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(srv.Close)
			args := append(discoverArgs(), "--wait", "0s")
			var out, errout bytes.Buffer
			code := run(args, nil, &out, &errout, deployEnv(srv.URL))
			if code != tc.code || (tc.code != 0 && !strings.Contains(errout.String(), "pages do not add up")) {
				t.Fatalf("exit %d (want %d), stderr %q", code, tc.code, errout.String())
			}
		})
	}
}

// The table has no length column and the help names no length of a finding
// (threat model 4.3.4.2).
func TestDiscoverCLIPrintsNoLength(t *testing.T) {
	body := `{"ok":false,"request_id":"dr-1","runner_id":"r","store_id":"s","host":"h","state":"completed","total":1,"findings":[{"verdict":"sprawl","path":"/a","name":"N","fingerprint":"kfp1:k1:abcdefghijklmnop","length":987654321,"incident":true}]}`
	srv := pagedServer(t, map[int]string{0: body}, map[int]int{})
	for _, extra := range [][]string{nil, {"--json"}} {
		var out, errout bytes.Buffer
		if code := run(discoverArgs(extra...), nil, &out, &errout, deployEnv(srv.URL)); code != 1 || !strings.Contains(out.String(), "sprawl") {
			t.Fatalf("%v: exit %d %q", extra, code, out.String())
		}
		if strings.Contains(strings.ToLower(out.String()), "length") || strings.Contains(out.String(), "987654321") {
			t.Fatalf("%v: output carries a length: %q", extra, out.String())
		}
	}
	i := strings.Index(usage, "keep carriers discover")
	if i < 0 {
		t.Fatal("help lacks keep carriers discover")
	}
	entry := usage[i:]
	if j := strings.Index(entry, "\n  keep "); j > 0 {
		entry = entry[:j]
	}
	if strings.Contains(entry, "length") || !strings.Contains(entry, "fingerprint") {
		t.Fatalf("help of discover: %q", entry)
	}
}

// Whatever a server puts into a finding beyond its closed fields (a value, a
// length) stays out of the output on every page, for every verdict.
func TestDiscoverCLIPrintsOnlyClosedFieldsOnEveryPage(t *testing.T) {
	c := canary.New()
	line := func(verdict string, i int) string {
		return fmt.Sprintf(`{"verdict":%q,"path":"/p/%d","name":"N%d","fingerprint":"kfp1:k1:abcdefghijklmnop","incident":true,"value":%q,"length":987654321}`,
			verdict, i, i, c.Value(i))
	}
	first := `{"ok":false,"request_id":"dr-1","runner_id":"r","store_id":"s","host":"h","state":"completed","offset":0,"total":4,"findings":[` +
		line("match", 0) + "," + line("stale", 1) + `]}`
	second := `{"ok":false,"request_id":"dr-1","runner_id":"r","store_id":"s","host":"h","state":"completed","offset":2,"total":4,"findings":[` +
		line("sprawl", 2) + "," + line("unknown_find", 3) + `]}`
	for _, extra := range [][]string{nil, {"--json"}} {
		gets := map[int]int{}
		srv := pagedServer(t, map[int]string{0: first, 2: second}, gets)
		var out, errout bytes.Buffer
		if code := run(discoverArgs(extra...), nil, &out, &errout, deployEnv(srv.URL)); code != 1 || gets[2] != 1 {
			t.Fatalf("%v: exit %d, pages read %v, stderr %q", extra, code, gets, errout.String())
		}
		for _, v := range []string{"match", "stale", "sprawl", "unknown_find"} {
			if !strings.Contains(out.String(), v) {
				t.Fatalf("%v: %s missing from %q", extra, v, out.String())
			}
		}
		if c.In(out.String()) || c.In(errout.String()) || strings.Contains(out.String(), "987654321") {
			t.Fatalf("%v: a field outside the closed list reached the output", extra)
		}
	}
}

// An empty first page of a report that has lines is a broken answer, not a
// reason to ask for line 0 again: the CLI refuses it without a GET, even
// when GET ?offset=0 would hand back a clean page. The positive control is
// the same report whose first answer carries its lines.
func TestDiscoverCLIRefusesAnEmptyFirstPageBeforeTotal(t *testing.T) {
	full := `{"ok":true,"request_id":"dr-1","runner_id":"r","store_id":"s","host":"h","state":"completed","offset":0,"total":2,"findings":[{"verdict":"match","path":"/a","name":"A","incident":false},{"verdict":"match","path":"/b","name":"B","incident":false}]}`
	empty := `{"ok":true,"request_id":"dr-1","runner_id":"r","store_id":"s","host":"h","state":"completed","offset":0,"total":2,"findings":[]}`
	for _, tc := range []struct {
		name  string
		first string
		code  int
	}{
		{"positive control", full, 0},
		{"empty first page", empty, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gets := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodPost && r.URL.Path == "/orgs/test-org/carriers/discover":
					_, _ = w.Write([]byte(tc.first))
				case r.Method == http.MethodGet && r.URL.Path == "/orgs/test-org/carriers/discover/dr-1":
					gets++
					_, _ = w.Write([]byte(full))
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
				}
			}))
			t.Cleanup(srv.Close)
			var out, errout bytes.Buffer
			code := run(discoverArgs(), nil, &out, &errout, deployEnv(srv.URL))
			if code != tc.code || gets != 0 {
				t.Fatalf("exit %d (want %d), GETs %d, stderr %q", code, tc.code, gets, errout.String())
			}
			if tc.code != 0 && !strings.Contains(errout.String(), "pages do not add up") {
				t.Fatalf("stderr %q", errout.String())
			}
		})
	}
}

// Only a completed report has lines: a pending answer under 202, or a failed
// or expired one under 200, that carries a total or lines is refused, even
// though its status agrees with its state and its lines fit its total. The
// positive controls are the same answers without lines.
func TestDiscoverCLIRefusesLinesOnAReportThatIsNotCompleted(t *testing.T) {
	answer := func(state string, total, lines int) string {
		f := []string{}
		for i := 0; i < lines; i++ {
			f = append(f, fmt.Sprintf(`{"verdict":"match","path":"/p/%d","name":"N","incident":false}`, i))
		}
		return fmt.Sprintf(`{"ok":false,"request_id":"dr-1","runner_id":"r","store_id":"s","host":"h","state":%q,"offset":0,"total":%d,"findings":[%s]}`, state, total, strings.Join(f, ","))
	}
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		refused bool
	}{
		{"pending control", http.StatusAccepted, answer("pending", 0, 0), false},
		{"failed control", http.StatusOK, answer("failed", 0, 0), false},
		{"pending with a line", http.StatusAccepted, answer("pending", 1, 1), true},
		{"failed with a line", http.StatusOK, answer("failed", 1, 1), true},
		{"expired with a line", http.StatusOK, answer("expired", 1, 1), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method != http.MethodPost || r.URL.Path != "/orgs/test-org/carriers/discover" {
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
					return
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(srv.Close)
			var out, errout bytes.Buffer
			code := run(discoverArgs("--wait", "0s"), nil, &out, &errout, deployEnv(srv.URL))
			refused := code == 1 && strings.Contains(errout.String(), "pages do not add up")
			if refused != tc.refused || code == 0 {
				t.Fatalf("exit %d, refused %v (want %v), stdout %q, stderr %q", code, refused, tc.refused, out.String(), errout.String())
			}
			if tc.refused && out.Len() != 0 {
				t.Fatalf("refused answer printed %q", out.String())
			}
		})
	}
}

// The streamed --json report escapes every terminal control the shared JSON
// writer escapes, in the header (host) and in finding lines (path, name),
// and decodes back to the values the server sent. The positive control is
// that the hostile string itself carries terminal controls.
func TestDiscoverCLIJSONEscapesControls(t *testing.T) {
	hostile := "x\u0085\u009b31m\u202e\u2066\u200e\u061c\U000e0001"
	if !hasTerminalControl(hostile) {
		t.Fatal("probe string carries no terminal control")
	}
	body, err := json.Marshal(discoverResult{OK: false, RequestID: "dr-1", Host: hostile, State: "completed", Total: 1,
		Findings: []discoverFound{{Verdict: "unknown_find", Path: "/" + hostile, Name: hostile}}})
	if err != nil {
		t.Fatal(err)
	}
	srv := pagedServer(t, map[int]string{0: string(body)}, map[int]int{})
	var out, errout bytes.Buffer
	if code := run(discoverArgs("--json"), nil, &out, &errout, deployEnv(srv.URL)); code != exitDiscoverFindings || errout.Len() != 0 {
		t.Fatalf("exit %d, stderr %q", code, errout.String())
	}
	if hasTerminalControl(out.String()) {
		t.Fatal("discover JSON emitted raw control")
	}
	var got discoverResult
	if json.Unmarshal(out.Bytes(), &got) != nil || got.Host != hostile || len(got.Findings) != 1 ||
		got.Findings[0].Path != "/"+hostile || got.Findings[0].Name != hostile {
		t.Fatalf("discover JSON changed values: %q", out.String())
	}
}
