//go:build quickstart

// The leak search of the quickstart check (scripts/check-quickstart.sh): the
// canary the human typed into the browser may be found in the target file and
// nowhere else — not in the stdout or stderr of any step of docs/quickstart.md,
// not in an API or MCP answer a step printed, not in a server or runner log,
// not in the journal or any table of the database. Three more values the run
// itself creates are searched the same way — db.pw, root.key and admin.token —
// each allowed in its own file and in the few files that must hold it. The test
// never prints a matched byte, only the name of the value and of the file.
package quickstart

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// partial reports whether s carries a window of the canary's random part: a
// value cut short in an error ("%.20s") or stripped of its prefix leaks no
// whole canary, but still leaks. The whole-value detector cannot see it.
func partial(base, s string) bool {
	const window = 12
	for i := 0; i+window <= len(base); i++ {
		if strings.Contains(s, base[i:i+window]) {
			return true
		}
	}
	return false
}

// watch is one value the search looks for: its name (the only thing a failure
// prints), the value, and the exact paths allowed to hold it.
type watch struct {
	name    string
	value   string
	allowed map[string]bool
}

func newWatch(name, value string, allowed ...string) watch {
	w := watch{name: name, value: value, allowed: map[string]bool{}}
	for _, a := range allowed {
		if a != "" {
			w.allowed[filepath.Clean(a)] = true
		}
	}
	return w
}

// found reports whether s carries the value in any encoding, or a window of it.
func (w watch) found(s string) bool {
	return canary.Of(w.value).In(s) || partial(w.value, s)
}

// scan returns "<name> found in <path>" for every file under roots that carries
// a watched value outside the exact paths allowed for that value. It also
// returns how many files it looked at and how many bytes they held, so a search
// over an empty tree cannot pass.
func scan(t *testing.T, ws []watch, roots ...string) (hits []string, files int, bytes int64) {
	t.Helper()
	for _, root := range roots {
		err := filepath.WalkDir(root, //nolint:gosec // G703: root is a directory of this check's own run, never external input
			func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() {
					return nil
				}
				b, err := os.ReadFile(path) //nolint:gosec // G304: paths come from the walk of this check's own directories
				if err != nil {
					return err
				}
				files++
				bytes += int64(len(b))
				for _, w := range ws {
					if !w.allowed[filepath.Clean(path)] && w.found(string(b)) {
						hits = append(hits, w.name+" found in "+path)
					}
				}
				return nil
			})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	return hits, files, bytes
}

// loadWatches builds the four watched values from the run: the typed canary
// (allowed only in the target file) and db.pw, root.key and admin.token (each in
// its own file; db.pw also in the server environment, where it is part of
// KEEP_DATABASE_URL). Each gets a positive control: the detector must find it
// where it belongs. In a partial run (a step failed) a file not yet written is
// skipped; in a full run it is an error.
func loadWatches(t *testing.T, partialRun bool) []watch {
	t.Helper()
	raw, err := os.ReadFile(os.Getenv("QS_CANARY_FILE")) //nolint:gosec // G304: the check's own file
	if err != nil {
		t.Fatal("QS_CANARY_FILE is not readable: the scan has no canary to look for")
	}
	value := strings.TrimSpace(string(raw))
	c := canary.Of(value)
	if value == "" || !c.In("xx"+value+"yy") || !c.In(base64.StdEncoding.EncodeToString([]byte("a"+value))) {
		t.Fatal("canary detector is blind (positive control)")
	}
	ws := []watch{newWatch("value canary", value, os.Getenv("QS_TARGET"))}
	for _, x := range []struct{ name, env string }{
		{"db.pw", "QS_DB_PW_FILE"}, {"root.key", "QS_ROOT_KEY_FILE"}, {"admin.token", "QS_ADMIN_TOKEN_FILE"},
	} {
		path := os.Getenv(x.env)
		b, err := os.ReadFile(path) //nolint:gosec // G304: the check's own file
		v := strings.TrimSpace(string(b))
		if err != nil || v == "" {
			if partialRun {
				continue
			}
			t.Errorf("%s: %s does not hold a value: the scan has nothing to look for", x.name, x.env)
			continue
		}
		w := newWatch(x.name, v, path)
		if x.name == "db.pw" {
			w.allowed[filepath.Clean(os.Getenv("QS_SERVER_ENV"))] = true
		}
		if !w.found(string(b)) || !w.found("x"+v+"y") {
			t.Errorf("%s: detector is blind (positive control)", x.name)
		}
		ws = append(ws, w)
	}
	if !partialRun && len(ws) != 4 {
		t.Errorf("watching %d values, want 4", len(ws))
	}
	return ws
}

// TestScanCanFail is the check's own red run: a tree holding the canary in
// each of the shapes a leak takes must be reported, a clean tree must not.
func TestScanCanFail(t *testing.T) {
	c := canary.New()
	v := c.Value(1)
	for name, body := range map[string]string{
		"raw":       "token=" + v,
		"base64":    base64.StdEncoding.EncodeToString([]byte("a" + v)),
		"json":      `{"value":"` + v + `"}`,
		"hex":       hex.EncodeToString([]byte(v)),
		"reversed":  reverse(v),
		"rawurl":    base64.RawURLEncoding.EncodeToString([]byte("ab" + v)),
		"truncated": "err: bad value " + v[:20] + "...",
		"no-prefix": v[2:],
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "step.out"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if hits, _, _ := scan(t, []watch{newWatch("value canary", v)}, dir); len(hits) != 1 {
			t.Errorf("%s: scan did not find the canary", name)
		}
	}
	// The exemption covers exact paths and nothing beside them, for every
	// watched value; one value's exemption does not carry over to another.
	for _, w := range []struct{ name, value string }{
		{"value canary", v},
		{"db.pw", randomBytes(t, 16, hex.EncodeToString)},
		{"root.key", randomBytes(t, 32, base64.StdEncoding.EncodeToString)},
		{"admin.token", "keep_a_" + randomBytes(t, 24, hex.EncodeToString)},
	} {
		exempt := t.TempDir()
		own, also := filepath.Join(exempt, "own"), filepath.Join(exempt, "also")
		for _, n := range []string{own, own + ".copy", also} {
			if err := os.WriteFile(n, []byte(w.value), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		hits, _, _ := scan(t, []watch{newWatch(w.name, w.value, own, also)}, exempt)
		if len(hits) != 1 || hits[0] != w.name+" found in "+own+".copy" {
			t.Errorf("%s: the allowed-file exemption is not exact: %v", w.name, hits)
		}
		if hits, _, _ := scan(t, []watch{newWatch(w.name, w.value, own)}, exempt); len(hits) != 2 {
			t.Errorf("%s: an exemption for another file leaked over: %v", w.name, hits)
		}
	}
	clean := t.TempDir()
	if err := os.WriteFile(filepath.Join(clean, "step.out"), []byte("org_id=1\nok: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if hits, files, _ := scan(t, []watch{newWatch("value canary", v)}, clean); len(hits) != 0 || files != 1 {
		t.Errorf("clean tree: hits=%d files=%d", len(hits), files)
	}
}

// rawLeaks fetches each path from the server with the token, as the CLI would,
// and returns "<name> found in the raw answer of <path>" for every watched value a raw answer carries. The CLI prints only
// the fields it knows, so a server that added a field would be invisible in
// every step's output; the raw answer is what an API client would see. A path
// that does not answer 200 or answers nothing is an error, not a pass.
func rawLeaks(base, token string, ws []watch, paths []string) (leaks []string, err error) {
	client := &http.Client{Timeout: 15 * time.Second}
	for _, path := range paths {
		req, rerr := http.NewRequest(http.MethodGet, base+path, nil) //nolint:noctx,gosec // G704: base is this check's own loopback server; a bounded client; no caller context exists in this check
		if rerr != nil {
			return nil, fmt.Errorf("build request for %s", path)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, derr := client.Do(req) //nolint:gosec // G704: the base is this check's own loopback server
		if derr != nil {
			return nil, fmt.Errorf("GET %s failed", path)
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if rerr != nil || resp.StatusCode != http.StatusOK || len(body) == 0 {
			return nil, fmt.Errorf("GET %s: status %d, %d bytes: no raw answer to search", path, resp.StatusCode, len(body))
		}
		for _, w := range ws {
			if w.found(string(body)) {
				leaks = append(leaks, w.name+" found in the raw answer of "+path)
			}
		}
	}
	return leaks, nil
}

// TestRawFetchCanFail is the red control of the raw-answer search: a server
// that adds a value field to its answer must be reported, a clean one must not,
// and an unreachable or failing path must be an error.
func TestRawFetchCanFail(t *testing.T) {
	c := canary.New()
	v := c.Value(1)
	dbpw := randomBytes(t, 16, hex.EncodeToString)
	ws := []watch{newWatch("value canary", v), newWatch("db.pw", dbpw)}
	serve := func(body string, status int) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer t" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}))
	}
	leaky := serve(`{"name":"DEMO","value":"`+v+`"}`, http.StatusOK)
	defer leaky.Close()
	if l, err := rawLeaks(leaky.URL, "t", ws, []string{"/x"}); err != nil || len(l) != 1 || l[0] != "value canary found in the raw answer of /x" {
		t.Errorf("an answer carrying the value was not reported: %v %v", l, err)
	}
	other := serve(`{"name":"DEMO","note":"`+dbpw+`"}`, http.StatusOK)
	defer other.Close()
	if l, err := rawLeaks(other.URL, "t", ws, []string{"/x"}); err != nil || len(l) != 1 || l[0] != "db.pw found in the raw answer of /x" {
		t.Errorf("an answer carrying another watched value was not reported: %v %v", l, err)
	}
	clean := serve(`{"name":"DEMO","length":36}`, http.StatusOK)
	defer clean.Close()
	if l, err := rawLeaks(clean.URL, "t", ws, []string{"/x"}); err != nil || len(l) != 0 {
		t.Errorf("a clean answer was reported: %v %v", l, err)
	}
	failing := serve(`{"error_class":"x"}`, http.StatusInternalServerError)
	defer failing.Close()
	if _, err := rawLeaks(failing.URL, "t", ws, []string{"/x"}); err == nil {
		t.Error("a failing path passed: nothing was searched")
	}
	if _, err := rawLeaks(clean.URL, "wrong", ws, []string{"/x"}); err == nil {
		t.Error("a refused token passed: nothing was searched")
	}
}

// TestRawAnswersNoLeak asks the running server for the raw answers an API
// client would get, which the CLI filters. It runs while the server is up,
// before the clean-up step stops it.
func TestRawAnswersNoLeak(t *testing.T) {
	ws := loadWatches(t, false)
	base := os.Getenv("QS_SERVER")
	if base == "" {
		t.Fatal("QS_SERVER is empty: nothing to ask")
	}
	tok, terr := os.ReadFile(os.Getenv("QS_TOKEN_FILE")) //nolint:gosec // G304: the check's own file
	if terr != nil {
		t.Fatal("QS_TOKEN_FILE is not readable")
	}
	paths := strings.Fields(os.Getenv("QS_RAW_PATHS"))
	if len(paths) < 4 {
		t.Fatalf("QS_RAW_PATHS lists %d paths: too few to mean anything", len(paths))
	}
	leaks, rerr := rawLeaks(base, strings.TrimSpace(string(tok)), ws, paths)
	if rerr != nil {
		t.Error(rerr)
	}
	for _, l := range leaks {
		t.Error(l)
	}
}

// TestQuickstartNoLeak reads the finished run: QS_CANARY_FILE holds the typed
// value, QS_TARGET is the one file that may hold it, QS_SCAN lists the
// directories to search (colon separated). QS_DB_PW_FILE, QS_ROOT_KEY_FILE and
// QS_ADMIN_TOKEN_FILE hold the other three values; QS_SERVER_ENV is the one
// other file that holds db.pw (inside KEEP_DATABASE_URL).
func TestQuickstartNoLeak(t *testing.T) {
	partialRun := os.Getenv("QS_PARTIAL") == "1"
	ws := loadWatches(t, partialRun)
	target := os.Getenv("QS_TARGET")
	if !partialRun {
		got, err := os.ReadFile(target) //nolint:gosec // G304: the check's own file
		if err != nil || strings.TrimSpace(string(got)) != ws[0].value {
			t.Fatal("the target file does not hold the typed value (positive control: the canary did arrive where it belongs)")
		}
	}
	roots := strings.Split(os.Getenv("QS_SCAN"), ":")
	hits, files, size := scan(t, ws, roots...)
	for _, h := range hits {
		t.Error(h)
	}
	// A search over nothing proves nothing: the steps, both logs and the
	// journal dump must be there and not empty.
	if partialRun {
		return // a step failed: only the search for the value matters, not completeness
	}
	if files < 20 || size < 2000 {
		t.Errorf("the leak search looked at %d files, %d bytes: too little to mean anything", files, size)
	}
	for _, must := range []string{"server.log", "runner.log", "journal.json", "tables.json"} {
		found := false
		for _, r := range roots {
			//nolint:gosec // G703: r is a directory of this check's own run, must a fixed name
			if st, err := os.Stat(filepath.Join(r, must)); err == nil && st.Size() > 0 {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is missing or empty in the scanned directories", must)
		}
	}
}

// randomBytes is a fresh fixture per run, so no value literal sits in the source.
func randomBytes(t *testing.T, n int, enc func([]byte) string) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return enc(b)
}

func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}
