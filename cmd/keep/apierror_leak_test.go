package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

const goodRequestID = "req-1"

// TestAPIErrorMessageNoLeak: the server's error message is untrusted even
// under a known error_class, so neither reportErr nor apiError.Error() may
// print it (nor an unknown class). The class alone picks a static local text;
// request_id is printed only inside the server's reqid.Valid contract and
// never reflects a value outside it. The exit code stays non-zero and stdout
// stays empty (threat model §4.3).
func TestAPIErrorMessageNoLeak(t *testing.T) {
	can := canary.New()
	raw := can.Value(0)
	forms := map[string]string{
		"raw":        raw,
		"controls":   "\x1b[2J\u200b" + raw + "\x07\u202e",
		"hex":        hex.EncodeToString([]byte(raw)),
		"base64":     base64.StdEncoding.EncodeToString([]byte(raw)),
		"percent":    url.QueryEscape("x " + raw),
		"multi-line": "line one\n" + raw + "\r\nline three",
	}

	// Positive control: the detector sees every form, and the old printing
	// path (sanitizeText of the message) still carries the printable ones.
	for name, form := range forms {
		if !can.In(form) {
			t.Fatalf("detector is blind to the %s form", name)
		}
	}
	if !can.In(sanitizeText(forms["controls"], maxErrTextRunes)) {
		t.Fatal("positive control: sanitizeText no longer keeps a printable canary, the test would be vacuous")
	}

	for _, class := range []string{"internal", "secret_not_found", "permission_denied", "totally_made_up"} {
		for name, form := range forms {
			for _, debug := range []bool{false, true} {
				wire := class
				if class == "totally_made_up" {
					wire = form // an unknown class is untrusted text too
				}
				body := apiError{ErrorClass: wire, Message: form, RequestID: goodRequestID}
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(body)
				}))
				getenv := func(k string) string {
					return map[string]string{"KEEP_SERVER": srv.URL, "KEEP_ORG": "org-1", "KEEP_TOKEN": "test-fixture-token"}[k]
				}
				args := []string{"list", "--scope-level", "user", "--scope-id", "u1"}
				if debug {
					args = append(args, "--debug")
				}
				var stdout, stderr bytes.Buffer
				rc := run(args, strings.NewReader(""), &stdout, &stderr, getenv)
				srv.Close()
				label := class + "/" + name
				if rc != 1 {
					t.Fatalf("%s debug=%t: exit %d, want 1", label, debug, rc)
				}
				if stdout.Len() != 0 {
					t.Errorf("%s debug=%t: stdout not empty (len=%d)", label, debug, stdout.Len())
				}
				// --debug prepends its redacted trace; the error line is the
				// last "keep: " line either way.
				var last string
				for _, l := range strings.Split(stderr.String(), "\n") {
					if strings.HasPrefix(l, "keep: ") {
						last = l
					}
				}
				if last == "" {
					t.Fatalf("%s debug=%t: no diagnostic on stderr (len=%d): the probe may not have reached the server", label, debug, stderr.Len())
				}
				if can.In(stderr.String()) {
					t.Errorf("%s debug=%t: server text reached stderr (len=%d)", label, debug, stderr.Len())
				}
				// The class still tells the user what happened: the static
				// local text for a known class, the generic one otherwise.
				wantLine := "keep: " + safeClass(wire) + ": " + staticMessage(wire) + " (request_id=" + goodRequestID + ")"
				if last != wantLine {
					t.Errorf("%s debug=%t: error line is not the static class text (len=%d)", label, debug, len(last))
				}
				if class == "secret_not_found" && last != "keep: secret_not_found: secret not found (request_id="+goodRequestID+")" {
					t.Errorf("%s: known class lost its static text", label)
				}
				if class == "totally_made_up" && last != "keep: (unexpected value): request failed (request_id="+goodRequestID+")" {
					t.Errorf("%s: unknown class not generic", label)
				}
				if got, ok := errorClassOf(last + "\n"); ok && class == "totally_made_up" && got != unexpectedValue {
					t.Errorf("%s: unknown class echoed", label)
				}
				e := (&apiError{ErrorClass: wire, Message: form, RequestID: goodRequestID}).Error()
				if can.In(e) || e != safeClass(wire)+": "+staticMessage(wire)+" (request_id="+goodRequestID+")" {
					t.Errorf("%s: apiError.Error() carries server text (len=%d)", label, len(e))
				}
			}
		}
	}

	// request_id: whatever the message carries, the id is printed inside the
	// server's contract (valid ids are the positive controls) and dropped to
	// the placeholder outside it, through reportErr and Error(), debug on/off.
	for _, debug := range []bool{false, true} {
		for i := range requestIDCases(canary.New()) {
			idCan := canary.New()
			tc := requestIDCases(idCan)[i]
			body := apiError{ErrorClass: "secret_not_found", Message: raw, RequestID: tc.id}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(body)
			}))
			getenv := func(k string) string {
				return map[string]string{"KEEP_SERVER": srv.URL, "KEEP_ORG": "org-1", "KEEP_TOKEN": "test-fixture-token"}[k]
			}
			args := []string{"list", "--scope-level", "user", "--scope-id", "u1"}
			if debug {
				args = append(args, "--debug")
			}
			var stdout, stderr bytes.Buffer
			rc := run(args, strings.NewReader(""), &stdout, &stderr, getenv)
			srv.Close()
			wantTail := ""
			switch {
			case tc.id == "":
			case tc.ok:
				wantTail = " (request_id=" + tc.id + ")"
			default:
				wantTail = " (request_id=" + unexpectedValue + ")"
			}
			want := "keep: secret_not_found: secret not found" + wantTail
			var last string
			for _, l := range strings.Split(stderr.String(), "\n") {
				if strings.HasPrefix(l, "keep: ") {
					last = l
				}
			}
			if rc != 1 || stdout.Len() != 0 || last != want {
				t.Errorf("request_id %s debug=%t: rc=%d stdout=%d, error line differs from the contract (len=%d)", tc.name, debug, rc, stdout.Len(), len(last))
			}
			if can.In(stderr.String()) || idCan.In(stderr.String()) && !tc.ok {
				t.Errorf("request_id %s debug=%t: a credential reached stderr (len=%d)", tc.name, debug, stderr.Len())
			}
			e := (&apiError{ErrorClass: "secret_not_found", Message: raw, RequestID: tc.id}).Error()
			if e != strings.TrimPrefix(want, "keep: ") {
				t.Errorf("request_id %s: apiError.Error() differs from the contract (len=%d)", tc.name, len(e))
			}
		}
	}

	// Healthy path stays healthy: an empty list is exit 0 with a result.
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	defer ok.Close()
	getenv := func(k string) string {
		return map[string]string{"KEEP_SERVER": ok.URL, "KEEP_ORG": "org-1", "KEEP_TOKEN": "test-fixture-token"}[k]
	}
	var stdout, stderr bytes.Buffer
	if rc := run([]string{"list", "--scope-level", "user", "--scope-id", "u1", "--json"}, strings.NewReader(""), &stdout, &stderr, getenv); rc != 0 {
		t.Fatalf("healthy [] exit %d: %q", rc, stderr.String())
	}

	// A 2xx body the CLI cannot decode must not echo the decoder's quote of
	// it (time.ParseError carries the bad string): static line, exit 1.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"a","created_at":"` + raw + `"}]`))
	}))
	defer bad.Close()
	getenv = func(k string) string {
		return map[string]string{"KEEP_SERVER": bad.URL, "KEEP_ORG": "org-1", "KEEP_TOKEN": "test-fixture-token"}[k]
	}
	stdout.Reset()
	stderr.Reset()
	if rc := run([]string{"list", "--scope-level", "user", "--scope-id", "u1"}, strings.NewReader(""), &stdout, &stderr, getenv); rc != 1 {
		t.Fatalf("undecodable 2xx body: exit %d, want 1", rc)
	}
	if stdout.Len() != 0 || can.In(stderr.String()) {
		t.Errorf("undecodable 2xx body leaked (stdout=%d stderr=%d bytes)", stdout.Len(), stderr.Len())
	}
	if !strings.Contains(stderr.String(), "parse server response") {
		t.Errorf("lost the static diagnostic (stderr len=%d)", stderr.Len())
	}
}

// TestBadBodyErrorsAreStatic: every ordinary command that decodes a 2xx body
// answers an undecodable one with errBadResponse itself — never a wrapped
// decoder error, which quotes the body (time.ParseError) — and the canary in
// the body stays off the terminal path.
func TestBadBodyErrorsAreStatic(t *testing.T) {
	can := canary.New()
	q := `"` + can.Value(0) + `"`
	// Every field a command reads is given the wrong type, so each decode fails.
	bad := `{"id":1,"created_at":` + q + `,"ok":` + q + `,"checked":` + q + `,"erased":` + q + `}`
	// The secret list answers well, so meta and version get past the name
	// lookup and reach their own decode; the list command itself runs with it off.
	var listGood atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if listGood.Load() && r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/secrets") {
			_, _ = w.Write([]byte(`[{"id":"s1","name":"n"}]`))
			return
		}
		_, _ = w.Write([]byte(bad))
	}))
	defer srv.Close()
	c := newClient(srv.URL, "org-1", "test-fixture-token", false, &bytes.Buffer{})
	in := createRefInput{ScopeLevel: "user", ScopeID: "u1", Name: "n", Class: "c", Type: "t", ProviderRef: "p"}
	calls := map[string]func() error{
		"list":           func() error { _, err := listSecrets(c, "user", "u1"); return err },
		"meta":           func() error { return cmdMeta(c, "user", "u1", "n", false, &bytes.Buffer{}) },
		"version":        func() error { return cmdVersion(c, "user", "u1", "n", false, &bytes.Buffer{}) },
		"create-ref":     func() error { return cmdCreateRef(c, in, false, &bytes.Buffer{}) },
		"audit-verify":   func() error { _, err := cmdAuditVerify(c, false, &bytes.Buffer{}); return err },
		"mesh-uninstall": func() error { return cmdMeshUninstall(c, "ws", false, &bytes.Buffer{}) },
	}
	for name, call := range calls {
		listGood.Store(name != "list")
		err := call()
		if err != errBadResponse { //nolint:errorlint // identity is the property
			t.Errorf("%s: undecodable 2xx body gave %v-shaped error (len=%d), want errBadResponse", name, err != nil, len(fmt.Sprint(err)))
		}
		if err != nil && can.In(err.Error()) {
			t.Errorf("%s: canary reached the error text", name)
		}
	}
	// Positive control: the unwrapped decoder error does carry the canary.
	var s secret
	if raw := json.Unmarshal([]byte(bad), &s); raw == nil || !can.In(raw.Error()) {
		t.Fatal("positive control: this decoder error no longer quotes the body, the test would be vacuous")
	}
}

// TestClassMessagesCoverEveryAPIClass: a class the server can answer with
// must have its own static text, and the table holds no class the server
// does not define; otherwise the user gets the generic line for a known error.
func TestClassMessagesCoverEveryAPIClass(t *testing.T) {
	for _, k := range apperr.Classes() {
		if m, ok := classMessages[string(k)]; !ok || m == "" || m == staticMessage("totally_made_up") {
			t.Errorf("class %q has no static text of its own", k)
		}
	}
	if len(classMessages) != len(apperr.Classes()) {
		t.Errorf("classMessages has %d entries, apperr defines %d classes", len(classMessages), len(apperr.Classes()))
	}
}
