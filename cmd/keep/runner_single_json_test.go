package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const singleJSONCanary = "CANARY-single-json-7f3a9c"

// TestRunnerSingleJSONDocument: the bounded decoder takes exactly one JSON
// document (plus trailing whitespace); a second document or garbage after the
// first is refused before the command acts, on the success and error paths.
func TestRunnerSingleJSONDocument(t *testing.T) {
	const revokeDoc = `{"ok":true,"request_id":"req1"}`
	const enrollDoc = `{"token":"keep_renr_fixture","token_id":"t1","expires_at":"2030-01-01T00:00:00Z"}`
	const errDoc = `{"error_class":"not_found","message":"m","request_id":"req1"}`
	trail := "{\"x\":\"" + singleJSONCanary + "\"}"
	cases := []struct {
		name   string
		suffix string
		prefix string
		accept bool
	}{
		{"single", "", "", true},
		{"trailing-whitespace", " \n\t\r\n", "", true},
		{"second-document", trail, "", false},
		{"second-document-after-space", " \n" + trail, "", false},
		{"empty-second-object", "{}", "", false},
		{"garbage", " invalid", "", false},
		{"canary-garbage", singleJSONCanary, "", false},
		{"malformed-first", "", "{", false},
	}
	for _, c := range cases {
		// decoder level
		t.Run("decode/"+c.name, func(t *testing.T) {
			var v struct{ OK bool }
			err := decodeBounded(strings.NewReader(c.prefix+`{"ok":true}`+c.suffix), &v)
			if c.name == "malformed-first" {
				err = decodeBounded(strings.NewReader(`{ {}`+c.suffix), &v)
			}
			if (err == nil) != c.accept {
				t.Fatalf("accepted=%v want %v (err=%v)", err == nil, c.accept, err)
			}
			if err != nil && strings.Contains(err.Error(), singleJSONCanary) {
				t.Fatalf("decoder error quotes the body")
			}
		})
		// command level: success path (revoke) and error path (printAPIError)
		for _, path := range []struct {
			name   string
			cmd    string
			status int
			doc    string
		}{
			{"revoke-success", "revoke", http.StatusOK, revokeDoc},
			{"enroll-token-success", "enroll", http.StatusCreated, enrollDoc},
			{"error", "revoke", http.StatusForbidden, errDoc},
		} {
			t.Run("cmd-"+path.name+"/"+c.name, func(t *testing.T) {
				srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(path.status)
					body := path.doc + c.suffix
					if c.name == "malformed-first" {
						body = "{ " + path.doc
					}
					_, _ = w.Write([]byte(body))
				}))
				defer srv.Close()
				t.Setenv("KEEP_ADMIN_TOKEN", testAdminTokenFixture)
				caPath := writePEMCert(t, srv.Certificate())
				rc, stdout, stderr := captureOutput(t, func() int {
					if path.cmd == "enroll" {
						return runRunnerEnrollToken([]string{"-host", "h1", "-policy", policyFileFixture(t), "-server", srv.URL, "-server-ca", caPath})
					}
					return runRunnerRevoke([]string{"-server", srv.URL, "-server-ca", caPath, "11111111-2222-4333-8444-555555555555"})
				})
				if strings.Contains(stdout+stderr, singleJSONCanary) {
					t.Fatalf("canary reached output")
				}
				if path.status != http.StatusForbidden {
					if c.accept != (rc == 0) {
						t.Fatalf("rc=%d accept=%v stderr=%q", rc, c.accept, stderr)
					}
					if !c.accept && (stdout != "" || !strings.Contains(stderr, "decoding response")) {
						t.Fatalf("refused answer acted on: stdout=%q stderr=%q", stdout, stderr)
					}
					return
				}
				if rc == 0 {
					t.Fatalf("error status exited 0")
				}
				if c.accept != strings.Contains(stderr, "not_found") {
					t.Fatalf("accept=%v stderr=%q", c.accept, stderr)
				}
				if !c.accept && !strings.Contains(stderr, "server rejected the request") {
					t.Fatalf("static line lost: %q", stderr)
				}
			})
		}
	}
}

// TestRunnerSingleJSONDocumentLimit: the single-document rule keeps the byte
// cap: exact limit passes, limit+1 is refused with the static error.
func TestRunnerSingleJSONDocumentLimit(t *testing.T) {
	var v struct{ OK bool }
	if err := decodeBounded(strings.NewReader(padJSON(`{"ok":true}`, maxRunnerResponseBytes)), &v); err != nil {
		t.Fatalf("exact limit refused: %v", err)
	}
	if err := decodeBounded(strings.NewReader(padJSON(`{"ok":true}`, maxRunnerResponseBytes+1)), &v); err != errResponseTooLarge {
		t.Fatalf("limit+1: got %v", err)
	}
}
