package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

const singleJSONCanary = "CANARY-single-json-7f3a9c"

// TestEnrollSingleJSONDocument: enroll's bounded decoder takes exactly one
// JSON document (plus trailing whitespace); a second document or garbage after
// the first is refused before any credential is saved.
func TestEnrollSingleJSONDocument(t *testing.T) {
	okJSON, err := json.Marshal(validEnrollResponse(t, enrollFixtureRunnerID))
	if err != nil {
		t.Fatal(err)
	}
	okDoc := string(okJSON)
	const errDoc = `{"error_class":"not_found","message":"m","request_id":"req1"}`
	trail := "{\"x\":\"" + singleJSONCanary + "\"}"
	cases := []struct {
		name   string
		suffix string
		accept bool
	}{
		{"single", "", true},
		{"trailing-whitespace", " \n\t\r\n", true},
		{"second-document", trail, false},
		{"second-document-after-space", " \n" + trail, false},
		{"empty-second-object", "{}", false},
		{"garbage", " invalid", false},
		{"canary-garbage", singleJSONCanary, false},
		{"malformed-first", "", false},
	}
	for _, c := range cases {
		t.Run("decode/"+c.name, func(t *testing.T) {
			in := `{"ok":true}` + c.suffix
			if c.name == "malformed-first" {
				in = `{ {}`
			}
			var v struct{ OK bool }
			err := decodeBounded(strings.NewReader(in), &v)
			if (err == nil) != c.accept {
				t.Fatalf("accepted=%v want %v (err=%v)", err == nil, c.accept, err)
			}
			if err != nil && strings.Contains(err.Error(), singleJSONCanary) {
				t.Fatalf("decoder error quotes the body")
			}
		})
		for _, path := range []struct {
			name   string
			status int
			doc    string
		}{{"success", http.StatusOK, okDoc}, {"error", http.StatusForbidden, errDoc}} {
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
				caPath := writePEMCert(t, srv.Certificate())
				credDir := t.TempDir()
				rc, stdout, stderr := captureEnrollOutput(t, testTokenFixture+"\n", func() int {
					return runEnroll([]string{
						"-host", "h1", "-policy", enrollPolicyFixture(t), "-server", srv.URL,
						"-cred-dir", credDir, "-server-ca", caPath,
					})
				})
				if strings.Contains(stdout+stderr, singleJSONCanary) {
					t.Fatalf("canary reached output")
				}
				if path.status == http.StatusOK {
					if c.accept != (rc == 0) {
						t.Fatalf("rc=%d accept=%v stderr=%q", rc, c.accept, stderr)
					}
					entries, _ := os.ReadDir(credDir)
					if !c.accept && (len(entries) != 0 || !strings.Contains(stderr, "decoding response")) {
						t.Fatalf("refused answer acted on: entries=%d stderr=%q", len(entries), stderr)
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

// TestEnrollSingleJSONDocumentLimit: the byte cap survives the stricter decode.
func TestEnrollSingleJSONDocumentLimit(t *testing.T) {
	var v struct{ OK bool }
	if err := decodeBounded(strings.NewReader(padJSON(`{"ok":true}`, maxEnrollResponseBytes)), &v); err != nil {
		t.Fatalf("exact limit refused: %v", err)
	}
	if err := decodeBounded(strings.NewReader(padJSON(`{"ok":true}`, maxEnrollResponseBytes+1)), &v); err != errResponseTooLarge {
		t.Fatalf("limit+1: got %v", err)
	}
}
