//go:build unix

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// A path given to -server-ca, -policy or -cred-dir may be a secret pasted
// into the wrong flag. No diagnostic about a local file may repeat it, nor
// the text of the underlying *os.PathError that quotes it.

// localFileCase runs one command with the canary spread into the path flags.
type localFileCase struct {
	name string
	run  func(t *testing.T, c canary.Canary) (rc int, out string)
}

func canaryPath(t *testing.T, c canary.Canary, i int) string {
	t.Helper()
	return filepath.Join(t.TempDir(), c.Value(i))
}

// dirAtPath creates a directory named with the canary: reading it as a file
// fails with an error that quotes the path, and unlike a mode-000 file this
// fails the same way for root, so no case is ever skipped.
func dirAtPath(t *testing.T, c canary.Canary, i int) string {
	t.Helper()
	p := canaryPath(t, c, i)
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal("fixture setup failed (error withheld: it quotes the canary path)")
	}
	return p
}

func enrollOut(t *testing.T, args ...string) (int, string) {
	t.Helper()
	rc, stdout, stderr := captureEnrollOutput(t, testTokenFixture+"\n", func() int { return runEnroll(args) })
	return rc, stdout + stderr
}

func localFileCases() []localFileCase {
	const httpsDummy = "https://127.0.0.1:1"
	return []localFileCase{
		{"enroll-ca-missing", func(t *testing.T, c canary.Canary) (int, string) {
			return enrollOut(t, "-host", "h1", "-server", httpsDummy, "-policy", enrollPolicyFixture(t), "-server-ca", canaryPath(t, c, 1))
		}},
		{"enroll-ca-is-directory", func(t *testing.T, c canary.Canary) (int, string) {
			return enrollOut(t, "-host", "h1", "-server", httpsDummy, "-policy", enrollPolicyFixture(t), "-server-ca", dirAtPath(t, c, 2))
		}},
		{"enroll-ca-malformed-pem", func(t *testing.T, c canary.Canary) (int, string) {
			p := canaryPath(t, c, 3)
			if err := os.WriteFile(p, []byte("not a pem"), 0o600); err != nil {
				t.Fatal("fixture setup failed (error withheld: it quotes the canary path)")
			}
			return enrollOut(t, "-host", "h1", "-server", httpsDummy, "-policy", enrollPolicyFixture(t), "-server-ca", p)
		}},
		{"enroll-policy-missing", func(t *testing.T, c canary.Canary) (int, string) {
			return enrollOut(t, "-host", "h1", "-server", httpsDummy, "-policy", canaryPath(t, c, 4))
		}},
		{"enroll-policy-is-directory", func(t *testing.T, c canary.Canary) (int, string) {
			return enrollOut(t, "-host", "h1", "-server", httpsDummy, "-policy", dirAtPath(t, c, 5))
		}},
		{"enroll-credential-save", func(t *testing.T, c canary.Canary) (int, string) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"runner_id":"r","certificate":"AA==","ca_certificate":"AA==","sign_key_id":"k","sign_pub_key":"AA==","not_after":"2030-01-01T00:00:00Z"}`))
			}))
			defer srv.Close()
			// A regular file as the parent makes the credential dir uncreatable.
			parent := canaryPath(t, c, 6)
			if err := os.WriteFile(parent, nil, 0o600); err != nil {
				t.Fatal("fixture setup failed (error withheld: it quotes the canary path)")
			}
			return enrollOut(t, "-host", "h1", "-server", srv.URL, "-policy", enrollPolicyFixture(t),
				"-server-ca", writePEMCert(t, srv.Certificate()), "-cred-dir", filepath.Join(parent, "sub"))
		}},
		{"check-credential-missing", func(t *testing.T, c canary.Canary) (int, string) {
			rc, o, e := captureEnrollOutput(t, "", func() int {
				return runCheck([]string{"-cred-dir", canaryPath(t, c, 7), "-policy", enrollPolicyFixture(t)})
			})
			return rc, o + e
		}},
		{"check-credential-not-a-directory", func(t *testing.T, c canary.Canary) (int, string) {
			f := canaryPath(t, c, 8)
			if err := os.WriteFile(f, nil, 0o600); err != nil {
				t.Fatal("fixture setup failed (error withheld: it quotes the canary path)")
			}
			rc, o, e := captureEnrollOutput(t, "", func() int {
				return runCheck([]string{"-cred-dir", f, "-policy", enrollPolicyFixture(t)})
			})
			return rc, o + e
		}},
		{"check-policy-missing", func(t *testing.T, c canary.Canary) (int, string) {
			rc, o, e := captureEnrollOutput(t, "", func() int {
				// A valid credential, so check reaches the policy read.
				return runCheck([]string{"-cred-dir", newPrefixHost(t).credDir, "-policy", canaryPath(t, c, 9)})
			})
			return rc, o + e
		}},
	}
}

func TestRunnerLocalFileErrors(t *testing.T) {
	for _, tc := range localFileCases() {
		t.Run(tc.name, func(t *testing.T) {
			c := canary.New()
			rc, out := tc.run(t, c)
			if rc == 0 {
				t.Fatalf("exit 0 on a local file error")
			}
			if out == "" {
				t.Errorf("no diagnostic printed")
			}
			if c.In(out) {
				t.Errorf("a local path reached the terminal (%d bytes of output)", len(out))
			}
		})
	}
}

// The detector must fail on a path-bearing diagnostic, or the test above
// proves nothing.
func TestRunnerLocalFileErrorsDetectorControl(t *testing.T) {
	c := canary.New()
	_, err := os.ReadFile(canaryPath(t, c, 1))
	if err == nil {
		t.Fatal("fixture: expected a read error")
	}
	if !c.In("keep-runner enroll: reading -server-ca: " + err.Error()) {
		t.Fatal("detector does not see a raw PathError carrying the canary path")
	}
}
