package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

const mcpTestOrg = "019a0000-0000-7000-8000-0000000000aa"

// runKeepMCP execs the built binary: stdout and stderr are what an agent host
// would see.
func runKeepMCP(t *testing.T, env []string, stdin string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(keepBinPath, append([]string{"mcp"}, args...)...) //nolint:gosec // G204: our own built binary
	cmd.Env = append([]string{"HOME=" + t.TempDir(), "PATH=" + "/usr/bin:/bin"}, env...)
	cmd.Stdin = strings.NewReader(stdin)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return o.String(), e.String(), code
}

func TestKeepMCPBinaryNeverPrintsAValueOrTheToken(t *testing.T) {
	c := canary.New()
	value, token := c.Value(1), c.Value(2)
	if !c.In("x"+value) || !c.In("x"+token) {
		t.Fatal("canary detector is blind")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Debug", value)
		_ = json.NewEncoder(w).Encode([]map[string]any{{"id": "x", "name": "db", "value": value, "plaintext": value}})
	}))
	defer srv.Close()
	call := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_secrets","arguments":{"scope_level":"org","scope_id":"` + mcpTestOrg + `"}}}`
	out, errOut, code := runKeepMCP(t, []string{"KEEP_SERVER=" + srv.URL, "KEEP_ORG=" + mcpTestOrg, "KEEP_TOKEN=" + token}, call+"\n")
	if code != 0 || !strings.Contains(out, "unexpected shape") {
		t.Fatalf("the server did not answer (positive control): code=%d out=%s err=%s", code, out, errOut)
	}
	if c.In(out) || c.In(errOut) {
		t.Fatalf("canary on stdout/stderr:\n%s\n%s", out, errOut)
	}

	// A wrong configuration reports a fixed message and never echoes the token or address.
	out, errOut, code = runKeepMCP(t, []string{"KEEP_SERVER=http://" + token + ".example", "KEEP_ORG=" + mcpTestOrg, "KEEP_TOKEN=" + token}, "")
	if code == 0 || c.In(out) || c.In(errOut) {
		t.Fatalf("bad config: code=%d out=%s err=%s", code, out, errOut)
	}
	_, errOut, code = runKeepMCP(t, []string{"KEEP_SERVER=" + srv.URL, "KEEP_ORG=" + mcpTestOrg}, "")
	if code == 0 || errOut == "" {
		t.Fatalf("a missing token must fail: code=%d", code)
	}
}

func TestKeepMCPListsTools(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	out, _, code := runKeepMCP(t, []string{"KEEP_SERVER=" + srv.URL, "KEEP_ORG=" + mcpTestOrg, "KEEP_TOKEN=t"},
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n")
	if code != 0 {
		t.Fatalf("code=%d", code)
	}
	for _, n := range []string{"list_secrets", "get_secret_meta", "request_secret_input", "deploy"} {
		if !strings.Contains(out, `"name":"`+n+`"`) {
			t.Fatalf("%s missing: %s", n, out)
		}
	}
}
