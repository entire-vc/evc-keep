package app

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
)

// serveWithEnv is runServeWithRoot plus extra environment entries.
func serveWithEnv(t *testing.T, bin, dsn string, d time.Duration, extra ...string) (out string, stillRunning bool, code int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin) //nolint:gosec // G204: bin is buildKeepServer's own output
	cmd.Env = append(os.Environ(), "KEEP_DATABASE_URL="+dsn, "KEEP_HTTP_ADDR=127.0.0.1:0",
		"KEEP_ROOT_KEY_FILE="+serverRootKeyFile(t), "KEEP_ROOT_KEY_ID=local-v1",
		"KEEP_RUNNER_ADDR=127.0.0.1:0", "KEEP_DEV_EPHEMERAL_TLS=1")
	cmd.Env = append(cmd.Env, extra...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	_ = cmd.Run() // outcome read from ctx and ProcessState below
	if ctx.Err() == context.DeadlineExceeded {
		return buf.String(), true, -1
	}
	return buf.String(), false, cmd.ProcessState.ExitCode()
}

// A half-set Mesh gate must stop the process before it listens, naming the
// variables and never a value; no Mesh variables at all starts it as before;
// a full set on the plain build (no plugin) is refused rather than silently
// running without the gate.
func TestServeMeshGateStartup(t *testing.T) {
	bin := buildKeepServer(t)
	dsn := pgscratch.New(t, requiredLogSettingsLiteral)
	migrate(t, bin, dsn)
	roleDSN := pgscratch.NewRole(t, dsn, "keep_app")

	const canary = "meshgate-canary-7f3a91c2"
	tokenFile := filepath.Join(t.TempDir(), "mesh-token")
	if err := os.WriteFile(tokenFile, []byte(canary), 0600); err != nil {
		t.Fatal("token fixture write failed")
	}
	project := uuid.NewString()
	status := uuid.NewString()

	t.Run("no mesh variables starts", func(t *testing.T) {
		out, running, code := serveWithEnv(t, bin, roleDSN, 3*time.Second)
		if !running {
			t.Fatalf("server did not stay up without Mesh variables (exit %d): %q", code, out)
		}
	})

	t.Run("partial set refused", func(t *testing.T) {
		out, running, code := serveWithEnv(t, bin, roleDSN, 15*time.Second,
			"KEEP_MESH_EXTENSION=1", "KEEP_MESH_PROJECT_ID="+project, "KEEP_MESH_TOKEN_FILE="+tokenFile)
		if running || code != 1 {
			t.Fatalf("partial config: running=%v code=%d, want exit 1: %q", running, code, out)
		}
		if !strings.Contains(out, "KEEP_MESH_URL") {
			t.Fatalf("refusal does not name the missing variable: %q", out)
		}
		for _, v := range []string{canary, project, tokenFile} {
			if strings.Contains(out, v) {
				t.Fatal("refusal output carries a configured value")
			}
		}
	})

	t.Run("full set without plugin refused", func(t *testing.T) {
		out, running, code := serveWithEnv(t, bin, roleDSN, 15*time.Second,
			"KEEP_MESH_EXTENSION=1", "KEEP_MESH_PROJECT_ID="+project, "KEEP_MESH_URL=https://mesh.invalid",
			"KEEP_MESH_CANCEL_STATUS_ID="+status, "KEEP_MESH_TOKEN_FILE="+tokenFile)
		if running || code != 1 {
			t.Fatalf("plain build with full gate config: running=%v code=%d, want exit 1: %q", running, code, out)
		}
		if strings.Contains(out, canary) {
			t.Fatal("refusal output carries the token")
		}
	})
}
