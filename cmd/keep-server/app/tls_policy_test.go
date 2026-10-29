package app

import (
	"bytes"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/config"
)

func TestServerTLSRequiresExplicitCertificateOrDevelopmentFlag(t *testing.T) {
	var log bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&log, nil))

	if _, err := serverTLSCert(config.Config{}, logger); err == nil {
		t.Fatal("server accepted implicit ephemeral TLS certificate")
	}
	if _, err := serverTLSCert(config.Config{ServerTLSCertFile: "cert.pem"}, logger); err == nil {
		t.Fatal("server accepted incomplete TLS configuration")
	}
	t.Setenv("KEEP_DATABASE_URL", "postgres://synthetic-test-only@127.0.0.1:1/keep")
	t.Setenv("KEEP_DEV_EPHEMERAL_TLS", "1")
	cfg, err := config.FromEnv()
	if err != nil {
		t.Fatal("development configuration rejected")
	}
	if _, err := serverTLSCert(cfg, logger); err != nil {
		t.Fatal("explicit development TLS mode failed")
	}
	if !strings.Contains(log.String(), "ephemeral") {
		t.Fatal("development TLS mode did not emit a warning")
	}
}

func TestServerProcessRefusesMissingTLSConfigurationBeforeDatabaseAccess(t *testing.T) {
	bin := buildKeepServer(t)
	cmd := exec.Command(bin) //nolint:gosec // G204: bin is built into this test's temp directory
	cmd.Env = []string{"KEEP_DATABASE_URL=postgres://synthetic-test-only@127.0.0.1:1/keep", "PATH=" + os.Getenv("PATH")}
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("server process started without TLS configuration")
	}
	if !strings.Contains(string(out), "KEEP_SERVER_TLS_CERT_FILE") {
		t.Fatal("server did not identify the missing TLS configuration")
	}
}
