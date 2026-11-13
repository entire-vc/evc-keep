//go:build upgradeprobe

package app

// The probe behind scripts/check-upgrade-rollback.sh. It is built only with
// -tags upgradeprobe, so no ordinary test run compiles it and it carries no
// skip. The script copies this one file into a checkout of the older release
// and runs it there too, so it may use only what both releases have.
//
// Actions (KEEP_PROBE_ACTION), state under KEEP_PROBE_DIR:
//
//	seal  seal a disposable canary into the builtin store of KEEP_PROBE_ORG
//	      and write its version, fingerprint and length to KEEP_PROBE_OUT;
//	read  open the newest version, check it is the same canary, write the same
//	      three fields to KEEP_PROBE_OUT;
//	scan  fail when KEEP_PROBE_LOG carries the canary in any encoding.
//
// The canary value lives only in KEEP_PROBE_DIR/canary.value (mode 0600); the
// probe prints name, version, fingerprint and length, never the value.

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/config"
	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

const upgradeProbePath = "upgrade-canary"

func upgradeProbeEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s is not set", name)
	}
	return v
}

func upgradeProbeOpen(t *testing.T, ctx context.Context) (*builtin.Provider, func()) {
	t.Helper()
	cfg, err := config.FromEnv()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	pool, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		t.Fatal("open database")
	}
	local, err := builtin.OpenLocalFile(pool, cfg.RootKeyFile, cfg.RootKeyID, slog.New(slog.DiscardHandler), func(builtin.KeyEvent) {})
	if err != nil {
		pool.Close()
		t.Fatal("open root key")
	}
	return local.Provider(upgradeProbeEnv(t, "KEEP_PROBE_ORG"), "", "", ""), pool.Close
}

func upgradeProbeReport(t *testing.T, ctx context.Context, p *builtin.Provider, v secret.Value, version string) {
	t.Helper()
	key, err := p.FingerprintKey(ctx)
	if err != nil {
		t.Fatalf("fingerprint key: %v", err)
	}
	fp, err := fingerprint.Compute(key, v)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	line := "version=" + version + " fingerprint=" + fp + " length=" + strconv.Itoa(v.Len()) + "\n"
	if err := os.WriteFile(upgradeProbeEnv(t, "KEEP_PROBE_OUT"), []byte(line), 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}
	t.Log(strings.TrimSpace(line))
}

func TestUpgradeProbe(t *testing.T) {
	ctx := context.Background()
	dir := upgradeProbeEnv(t, "KEEP_PROBE_DIR")
	valueFile := filepath.Join(dir, "canary.value")

	switch action := upgradeProbeEnv(t, "KEEP_PROBE_ACTION"); action {
	case "seal":
		p, closeDB := upgradeProbeOpen(t, ctx)
		defer closeDB()
		value := canary.New().Value(1)
		if err := os.WriteFile(valueFile, []byte(value), 0o600); err != nil {
			t.Fatalf("write canary: %v", err)
		}
		meta, err := p.Write(ctx, provider.Ref{Path: upgradeProbePath}, secret.New([]byte(value)))
		if err != nil {
			t.Fatalf("seal canary: %v", err)
		}
		upgradeProbeReport(t, ctx, p, secret.New([]byte(value)), meta.Version)

	case "read":
		p, closeDB := upgradeProbeOpen(t, ctx)
		defer closeDB()
		want, err := os.ReadFile(valueFile) //nolint:gosec // G304: the probe's own state file
		if err != nil {
			t.Fatalf("read canary: %v", err)
		}
		got, meta, err := p.Resolve(ctx, provider.Ref{Path: upgradeProbePath})
		if err != nil {
			t.Fatalf("open the sealed canary: %v", err)
		}
		if !got.Equal(secret.New(want)) {
			t.Fatal("the opened value differs from the sealed canary")
		}
		upgradeProbeReport(t, ctx, p, got, meta.Version)

	case "scan":
		raw, err := os.ReadFile(valueFile) //nolint:gosec // G304: the probe's own state file
		if err != nil {
			t.Fatalf("read canary: %v", err)
		}
		c := canary.Of(string(raw))
		// Positive control: the detector must see the canary before its
		// silence on the log means anything.
		if !c.In("xx"+string(raw)+"yy") || c.In("nothing to see here") {
			t.Fatal("canary detector is blind or sees everything")
		}
		log, err := os.ReadFile(upgradeProbeEnv(t, "KEEP_PROBE_LOG")) //nolint:gosec // G304: the job's own log
		if err != nil {
			t.Fatalf("read log: %v", err)
		}
		if len(log) == 0 {
			t.Fatal("the job log is empty, nothing was scanned")
		}
		if c.In(string(log)) {
			t.Fatal("the canary appears in the job output")
		}
		t.Logf("scanned %d bytes of job output: the canary is absent", len(log))

	default:
		t.Fatalf("unknown KEEP_PROBE_ACTION %q", action)
	}
}
