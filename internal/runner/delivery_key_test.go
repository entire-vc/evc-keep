package runner

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

func TestDeliveryKeyRoundTripAndRedaction(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate delivery key")
	}
	cred := testCredential(t)
	cred.DeliveryKey = key
	dir := t.TempDir()
	if err := Save(dir, cred); err != nil {
		t.Fatal("save credential")
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatal("load credential")
	}
	if got.DeliveryKey == nil || !got.DeliveryKey.Equal(key) {
		t.Fatal("delivery key changed during save/load")
	}
	for _, name := range []string{deliveryKeyFileName} {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatal("delivery key file is missing or has unsafe permissions")
		}
	}
	raw := key.Bytes()
	probe := canary.Of(string(raw))
	leaked := func(s string) bool {
		return probe.In(s) || strings.Contains(s, fmt.Sprintf("%v", raw))
	}
	for _, bad := range []string{string(raw), hex.EncodeToString(raw), base64.StdEncoding.EncodeToString(raw), fmt.Sprintf("%v", raw)} {
		if !leaked(bad) {
			t.Fatal("delivery key leak detector missed a known encoding")
		}
	}
	for _, rendered := range []string{fmt.Sprintf("%v", got), fmt.Sprintf("%+v", got), fmt.Sprintf("%#v", got), fmt.Sprintf("%s", got)} {
		if leaked(rendered) || !strings.Contains(rendered, "[REDACTED]") {
			t.Fatal("delivery key escaped through formatting or redaction missing")
		}
	}
	jsonOut, err := json.Marshal(got)
	if err != nil || leaked(string(jsonOut)) || !bytes.Contains(jsonOut, []byte("[REDACTED]")) {
		t.Fatal("delivery key escaped through JSON or redaction missing")
	}
	for _, handler := range []func(*bytes.Buffer) slog.Handler{
		func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
		func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
	} {
		var out bytes.Buffer
		slog.New(handler(&out)).Info("credential", "value", got)
		if leaked(out.String()) || !strings.Contains(out.String(), "[REDACTED]") {
			t.Fatal("delivery key escaped through slog or redaction missing")
		}
	}
}

func TestDeliveryKeyFileRefusesWideModeAndSymlink(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate delivery key")
	}
	cred := testCredential(t)
	cred.DeliveryKey = key
	dir := t.TempDir()
	if err := Save(dir, cred); err != nil {
		t.Fatal("save credential")
	}
	path := filepath.Join(dir, deliveryKeyFileName)
	if _, err := Load(dir); err != nil {
		t.Fatal("secure delivery key should load")
	}
	if err := os.Chmod(path, 0o644); err != nil { //nolint:gosec // G302: deliberately unsafe permission fixture for the refusal test
		t.Fatal("widen delivery key permissions")
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("world-readable delivery key accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal("restore delivery key permissions")
	}
	elsewhere := filepath.Join(t.TempDir(), "delivery.key")
	if err := os.Rename(path, elsewhere); err != nil {
		t.Fatal("move delivery key")
	}
	if err := os.Symlink(elsewhere, path); err != nil {
		t.Fatal("link delivery key")
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("symlinked delivery key accepted")
	}
}

func TestLegacyCredentialWithoutDeliveryKeyStillLoads(t *testing.T) {
	dir := t.TempDir()
	if err := Save(dir, testCredential(t)); err != nil {
		t.Fatal("save legacy credential")
	}
	got, err := Load(dir)
	if err != nil || got.DeliveryKey != nil {
		t.Fatal("legacy credential should load without a delivery key")
	}
}
