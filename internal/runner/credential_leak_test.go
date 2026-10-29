package runner

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// TestCredentialNeverLeaksPrivateKey is the leak test for Credential's
// redaction methods (credential.go): a canary planted in Key must not
// survive through fmt's verbs, json.Marshal, or either slog handler — every
// path found by keep-leak-reviewer's second pass (json.Marshal and slog
// with a JSON handler bypass Stringer entirely and dispatch to
// json.Marshaler / slog.LogValuer instead). The positive control proves the
// canary would be caught if a redaction method were missing.
func TestCredentialNeverLeaksPrivateKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	c := canary.Of(string(priv))
	cred := Credential{Key: priv, Host: "h", SignKeyID: "k"}

	forms := map[string]string{
		"%v":  fmt.Sprintf("%v", cred),
		"%+v": fmt.Sprintf("%+v", cred),
		"%#v": fmt.Sprintf("%#v", cred),
		"%s":  fmt.Sprintf("%s", cred),
	}
	for name, out := range forms {
		if c.In(out) {
			t.Errorf("Credential leaked its private key through %s: %q", name, out)
		}
	}

	jsonOut, err := json.Marshal(cred)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if c.In(string(jsonOut)) {
		t.Errorf("Credential leaked its private key through json.Marshal: %q", jsonOut)
	}

	var jsonBuf bytes.Buffer
	slog.New(slog.NewJSONHandler(&jsonBuf, nil)).Info("cred", "cred", cred)
	if c.In(jsonBuf.String()) {
		t.Errorf("Credential leaked its private key through the slog JSON handler: %q", jsonBuf.String())
	}

	var textBuf bytes.Buffer
	slog.New(slog.NewTextHandler(&textBuf, nil)).Info("cred", "cred", cred)
	if c.In(textBuf.String()) {
		t.Errorf("Credential leaked its private key through the slog text handler: %q", textBuf.String())
	}

	// Positive control: canary.In must actually detect the key when it IS
	// present, raw and hex-encoded, or the checks above prove nothing.
	if !c.In(string(priv)) {
		t.Fatal("positive control: canary.In did not detect the raw key bytes")
	}
	if !c.In(fmt.Sprintf("%x", []byte(priv))) {
		t.Fatal("positive control: canary.In did not detect the hex-encoded key bytes")
	}
}
