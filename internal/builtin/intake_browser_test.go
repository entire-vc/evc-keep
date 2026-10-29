//go:build intake_browser

package builtin

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
)

// The browser uses fresh randomness and WebCrypto; only the zone opens its
// ciphertext. Subprocess output is captured, never printed as diagnostic data.
func TestIntakeBrowserInteroperatesWithGo(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Fatal("Node 22 and Chromium are required for the intake cross-test")
	}
	kemID := hpke.KEM_X25519_HKDF_SHA256
	pk, sk, err := kemID.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatal("generate intake key")
	}
	public, err := pk.MarshalBinary()
	if err != nil {
		t.Fatal("encode public key")
	}
	requestID := uuid.Must(uuid.NewV7()).String()
	probe := canary.New()
	plaintext := []byte(probe.Value(1))
	defer clear(plaintext)
	input, err := json.Marshal(struct {
		PublicKey []byte `json:"public_key"`
		RequestID string `json:"request_id"`
		Plaintext []byte `json:"plaintext"`
	}{public, requestID, plaintext})
	if err != nil {
		t.Fatal("encode browser test fixture")
	}
	defer clear(input)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", "../../scripts/check-intake-browser.mjs", "--cross")
	cmd.Stdin = bytes.NewReader(input)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatal("browser cross-encryption failed: " + crossFailureClass(stderr.String()))
	}
	if probe.In(out.String()) || probe.In(stderr.String()) {
		t.Fatal("browser test exposed plaintext in its result")
	}
	var envelope struct {
		Enc        []byte `json:"enc"`
		Ciphertext []byte `json:"ciphertext"`
	}
	if err := json.Unmarshal(out.Bytes(), &envelope); err != nil {
		t.Fatal("parse browser ciphertext")
	}
	suite := hpke.NewSuite(kemID, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)
	receiver, err := suite.NewReceiver(sk, []byte("keep/intake/v1\x00"+requestID))
	if err != nil {
		t.Fatal("construct receiver")
	}
	opener, err := receiver.Setup(envelope.Enc)
	if err != nil {
		t.Fatal("decapsulate browser message")
	}
	opened, err := opener.Open(envelope.Ciphertext, nil)
	if err != nil {
		t.Fatal("Go could not open browser ciphertext")
	}
	defer clear(opened)
	if !bytes.Equal(opened, plaintext) {
		t.Fatal("browser and Go disagree on plaintext")
	}
	// A different link must not accept this ciphertext.
	other, err := suite.NewReceiver(sk, []byte("keep/intake/v1\x00"+uuid.Must(uuid.NewV7()).String()))
	if err != nil {
		t.Fatal("construct second receiver")
	}
	wrong, err := other.Setup(envelope.Enc)
	if err != nil {
		t.Fatal("decapsulate second receiver")
	}
	bad, err := wrong.Open(envelope.Ciphertext, nil)
	defer clear(bad)
	if err == nil {
		t.Fatal("ciphertext was accepted under another intake request")
	}
}

// crossFailureClass names why the browser run failed from a fixed vocabulary:
// a cleanup code or an assertion, never subprocess text. A cleanup failure
// after a passing run and a broken check are different defects.
func crossFailureClass(stderr string) string {
	for _, code := range []string{"CLEANUP_BOUNDARY", "CLEANUP_BROWSER", "CLEANUP_PROFILE"} {
		if strings.Contains(stderr, "code: '"+code+"'") {
			return code
		}
	}
	if strings.Contains(stderr, "AssertionError [ERR_ASSERTION]") {
		return "assertion"
	}
	return "other"
}

func TestCrossFailureClassIsFixed(t *testing.T) {
	for stderr, want := range map[string]string{
		"Error: PRIVATE_SENTINEL\n  code: 'CLEANUP_BOUNDARY'\n}": "CLEANUP_BOUNDARY",
		"Error: PRIVATE_SENTINEL\n  code: 'CLEANUP_PROFILE'\n}":  "CLEANUP_PROFILE",
		"AssertionError [ERR_ASSERTION]: PRIVATE_SENTINEL":       "assertion",
		"PRIVATE_SENTINEL code: 'PRIVATE_SENTINEL'":              "other",
	} {
		if got := crossFailureClass(stderr); got != want || strings.Contains(got, "PRIVATE_SENTINEL") {
			t.Fatalf("failure class %q, want %q", got, want)
		}
	}
}
