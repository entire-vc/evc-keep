//go:build intake_browser

package builtin

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/intake"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

func TestIntakeBrowserDeliveryToSealedStore(t *testing.T) {
	f := newIntakeFixture(t)
	link, token, view := f.issue(t)
	probe := canary.New()
	plain := []byte(probe.Value(1))
	defer clear(plain)
	input, err := json.Marshal(struct {
		PublicKey []byte `json:"public_key"`
		RequestID string `json:"request_id"`
		Plaintext []byte `json:"plaintext"`
	}{view.PublicKey, link.RequestID, plain})
	if err != nil {
		t.Fatal("browser fixture")
	}
	defer clear(input)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", "../../scripts/check-intake-browser.mjs", "--cross")
	cmd.Stdin = bytes.NewReader(input)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if cmd.Run() != nil {
		t.Fatal("browser encryption failed")
	}
	if probe.In(out.String()) || probe.In(stderr.String()) {
		t.Fatal("browser exposed canary")
	}
	var envelope intake.Envelope
	if json.Unmarshal(out.Bytes(), &envelope) != nil {
		t.Fatal("browser ciphertext")
	}
	result, err := f.svc.Complete(f.ctx, token, envelope)
	if err != nil {
		t.Fatal("browser ciphertext completion")
	}
	value, meta, err := f.provider.Resolve(f.ctx, provider.Ref{Path: f.ref.ProviderRef})
	if err != nil {
		t.Fatal("resolve browser input")
	}
	defer value.Wipe()
	fk, err := f.provider.FingerprintKey(f.ctx)
	if err != nil {
		t.Fatal("fingerprint key")
	}
	defer fk.Wipe()
	expected, err := fingerprint.Compute(fk, value)
	if err != nil || expected != result.Fingerprint {
		t.Fatal("completion fingerprint differs from sealed input")
	}
	control := secret.New(plain)
	defer control.Wipe()
	if !value.Equal(control) || meta.Version != result.Version {
		t.Fatal("browser delivery differs from resolved version")
	}
	if probe.In(out.String() + stderr.String()) {
		t.Fatal("canary in browser diagnostics")
	}
}
