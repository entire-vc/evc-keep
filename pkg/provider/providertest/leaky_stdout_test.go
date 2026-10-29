// Attacks against pkg/provider/providertest — the conformance suite every
// Keep provider must pass. providertest/broken_test.go already proves the
// suite is not vacuous against ITS OWN broken-provider fixtures; this
// file's independent contribution is a broken provider of a DIFFERENT
// shape, designed from the outside without reading that fixture list
// first, to find a blind spot the fixture list shares with itself.
//
// This file is part of an independent test/security attack suite; it
// lives here rather than under test/security/ because building a Provider
// fixture requires secret.Expose, and .golangci.yml's "expose-callers"
// forbidigo rule confines that call to the plaintext zone (pkg/provider is
// on the allow-list — this directory is exactly where a provider, real or
// deliberately broken, belongs).
package providertest_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/provider/providertest"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// stdoutLeakProvider is a minimal, deliberately-broken Provider that
// leaks every value it is given straight to the process's real stdout,
// bypassing the *slog.Logger the conformance harness hands it entirely.
type stdoutLeakProvider struct {
	output io.Writer
	val    secret.Value
	ver    string
}

func (p *stdoutLeakProvider) Capabilities() provider.Capabilities {
	return provider.Capabilities{Versioning: true, Write: true, Disable: true}
}

func (p *stdoutLeakProvider) Resolve(_ context.Context, _ provider.Ref) (secret.Value, provider.Meta, error) {
	if p.ver == "" {
		return secret.Value{}, provider.Meta{}, provider.ErrNotFound
	}
	return p.val, provider.Meta{Version: p.ver, Length: p.val.Len()}, nil
}

func (p *stdoutLeakProvider) Write(_ context.Context, ref provider.Ref, v secret.Value) (provider.Meta, error) {
	if ref.Version != "" {
		return provider.Meta{}, provider.ErrInvalidRef
	}
	p.val, p.ver = v, "v1"
	// THE LEAK: a real bug shape (a stray debug print, a vendored SDK's
	// own logging, a panic handler that writes to os.Stderr directly) that
	// bypasses the injected *slog.Logger entirely.
	secret.Expose(v, func(b []byte) {
		out := p.output
		if out == nil {
			out = os.Stdout
		}
		_, _ = fmt.Fprintln(out, "debug: wrote secret =", string(b))
	})
	return provider.Meta{Version: p.ver, Length: v.Len()}, nil
}

func (p *stdoutLeakProvider) Version(_ context.Context, _ provider.Ref) (provider.Meta, error) {
	if p.ver == "" {
		return provider.Meta{}, provider.ErrNotFound
	}
	return provider.Meta{Version: p.ver, Length: p.val.Len()}, nil
}

func (p *stdoutLeakProvider) Disable(_ context.Context, _ provider.Ref) error {
	return provider.ErrLastVersion
}

// TestProviderConformance_StdoutLeakEscapesDetection was a FINDING:
// providertest's leak detection (runOne in providertest.go) used to inspect
// only the *slog.Logger buffer the factory was handed, never a provider's
// writes to any other channel. runOne now also captures os.Stdout and
// os.Stderr for the duration of each check (captureStdio), so a provider
// that fmt.Println/os.Stderr.Write's the plaintext value on every Write
// call — a stray debug print, or a vendored SDK's own logging outside the
// injected logger — is caught by no_value_in_errors like any other leak.
//
// The positive control routes the fixture to a private buffer and confirms
// that its Write really emits the canary. The suite then uses the same
// fixture with its default real stdout, without swapping process variables.
func TestProviderConformance_StdoutLeakEscapesDetection(t *testing.T) {
	c := canary.New()
	var output bytes.Buffer
	leaker := &stdoutLeakProvider{output: &output}
	_, err := leaker.Write(context.Background(), provider.Ref{Path: "conformance/canary-demo"}, secret.New([]byte(c.Value(1))))
	if err != nil {
		t.Fatal("attack fixture Write failed")
	}
	if !c.In(output.String()) {
		t.Fatal("attack fixture did not emit the canary")
	}

	results := providertest.Check(context.Background(), func(log *slog.Logger) providertest.Harness {
		return providertest.Harness{Provider: &stdoutLeakProvider{}}
	})

	for _, res := range results {
		if res.Check == "no_value_in_errors" && res.Failed() {
			return // expected once the gap is fixed
		}
	}
	t.Fatal("expected the no_value_in_errors check to flag the stdout leak, but it reported clean — " +
		"the leak escaped detection despite the positive control proving that Write emits a value")
}
