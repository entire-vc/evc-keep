package providertest_test

import (
	"context"
	"errors"
	"fmt"
	stdlog "log"
	"log/slog"
	"os"
	"slices"
	"testing"

	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/provider/memory"
	"github.com/entire-vc/evc-keep/pkg/provider/providertest"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// Each broken provider breaks exactly one rule. The suite must fail it on the
// named check — otherwise that check is proven unable to fail.

// leakyError prints the value into an error: the case the AC names.
type leakyError struct{ *memory.Provider }

func (p leakyError) Resolve(ctx context.Context, ref provider.Ref) (secret.Value, provider.Meta, error) {
	v, m, err := p.Provider.Resolve(ctx, ref)
	if err != nil && ref.Version != "" {
		cur, _, cerr := p.Provider.Resolve(ctx, provider.Ref{Path: ref.Path})
		if cerr == nil {
			secret.Expose(cur, func(b []byte) {
				err = fmt.Errorf("%w: wanted %s, current value is %s", provider.ErrNotFound, ref.Version, b)
			})
		}
	}
	return v, m, err
}

// leakyLog logs the raw value on write.
type leakyLog struct {
	*memory.Provider
	log *slog.Logger
}

func (p leakyLog) Write(ctx context.Context, ref provider.Ref, v secret.Value) (provider.Meta, error) {
	secret.Expose(v, func(b []byte) { p.log.Debug("writing", "value", string(b)) })
	return p.Provider.Write(ctx, ref, v)
}

// hexLog logs the value hex-encoded: encodings must be caught too.
type hexLog struct {
	*memory.Provider
	log *slog.Logger
}

func (p hexLog) Write(ctx context.Context, ref provider.Ref, v secret.Value) (provider.Meta, error) {
	secret.Expose(v, func(b []byte) { p.log.Debug("writing", "digest", fmt.Sprintf("%x", b)) })
	return p.Provider.Write(ctx, ref, v)
}

// stdoutLog prints the value straight to the process's real os.Stdout,
// bypassing the *slog.Logger the factory handed it entirely — the shape a
// stray debug print or a vendored SDK's own logging takes.
type stdoutLog struct{ *memory.Provider }

func (p stdoutLog) Write(ctx context.Context, ref provider.Ref, v secret.Value) (provider.Meta, error) {
	secret.Expose(v, func(b []byte) { fmt.Println("debug: wrote secret =", string(b)) })
	return p.Provider.Write(ctx, ref, v)
}

// stderrLog prints the value straight to the process's real os.Stderr, the
// same shape as stdoutLog but the other stream — proves both fds are
// redirected, not just one.
type stderrLog struct{ *memory.Provider }

func (p stderrLog) Write(ctx context.Context, ref provider.Ref, v secret.Value) (provider.Meta, error) {
	secret.Expose(v, func(b []byte) { fmt.Fprintln(os.Stderr, "debug: wrote secret =", string(b)) })
	return p.Provider.Write(ctx, ref, v)
}

// stdlibLogLeak leaks through the stdlib log package's default logger.
// log.Printf writes through an *os.File the log package captured once, at
// its own init time — reading the (possibly swapped) os.Stdout/os.Stderr
// variable at call time would never see this; only redirecting the
// underlying fd number does (see captureStdio's doc comment).
type stdlibLogLeak struct{ *memory.Provider }

func (p stdlibLogLeak) Write(ctx context.Context, ref provider.Ref, v secret.Value) (provider.Meta, error) {
	secret.Expose(v, func(b []byte) { stdlog.Printf("debug: wrote secret = %s", string(b)) })
	return p.Provider.Write(ctx, ref, v)
}

// slogDefaultLeak leaks through slog's package-level default logger
// (slog.Info, not the *slog.Logger the factory was handed) — same class of
// gap as stdlibLogLeak, different stdlib package.
type slogDefaultLeak struct{ *memory.Provider }

func (p slogDefaultLeak) Write(ctx context.Context, ref provider.Ref, v secret.Value) (provider.Meta, error) {
	secret.Expose(v, func(b []byte) { slog.Info("debug: wrote secret", "value", string(b)) })
	return p.Provider.Write(ctx, ref, v)
}

// printlnLeak leaks through the println builtin, which the runtime writes
// straight to file descriptor 2 with no Go-level io.Writer at all — the
// bluntest instance of "not reachable by swapping a variable".
type printlnLeak struct{ *memory.Provider }

func (p printlnLeak) Write(ctx context.Context, ref provider.Ref, v secret.Value) (provider.Meta, error) {
	secret.Expose(v, func(b []byte) { println("debug: wrote secret =", string(b)) })
	return p.Provider.Write(ctx, ref, v)
}

// realProcessStdout is captured once at test-binary startup, long before
// any providertest capture window has ever opened — the "handle stored in
// the provider constructor" shape, made as extreme as possible. It is still
// caught: dup2 redirects what file descriptor number 1 itself resolves to,
// and this *os.File carries fd number 1 regardless of when it was read.
var realProcessStdout = os.Stdout

// capturedHandleLog writes through realProcessStdout instead of reading
// os.Stdout fresh on every call.
type capturedHandleLog struct{ *memory.Provider }

func (p capturedHandleLog) Write(ctx context.Context, ref provider.Ref, v secret.Value) (provider.Meta, error) {
	secret.Expose(v, func(b []byte) { _, _ = fmt.Fprintln(realProcessStdout, "debug: wrote secret =", string(b)) })
	return p.Provider.Write(ctx, ref, v)
}

// overwriting claims versioning but replaces the value in place.
type overwriting struct {
	*memory.Provider
	cur map[string]secret.Value
}

func (p *overwriting) Write(ctx context.Context, ref provider.Ref, v secret.Value) (provider.Meta, error) {
	if ref.Version != "" {
		return p.Provider.Write(ctx, ref, v)
	}
	p.cur[ref.Path] = v.Clone()
	return provider.Meta{Version: "1", Length: v.Len()}, nil
}

func (p *overwriting) Resolve(ctx context.Context, ref provider.Ref) (secret.Value, provider.Meta, error) {
	v, ok := p.cur[ref.Path]
	if !ok || (ref.Version != "" && ref.Version != "1") {
		return p.Provider.Resolve(ctx, ref)
	}
	return v.Clone(), provider.Meta{Version: "1", Length: v.Len()}, nil
}

// unclassified returns bare errors for missing secrets.
type unclassified struct{ *memory.Provider }

func (p unclassified) Resolve(ctx context.Context, ref provider.Ref) (secret.Value, provider.Meta, error) {
	v, m, err := p.Provider.Resolve(ctx, ref)
	if errors.Is(err, provider.ErrNotFound) {
		err = errors.New("no such thing")
	}
	return v, m, err
}

// silentOutage ignores the outage on Resolve and answers from memory.
type silentOutage struct {
	*memory.Provider
	down *bool
}

func (p silentOutage) Resolve(ctx context.Context, ref provider.Ref) (secret.Value, provider.Meta, error) {
	if *p.down {
		p.SetUnavailable(false)
		defer p.SetUnavailable(true)
	}
	return p.Provider.Resolve(ctx, ref)
}

// disablesLast lets the last enabled version be disabled.
type disablesLast struct{ *memory.Provider }

func (p disablesLast) Disable(ctx context.Context, ref provider.Ref) error {
	err := p.Provider.Disable(ctx, ref)
	if errors.Is(err, provider.ErrLastVersion) {
		return nil
	}
	return err
}

// panicky panics with the value in the message.
type panicky struct{ *memory.Provider }

func (p panicky) Version(ctx context.Context, ref provider.Ref) (provider.Meta, error) {
	v, _, err := p.Resolve(ctx, ref)
	if err == nil {
		secret.Expose(v, func(b []byte) { panic("unexpected state for " + string(b)) })
	}
	return p.Provider.Version(ctx, ref)
}

// metaMismatch reports a different length from Version than from Resolve.
type metaMismatch struct{ *memory.Provider }

func (p metaMismatch) Version(ctx context.Context, ref provider.Ref) (provider.Meta, error) {
	m, err := p.Provider.Version(ctx, ref)
	m.Length++
	return m, err
}

// acceptsNamedVersion silently writes when the caller names a version.
type acceptsNamedVersion struct{ *memory.Provider }

func (p acceptsNamedVersion) Write(ctx context.Context, ref provider.Ref, v secret.Value) (provider.Meta, error) {
	ref.Version = ""
	return p.Provider.Write(ctx, ref, v)
}

// ignoresCancel resolves even when the context is already cancelled.
type ignoresCancel struct{ *memory.Provider }

func (p ignoresCancel) Resolve(_ context.Context, ref provider.Ref) (secret.Value, provider.Meta, error) {
	return p.Provider.Resolve(context.Background(), ref)
}

type brokenCase struct {
	name      string
	factory   providertest.Factory
	wantCheck string
}

func brokenCases() []brokenCase {
	withOutage := func(p provider.Provider, m *memory.Provider) providertest.Harness {
		return providertest.Harness{Provider: p, SetUnavailable: m.SetUnavailable}
	}
	return []brokenCase{
		{"leaky_error", func(l *slog.Logger) providertest.Harness {
			m := memory.New(l)
			return withOutage(leakyError{m}, m)
		}, "no_value_in_errors"},
		{"leaky_log", func(l *slog.Logger) providertest.Harness {
			m := memory.New(l)
			return withOutage(leakyLog{m, l}, m)
		}, "write_resolve_roundtrip"},
		{"hex_log", func(l *slog.Logger) providertest.Harness {
			m := memory.New(l)
			return withOutage(hexLog{m, l}, m)
		}, "write_resolve_roundtrip"},
		{"stdout_log", func(l *slog.Logger) providertest.Harness {
			m := memory.New(l)
			return withOutage(stdoutLog{m}, m)
		}, "write_resolve_roundtrip"},
		{"stderr_log", func(l *slog.Logger) providertest.Harness {
			m := memory.New(l)
			return withOutage(stderrLog{m}, m)
		}, "write_resolve_roundtrip"},
		{"stdlib_log_leak", func(l *slog.Logger) providertest.Harness {
			m := memory.New(l)
			return withOutage(stdlibLogLeak{m}, m)
		}, "write_resolve_roundtrip"},
		{"slog_default_leak", func(l *slog.Logger) providertest.Harness {
			m := memory.New(l)
			return withOutage(slogDefaultLeak{m}, m)
		}, "write_resolve_roundtrip"},
		{"println_leak", func(l *slog.Logger) providertest.Harness {
			m := memory.New(l)
			return withOutage(printlnLeak{m}, m)
		}, "write_resolve_roundtrip"},
		{"captured_handle_log", func(l *slog.Logger) providertest.Harness {
			m := memory.New(l)
			return withOutage(capturedHandleLog{m}, m)
		}, "write_resolve_roundtrip"},
		{"overwriting", func(l *slog.Logger) providertest.Harness {
			m := memory.New(l)
			return withOutage(&overwriting{m, map[string]secret.Value{}}, m)
		}, "versions_distinct"},
		{"unclassified", func(l *slog.Logger) providertest.Harness {
			m := memory.New(l)
			return withOutage(unclassified{m}, m)
		}, "not_found_classified"},
		{"silent_outage", func(l *slog.Logger) providertest.Harness {
			m := memory.New(l)
			down := new(bool)
			return providertest.Harness{Provider: silentOutage{m, down}, SetUnavailable: func(d bool) {
				*down = d
				m.SetUnavailable(d)
			}}
		}, "backend_unavailable"},
		{"disables_last", func(l *slog.Logger) providertest.Harness {
			m := memory.New(l)
			return withOutage(disablesLast{m}, m)
		}, "disable_two_phase"},
		{"panicky", func(l *slog.Logger) providertest.Harness {
			m := memory.New(l)
			return withOutage(panicky{m}, m)
		}, "read_idempotent"},
		{"meta_mismatch", func(l *slog.Logger) providertest.Harness {
			m := memory.New(l)
			return withOutage(metaMismatch{m}, m)
		}, "version_matches_resolve"},
		{"accepts_named_version", func(l *slog.Logger) providertest.Harness {
			m := memory.New(l)
			return withOutage(acceptsNamedVersion{m}, m)
		}, "write_rejects_named_version"},
		{"ignores_cancel", func(l *slog.Logger) providertest.Harness {
			m := memory.New(l)
			return withOutage(ignoresCancel{m}, m)
		}, "cancelled_context"},
	}
}

// TestEveryCheckHasARedRun keeps the suite honest: each check must be the
// expected failure of at least one broken provider above.
func TestEveryCheckHasARedRun(t *testing.T) {
	covered := map[string]bool{}
	for _, bc := range brokenCases() {
		covered[bc.wantCheck] = true
	}
	for _, c := range providertest.Checks() {
		if !covered[c] {
			t.Errorf("check %s has no broken provider proving it can fail", c)
		}
	}
}

func TestReferencePasses(t *testing.T) {
	for _, r := range providertest.Check(context.Background(), func(l *slog.Logger) providertest.Harness {
		m := memory.New(l)
		return providertest.Harness{Provider: m, SetUnavailable: m.SetUnavailable}
	}) {
		if r.Failed() || r.Skipped != "" {
			t.Errorf("reference provider: %s failed=%v skipped=%q violations=%q", r.Check, r.Failed(), r.Skipped, r.Violations)
		}
	}
}

// TestSuiteFailsBrokenProviders is the red run: every broken provider must
// fail, and on the check that targets its defect.
func TestSuiteFailsBrokenProviders(t *testing.T) {
	for _, bc := range brokenCases() {
		t.Run(bc.name, func(t *testing.T) {
			var failed []string
			for _, r := range providertest.Check(context.Background(), bc.factory) {
				if r.Failed() {
					failed = append(failed, r.Check)
					t.Logf("RED %s: %q", r.Check, r.Violations)
				}
			}
			if len(failed) == 0 {
				t.Fatalf("suite passed a provider that is broken on purpose (%s)", bc.name)
			}
			if !slices.Contains(failed, bc.wantCheck) {
				t.Errorf("expected check %s to fail, failed: %v", bc.wantCheck, failed)
			}
		})
	}
}

// TestDemoBrokenStubThroughRun shows the literal red output of Run on the
// value-in-error stub. Enabled only by KEEP_CONFORMANCE_DEMO_RED=1, because
// it is supposed to fail.
func TestDemoBrokenStubThroughRun(t *testing.T) {
	if os.Getenv("KEEP_CONFORMANCE_DEMO_RED") != "1" {
		t.Skip("set KEEP_CONFORMANCE_DEMO_RED=1 to see the suite fail a broken provider")
	}
	providertest.Run(t, brokenCases()[0].factory)
}
