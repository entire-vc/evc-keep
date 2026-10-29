package builtin

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/provider/providertest"
)

// testSetUnavailable is providertest's outage control. It is not exported —
// see pkg/provider/providertest's package doc: "in a real provider, don't
// export the test lever in the production API; make it in a _test.go file
// of the same package."
func (p *Provider) testSetUnavailable(down bool) { p.unavailable.Store(down) }

// TestConformance runs the full providertest suite against builtin backed by
// a real PostgreSQL database: every check in
// pkg/provider/providertest.Checks() must PASS, none skipped.
func TestConformance(t *testing.T) {
	pool := testPool(t)
	providertest.Run(t, func(log *slog.Logger) providertest.Harness {
		seal, _ := testSealer(t, pool)
		org := randID(t, "org")
		scope := sealer.Scope{Org: org, User: "conformance"}
		p := New(pool, seal, scope, log)
		return providertest.Harness{Provider: p, SetUnavailable: p.testSetUnavailable}
	})
}

func TestConformance_EveryCheckRanNoneSkipped(t *testing.T) {
	pool := testPool(t)
	results := providertest.Check(context.Background(), func(log *slog.Logger) providertest.Harness {
		seal, _ := testSealer(t, pool)
		scope := sealer.Scope{Org: randID(t, "org"), User: "conformance"}
		p := New(pool, seal, scope, log)
		return providertest.Harness{Provider: p, SetUnavailable: p.testSetUnavailable}
	})
	if len(results) != len(providertest.Checks()) {
		t.Fatalf("got %d results, want %d (one per check)", len(results), len(providertest.Checks()))
	}
	for _, r := range results {
		if r.Skipped != "" {
			t.Errorf("check %s skipped: %s — every check must actually run against the builtin provider", r.Check, r.Skipped)
		}
		if r.Failed() {
			t.Errorf("check %s failed: %v", r.Check, r.Violations)
		}
	}
}

// TestCheckAvailable_ClassifiesBothOutageReasons is a direct, DB-independent
// unit test of checkAvailable's two guards: a cancelled context and the
// forced-outage test lever must each classify as provider.ErrUnavailable on
// their own, not merely happen to surface as some error once a query
// actually runs (a cancelled-context query already fails inside pgx too,
// which made scripts/check-builtin-mutations.sh's ignore-cancelled-context
// mutation stop being distinguishing once errors from pgx itself started
// being wrapped into provider.ErrUnavailable — this test targets
// checkAvailable in isolation so the guard's own contribution is still
// provable regardless of what else happens to also catch a bad context
// downstream).
func TestCheckAvailable_ClassifiesBothOutageReasons(t *testing.T) {
	p := &Provider{}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.checkAvailable(ctx); !errors.Is(err, provider.ErrUnavailable) {
		t.Fatalf("cancelled context: err = %v, want provider.ErrUnavailable", err)
	}

	p.testSetUnavailable(true)
	if err := p.checkAvailable(context.Background()); !errors.Is(err, provider.ErrUnavailable) {
		t.Fatalf("forced outage: err = %v, want provider.ErrUnavailable", err)
	}
}

// ── crypto-erasure (AC red run #2) ──────────────────────────────────────

// TestErase_DeletesWrappedDEK_KeepsCiphertext is the AC's crypto-erasure
// check: after Erase, wrapped_dek is gone (nothing can unwrap the DEK any
// more), the ciphertext row stays (its length is still visible), status is
// 'erased', and neither Resolve nor a direct sealer.Open can produce the
// value again.
func TestErase_DeletesWrappedDEK_KeepsCiphertext(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	seal, _ := testSealer(t, pool)
	scope := sealer.Scope{Org: randID(t, "org"), User: "alice"}
	p := New(pool, seal, scope, nil)
	c := canary.New()

	meta, err := p.Write(ctx, providerRef("s1"), secretOf(c.Value(1)))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	before, err := p.db.byVersion(ctx, scope, "s1", 1)
	if err != nil {
		t.Fatalf("byVersion before erase: %v", err)
	}
	if len(before.wrapped) == 0 {
		t.Fatal("test setup: no wrapped DEK before Erase — nothing to prove was deleted")
	}
	cipherBefore := append([]byte(nil), before.cipher...)

	if err := p.Erase(ctx, providerRefVersion("s1", meta.Version)); err != nil {
		t.Fatalf("Erase: %v", err)
	}

	after, err := p.db.byVersion(ctx, scope, "s1", 1)
	if err != nil {
		t.Fatalf("byVersion after erase: %v", err)
	}
	if after.wrapped != nil {
		t.Fatalf("wrapped DEK still present after Erase (%d bytes) — crypto-erasure did not delete it", len(after.wrapped))
	}
	if after.status != "erased" {
		t.Fatalf("status = %q, want erased", after.status)
	}
	if !bytes.Equal(after.cipher, cipherBefore) {
		t.Fatal("ciphertext changed by Erase — it must stay (permanently undecryptable, not removed)")
	}

	if _, _, err := p.Resolve(ctx, providerRefVersion("s1", meta.Version)); !errors.Is(err, provider.ErrDisabled) {
		t.Fatalf("Resolve(erased) err = %v, want provider.ErrDisabled-class", err)
	}
	sref := sealer.Ref{Store: scope, SecretID: "s1", Name: "s1", Version: meta.Version}
	if _, err := seal.Open(ctx, sref, sealer.Envelope{KEKID: after.kekID, WrappedDEK: after.wrapped, Ciphertext: after.cipher}); err == nil {
		t.Fatal("sealer.Open succeeded on an erased envelope with no wrapped DEK")
	}
}

// TestErase_MissingVersion is the negative control for the AC's red run:
// if Erase forgot to check RowsAffected and reported success on a
// nonexistent version, this would false-pass.
func TestErase_MissingVersion(t *testing.T) {
	pool := testPool(t)
	seal, _ := testSealer(t, pool)
	scope := sealer.Scope{Org: randID(t, "org"), User: "alice"}
	p := New(pool, seal, scope, nil)
	if err := p.Erase(context.Background(), providerRefVersion("never-written", "1")); !errors.Is(err, provider.ErrNotFound) {
		t.Fatalf("err = %v, want provider.ErrNotFound", err)
	}
}

// ── leak surfaces beyond pkg/provider.Provider ──────────────────────────

// TestReservedSecretID_RejectedByProvider guards against a real leak path:
// the store's fingerprint key lives in keep_envelope under the reserved id
// fpKeySecretID, sealed and opened through the exact same sealer.Seal/Open
// path as any ordinary secret — which means that without this guard,
// Resolve(reserved-id) decrypts and returns the raw fingerprint key as if it
// were a caller's secret. Every Provider method must refuse that id before
// it ever reaches a lookup, and FingerprintKey itself must still work (it
// never goes through these guarded methods — see isReservedSecretID's doc
// comment).
func TestReservedSecretID_RejectedByProvider(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	seal, _ := testSealer(t, pool)
	scope := sealer.Scope{Org: randID(t, "org"), User: "alice"}
	p := New(pool, seal, scope, nil)

	// Make sure the reserved row actually exists — the guard must hold even
	// when there is something real to leak, not only against a missing row.
	if _, err := p.FingerprintKey(ctx); err != nil {
		t.Fatalf("FingerprintKey (setup): %v", err)
	}

	reserved := providerRef(fpKeySecretID)
	if _, _, err := p.Resolve(ctx, reserved); !errors.Is(err, provider.ErrInvalidRef) {
		t.Fatalf("Resolve(reserved) err = %v, want provider.ErrInvalidRef", err)
	}
	if _, err := p.Write(ctx, reserved, secretOf("attacker-controlled")); !errors.Is(err, provider.ErrInvalidRef) {
		t.Fatalf("Write(reserved) err = %v, want provider.ErrInvalidRef", err)
	}
	if _, err := p.Version(ctx, reserved); !errors.Is(err, provider.ErrInvalidRef) {
		t.Fatalf("Version(reserved) err = %v, want provider.ErrInvalidRef", err)
	}
	if err := p.Disable(ctx, providerRefVersion(fpKeySecretID, "1")); !errors.Is(err, provider.ErrInvalidRef) {
		t.Fatalf("Disable(reserved) err = %v, want provider.ErrInvalidRef", err)
	}
	if err := p.Erase(ctx, providerRefVersion(fpKeySecretID, "1")); !errors.Is(err, provider.ErrInvalidRef) {
		t.Fatalf("Erase(reserved) err = %v, want provider.ErrInvalidRef", err)
	}

	// FingerprintKey itself is unaffected by the guard.
	if _, err := p.FingerprintKey(ctx); err != nil {
		t.Fatalf("FingerprintKey (after guard checks): %v", err)
	}
}

// TestLeakInLogs_BuiltinSurfaces covers what providertest's own per-check
// log scan does not reach: Erase and FingerprintKey are not part of
// pkg/provider.Provider, so no conformance check ever exercises them.
//
// The logger under test is obs.NewHandler, the same allow-list filter
// Provider actually runs behind in the server — not a bare
// slog.NewJSONHandler. A bare JSON handler would only prove the canary
// itself never appears in what this test happens to log; it says nothing
// about whether the real production filter would have silently dropped the
// new keys this package logs under (secret_id, version_id) and left the
// canary check trivially true for the wrong reason.
func TestLeakInLogs_BuiltinSurfaces(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	var logbuf bytes.Buffer
	log := slog.New(obs.NewHandler(&logbuf, slog.LevelDebug))
	seal, _ := testSealer(t, pool)
	scope := sealer.Scope{Org: randID(t, "org"), User: "alice"}
	p := New(pool, seal, scope, log)
	c := canary.New()

	meta, err := p.Write(ctx, providerRef("s1"), secretOf(c.Value(1)))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, _, err := p.Resolve(ctx, providerRefVersion("s1", meta.Version)); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if err := p.Erase(ctx, providerRefVersion("s1", meta.Version)); err != nil {
		t.Fatalf("Erase: %v", err)
	}
	k, err := p.FingerprintKey(ctx)
	if err != nil {
		t.Fatalf("FingerprintKey: %v", err)
	}
	if k.ID() == "" {
		t.Fatal("FingerprintKey returned an empty id")
	}
	// Provoke every error path with the canary present too — a provider
	// that echoes the value into an error would have a chance to here.
	_, _, _ = p.Resolve(ctx, providerRefVersion("s1", "999999"))
	_ = p.Disable(ctx, providerRefVersion("s1", meta.Version))
	_ = p.Erase(ctx, providerRefVersion("does-not-exist", "1"))

	if logbuf.Len() == 0 {
		t.Fatal("log buffer is empty — the logger is not wired in, the canary check below proves nothing")
	}
	if c.In(logbuf.String()) {
		t.Fatalf("canary leaked into logs: %s", logbuf.String())
	}
	// obs.Handler drops any key not on its allow-list — proving the canary
	// is absent is not useful if secret_id/version_id were silently dropped
	// too, since then this test would pass the same way against a logger
	// that logs nothing at all. secret_id is on every call site above.
	if !bytes.Contains(logbuf.Bytes(), []byte(`"secret_id"`)) {
		t.Fatalf("obs.Handler dropped secret_id — allow-list check needs updating, or the test proves nothing: %s", logbuf.String())
	}
}
