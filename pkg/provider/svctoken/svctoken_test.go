package svctoken_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/provider/memory"
	"github.com/entire-vc/evc-keep/pkg/provider/svctoken"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/google/uuid"
)

func rig(t *testing.T) (*svctoken.Store, *memory.Provider, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	mem := memory.New(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	s, err := svctoken.New(mem, "mesh-service-token")
	if err != nil {
		t.Fatal(err)
	}
	return s, mem, &logs
}

// The canary token must not reach a log line, an error text or a formatted
// Store, through any path of the rotation: stage, activate, discard, failure.
func TestCanaryDoesNotSurface(t *testing.T) {
	c := canary.New()
	s, mem, logs := rig(t)
	ctx := context.Background()
	id := uuid.NewString()
	var out []string
	note := func(err error) {
		if err != nil {
			out = append(out, err.Error())
		}
	}
	note(s.Stage(ctx, id, secret.New([]byte(c.Value(0)))))
	note(s.Activate(ctx, id))
	if _, err := s.Token(ctx); err != nil {
		t.Fatal(err)
	}
	mem.SetUnavailable(true)
	note(s.Activate(ctx, id))
	_, err := s.Token(ctx)
	note(err)
	mem.SetUnavailable(false)
	note(s.Discard(ctx, id))
	out = append(out, fmt.Sprintf("%v %+v %#v", s, s, s))
	if !strings.Contains(logs.String(), "resolve") {
		t.Fatal("positive control: nothing logged by the provider")
	}
	if c.In(logs.String() + strings.Join(out, "\n")) {
		t.Fatalf("canary surfaced: %s %v", logs.String(), out)
	}
}

func TestStageDoesNotChangeToken(t *testing.T) {
	s, _, _ := rig(t)
	ctx := context.Background()
	if _, err := s.Token(ctx); !errors.Is(err, provider.ErrNotFound) {
		t.Fatalf("no token yet: %v", err)
	}
	a, b := uuid.NewString(), uuid.NewString()
	for id, val := range map[string]string{a: "first-token", b: "second-token"} {
		if err := s.Stage(ctx, id, secret.New([]byte(val))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Token(ctx); !errors.Is(err, provider.ErrNotFound) {
		t.Fatalf("staged value must not be the token: %v", err)
	}
	if err := s.Activate(ctx, a); err != nil {
		t.Fatal(err)
	}
	if tok, _ := s.Token(ctx); tok != "first-token" {
		t.Fatalf("token %q", tok)
	}
	if err := s.Activate(ctx, b); err != nil {
		t.Fatal(err)
	}
	if tok, _ := s.Token(ctx); tok != "second-token" {
		t.Fatalf("newest activation must win, got %q", tok)
	}
}

func TestDiscardedStageCannotBeActivated(t *testing.T) {
	s, mem, _ := rig(t)
	ctx := context.Background()
	id := uuid.NewString()
	for range 2 { // a retried stage leaves two versions
		if err := s.Stage(ctx, id, secret.New([]byte("tok"))); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Discard(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate(ctx, id); !errors.Is(err, svctoken.ErrDiscarded) {
		t.Fatalf("a discarded stage was activated: %v", err)
	}
	if _, err := s.Token(ctx); !errors.Is(err, provider.ErrNotFound) {
		t.Fatalf("token appeared: %v", err)
	}
	// The only version of a name cannot be disabled; Discard is still clean.
	other := uuid.NewString()
	if err := s.Stage(ctx, other, secret.New([]byte("tok"))); err != nil {
		t.Fatal(err)
	}
	if err := s.Discard(ctx, other); err != nil {
		t.Fatalf("last-version refusal must not fail Discard: %v", err)
	}
	mem.SetUnavailable(true)
	if err := s.Stage(ctx, uuid.NewString(), secret.New([]byte("x"))); !errors.Is(err, provider.ErrUnavailable) {
		t.Fatalf("outage: %v", err)
	}
}

func TestRefusals(t *testing.T) {
	s, mem, _ := rig(t)
	ctx := context.Background()
	// A value that exists under a staged name with a malformed id (written
	// behind the Store's back) must still not be activated: the id check is
	// the Store's own, not the provider's.
	if _, err := mem.Write(ctx, provider.Ref{Path: "builtin://mesh-service-token-staged-x"}, secret.New([]byte("planted"))); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate(ctx, "x"); err == nil {
		t.Fatal("malformed key id activated")
	}
	if _, err := s.Token(ctx); err == nil {
		t.Fatal("planted value became the token")
	}
	for _, bad := range []string{"", "x", "../a", strings.ToUpper(uuid.NewString())} {
		if s.Stage(ctx, bad, secret.New([]byte("v"))) == nil || s.Activate(ctx, bad) == nil || s.Discard(ctx, bad) == nil {
			t.Fatalf("key id %q accepted", bad)
		}
	}
	if s.Stage(ctx, uuid.NewString(), secret.Value{}) == nil {
		t.Fatal("empty value staged")
	}
	for _, name := range []string{"", "UP", "a b", "a/b", strings.Repeat("a", 65)} {
		if _, err := svctoken.New(memory.New(nil), name); err == nil {
			t.Fatalf("name %q accepted", name)
		}
	}
	if _, err := svctoken.New(nil, "ok"); err == nil {
		t.Fatal("nil provider accepted")
	}
}

// A blank token stored behind Keep's back is not a token.
func TestBlankTokenIsNotAToken(t *testing.T) {
	s, mem, _ := rig(t)
	if _, err := mem.Write(context.Background(), provider.Ref{Path: "builtin://mesh-service-token"}, secret.New([]byte{})); err != nil {
		t.Skipf("provider refuses an empty value: %v", err)
	}
	if _, err := s.Token(context.Background()); err == nil {
		t.Fatal("empty token returned")
	}
}

// A discard outlives the Store: after a restart the staged value, which the
// provider may still resolve, cannot be activated.
func TestDiscardSurvivesRestart(t *testing.T) {
	s, mem, _ := rig(t)
	ctx := context.Background()
	id := uuid.NewString()
	if err := s.Stage(ctx, id, secret.New([]byte("tok"))); err != nil {
		t.Fatal(err)
	}
	if err := s.Discard(ctx, id); err != nil {
		t.Fatal(err)
	}
	again, err := svctoken.New(mem, "mesh-service-token")
	if err != nil {
		t.Fatal(err)
	}
	if err := again.Activate(ctx, id); !errors.Is(err, svctoken.ErrDiscarded) {
		t.Fatalf("a discarded stage was activated after a restart: %v", err)
	}
	if _, err := again.Token(ctx); !errors.Is(err, provider.ErrNotFound) {
		t.Fatalf("token appeared: %v", err)
	}
}

// Seed seals once: a second seed, for example a restart with the bootstrap
// file still in place, must not replace a token that was rotated since.
func TestSeedNeverReplacesAToken(t *testing.T) {
	s, _, _ := rig(t)
	ctx := context.Background()
	m, ok, err := s.Seed(ctx, secret.New([]byte("ext_first-token")))
	if err != nil || !ok || m.Version == "" || m.Length != len("ext_first-token") {
		t.Fatalf("first seed: %v %v %+v", err, ok, m)
	}
	if _, ok, err := s.Seed(ctx, secret.New([]byte("ext_other-token"))); err != nil || ok {
		t.Fatalf("second seed replaced the token: ok=%v err=%v", ok, err)
	}
	if tok, _ := s.Token(ctx); tok != "ext_first-token" {
		t.Fatal("token changed by a second seed")
	}
	if _, _, err := s.Seed(ctx, secret.Value{}); !errors.Is(err, svctoken.ErrConfig) {
		t.Fatalf("zero value seeded: %v", err)
	}
}

// capturing keeps every value its provider resolved, to look at them after the
// Store is done with them.
type capturing struct {
	provider.Provider
	got []secret.Value
}

func (c *capturing) Resolve(ctx context.Context, ref provider.Ref) (secret.Value, provider.Meta, error) {
	v, m, err := c.Provider.Resolve(ctx, ref)
	if err == nil {
		c.got = append(c.got, v)
	}
	return v, m, err
}

// Has and Seed open the sealed token only to learn that it exists: the opened
// bytes must be zero when they return.
func TestHasAndSeedWipeTheOpenedToken(t *testing.T) {
	ctx := context.Background()
	c := &capturing{Provider: memory.New(nil)}
	s, err := svctoken.New(c, "mesh-service-token")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.Seed(ctx, secret.New([]byte("ext_first-token"))); err != nil || !ok {
		t.Fatalf("seed: %v %v", err, ok)
	}
	for name, call := range map[string]func() error{
		"Has":  func() error { ok, err := s.Has(ctx); _ = ok; return err },
		"Seed": func() error { _, _, err := s.Seed(ctx, secret.New([]byte("ext_other-token"))); return err },
	} {
		c.got = nil
		if err := call(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(c.got) != 1 {
			t.Fatalf("%s resolved %d values, want 1", name, len(c.got))
		}
		secret.Expose(c.got[0], func(b []byte) {
			if len(b) == 0 {
				t.Fatalf("%s: captured value is empty, the check sees nothing", name)
			}
			for _, x := range b {
				if x != 0 {
					t.Fatalf("%s left the opened token in memory", name)
				}
			}
		})
	}
}
