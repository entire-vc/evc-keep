package svctoken_test

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/provider/memory"
	"github.com/entire-vc/evc-keep/pkg/provider/svctoken"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/google/uuid"
)

// erasing is the memory provider with the crypto-erasure of the builtin one:
// an erased version never resolves again, and a latest-version read falls back
// to the newest version that is still readable.
type erasing struct {
	*memory.Provider
	mu    sync.Mutex
	gone  map[string]bool
	fail  error
	calls int
	// afterMain runs once the main name is written, as a caller's deadline
	// that ends right after the switch.
	afterMain func()
}

func newErasing() *erasing { return &erasing{Provider: memory.New(nil), gone: map[string]bool{}} }

func (e *erasing) Write(ctx context.Context, ref provider.Ref, v secret.Value) (provider.Meta, error) {
	m, err := e.Provider.Write(ctx, ref, v)
	if err == nil && ref.Path == "builtin://mesh-service-token" && e.afterMain != nil {
		e.afterMain()
	}
	return m, err
}

func (e *erasing) Erase(ctx context.Context, ref provider.Ref) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls++
	if e.fail != nil {
		return e.fail
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	e.gone[ref.Path+"@"+ref.Version] = true
	return nil
}

func (e *erasing) erased(ref provider.Ref, version string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.gone[ref.Path+"@"+version]
}

func (e *erasing) Resolve(ctx context.Context, ref provider.Ref) (secret.Value, provider.Meta, error) {
	if ref.Version != "" {
		if e.erased(ref, ref.Version) {
			return secret.Value{}, provider.Meta{}, provider.ErrNotFound
		}
		return e.Provider.Resolve(ctx, ref)
	}
	v, m, err := e.Provider.Resolve(ctx, ref)
	if err != nil || !e.erased(ref, m.Version) {
		return v, m, err
	}
	v.Wipe()
	n, _ := strconv.Atoi(m.Version)
	for i := n - 1; i >= 1; i-- {
		older := ref
		older.Version = strconv.Itoa(i)
		if e.erased(older, older.Version) {
			continue
		}
		if v, m, err := e.Provider.Resolve(ctx, older); err == nil {
			return v, m, nil
		}
	}
	return secret.Value{}, provider.Meta{}, provider.ErrNotFound
}

// Version falls back past erased versions as Resolve does, without opening one.
func (e *erasing) Version(ctx context.Context, ref provider.Ref) (provider.Meta, error) {
	v, m, err := e.Resolve(ctx, ref)
	if err == nil {
		v.Wipe()
	}
	return m, err
}

func stagedRef(id string) provider.Ref {
	return provider.Ref{Path: "builtin://mesh-service-token-staged-" + id}
}

// stagedReadable reports whether any version of the staged name of id still
// opens.
func stagedReadable(t *testing.T, p provider.Provider, id string) bool {
	t.Helper()
	v, _, err := p.Resolve(context.Background(), stagedRef(id))
	if err == nil {
		v.Wipe()
		return true
	}
	if !errors.Is(err, provider.ErrNotFound) && !errors.Is(err, provider.ErrDisabled) {
		t.Fatalf("staged read: %v", err)
	}
	return false
}

// After a successful Activate the live token has one sealed copy: every staged
// version of its key id is erased, also those a Store restarted since Stage no
// longer remembers.
func TestActivateErasesStagedCopy(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run("restart="+strconv.FormatBool(restart), func(t *testing.T) {
			p := newErasing()
			s, err := svctoken.New(p, "mesh-service-token")
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			id := uuid.NewString()
			for range 2 { // a retried stage leaves two versions
				if err := s.Stage(ctx, id, secret.New([]byte("new-token"))); err != nil {
					t.Fatal(err)
				}
			}
			if restart {
				if s, err = svctoken.New(p, "mesh-service-token"); err != nil {
					t.Fatal(err)
				}
			}
			if !stagedReadable(t, p, id) {
				t.Fatal("positive control: the staged copy does not open before Activate")
			}
			if err := s.Activate(ctx, id); err != nil {
				t.Fatal(err)
			}
			if stagedReadable(t, p, id) {
				t.Fatal("a staged copy of the live token is still readable after Activate")
			}
			for _, ver := range []string{"1", "2"} {
				if !p.erased(stagedRef(id), ver) {
					t.Fatalf("staged version %s not erased", ver)
				}
			}
			if tok, err := s.Token(ctx); err != nil || tok != "new-token" {
				t.Fatalf("token after Activate: %q %v", tok, err)
			}
		})
	}
}

// A restarted Store erases up to 16 staged versions it learns from the
// provider; one more is reported as left, never taken for a clean store.
func TestActivateReportsStagedPastTheBound(t *testing.T) {
	for _, tc := range []struct {
		versions int
		left     bool
	}{{16, false}, {17, true}} {
		t.Run(strconv.Itoa(tc.versions), func(t *testing.T) {
			p := newErasing()
			s, err := svctoken.New(p, "mesh-service-token")
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			id := uuid.NewString()
			for range tc.versions {
				if err := s.Stage(ctx, id, secret.New([]byte("new-token"))); err != nil {
					t.Fatal(err)
				}
			}
			if s, err = svctoken.New(p, "mesh-service-token"); err != nil {
				t.Fatal(err)
			}
			var reported []error
			s.OnStagedLeft(func(err error) { reported = append(reported, err) })
			if err := s.Activate(ctx, id); err != nil {
				t.Fatal(err)
			}
			left := stagedReadable(t, p, id)
			if left != tc.left {
				t.Fatalf("staged copy readable=%v, want %v", left, tc.left)
			}
			if tc.left != (len(reported) == 1 && errors.Is(reported[0], svctoken.ErrStagedLeft)) {
				t.Fatalf("reported %v, want ErrStagedLeft=%v", reported, tc.left)
			}
		})
	}
}

// The caller's context may end right after the switch; the staged copies are
// still erased, since nothing retries their cleanup later.
func TestActivateErasesAfterCallerCancels(t *testing.T) {
	p := newErasing()
	s, err := svctoken.New(p, "mesh-service-token")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.afterMain = cancel
	id := uuid.NewString()
	if err := s.Stage(ctx, id, secret.New([]byte("new-token"))); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate(ctx, id); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() == nil {
		t.Fatal("positive control: the caller's context did not end")
	}
	if stagedReadable(t, p, id) {
		t.Fatal("a cancelled caller left the staged copy of the live token readable")
	}
}

// The token is switched once the main name is written; a failed erasure is
// reported apart and must not make Activate fail, or the rotation would revoke
// the key the token now holds.
func TestActivateEraseFailureIsNotAnActivateFailure(t *testing.T) {
	c := canary.New()
	p := newErasing()
	p.fail = fmt.Errorf("%w: %s", provider.ErrUnavailable, c.Value(0))
	s, err := svctoken.New(p, "mesh-service-token")
	if err != nil {
		t.Fatal(err)
	}
	var reported []error
	s.OnStagedLeft(func(err error) { reported = append(reported, err) })
	ctx := context.Background()
	id := uuid.NewString()
	if err := s.Stage(ctx, id, secret.New([]byte("new-token"))); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate(ctx, id); err != nil {
		t.Fatalf("an erase failure failed Activate: %v", err)
	}
	if tok, err := s.Token(ctx); err != nil || tok != "new-token" {
		t.Fatalf("token after Activate: %q %v", tok, err)
	}
	if p.calls == 0 {
		t.Fatal("positive control: Erase was never asked")
	}
	if len(reported) != 1 || !errors.Is(reported[0], provider.ErrUnavailable) {
		t.Fatalf("the leftover was not reported once: %v", reported)
	}
	// The callback hears the class, not the provider's text.
	if c.In(reported[0].Error()) {
		t.Fatal("canary from the provider error reached OnStagedLeft")
	}
	if reported[0] != provider.ErrUnavailable {
		t.Fatalf("reported %v, want the bare class", reported[0])
	}
}

// An abandoned rotation keeps its staged value: a failed Activate and Discard
// erase nothing, and a later manual Activate still works.
func TestAbandonedRotationKeepsStaged(t *testing.T) {
	p := newErasing()
	s, err := svctoken.New(p, "mesh-service-token")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	id := uuid.NewString()
	if err := s.Stage(ctx, id, secret.New([]byte("new-token"))); err != nil {
		t.Fatal(err)
	}
	p.SetUnavailable(true)
	if err := s.Activate(ctx, id); !errors.Is(err, provider.ErrUnavailable) {
		t.Fatalf("Activate in an outage: %v", err)
	}
	p.SetUnavailable(false)
	if p.calls != 0 || !stagedReadable(t, p, id) {
		t.Fatalf("a failed Activate touched the staged copy: erase calls %d", p.calls)
	}
	// Manual Activate of the staged value after the grace window.
	if err := s.Activate(ctx, id); err != nil {
		t.Fatal(err)
	}
	if tok, _ := s.Token(ctx); tok != "new-token" {
		t.Fatalf("token %q", tok)
	}

	dropped := uuid.NewString()
	if err := s.Stage(ctx, dropped, secret.New([]byte("dropped-token"))); err != nil {
		t.Fatal(err)
	}
	calls := p.calls
	if err := s.Discard(ctx, dropped); err != nil {
		t.Fatal(err)
	}
	if p.calls != calls || !stagedReadable(t, p, dropped) {
		t.Fatal("Discard erased the staged copy of an abandoned rotation")
	}
}

// A provider without crypto-erasure gets its staged versions disabled; the
// last one it refuses to disable, and that refusal is not a leftover to report.
func TestActivateWithoutEraseDisables(t *testing.T) {
	s, mem, _ := rig(t)
	if s.CanErase() {
		t.Fatal("the memory provider has no Erase")
	}
	var reported []error
	s.OnStagedLeft(func(err error) { reported = append(reported, err) })
	ctx := context.Background()
	id := uuid.NewString()
	for range 2 {
		if err := s.Stage(ctx, id, secret.New([]byte("new-token"))); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Activate(ctx, id); err != nil {
		t.Fatal(err)
	}
	ref := stagedRef(id)
	ref.Version = "2"
	if _, _, err := mem.Resolve(ctx, ref); !errors.Is(err, provider.ErrDisabled) {
		t.Fatalf("newest staged version not disabled: %v", err)
	}
	if len(reported) != 0 {
		t.Fatalf("a last-version refusal was reported: %v", reported)
	}
	if !newErasingStore(t).CanErase() {
		t.Fatal("positive control: an erasing provider is not seen")
	}
}

func newErasingStore(t *testing.T) *svctoken.Store {
	t.Helper()
	s, err := svctoken.New(newErasing(), "mesh-service-token")
	if err != nil {
		t.Fatal(err)
	}
	return s
}
