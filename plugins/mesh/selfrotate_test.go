package mesh_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/entire-vc/evc-keep/plugins/mesh"
	"github.com/google/uuid"
)

// selfRotation wires NewSelfRotation to a stub Mesh, a store holding old and
// a hook script that records its own argv and environment into dump.
type selfRotation struct {
	s      *stubExtMesh
	store  *tokenStore
	run    func(context.Context) error
	logs   *bytes.Buffer
	dump   string
	hookAt string
}

func newSelfRotation(t *testing.T, old string, withHook bool) *selfRotation {
	t.Helper()
	s := newStubExt(t, old)
	store := &tokenStore{token: old}
	r := &selfRotation{s: s, store: store, logs: &bytes.Buffer{}, dump: filepath.Join(t.TempDir(), "hook.out")}
	cfg := mesh.SelfRotateConfig{
		BaseURL:   s.srv.URL,
		AccountID: uuid.NewString(),
		Store:     store,
		Log:       slog.New(slog.NewTextHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	if withHook {
		r.hookAt = filepath.Join(t.TempDir(), "hook.sh")
		script := "#!/bin/sh\nprintf '%s\\n' \"$0\" \"$@\" > " + r.dump + "\nenv >> " + r.dump + "\n"
		if err := os.WriteFile(r.hookAt, []byte(script), 0o700); err != nil { //nolint:gosec // G306: a test hook script must be executable
			t.Fatal(err)
		}
		cfg.HookPath = r.hookAt
	}
	var err error
	r.run, err = mesh.NewSelfRotation(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// The canary is both the old and the new ext_ token. It must not reach a log
// line, an error text, the hook's argv or environment: those are the surfaces
// of this run. The positive controls prove each surface was actually looked at.
func TestSelfRotationCanaryDoesNotSurface(t *testing.T) {
	c := canary.New()
	oldTok, newTok := "ext_"+c.Value(0), "ext_"+c.Value(1)
	r := newSelfRotation(t, oldTok, true)
	r.s.nextTok, r.store.after = newTok, newTok

	if err := r.run(context.Background()); err != nil {
		t.Fatalf("rotation failed: %v", err)
	}
	if got := r.store.calls(); got != "stage,activate" {
		t.Fatalf("positive control: the store saw %q, want stage,activate", got)
	}
	r.s.mu.Lock()
	cur := r.s.current
	r.s.mu.Unlock()
	if cur != newTok {
		t.Fatal("positive control: Mesh does not hold the new token")
	}
	dump, err := os.ReadFile(r.dump)
	if err != nil {
		t.Fatalf("positive control: hook did not run: %v", err)
	}
	if !strings.Contains(string(dump), "KEEP_KEY_ID=") || !strings.Contains(string(dump), r.hookAt) {
		t.Fatalf("positive control: hook dump lacks its argv/env:\n%s", dump)
	}
	if !strings.Contains(r.logs.String(), "mesh self-rotation") {
		t.Fatal("positive control: nothing was logged")
	}
	if c.In(string(dump)) {
		t.Fatalf("token reached the hook argv/env:\n%s", dump)
	}
	if c.In(r.logs.String()) {
		t.Fatalf("token reached the log:\n%s", r.logs.String())
	}
}

// Failure paths put errors into the log and the returned error; the tokens ride
// in the stub's failure bodies as well.
func TestSelfRotationFailuresDoNotLeak(t *testing.T) {
	c := canary.New()
	oldTok, newTok := "ext_"+c.Value(0), "ext_"+c.Value(1)
	for name, setup := range map[string]func(*stubExtMesh){
		"revoke fails":  func(s *stubExtMesh) { s.delFail = 10 },
		"reply is lost": func(s *stubExtMesh) { s.dropReply = true },
		"bad answer":    func(s *stubExtMesh) { s.answer = `{"extension_token":"` + c.Value(2) + `"}` },
		"no capability": func(s *stubExtMesh) { s.noCap = true },
		"new refused":   func(s *stubExtMesh) { s.rejectNew = true },
	} {
		t.Run(name, func(t *testing.T) {
			r := newSelfRotation(t, oldTok, true)
			r.s.nextTok, r.store.after = newTok, newTok
			setup(r.s)
			err := r.run(context.Background())
			if err == nil {
				t.Fatal("expected a failure")
			}
			all := err.Error() + "\n" + r.logs.String() + "\n" + fmt.Sprintf("%v %+v", err, err)
			if !strings.Contains(r.logs.String(), "mesh self-rotation") {
				t.Fatal("positive control: failure not logged")
			}
			if c.In(all) {
				t.Fatalf("token surfaced in log/error:\n%s", all)
			}
		})
	}
}

// A failed revoke of the old token is retried once inside the same run, so a
// transient 503 does not leave two active tokens.
func TestSelfRotationRetriesRevokeOnce(t *testing.T) {
	r := newSelfRotation(t, "ext_"+uuid.NewString(), false)
	newTok := "ext_" + uuid.NewString()
	r.s.nextTok, r.store.after = newTok, newTok
	r.s.delFail = 1
	if err := r.run(context.Background()); err != nil {
		t.Fatalf("expected the retried revoke to succeed: %v", err)
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if r.s.previous != "" {
		t.Fatal("the old token is still valid at Mesh")
	}
}

func TestSelfRotationConfigRefusals(t *testing.T) {
	store := &tokenStore{token: "ext_x"}
	good := mesh.SelfRotateConfig{BaseURL: "https://mesh.example", AccountID: uuid.NewString(), Store: store}
	if _, err := mesh.NewSelfRotation(good); err != nil {
		t.Fatalf("good config refused: %v", err)
	}
	for name, mut := range map[string]func(*mesh.SelfRotateConfig){
		"no store":          func(c *mesh.SelfRotateConfig) { c.Store = nil },
		"relative hook":     func(c *mesh.SelfRotateConfig) { c.HookPath = "hook.sh" },
		"plain http remote": func(c *mesh.SelfRotateConfig) { c.BaseURL = "http://mesh.example" },
		"account not uuid":  func(c *mesh.SelfRotateConfig) { c.AccountID = "x" },
	} {
		c := good
		mut(&c)
		if _, err := mesh.NewSelfRotation(c); !errors.Is(err, mesh.ErrConfig) {
			t.Errorf("%s: got %v, want ErrConfig", name, err)
		}
	}
}

// tokenStore is a stand-in for Keep's sealed store: the plugin may not import
// the plaintext zone, so the test reads no value back. It serves a fixed token
// to authenticate with and records the order of the calls it receives.
type tokenStore struct {
	mu    sync.Mutex
	token string
	after string // what Token serves once Activate has run
	seen  []string
}

func (f *tokenStore) note(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, s)
}

func (f *tokenStore) calls() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.seen, ",")
}

func (f *tokenStore) Stage(context.Context, string, secret.Value) error { f.note("stage"); return nil }
func (f *tokenStore) Activate(context.Context, string) error {
	f.note("activate")
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.after != "" {
		f.token = f.after
	}
	return nil
}
func (f *tokenStore) Discard(context.Context, string) error { f.note("discard"); return nil }
func (f *tokenStore) Token(context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.token, nil
}
