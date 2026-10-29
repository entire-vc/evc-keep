package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/cmd/keep-server/app"
	"github.com/entire-vc/evc-keep/internal/config"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/restart"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/gatecard"
	mesh "github.com/entire-vc/evc-keep/plugins/mesh"
	"github.com/google/uuid"
)

func writeToken(t *testing.T, mode os.FileMode, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "mesh.token")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// meshStub is a Mesh that records every call with the bearer it carried.
type meshStub struct {
	mu     sync.Mutex
	calls  []string
	bearer []string
	status int // 0 means 200
	srv    *httptest.Server
}

func newMeshStub(t *testing.T) *meshStub {
	t.Helper()
	m := &meshStub{}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.calls = append(m.calls, r.Method+" "+r.URL.Path)
		m.bearer = append(m.bearer, r.Header.Get("Authorization"))
		st := m.status
		m.mu.Unlock()
		if st != 0 {
			w.WriteHeader(st)
			_, _ = fmt.Fprint(w, "mesh says no: ", r.Header.Get("Authorization")) //nolint:gosec // G705: a test server that deliberately echoes the token, to prove the client never repeats it.
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "11111111-2222-4333-8444-555555555555"})
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *meshStub) cfg(tokenFile string) config.MeshGate {
	return config.MeshGate{Enabled: true, ProjectID: uuid.NewString(), URL: m.srv.URL, CancelStatusID: uuid.NewString(), TokenFile: tokenFile, SweepEvery: time.Minute}
}

var spec = gatecard.Spec{Title: "Keep: confirm deploy of DB", Body: "Secret: DB", ExternalRef: "keep:approval/x", RequestHash: strings.Repeat("ab", 32), Deadline: time.Now().Add(time.Hour)}

// Create and Cancel reach Mesh (they are not no-ops) carrying the token of the
// file, and the file is read again on every call.
func TestCardsReachMeshWithTheTokenOfTheFileEachCall(t *testing.T) {
	c := canary.New()
	m := newMeshStub(t)
	file := writeToken(t, 0o600, c.Value(1)+"\n")
	var logs bytes.Buffer
	cards, err := newCards(m.cfg(file), nil, obs.New(&logs))
	if err != nil {
		t.Fatal(err)
	}
	id, err := cards.Create(context.Background(), spec)
	if err != nil || id == "" {
		t.Fatalf("Create: %q, %v", id, err)
	}
	if len(m.calls) != 3 || !strings.HasPrefix(m.calls[0], "POST /api/v1/projects/") || !strings.HasPrefix(m.calls[1], "PUT /api/v1/tasks/") {
		t.Fatalf("Mesh calls = %v", m.calls)
	}
	for _, b := range m.bearer {
		if b != "Bearer "+c.Value(1) {
			t.Fatal("a call did not carry the token of the file")
		}
	}
	// The token is rotated in place: the next call uses the new one.
	if err := os.WriteFile(file, []byte(c.Value(2)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cards.Cancel(context.Background(), id, "request expired"); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if last := m.bearer[len(m.bearer)-1]; last != "Bearer "+c.Value(2) {
		t.Fatal("Cancel did not use the rotated token")
	}
	if c.In(logs.String()) || strings.Contains(logs.String(), c.Value(2)) {
		t.Fatalf("token reached the log: %s", logs.String())
	}
}

// Whatever goes wrong, the token and the Mesh answer (which echoes the bearer
// here) are in no error and no log line.
func TestCardsNeverLeakTheTokenOnFailure(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusInternalServerError} {
		c := canary.New()
		m := newMeshStub(t)
		m.status = status
		var logs bytes.Buffer
		cards, err := newCards(m.cfg(writeToken(t, 0o600, c.Value(1))), nil, obs.New(&logs))
		if err != nil {
			t.Fatal(err)
		}
		_, cerr := cards.Create(context.Background(), spec)
		xerr := cards.Cancel(context.Background(), "11111111-2222-4333-8444-555555555555", "x")
		if cerr == nil || xerr == nil {
			t.Fatalf("status %d: Mesh refused but Create=%v Cancel=%v", status, cerr, xerr)
		}
		for _, text := range []string{cerr.Error(), xerr.Error(), logs.String()} {
			if c.In(text) || strings.Contains(text, "mesh says no") {
				t.Fatalf("status %d: token or Mesh text leaked: %s", status, text)
			}
		}
	}
}

func TestTokenFileProblemsAreUnavailableAndNameNothing(t *testing.T) {
	c := canary.New()
	dir := t.TempDir()
	cases := map[string]string{
		"world readable":  writeToken(t, 0o644, c.Value(1)),
		"owner read only": writeToken(t, 0o400, c.Value(1)),
		"owner exec":      writeToken(t, 0o700, c.Value(1)),
		"empty":           writeToken(t, 0o600, " \n"),
		"too large":       writeToken(t, 0o600, strings.Repeat("x", maxTokenFile+1)),
		"missing":         filepath.Join(dir, "absent-"+c.Value(3)),
		"directory":       dir,
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal("mkfifo")
	}
	cases["fifo"] = fifo
	for name, path := range cases {
		done := make(chan error, 1)
		go func() { _, err := tokenFromFile(path)(context.Background()); done <- err }()
		var err error
		select {
		case err = <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the token read hung", name)
		}
		if !errors.Is(err, errToken) {
			t.Errorf("%s: err = %v, want errToken", name, err)
			continue
		}
		if c.In(err.Error()) || strings.Contains(err.Error(), path) {
			t.Errorf("%s: error carries file text or path: %v", name, err)
		}
	}
}

func TestNewCardsRefusesUnsafeConfigWithoutValues(t *testing.T) {
	c := canary.New()
	file := writeToken(t, 0o600, c.Value(1))
	for name, mutate := range map[string]func(*config.MeshGate){
		"plain http to a remote host": func(g *config.MeshGate) { g.URL = "http://mesh.example.test" },
		"project is not a uuid":       func(g *config.MeshGate) { g.ProjectID = "p-" + c.Value(2) },
	} {
		g := newMeshStub(t).cfg(file)
		mutate(&g)
		cards, err := newCards(g, nil, nil)
		if err == nil || cards != nil {
			t.Fatalf("%s: accepted (%v, %v)", name, cards, err)
		}
		if c.In(err.Error()) || strings.Contains(err.Error(), "mesh.example.test") {
			t.Fatalf("%s: error carries a value: %v", name, err)
		}
	}
}

// The shipped binary hands the server the Mesh plugin; the plain build does not.
func TestPluginBinaryProvidesTheMeshCards(t *testing.T) {
	if options().Cards == nil {
		t.Fatal("the plugin binary starts without the Mesh gate")
	}
	if options().SelfRotate == nil {
		t.Fatal("the plugin binary cannot rotate its own service token")
	}
}

// The grace the plugin asks for with the queue must cover the queue's longest
// open request: a lease taken just before the pending TTL ends.
func TestRestartGraceCoversTheQueueWindow(t *testing.T) {
	window := restart.PendingTTL + restart.Lease
	if got := time.Duration(mesh.RestartGraceSeconds) * time.Second; got < window {
		t.Fatalf("restart grace %v is shorter than the queue window %v", got, window)
	}
}

// rotatingSource is the core's vault source: it returns whatever token is
// sealed now, or fails with a text that names the vault and the token.
type rotatingSource struct {
	mu    sync.Mutex
	tok   string
	err   error
	calls int
}

func (s *rotatingSource) set(tok string) { s.mu.Lock(); s.tok = tok; s.mu.Unlock() }

func (s *rotatingSource) Token(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return s.tok, s.err
}

// Given the core's source, every Mesh call asks it again (a token sealed
// between two calls is the one sent next), no token file is needed, and the
// token is in no log line.
func TestCardsAskTheVaultSourceOnEveryCall(t *testing.T) {
	c := canary.New()
	m := newMeshStub(t)
	src := &rotatingSource{tok: c.Value(1)}
	var logs bytes.Buffer
	cfg := m.cfg("")
	cfg.WorkspaceID = uuid.NewString()
	cards, err := newCards(cfg, src, obs.New(&logs))
	if err != nil {
		t.Fatal(err)
	}
	id, err := cards.Create(context.Background(), spec)
	if err != nil || id == "" {
		t.Fatalf("Create: %q, %v", id, err)
	}
	for _, b := range m.bearer {
		if b != "Bearer "+c.Value(1) {
			t.Fatal("a call did not carry the token of the source")
		}
	}
	if src.calls != len(m.calls) {
		t.Fatalf("source asked %d times for %d Mesh calls", src.calls, len(m.calls))
	}
	src.set(c.Value(2))
	if err := cards.Cancel(context.Background(), id, "request expired"); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if last := m.bearer[len(m.bearer)-1]; last != "Bearer "+c.Value(2) {
		t.Fatal("Cancel did not use the token sealed after the rotation")
	}
	if c.In(logs.String()) || strings.Contains(logs.String(), c.Value(2)) {
		t.Fatalf("token reached the log: %s", logs.String())
	}
}

// A failing source is unavailable without a call to Mesh, and neither its
// text nor the token reaches the error or the log.
func TestCardsWithAFailingVaultSourceCallNoMeshAndNameNothing(t *testing.T) {
	c := canary.New()
	m := newMeshStub(t)
	src := &rotatingSource{tok: c.Value(1), err: errors.New("vault mesh/ws/extension_token: " + c.Value(1))}
	var logs bytes.Buffer
	cfg := m.cfg("")
	cfg.WorkspaceID = uuid.NewString()
	cards, err := newCards(cfg, src, obs.New(&logs))
	if err != nil {
		t.Fatal(err)
	}
	_, cerr := cards.Create(context.Background(), spec)
	if !errors.Is(cerr, gatecard.ErrUnavailable) {
		t.Fatalf("Create = %v, want unavailable", cerr)
	}
	if len(m.calls) != 0 {
		t.Fatalf("Mesh was called without a token: %v", m.calls)
	}
	for _, text := range []string{cerr.Error(), logs.String()} {
		if c.In(text) || strings.Contains(text, "mesh/") || strings.Contains(text, cfg.WorkspaceID) {
			t.Fatalf("source text or token leaked: %s", text)
		}
	}
}

// The adapter itself: a refusing source is errToken, with neither the
// source's text nor the token in the error.
func TestTokenFromSourceRefusalIsOpaque(t *testing.T) {
	c := canary.New()
	for name, src := range map[string]*rotatingSource{
		"refused": {tok: c.Value(1), err: errors.New("vault mesh/ws/extension_token: " + c.Value(1))},
		"empty":   {},
	} {
		_, err := tokenFromSource(src)(context.Background())
		if !errors.Is(err, errToken) {
			t.Fatalf("%s: err = %v, want errToken", name, err)
		}
		if c.In(err.Error()) || strings.Contains(err.Error(), "mesh/") {
			t.Fatalf("%s: error carries the source text: %v", name, err)
		}
	}
}

// The plugin's pending restart reaches the core loop as its own sentinel, so the
// loop checks again soon; other results pass through as they are.
func TestPendingRestartReachesTheLoop(t *testing.T) {
	other := errors.New("other")
	for in, want := range map[error]error{
		mesh.ErrRestartPending:                            app.ErrSelfRotatePending,
		fmt.Errorf("wrapped: %w", mesh.ErrRestartPending): app.ErrSelfRotatePending,
		mesh.ErrOrphaned:                                  mesh.ErrOrphaned,
		other:                                             other,
	} {
		got := pendingForApp(func(context.Context) error { return in })(context.Background())
		if !errors.Is(got, want) {
			t.Fatalf("%v: got %v, want %v", in, got, want)
		}
	}
	if err := pendingForApp(func(context.Context) error { return nil })(context.Background()); err != nil {
		t.Fatalf("nil: %v", err)
	}
}
