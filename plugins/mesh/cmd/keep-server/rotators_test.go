package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/entire-vc/evc-keep/pkg/rotation"
	"github.com/google/uuid"
)

const rotToken = "ext_rotator-token-for-tests" //nolint:gosec // fake token of the in-process stub

func writeBindings(t *testing.T, m map[string]string) string {
	t.Helper()
	b, _ := json.Marshal(m)
	p := filepath.Join(t.TempDir(), "bindings.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// agentStub answers the agent-keys API of one agent and counts what it saw.
func agentStub(t *testing.T, agent string, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	keys := map[string]bool{uuid.NewString(): true}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+rotToken || !strings.HasPrefix(r.URL.Path, "/api/v1/agents/"+agent+"/keys") {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodPost:
			id := uuid.NewString()
			keys[id] = true
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"key_id": id, "key": "agk_fake-key-for-tests"})
		case http.MethodGet:
			out := []map[string]string{}
			for id, on := range keys {
				st := "revoked"
				if on {
					st = "active"
				}
				out = append(out, map[string]string{"key_id": id, "status": st})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": out})
		case http.MethodDelete:
			keys[strings.TrimPrefix(r.URL.Path, "/api/v1/agents/"+agent+"/keys/")] = false
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func setRotateEnv(t *testing.T, url, tok, bind string) {
	t.Helper()
	t.Setenv(envRotateURL, url)
	t.Setenv(envRotateToken, tok)
	t.Setenv(envRotateBindings, bind)
}

func TestRotators_OffWithoutSettings(t *testing.T) {
	setRotateEnv(t, "", "", "")
	src, err := newRotators(nil)
	if err != nil || src != nil {
		t.Fatalf("no settings must mean no source, got %v %v", src != nil, err)
	}
}

func TestRotators_PartialSettingsRefuseTheStart(t *testing.T) {
	tok := writeToken(t, 0o600, rotToken)
	bind := writeBindings(t, nil)
	for _, c := range []struct{ url, tok, bind string }{
		{"http://127.0.0.1:1", "", ""}, {"", tok, ""}, {"", "", bind},
		{"http://127.0.0.1:1", tok, ""}, {"http://127.0.0.1:1", "", bind}, {"", tok, bind},
	} {
		setRotateEnv(t, c.url, c.tok, c.bind)
		if _, err := newRotators(nil); err == nil {
			t.Fatalf("a partial configuration must refuse the start: %+v", c)
		}
	}
}

func TestRotators_BadBindingsRefuseTheStart(t *testing.T) {
	tok := writeToken(t, 0o600, rotToken)
	good, other := uuid.NewString(), uuid.NewString()
	for name, m := range map[string]map[string]string{
		"secret not a uuid":  {"Sage": good},
		"agent not a uuid":   {good: "Sage"},
		"uppercase agent id": {good: strings.ToUpper(other)},
	} {
		setRotateEnv(t, "http://127.0.0.1:1", tok, writeBindings(t, m))
		if _, err := newRotators(nil); err == nil {
			t.Fatalf("%s must refuse the start", name)
		}
	}
	setRotateEnv(t, "https://mesh.example.test", tok, filepath.Join(t.TempDir(), "missing.json"))
	if _, err := newRotators(nil); err == nil {
		t.Fatal("a missing bindings file must refuse the start")
	}
	setRotateEnv(t, "http://mesh.example.test", tok, writeBindings(t, nil))
	if _, err := newRotators(nil); err == nil {
		t.Fatal("plain http to a non-loopback host must refuse the start")
	}
}

// A bound secret gets the Mesh provider of its agent, which issues and revokes
// keys over the agent-keys API; an unbound one gets none and is never sent to Mesh.
func TestRotators_BoundSecretGetsItsAgentUnboundGetsNone(t *testing.T) {
	var calls atomic.Int32
	agent, secretID := uuid.NewString(), uuid.New()
	srv := agentStub(t, agent, &calls)
	tok := writeToken(t, 0o600, rotToken)
	bindFile := writeBindings(t, map[string]string{secretID.String(): agent})
	setRotateEnv(t, srv.URL, tok, bindFile)
	src, err := newRotators(nil)
	if err != nil || src == nil {
		t.Fatalf("source: %v", err)
	}
	ctx := context.Background()
	if p, ok, err := src(ctx, uuid.New(), uuid.New()); p != nil || ok || err != nil {
		t.Fatalf("an unbound secret must keep the generator: %v %v %v", p, ok, err)
	}
	if calls.Load() != 0 {
		t.Fatal("Mesh was called for an unbound secret")
	}
	p, ok, err := src(ctx, uuid.New(), secretID)
	if err != nil || !ok || p.Kind() != "mesh-agent-key" || !p.Capabilities().DualKey {
		t.Fatalf("a bound secret must get the Mesh provider: %v %v %v", p, ok, err)
	}
	iss, err := p.Issue(ctx, rotation.IssueRequest{Subject: secretID.String(), RunID: uuid.New()})
	if err != nil || !rotation.ValidKeyID(iss.KeyID) || iss.Value.Len() == 0 {
		t.Fatalf("issue: %v", err)
	}
	if err := p.Revoke(ctx, iss.KeyID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if st, err := p.Check(ctx, iss.KeyID); err != nil || st.Active {
		t.Fatalf("a revoked key must not be active: %v %v", st, err)
	}
}

// The bindings are read on every call: a binding added after the start is used
// by the next run, and a file that turned bad fails that run closed instead of
// falling back to a generated value.
func TestRotators_BindingsAreReadPerCall(t *testing.T) {
	var calls atomic.Int32
	agent, secretID := uuid.NewString(), uuid.New()
	srv := agentStub(t, agent, &calls)
	tok := writeToken(t, 0o600, rotToken)
	bindFile := writeBindings(t, nil)
	setRotateEnv(t, srv.URL, tok, bindFile)
	src, err := newRotators(nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, ok, _ := src(ctx, uuid.New(), secretID); ok {
		t.Fatal("not bound yet")
	}
	b, _ := json.Marshal(map[string]string{secretID.String(): agent})
	if err := os.WriteFile(bindFile, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := src(ctx, uuid.New(), secretID); !ok || err != nil {
		t.Fatalf("a new binding must apply without a restart: %v %v", ok, err)
	}
	if err := os.WriteFile(bindFile, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if p, ok, err := src(ctx, uuid.New(), secretID); err == nil || ok || p != nil {
		t.Fatal("an unreadable bindings file must fail the run closed")
	}
}

// Only a regular file of bounded size is a bindings file: a directory, a FIFO
// (which would block) or an oversized file is refused.
func TestRotators_BindingsFileMustBeRegularAndBounded(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, []byte(`{"`+strings.Repeat("a", maxBindingsFile)+`":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]string{"directory": dir, "fifo": fifo, "oversized": big} {
		if _, err := readBindings(p); err == nil {
			t.Fatalf("%s must be refused", name)
		}
	}
	if _, err := readBindings(writeBindings(t, nil)); err != nil {
		t.Fatalf("positive control: %v", err)
	}
}

// One agent holds one secret, and the files must be the process's own, not
// writable by others: they decide whose key is issued and revoked.
func TestRotators_RefusesSharedAgentLooseModesAndRelativePaths(t *testing.T) {
	tok := writeToken(t, 0o600, rotToken)
	a, s1, s2 := uuid.NewString(), uuid.NewString(), uuid.NewString()
	dup := writeBindings(t, map[string]string{s1: a, s2: a})
	setRotateEnv(t, "http://127.0.0.1:1", tok, dup)
	if _, err := newRotators(nil); err == nil {
		t.Fatal("two secrets on one agent must refuse the start")
	}
	loose := writeBindings(t, map[string]string{s1: a})
	if err := os.Chmod(loose, 0o666); err != nil { //nolint:gosec // G302: a deliberately loose file, the case under test.
		t.Fatal(err)
	}
	setRotateEnv(t, "http://127.0.0.1:1", tok, loose)
	if _, err := newRotators(nil); err == nil {
		t.Fatal("a world-writable bindings file must refuse the start")
	}
	good := writeBindings(t, map[string]string{s1: a})
	setRotateEnv(t, "http://127.0.0.1:1", writeToken(t, 0o644, rotToken), good)
	if _, err := newRotators(nil); err == nil {
		t.Fatal("a token file of mode 0644 must refuse the start")
	}
	setRotateEnv(t, "http://127.0.0.1:1", "rel.token", good)
	if _, err := newRotators(nil); err == nil {
		t.Fatal("a relative token path must refuse the start")
	}
	setRotateEnv(t, "http://127.0.0.1:1", tok, good)
	if _, err := newRotators(nil); err != nil {
		t.Fatalf("positive control: %v", err)
	}
}

// A valid, tiny document padded past the limit is refused by size alone: the
// content is fine, so only a size bound can catch it. One byte over the limit
// is the edge.
func TestRotators_BindingsOverTheLimitAreRefusedBySizeAlone(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, n int) string {
		p := filepath.Join(dir, name)
		body := "{}" + strings.Repeat(" ", n-2)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := readBindings(write("at.json", maxBindingsFile)); err != nil {
		t.Fatalf("a file exactly at the limit is valid: %v", err)
	}
	if _, err := readBindings(write("over.json", maxBindingsFile+1)); err == nil {
		t.Fatal("one byte over the limit must be refused")
	}
	if _, err := readBindings(write("way-over.json", 2*maxBindingsFile)); err == nil {
		t.Fatal("a file twice the limit must be refused")
	}
}

// Existing files named by a relative path are refused: the working directory
// is not part of the configuration, so the path must not depend on it.
func TestRotators_ExistingFilesByRelativePathAreRefused(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile("rel.token", []byte(rotToken), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("rel.json", []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	absTok, absBind := filepath.Join(dir, "rel.token"), filepath.Join(dir, "rel.json")
	setRotateEnv(t, "http://127.0.0.1:1", absTok, absBind)
	if _, err := newRotators(nil); err != nil {
		t.Fatalf("positive control, the same files by absolute path: %v", err)
	}
	setRotateEnv(t, "http://127.0.0.1:1", "rel.token", absBind)
	if _, err := newRotators(nil); err == nil {
		t.Fatal("an existing token file by a relative path must refuse the start")
	}
	setRotateEnv(t, "http://127.0.0.1:1", absTok, "rel.json")
	if _, err := newRotators(nil); err == nil {
		t.Fatal("an existing bindings file by a relative path must refuse the start")
	}
}
