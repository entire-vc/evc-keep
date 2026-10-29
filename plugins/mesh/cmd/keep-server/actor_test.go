package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/cmd/keep-server/app"
	"github.com/entire-vc/evc-keep/internal/config"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/google/uuid"
)

// meActor is a Mesh whose GET /api/v1/ext/me answers actor for the bearer tok
// and refuses any other; the answer also carries echo. Other routes answer 404
// and are counted, so a test sees whether anything but the probe was called.
type meActor struct {
	mu    sync.Mutex
	tok   string
	actor string
	echo  string
	me    int
	other []string
	srv   *httptest.Server
}

func newMeActor(t *testing.T, tok, actor, echo string) *meActor {
	t.Helper()
	m := &meActor{tok: tok, actor: actor, echo: echo}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/ext/me" {
			m.other = append(m.other, r.Method+" "+r.URL.Path)
			http.NotFound(w, r)
			return
		}
		m.me++
		if r.Header.Get("Authorization") != "Bearer "+m.tok {
			http.Error(w, "unauthorized "+m.echo, http.StatusUnauthorized)
			return
		}
		_, _ = fmt.Fprintf(w, `{"actor":"ext:x","actor_id":%q,"note":%q}`, m.actor, m.echo)
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *meActor) calls() (int, []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.me, append([]string(nil), m.other...)
}

// The plugin's check reads the gate's token file and maps the same actor onto
// the core's sentinel; the token is in neither the error nor the log.
func TestCheckSelfRotateActorFromTokenFile(t *testing.T) {
	c := canary.New()
	tok := "ext_" + c.Value(0)
	same := uuid.NewString()
	m := newMeActor(t, tok, same, c.Value(1))
	gate := config.MeshGate{URL: m.srv.URL, TokenFile: writeToken(t, 0o600, tok+"\n")}
	var logs bytes.Buffer
	err := checkSelfRotateActor(context.Background(), gate, nil, same, obs.New(&logs))
	if !errors.Is(err, app.ErrSelfRotateSameActor) {
		t.Fatalf("same actor: %v", err)
	}
	if err := checkSelfRotateActor(context.Background(), gate, nil, uuid.NewString(), obs.New(&logs)); err != nil {
		t.Fatalf("different actors: %v", err)
	}
	if n, _ := m.calls(); n != 2 {
		t.Fatalf("/me called %d times, want 2", n)
	}
	if logs.Len() == 0 {
		t.Fatal("no log line: the logger is not connected")
	}
	if c.In(err.Error()) || c.In(logs.String()) {
		t.Fatalf("canary leaked: %q %s", err, logs.String())
	}
}

// With a vault source the token is asked of the core, not of a file.
func TestCheckSelfRotateActorFromSource(t *testing.T) {
	same := uuid.NewString()
	m := newMeActor(t, stubTokenValue, same, "")
	gate := config.MeshGate{URL: m.srv.URL, TokenFile: filepath.Join(t.TempDir(), "absent")}
	err := checkSelfRotateActor(context.Background(), gate, staticSource(stubTokenValue), same, obs.New(&bytes.Buffer{}))
	if !errors.Is(err, app.ErrSelfRotateSameActor) {
		t.Fatalf("same actor from the vault source: %v", err)
	}
}

const stubTokenValue = "ext_gate-token-for-tests" //nolint:gosec // fake token of the in-process stub

type staticSource string

func (s staticSource) Token(context.Context) (string, error) { return string(s), nil }

// The plugin binary with the Mesh gate and self-rotation on refuses to start
// when the self-rotation account is the gate's actor: exit 1, the class text,
// and the gate's token (the canary) and the bootstrap token in no output. It
// calls nothing at Mesh but the probe, so nothing was rotated. With different
// actors the same start stays up.
func TestE2ESameActorRefusesStart(t *testing.T) {
	plugin := goBuild(t, ".")
	dsn := pgscratch.New(t, logSettings)
	migrate := exec.Command(plugin, "migrate", "up") //nolint:gosec // G204: goBuild's own output
	migrate.Env = append(os.Environ(), "KEEP_DATABASE_URL="+dsn)
	if out, err := migrate.CombinedOutput(); err != nil {
		t.Fatalf("migrate up: %v\n%s", err, out)
	}
	roleDSN := pgscratch.NewRole(t, dsn, "keep_app")
	org, _, _ := orgWithBearers(t, dsn)

	c := canary.New()
	gateTok := "ext_" + c.Value(0)
	actor := uuid.NewString()
	m := newMeActor(t, gateTok, actor, c.Value(1))
	dir := t.TempDir()
	gateFile := filepath.Join(dir, "gate.token")
	svcFile := filepath.Join(dir, "svc.token")
	if err := os.WriteFile(gateFile, []byte(gateTok+"\n"), 0o600); err != nil {
		t.Fatal("token fixture write failed")
	}
	if err := os.WriteFile(svcFile, []byte("ext_"+c.Value(2)+"\n"), 0o600); err != nil {
		t.Fatal("token fixture write failed")
	}
	env := func(account string) []string {
		return []string{
			"KEEP_DATABASE_URL=" + roleDSN, "KEEP_HTTP_ADDR=" + freeAddr(t), "KEEP_RUNNER_ADDR=127.0.0.1:0",
			"KEEP_ROOT_KEY_FILE=" + rootKeyFile(t), "KEEP_ROOT_KEY_ID=local-v1", "KEEP_DEV_EPHEMERAL_TLS=1",
			"KEEP_MESH_EXTENSION=1",
			"KEEP_MESH_URL=" + m.srv.URL, "KEEP_MESH_PROJECT_ID=" + uuid.NewString(),
			"KEEP_MESH_CANCEL_STATUS_ID=" + uuid.NewString(), "KEEP_MESH_TOKEN_FILE=" + gateFile,
			"KEEP_MESH_WORKSPACE_ID=",
			"KEEP_MESH_SELF_ROTATE=1", "KEEP_MESH_SELF_ROTATE_URL=" + m.srv.URL,
			"KEEP_MESH_SELF_ROTATE_ACCOUNT_ID=" + account, "KEEP_MESH_SELF_ROTATE_ORG_ID=" + org.String(),
			"KEEP_MESH_SVC_BOOTSTRAP_FILE=" + svcFile, "KEEP_MESH_SELF_ROTATE_INTERVAL=1h",
		}
	}

	out, running, code := serve(t, plugin, 15*time.Second, nil, env(actor)...)
	if running || code != 1 || !strings.Contains(out, "self-rotation account is the gate's actor") || !strings.Contains(out, `"error_class":"same_actor"`) {
		t.Fatalf("same actor: running=%v code=%d, want the refusal: %q", running, code, out)
	}
	if n, other := m.calls(); n != 1 || len(other) != 0 {
		t.Fatalf("same actor: /me %d times, other calls %v; want only the probe", n, other)
	}
	all := out

	out, running, code = serve(t, plugin, 6*time.Second, nil, env(uuid.NewString())...)
	if !running || !strings.Contains(out, "keep-server listening") {
		t.Fatalf("different actors: running=%v code=%d, want the server up: %q", running, code, out)
	}
	all += out

	if c.In(all) {
		t.Fatalf("a token or the probe's answer reached the process output: %q", all)
	}
}
