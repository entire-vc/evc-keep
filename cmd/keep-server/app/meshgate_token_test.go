package app

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/config"
	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/gatecard"
	"github.com/google/uuid"
)

// meshAt is the Mesh the test installations were made from.
const meshAt = "https://mesh.example.test"

// fakeOwners is the installation record: workspace → organisation and the
// Mesh address recorded at install (meshAt when url is empty).
type fakeOwners struct {
	org uuid.UUID
	url string
	ok  bool
	err error
}

func (o fakeOwners) Installation(context.Context, uuid.UUID) (uuid.UUID, string, bool, error) {
	u := o.url
	if u == "" {
		u = meshAt
	}
	return o.org, u, o.ok, o.err
}

// fakeVault holds the sealed token of one installation; Put replaces it, as a
// new install or a rotation does.
type fakeVault struct {
	mu       sync.Mutex
	org, ws  string
	tok      string
	err      error
	reads    int
	failWith string // text of the vault's own error, to prove it is not forwarded
	asked    [][2]string
}

func (v *fakeVault) put(tok string) { v.mu.Lock(); v.tok = tok; v.mu.Unlock() }

func (v *fakeVault) ExtensionToken(_ context.Context, org, ws string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.reads++
	v.asked = append(v.asked, [2]string{org, ws})
	if v.err != nil {
		return "", v.err
	}
	if org != v.org || ws != v.ws {
		return "", errors.New("not found " + v.failWith)
	}
	return v.tok, nil
}

// The source asks the vault on every call, with the organisation of the
// installation record: a token sealed between two calls (a rotation, a new
// install) is the one the next call returns, without a restart.
func TestGateTokenFromVaultIsReadAnewOnEveryCall(t *testing.T) {
	c := canary.New()
	org, ws := uuid.New(), uuid.New()
	v := &fakeVault{org: org.String(), ws: ws.String(), tok: c.Value(0)}
	src := vaultGateToken{installs: fakeOwners{org: org, ok: true}, vault: v, workspace: ws, meshURL: meshAt + "/"}
	got, err := src.Token(context.Background())
	if err != nil || got != c.Value(0) {
		t.Fatalf("first call: err=%v, token is the sealed one: %v", err, got == c.Value(0))
	}
	v.put(c.Value(1))
	got, err = src.Token(context.Background())
	if err != nil || got != c.Value(1) {
		t.Fatalf("after rotation: err=%v, the new token was returned: %v", err, got == c.Value(1))
	}
	if v.reads != 2 {
		t.Fatalf("vault read %d times for 2 calls", v.reads)
	}
}

// No installation, a failing record, a failing vault or an empty token: every
// refusal is ErrGateToken, whose text names no value, no workspace and no vault
// path, and nothing is logged.
func TestGateTokenRefusalsAreUnavailableAndNameNothing(t *testing.T) {
	c := canary.New()
	org, ws := uuid.New(), uuid.New()
	vaultErr := errors.New("resolve mesh/" + ws.String() + "/extension_token: " + c.Value(1))
	cases := map[string]vaultGateToken{
		"no installation":    {installs: fakeOwners{}, vault: &fakeVault{org: org.String(), ws: ws.String(), tok: c.Value(0)}},
		"record unavailable": {installs: fakeOwners{err: errors.New("db: " + c.Value(2))}, vault: &fakeVault{tok: c.Value(0)}},
		"vault refuses":      {installs: fakeOwners{org: org, ok: true}, vault: &fakeVault{err: vaultErr}},
		"other organisation": {installs: fakeOwners{org: uuid.New(), ok: true}, vault: &fakeVault{org: org.String(), ws: ws.String(), tok: c.Value(0), failWith: c.Value(3)}},
		"empty token":        {installs: fakeOwners{org: org, ok: true}, vault: &fakeVault{org: org.String(), ws: ws.String()}},
		// KEEP_MESH_URL is not the Mesh the workspace was installed from: the
		// token would be sent to another origin.
		"other mesh host":   {installs: fakeOwners{org: org, ok: true, url: "https://mesh.other.test"}, vault: &fakeVault{org: org.String(), ws: ws.String(), tok: c.Value(0)}},
		"other mesh scheme": {installs: fakeOwners{org: org, ok: true, url: "http://mesh.example.test"}, vault: &fakeVault{org: org.String(), ws: ws.String(), tok: c.Value(0)}},
		"other mesh port":   {installs: fakeOwners{org: org, ok: true, url: "https://mesh.example.test:8443"}, vault: &fakeVault{org: org.String(), ws: ws.String(), tok: c.Value(0)}},
		"unparsable record": {installs: fakeOwners{org: org, ok: true, url: "::" + c.Value(4)}, vault: &fakeVault{org: org.String(), ws: ws.String(), tok: c.Value(0)}},
	}
	for name, src := range cases {
		src.workspace, src.meshURL = ws, meshAt
		tok, err := src.Token(context.Background())
		if tok != "" || !errors.Is(err, ErrGateToken) {
			t.Fatalf("%s: token returned=%v, err=%v", name, tok != "", err)
		}
		if msg := err.Error(); c.In(msg) || strings.Contains(msg, ws.String()) || strings.Contains(msg, "mesh/") || strings.Contains(msg, org.String()) {
			t.Fatalf("%s: the error names a value, the workspace or the path: %v", name, err)
		}
		if v := src.vault.(*fakeVault); (!src.installs.(fakeOwners).ok || src.installs.(fakeOwners).url != "") && v.reads != 0 {
			t.Fatalf("%s: the vault was asked without a matching installation", name)
		}
	}
}

// With KEEP_MESH_WORKSPACE_ID the plugin is handed a token source and no file;
// with KEEP_MESH_TOKEN_FILE it is handed none and reads its file. The start
// log says which source is on, by name only.
func TestMeshGateHandsThePluginTheVaultSourceOnlyForAWorkspace(t *testing.T) {
	pool := testPool(t)
	for _, tc := range []struct {
		name      string
		workspace string
		wantSrc   bool
		wantLog   string
	}{
		{"workspace", uuid.NewString(), true, "mesh gate on: actor token from the vault"},
		{"file", "", false, "mesh gate on: actor token from a file"},
	} {
		cfg := gateConfig(true)
		if tc.workspace != "" {
			cfg.MeshGate.TokenFile, cfg.MeshGate.WorkspaceID = "", tc.workspace
		}
		var got GateTokenSource
		opts := Options{Cards: func(_ config.MeshGate, tokens GateTokenSource, _ *slog.Logger) (gatecard.Cards, error) {
			got = tokens
			return &recCards{}, nil
		}}
		buf := &syncBuf{}
		ctx, cancel := context.WithCancel(context.Background())
		gates, err := wireMeshGate(ctx, cfg, opts, pool, &fakeVault{}, deployment.NewRepo(pool, audit.NewJournal(pool)), nil, obs.New(buf))
		cancel()
		if err != nil || gates == nil {
			t.Fatalf("%s: wire = %v, %v", tc.name, gates, err)
		}
		if (got != nil) != tc.wantSrc {
			t.Fatalf("%s: plugin got a token source: %v, want %v", tc.name, got != nil, tc.wantSrc)
		}
		logs := string(buf.Bytes())
		if !strings.Contains(logs, tc.wantLog) {
			t.Fatalf("%s: start log does not say %q: %s", tc.name, tc.wantLog, logs)
		}
		if tc.workspace != "" && strings.Contains(logs, tc.workspace) {
			t.Fatalf("%s: start log names the workspace", tc.name)
		}
	}
}
