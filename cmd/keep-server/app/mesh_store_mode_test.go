package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/api"
	"github.com/entire-vc/evc-keep/internal/config"
	"github.com/entire-vc/evc-keep/internal/meshext"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
)

// storeFetcher counts the hierarchy fetches Keep starts, per workspace.
type storeFetcher struct {
	mu   sync.Mutex
	seen map[uuid.UUID]int
}

func (s *storeFetcher) FetchHierarchy(_ context.Context, _, ws uuid.UUID, _, _ string) (meshext.Fetched, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen[ws]++
	return meshext.Fetched{}, errors.New("unauthorized")
}

func (f *meshFixture) installStore(ws uuid.UUID, token string) *httptest.ResponseRecorder {
	f.t.Helper()
	b, _ := json.Marshal(map[string]string{
		"mesh_url": "https://mesh.example.test", "workspace_id": ws.String(),
		"extension_token": token, "events_endpoint_secret": meshTestEventsSecret, "mode": "store",
	})
	rec := f.post("/mesh/install", f.admin, b, nil)
	installedKeepSecret(f.t, rec)
	return rec
}

// A workspace installed as a secret store only keeps working for the calls
// its Mesh makes into Keep: a secret it puts is resolved back through the
// same signed Mesh path. Keep makes no call of its own to that Mesh: no
// hierarchy fetch and no gate token, while an extension installation of the
// same organisation is still fetched. Neither the token handed over at a store
// install nor a secret value reaches a log, the journal, a metadata table, the
// sealed storage in clear, or the install answer.
func TestMeshStoreInstallServesSecretsAndIsNeverCalled(t *testing.T) {
	f := newMeshFixture(t, true)
	c := canary.New()
	st := uuid.New()
	install := f.installStore(st, c.Value(1))
	var mode string
	if err := f.pool.QueryRow(context.Background(), `SELECT mode FROM mesh_installations WHERE workspace_id=$1`, st).Scan(&mode); err != nil || mode != "store" {
		t.Fatalf("admin install with mode store recorded %q (%v)", mode, err)
	}

	val := c.Value(2)
	if rec := f.putSecret(st, "store-ref", val); rec.Code != http.StatusOK {
		t.Fatalf("PUT through the Mesh path of a store installation: %d", rec.Code)
	}
	rec := f.resolveSecret(st, "store-ref")
	var out map[string]string
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil || out["value"] != val {
		t.Fatalf("resolve through the Mesh path of a store installation: %d", rec.Code)
	}
	if !c.In(rec.Body.String()) {
		t.Fatal("the canary detector misses the value in the resolve body; the leak check proves nothing")
	}

	ext := f.installedWorkspace()
	fetch := &storeFetcher{seen: map[uuid.UUID]int{}}
	f.repo.ReconcileAll(context.Background(), fetch, f.logger)
	if fetch.seen[st] != 0 {
		t.Fatalf("store installation fetched %d times, want 0", fetch.seen[st])
	}
	if fetch.seen[ext] != 1 {
		t.Fatalf("extension installation fetched %d times, want 1 (positive control)", fetch.seen[ext])
	}

	// The gate's token source exactly as the server wires it.
	gateFor := func(ws uuid.UUID) (string, error) {
		src, err := gateTokens(config.MeshGate{WorkspaceID: ws.String(), URL: "https://mesh.example.test"}, f.pool, f.local.MeshVault())
		if err != nil || src == nil {
			t.Fatalf("gate token source: %v", err)
		}
		return src.Token(context.Background())
	}
	if _, err := gateFor(st); !errors.Is(err, ErrGateToken) {
		t.Fatalf("gate token of a store installation: %v, want ErrGateToken", err)
	}
	if tok, err := gateFor(ext); err != nil || tok == "" {
		t.Fatalf("gate token of the extension installation: %v (positive control)", err)
	}

	if f.logbuf.Len() == 0 {
		t.Fatal("logger captured nothing; the log check proves nothing")
	}
	for i, s := range append(f.surfaces(), install.Body.String(), headersText(install)) {
		if c.In(s) {
			t.Fatalf("surface %d carries the store install token or a secret value", i)
		}
	}
}

// Mesh's install handshake is the extension install: the workspace it binds is
// recorded as an extension and is reconciled.
func TestMeshHandshakeInstallsAnExtension(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := uuid.New()
	f.handshakeBound(ws, "mode-signing-"+strings.Repeat("m", 40))
	var mode string
	if err := f.pool.QueryRow(context.Background(), `SELECT mode FROM mesh_installations WHERE workspace_id=$1`, ws).Scan(&mode); err != nil || mode != "extension" {
		t.Fatalf("handshake install recorded mode %q (%v), want extension", mode, err)
	}
	fetch := &storeFetcher{seen: map[uuid.UUID]int{}}
	f.repo.ReconcileAll(context.Background(), fetch, f.logger)
	if fetch.seen[ws] != 1 {
		t.Fatalf("handshake installation fetched %d times, want 1", fetch.seen[ws])
	}
}

// Mesh's install handshake over a workspace that already holds a store-only
// binding of the same organisation upgrades that binding to the extension,
// when an admin of that organisation opened a live window for the handshake's
// secret. Every other handshake over the store binding stays the uniform 401
// and writes nothing: no window, a window for another secret, an expired
// one, a window of another organisation, and a second handshake once the
// window is spent.
func TestMeshHandshakeUpgradesStoreBinding(t *testing.T) {
	f := newMeshFixture(t, true)
	c := canary.New()
	secret, other := "up-"+c.Value(1), "up-"+c.Value(2)
	mode := func(ws uuid.UUID) string {
		var m string
		if err := f.pool.QueryRow(context.Background(), `SELECT mode FROM mesh_installations WHERE workspace_id=$1`, ws).Scan(&m); err != nil {
			t.Fatalf("mode: %v", err)
		}
		return m
	}
	windows := func(ws uuid.UUID) int {
		return f.count(`SELECT count(*) FROM mesh_pending_installs WHERE workspace_id=$1`, ws)
	}
	eventOK := func(ws uuid.UUID, s, id string) bool {
		b := eventBody(ws, id, "project.created")
		return f.post("/mesh/events", "", b, signedHeaders(ws, s, time.Now(), b)).Code == http.StatusOK
	}
	storeWS := func() uuid.UUID {
		ws := uuid.New()
		if rec := f.installStore(ws, c.Value(3)); rec.Code != http.StatusOK {
			t.Fatalf("store install: %d", rec.Code)
		}
		return ws
	}
	refused := func(name string, ws uuid.UUID, s string) {
		t.Helper()
		if rec := f.handshake(ws, s); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: status %d, want 401", name, rec.Code)
		}
		if mode(ws) != "store" {
			t.Fatalf("%s: the refusal changed the binding", name)
		}
		if !eventOK(ws, meshTestEventsSecret, uuid.NewString()) {
			t.Fatalf("%s: the refusal replaced the store events secret", name)
		}
	}

	t.Run("upgrades with a live window", func(t *testing.T) {
		ws := storeWS()
		const stored = "upgrade-kept-value"
		if rec := f.putSecret(ws, "kept-ref", stored); rec.Code != http.StatusOK {
			t.Fatalf("put before the upgrade: %d", rec.Code)
		}
		f.mustOpenWindow(ws, secret)
		up := f.handshake(ws, secret)
		if up.Code != http.StatusOK {
			t.Fatalf("handshake over a store binding: %d, %s", up.Code, answerDiag(up))
		}
		if mode(ws) != "extension" || windows(ws) != 0 {
			t.Fatalf("mode %q, windows %d: want an extension and a spent window", mode(ws), windows(ws))
		}
		// The lookup comes first: the secret the store stored is read back
		// signed by the store (producer) and by the extension (consumer), the
		// path the extension's health check goes through. The base reaches
		// this point after a 200 upgrade and fails here.
		for _, who := range []struct{ name, signer string }{{"store", meshTestEventsSecret}, {"extension", secret}} {
			var got map[string]string
			rec := f.secretsDo(secretCall{method: http.MethodPost, path: f.secretPath(f.org.ID, "kept-ref", true), ws: ws, secret: who.signer})
			if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got["value"] != stored {
				t.Fatalf("signing-secret lookup after the upgrade: %s-signed resolve: %d", who.name, rec.Code)
			}
		}
		// The store and the extension work side by side: the handshake secret
		// is sealed beside the store's events secret, never over it. A secret
		// that was never bound is the negative control.
		if !eventOK(ws, secret, uuid.NewString()) || !eventOK(ws, meshTestEventsSecret, uuid.NewString()) {
			t.Fatal("after the upgrade both the handshake secret and the store events secret must verify")
		}
		if eventOK(ws, other, uuid.NewString()) {
			t.Fatal("an unbound secret verifies after the upgrade")
		}
		if !c.In(secret) {
			t.Fatal("the canary detector is blind to the signing secret; the surface check proves nothing")
		}
		for i, surf := range append(f.surfaces(), up.Body.String(), headersText(up)) {
			if c.In(surf) {
				t.Fatalf("surface %d carries a canary after the upgrade", i)
			}
		}
		// Mesh repeats the handshake with the bound secret: still 200.
		if rec := f.handshake(ws, secret); rec.Code != http.StatusOK {
			t.Fatalf("repeat: %d", rec.Code)
		}
		// Spent window: another secret is refused now that it is an extension.
		if rec := f.handshake(ws, other); rec.Code != http.StatusUnauthorized {
			t.Fatalf("replay with another secret: %d", rec.Code)
		}
		if !eventOK(ws, secret, uuid.NewString()) {
			t.Fatal("a refused replay replaced the events secret")
		}
	})
	// The upgrade spends the workspace's budget before it writes: with a
	// budget of one, the repeat that follows is refused, and a refusal is
	// never left after a committed upgrade.
	// A store reinstall rotates every signing key: the extension's secret from
	// the upgrade stops verifying, the store's keeps working.
	t.Run("reinstall revokes the extension secret", func(t *testing.T) {
		ws := storeWS()
		f.mustOpenWindow(ws, secret)
		if rec := f.handshake(ws, secret); rec.Code != http.StatusOK {
			t.Fatalf("upgrade: %d", rec.Code)
		}
		if !eventOK(ws, secret, uuid.NewString()) {
			t.Fatal("extension secret does not verify before the reinstall")
		}
		if rec := f.installStore(ws, c.Value(6)); rec.Code != http.StatusOK {
			t.Fatalf("store reinstall: %d", rec.Code)
		}
		if eventOK(ws, secret, uuid.NewString()) {
			t.Fatal("the extension secret survived a reinstall")
		}
		if !eventOK(ws, meshTestEventsSecret, uuid.NewString()) {
			t.Fatal("the store events secret stopped verifying after its own reinstall")
		}
	})
	t.Run("upgrade spends the budget", func(t *testing.T) {
		frozen := time.Now()
		g := newMeshFixtureOn(t, f.pool, true, func(d *api.MeshDeps) {
			d.ResolveLimit = api.CatalogLimit{PerMinute: 1, Burst: 1, Now: func() time.Time { return frozen }}
		})
		ws := uuid.New()
		if rec := g.installStore(ws, c.Value(5)); rec.Code != http.StatusOK {
			t.Fatalf("store install: %d", rec.Code)
		}
		g.mustOpenWindow(ws, secret)
		if rec := g.handshake(ws, secret); rec.Code != http.StatusOK {
			t.Fatalf("upgrading handshake: %d", rec.Code)
		}
		if rec := g.handshake(ws, secret); rec.Code != http.StatusTooManyRequests {
			t.Fatalf("repeat after the upgrade spent the budget: %d, want 429", rec.Code)
		}
	})
	t.Run("no window", func(t *testing.T) {
		refused("no window", storeWS(), secret)
	})
	t.Run("window for another secret", func(t *testing.T) {
		ws := storeWS()
		f.mustOpenWindow(ws, other)
		refused("digest mismatch", ws, secret)
		if windows(ws) != 1 {
			t.Fatal("a digest mismatch spent the window")
		}
	})
	t.Run("expired window", func(t *testing.T) {
		ws := storeWS()
		f.mustOpenWindow(ws, secret)
		f.expireWindow(ws)
		refused("expired", ws, secret)
	})
	t.Run("window naming another Mesh", func(t *testing.T) {
		ws := storeWS()
		b, _ := json.Marshal(map[string]string{"workspace_id": ws.String(), "mesh_url": "https://mesh.attacker.test", "signing_secret_sha256": meshSecretSHA256(secret)})
		if rec := f.post("/orgs/"+f.org.ID.String()+"/mesh/pending-installs", f.admin, b, nil); rec.Code != http.StatusCreated {
			t.Fatalf("open window: %d", rec.Code)
		}
		refused("redirecting window", ws, secret)
		if windows(ws) != 1 {
			t.Fatal("a refused redirect spent the window")
		}
	})
	t.Run("extension binding is not replaced", func(t *testing.T) {
		ws := uuid.New()
		f.handshakeBound(ws, "ext-"+c.Value(4))
		// A window for a workspace already held is only possible for the
		// same organisation; open it and present another secret.
		f.mustOpenWindow(ws, secret)
		if rec := f.handshake(ws, secret); rec.Code != http.StatusUnauthorized {
			t.Fatalf("handshake with a window over an extension: %d, want 401", rec.Code)
		}
		if mode(ws) != "extension" || windows(ws) != 1 {
			t.Fatalf("mode %q, windows %d: the extension was touched or the window spent", mode(ws), windows(ws))
		}
		if !eventOK(ws, "ext-"+c.Value(4), uuid.NewString()) || eventOK(ws, secret, uuid.NewString()) {
			t.Fatal("the extension's events secret was replaced")
		}
	})
	t.Run("window of another organisation", func(t *testing.T) {
		ws := storeWS()
		tr := tenancy.New(f.pool)
		foreign, err := tr.CreateOrganization(context.Background(), t.Name()+"-foreign", "")
		if err != nil {
			t.Fatal(err)
		}
		fu, err := tr.CreateUser(context.Background(), foreign.ID, "foreign@example.test")
		if err != nil {
			t.Fatal(err)
		}
		// OpenPending refuses this window for a held workspace; a row from
		// before the binding is the only way one can exist.
		if _, err := f.pool.Exec(context.Background(), `
INSERT INTO mesh_pending_installs (workspace_id, org_id, opened_by, mesh_url, secret_sha256, expires_at)
VALUES ($1, $2, $3, 'https://mesh.example.test', $4, now() + interval '10 minutes')`,
			ws, foreign.ID, fu.ID, meshSecretSHA256(secret)); err != nil {
			t.Fatalf("seed a foreign window: %v", err)
		}
		refused("foreign window", ws, secret)
	})
}

// The order a Mesh admin follows: the workspace is a store binding, keep is
// connected over it (the upgrade), then keep-rotator is connected to the same
// installation. Both handshakes answer 200 on repeat, the store binding and
// its secrets are intact, and the rotator's secret is accepted nowhere but
// its own handshake.
func TestMeshRotatorConnectsAfterStoreUpgradeAndKeepsTheStore(t *testing.T) {
	f := newMeshFixture(t, true)
	c := canary.New()
	keepSecret, rotSecret := "up-"+c.Value(1), "rot-"+c.Value(2)
	ws := uuid.New()
	if rec := f.installStore(ws, c.Value(3)); rec.Code != http.StatusOK {
		t.Fatalf("store install: %d", rec.Code)
	}
	const stored = "rotator-kept-value"
	if rec := f.putSecret(ws, "kept-ref", stored); rec.Code != http.StatusOK {
		t.Fatalf("put into the store: %d", rec.Code)
	}
	f.mustOpenWindow(ws, keepSecret)
	if rec := f.handshake(ws, keepSecret); rec.Code != http.StatusOK {
		t.Fatalf("keep connect over the store: %d", rec.Code)
	}
	if rec := f.openRotatorWindow(ws, rotSecret); rec.Code != http.StatusCreated {
		t.Fatalf("rotator window: %d", rec.Code)
	}
	rotate := func() *httptest.ResponseRecorder {
		return f.handshakeSigned(meshHandshakeBody(ws, "keep-rotator", rotSecret), rotSecret, time.Now())
	}
	// Mesh's Handshaker.install treats any 2xx as a successful install and
	// discards the body (evc-mesh internal/extensions/external/handshake.go);
	// a connection is healthy exactly then. The answer's own ok flag is only
	// kept as an extra check on Keep's side. A failure names the status and
	// answerDiag, never the body.
	healthy := func(who string, rec *httptest.ResponseRecorder) {
		t.Helper()
		if rec.Code < 200 || rec.Code > 299 || !strings.Contains(rec.Body.String(), `"ok":true`) {
			t.Fatalf("%s health: status %d, %s", who, rec.Code, answerDiag(rec))
		}
	}
	first := rotate()
	if first.Code != http.StatusOK || !strings.Contains(first.Body.String(), `"ok":true`) {
		t.Fatalf("rotator connect: %d, %s", first.Code, answerDiag(first))
	}
	healthy("rotator", first)
	healthy("rotator repeat", rotate())
	healthy("keep repeat after the rotator connected", f.handshake(ws, keepSecret))
	// Identities: each extension id is bound to its own secret only.
	if rec := f.handshakeSigned(meshHandshakeBody(ws, "keep-rotator", keepSecret), keepSecret, time.Now()); rec.Code != http.StatusUnauthorized {
		t.Fatalf("keep's secret as the rotator: %d, want 401", rec.Code)
	}
	if rec := f.handshakeSigned(meshHandshakeBody(ws, "keep", rotSecret), rotSecret, time.Now()); rec.Code != http.StatusUnauthorized {
		t.Fatalf("rotator's secret as keep: %d, want 401", rec.Code)
	}
	// The store binding is as before: still the extension of the keep upgrade
	// with the store's own events secret and the secret it holds.
	var mode string
	if err := f.pool.QueryRow(context.Background(), `SELECT mode FROM mesh_installations WHERE workspace_id=$1`, ws).Scan(&mode); err != nil || mode != "extension" {
		t.Fatalf("installation mode %q (%v), want the keep upgrade's extension", mode, err)
	}
	eventOK := func(s string) bool {
		b := eventBody(ws, uuid.NewString(), "project.created")
		return f.post("/mesh/events", "", b, signedHeaders(ws, s, time.Now(), b)).Code == http.StatusOK
	}
	if !eventOK(meshTestEventsSecret) || !eventOK(keepSecret) {
		t.Fatal("the store's events secret or keep's stopped verifying after the rotator connected")
	}
	if eventOK(rotSecret) {
		t.Fatal("the rotator's secret signs events")
	}
	for _, who := range []struct {
		name, signer string
		ok           bool
	}{{"store", meshTestEventsSecret, true}, {"keep", keepSecret, true}, {"rotator", rotSecret, false}} {
		var got map[string]string
		rec := f.secretsDo(secretCall{method: http.MethodPost, path: f.secretPath(f.org.ID, "kept-ref", true), ws: ws, secret: who.signer})
		resolved := rec.Code == http.StatusOK && json.Unmarshal(rec.Body.Bytes(), &got) == nil && got["value"] == stored
		if resolved != who.ok {
			t.Fatalf("%s-signed resolve: status %d, resolved=%v, want %v", who.name, rec.Code, resolved, who.ok)
		}
	}
	if !c.In(rotSecret) {
		t.Fatal("the canary detector is blind to the rotator secret; the surface check proves nothing")
	}
	for i, surf := range append(f.surfaces(), first.Body.String(), headersText(first)) {
		if c.In(surf) {
			t.Fatalf("surface %d carries a canary after the rotator connected", i)
		}
	}
}

// meshProducerVector is a request captured from the real evc-mesh
// Handshaker.Run for extension keep-rotator (testdata/mesh-producer-install.json).
type meshProducerVector struct {
	MeshCommit  string `json:"mesh_commit"`
	Path        string `json:"path"`
	Timestamp   string `json:"timestamp"`
	Signature   string `json:"signature"`
	UserAgent   string `json:"user_agent"`
	ContentType string `json:"content_type"`
	Body        string `json:"body"`
}

// The bytes Mesh's real producer sends, not a hand-written copy: its body,
// headers and signature drive the rotator connect over a store binding that
// the keep upgrade turned into an extension. The producer treats 2xx as a
// successful install and ignores the body, so that is the health asserted.
func TestMeshRotatorAcceptsTheRealMeshProducerRequest(t *testing.T) {
	raw, err := os.ReadFile("testdata/mesh-producer-install.json")
	if err != nil {
		t.Fatal(err)
	}
	var v meshProducerVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	var req meshInstallRequest
	if err := json.Unmarshal([]byte(v.Body), &req); err != nil || req.ExtensionID != "keep-rotator" {
		t.Fatalf("vector body: extension %q (%v)", req.ExtensionID, err)
	}
	secret := req.SigningSecret
	// Positive control on the vector itself: the producer's own signature is
	// the documented HMAC over "<ts>.<body>", so the vector is intact.
	if v.Signature != meshSign(secret, v.Timestamp, []byte(v.Body)) {
		t.Fatal("the captured signature is not the documented HMAC of its own body; the vector is damaged")
	}
	f := newMeshFixture(t, true)
	c := canary.New()
	ws, keepSecret := req.WorkspaceID, "up-"+c.Value(1)
	if rec := f.installStore(ws, c.Value(3)); rec.Code != http.StatusOK {
		t.Fatalf("store install: %d", rec.Code)
	}
	f.mustOpenWindow(ws, keepSecret)
	if rec := f.handshake(ws, keepSecret); rec.Code != http.StatusOK {
		t.Fatalf("keep connect over the store: %d", rec.Code)
	}
	if rec := f.openRotatorWindow(ws, secret); rec.Code != http.StatusCreated {
		t.Fatalf("rotator window: %d", rec.Code)
	}
	// The producer's bytes with a fresh timestamp (the captured one is
	// outside the window by now), signed the way the producer signs.
	send := func(secret string) *httptest.ResponseRecorder {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		return f.post(v.Path, "", []byte(v.Body), map[string]string{
			"Content-Type": v.ContentType, "User-Agent": v.UserAgent,
			"X-Mesh-Timestamp": ts, "X-Mesh-Signature": meshSign(secret, ts, []byte(v.Body)),
		})
	}
	for i, name := range []string{"first connect", "repeat"} {
		if rec := send(secret); rec.Code < 200 || rec.Code > 299 {
			t.Fatalf("%s %d: status %d, %s (Mesh reads non-2xx as unhealthy)", name, i, rec.Code, answerDiag(rec))
		}
	}
	// Negative control: the same body signed with another secret is refused,
	// so the 2xx above is the producer's secret being honoured.
	if rec := send("not-the-producers-secret"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a body signed with another secret: %d, want 401", rec.Code)
	}
	var mode string
	if err := f.pool.QueryRow(context.Background(), `SELECT mode FROM mesh_installations WHERE workspace_id=$1`, ws).Scan(&mode); err != nil || mode != "extension" {
		t.Fatalf("installation mode %q (%v), want extension", mode, err)
	}
}
