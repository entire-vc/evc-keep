package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/api"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/config"
	"github.com/google/uuid"
)

const (
	attackerPeer = "198.51.100.7:40000"
	meshPeer     = "203.0.113.20:40000"
)

// tightLimits leave a pre-authentication budget of two calls and a workspace
// budget of one, with no refill.
func tightLimits(d *api.MeshDeps) {
	frozen := time.Now()
	d.PreauthLimit = api.CatalogLimit{PerMinute: 1, Burst: 2, Now: func() time.Time { return frozen }}
	d.ResolveLimit = api.CatalogLimit{PerMinute: 1, Burst: 1, Now: func() time.Time { return frozen }}
}

// A caller who knows a workspace id floods its install handshake with bad
// signatures, and with good signatures under its own secret (the handshake is
// keyed with the secret of the body, so anyone can sign for any workspace):
// the flood runs out of its own budget, and Mesh's handshake for that
// workspace is still accepted.
func TestMeshPreauthBadHandshakesDoNotLockOutWorkspace(t *testing.T) {
	f := newMeshFixtureOn(t, testPool(t), true, tightLimits)
	ws := uuid.New()
	secret := "mesh-signing-secret-" + uuid.NewString()
	f.mustOpenWindow(ws, secret)
	installs := func() int { return f.count(`SELECT count(*) FROM mesh_installations WHERE workspace_id=$1`, ws) }

	f.peer = attackerPeer
	forged := "attacker-secret-" + uuid.NewString()
	floods := map[string]func() *httptest.ResponseRecorder{
		"wrong signature": func() *httptest.ResponseRecorder {
			return f.handshakeSigned(meshHandshakeBody(ws, "keep", secret), forged, time.Now())
		},
		"own secret": func() *httptest.ResponseRecorder {
			return f.handshakeSigned(meshHandshakeBody(ws, "keep", forged), forged, time.Now())
		},
	}
	limited := 0
	for name, send := range floods {
		for i := 0; i < 3; i++ {
			switch rec := send(); rec.Code {
			case http.StatusUnauthorized:
			case http.StatusTooManyRequests:
				limited++
			default:
				t.Fatalf("%s %d: status %d", name, i, rec.Code)
			}
		}
	}
	if installs() != 0 {
		t.Fatalf("the flood bound the workspace: %d installs", installs())
	}

	f.peer = meshPeer
	if rec := f.handshake(ws, secret); rec.Code != http.StatusOK || installs() != 1 {
		t.Fatalf("Mesh handshake after the flood: status %d, installs %d", rec.Code, installs())
	}
	if limited != 4 {
		t.Fatalf("flood of 6 over a budget of 2: %d limited, want 4", limited)
	}
}

// The same for events: bad signatures from one address spend that address's
// budget, never the workspace's, and Mesh's own stream, longer than the
// budget, all goes through since an authenticated call gets its token back.
func TestMeshPreauthBadEventsDoNotLockOutWorkspace(t *testing.T) {
	f := newMeshFixtureOn(t, testPool(t), true, tightLimits)
	ws := uuid.New()
	secret := "events-secret-" + uuid.NewString()
	installedKeepSecret(t, f.install(f.admin, ws, "tok-"+uuid.NewString(), secret))

	f.peer = attackerPeer
	codes := map[int]int{}
	for i := 0; i < 5; i++ {
		body := eventBody(ws, "evt-forged-"+strconv.Itoa(i), "project.created")
		codes[f.post("/mesh/events", "", body, signedHeaders(ws, secret+"x", time.Now(), body)).Code]++
	}
	if codes[http.StatusUnauthorized] != 2 || codes[http.StatusTooManyRequests] != 3 {
		t.Fatalf("forged events over a budget of 2: %v", codes)
	}

	f.peer = meshPeer
	for i := 0; i < 5; i++ {
		body := eventBody(ws, "evt-"+strconv.Itoa(i), "project.created")
		if rec := f.post("/mesh/events", "", body, signedHeaders(ws, secret, time.Now(), body)); rec.Code != http.StatusOK {
			t.Fatalf("Mesh event %d of 5 over a budget of 2: status %d", i, rec.Code)
		}
	}
	if n := f.eventRows(ws); n != 5 {
		t.Fatalf("event rows = %d, want 5", n)
	}
}

// POST /mesh/session is unauthenticated and calls out to Mesh: refused
// sign-ins spend the address's budget, then 429; another address signs in.
func TestMeshPreauthLimitsSessionSignIn(t *testing.T) {
	f := newSessionFixture(t, tightLimits)
	f.peer = attackerPeer
	for i, want := range []int{http.StatusUnauthorized, http.StatusUnauthorized, http.StatusTooManyRequests} {
		if rec := f.signIn("x.y.z"); rec.Code != want {
			t.Fatalf("bad context %d: status %d, want %d", i, rec.Code, want)
		}
	}
	f.peer = meshPeer
	for i := 0; i < 3; i++ {
		if rec := f.signIn(f.token("u1", "a@example.test")); rec.Code != http.StatusOK {
			t.Fatalf("valid sign-in %d of 3 over a budget of 2: status %d", i, rec.Code)
		}
	}
}

// Signed secrets calls: fresh ones over the budget all go through, a replayed
// nonce keeps its token spent, so a captured call cannot be replayed without
// limit.
func TestMeshPreauthSecretsRefundOnlyFreshNonce(t *testing.T) {
	f := newMeshFixtureOn(t, testPool(t), true, tightLimits)
	ws := f.installedWorkspace()
	body, _ := json.Marshal(map[string]string{"value": "v-" + uuid.NewString()})
	put := func(nonce string) int {
		return f.secretsDo(secretCall{method: http.MethodPut, path: f.secretPath(f.org.ID, "db.password", false),
			body: body, ws: ws, secret: meshTestEventsSecret, nonce: nonce}).Code
	}
	for i := 0; i < 3; i++ {
		if code := put(""); code != http.StatusOK {
			t.Fatalf("fresh call %d of 3 over a budget of 2: status %d", i, code)
		}
	}
	nonce := freshNonce(t)
	for i, want := range []int{http.StatusOK, http.StatusUnauthorized, http.StatusUnauthorized, http.StatusTooManyRequests} {
		if code := put(nonce); code != want {
			t.Fatalf("call %d with one nonce: status %d, want %d", i, code, want)
		}
	}
}

// Authenticated handshakes, by an open window and then by the bound secret,
// give their token back: Mesh repeating its handshake from one address goes
// through on a pre-authentication budget of one.
func TestMeshPreauthHandshakeRefundsOnAuthentication(t *testing.T) {
	f := newMeshFixtureOn(t, testPool(t), true, func(d *api.MeshDeps) {
		frozen := time.Now()
		d.PreauthLimit = api.CatalogLimit{PerMinute: 1, Burst: 1, Now: func() time.Time { return frozen }}
	})
	ws := uuid.New()
	secret := "mesh-signing-secret-" + uuid.NewString()
	f.mustOpenWindow(ws, secret)
	f.peer = meshPeer
	for i, what := range []string{"by the window", "bound", "bound again"} {
		if rec := f.handshake(ws, secret); rec.Code != http.StatusOK {
			t.Fatalf("handshake %d (%s): status %d", i, what, rec.Code)
		}
	}
}

// POST /mesh/token: deliveries a caller cannot sign, for a workspace that is
// not connected and for one that is, spend the address's budget, then 429
// before the workspace is looked up. Mesh's signed deliveries from one
// address, more than the budget, all go through, since each gets its token
// back, and leave the whole budget to the next caller from that address.
func TestMeshPreauthLimitsTokenDelivery(t *testing.T) {
	f := newMeshFixtureOn(t, testPool(t), true, func(d *api.MeshDeps) {
		frozen := time.Now()
		d.PreauthLimit = api.CatalogLimit{PerMinute: 1, Burst: 2, Now: func() time.Time { return frozen }}
	})
	ws := uuid.New()
	secret := "token-signing-" + uuid.NewString()
	f.peer = meshPeer
	f.handshakeBound(ws, secret)
	now := time.Now()

	f.peer = attackerPeer
	forged := "forged-" + uuid.NewString()
	for i, d := range []struct {
		ws   uuid.UUID
		want int
	}{{uuid.New(), http.StatusUnauthorized}, {ws, http.StatusUnauthorized}, {uuid.New(), http.StatusTooManyRequests}, {ws, http.StatusTooManyRequests}} {
		rec := f.deliver(d.ws, forged, "ext_forged", now)
		if rec.Code != d.want {
			t.Fatalf("forged delivery %d: status %d, want %d", i, rec.Code, d.want)
		}
		if d.want == http.StatusTooManyRequests && rec.Header().Get("Retry-After") == "" {
			t.Fatalf("forged delivery %d: 429 without Retry-After", i)
		}
	}

	f.peer = meshPeer
	for i := 0; i < 3; i++ {
		token := "ext_rotated_" + strconv.Itoa(i)
		if rec := f.deliver(ws, secret, token, now.Add(time.Duration(i+1)*time.Second)); rec.Code != http.StatusOK {
			t.Fatalf("signed delivery %d of 3 over a budget of 2: status %d", i, rec.Code)
		}
		if got, err := f.gateToken(ws); err != nil || got != token {
			t.Fatalf("gate token after delivery %d: match %v, err %v", i, got == token, err)
		}
	}
	// The signed deliveries left the address's budget whole: two refusals,
	// then the limit.
	for i, want := range []int{http.StatusUnauthorized, http.StatusUnauthorized, http.StatusTooManyRequests} {
		if rec := f.deliver(ws, forged, "ext_forged", now); rec.Code != want {
			t.Fatalf("forged delivery %d from Mesh's address: status %d, want %d", i, rec.Code, want)
		}
	}
}

// KEEP_TRUSTED_PROXIES reaches the Mesh routes.
func TestMeshDepsCarryTrustedProxies(t *testing.T) {
	f := newMeshFixture(t, true)
	want := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	d := meshDeps(config.Config{MeshExtension: true, TrustedProxies: want}, f.pool, f.local, f.outcomes, nil, audit.NewJournal(f.pool), f.logger)
	if len(d.TrustedProxies) != 1 || d.TrustedProxies[0] != want[0] {
		t.Fatalf("trusted proxies = %v, want %v", d.TrustedProxies, want)
	}
}
