package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/api"
	"github.com/entire-vc/evc-keep/internal/meshext"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// meshTokenRequest is the body Mesh sends to token_path: the workspace and the
// actor token, signed like the install handshake but with the events secret
// already bound to the workspace.
type meshTokenRequest struct {
	ExtensionID    string    `json:"extension_id"`
	WorkspaceID    uuid.UUID `json:"workspace_id"`
	ExtensionToken string    `json:"extension_token"`
}

func meshTokenBody(ws uuid.UUID, ext, token string) []byte {
	b, _ := json.Marshal(meshTokenRequest{ExtensionID: ext, WorkspaceID: ws, ExtensionToken: token})
	return b
}

// deliverSigned sends body to POST /mesh/token the way Mesh does: no
// Authorization, the timestamp and signature headers, signed with signer.
func (f *meshFixture) deliverSigned(body []byte, signer string, ts time.Time) *httptest.ResponseRecorder {
	tsStr := strconv.FormatInt(ts.Unix(), 10)
	return f.post("/mesh/token", "", body, map[string]string{
		"Content-Type": "application/json", "User-Agent": "evc-mesh-extension/1.0",
		"X-Mesh-Timestamp": tsStr, "X-Mesh-Signature": meshSign(signer, tsStr, body),
	})
}

// deliver is a well-formed delivery of token for ws, signed at ts.
func (f *meshFixture) deliver(ws uuid.UUID, secret, token string, ts time.Time) *httptest.ResponseRecorder {
	return f.deliverSigned(meshTokenBody(ws, "keep", token), secret, ts)
}

// handshakeBound connects ws through Mesh's install handshake with secret as
// its events secret, the way a production installation is made: no actor
// token is sealed.
func (f *meshFixture) handshakeBound(ws uuid.UUID, secret string) {
	f.t.Helper()
	f.mustOpenWindow(ws, secret)
	if rec := f.handshake(ws, secret); rec.Code != http.StatusOK {
		f.t.Fatalf("handshake: status %d, body of %d bytes", rec.Code, rec.Body.Len())
	}
}

// gateToken is what the gate reads for ws with KEEP_MESH_WORKSPACE_ID: the
// real installation record and the real vault.
func (f *meshFixture) gateToken(ws uuid.UUID) (string, error) {
	src := vaultGateToken{installs: f.repo, vault: f.local.MeshVault(), workspace: ws, meshURL: "https://mesh.example.test"}
	return src.Token(context.Background())
}

func wantStatus(t *testing.T, rec *httptest.ResponseRecorder, want int, what string) {
	t.Helper()
	if rec.Code != want {
		// The body is not printed: a failing leak test must not echo the
		// token it found.
		t.Fatalf("%s: status %d, want %d, body of %d bytes", what, rec.Code, want, rec.Body.Len())
	}
}

// Leak test (written before the feature): the actor token Mesh delivers is on
// no surface — response, headers, log, audit journal, metadata tables, sealed
// storage — in any outcome: a delivery, a rotation, and every refusal. The
// gate still reads it back, so the delivery really happened.
func TestMeshTokenDeliveryNeverLeaks(t *testing.T) {
	f := newMeshFixture(t, true)
	c := canary.New()
	if !c.In(strings.ToUpper(c.Value(3))) || !c.In("x"+c.Value(1)+"x") {
		t.Fatal("canary detector is blind; the test proves nothing")
	}
	secret, other := "s3cr3t-"+strings.Repeat("a", 40), "0th3r-"+strings.Repeat("b", 40)
	tok1, tok2 := c.Value(1), c.Value(2)
	ws := uuid.New()
	var answers []string
	collect := func(want int, rec *httptest.ResponseRecorder, what string) {
		t.Helper()
		wantStatus(t, rec, want, what)
		answers = append(answers, rec.Body.String(), headersText(rec))
	}
	now := time.Now()

	collect(http.StatusUnauthorized, f.deliver(ws, secret, tok1, now), "not connected")
	f.handshakeBound(ws, secret)
	collect(http.StatusUnauthorized, f.deliver(ws, other, tok1, now), "wrong key")
	collect(http.StatusUnauthorized, f.deliver(ws, secret, tok1, now.Add(-time.Hour)), "stale timestamp")
	collect(http.StatusUnauthorized, f.deliverSigned(meshTokenBody(ws, "vault", tok1), secret, now), "foreign extension")
	collect(http.StatusUnauthorized, f.deliver(ws, secret, tok1+strings.Repeat("t", 4096), now), "token too long")
	collect(http.StatusUnauthorized, f.deliver(ws, secret, tok1+strings.Repeat("t", 70<<10), now), "body over the limit")
	collect(http.StatusOK, f.deliver(ws, secret, tok1, now.Add(-2*time.Second)), "delivery")
	collect(http.StatusOK, f.deliver(ws, secret, tok2, now), "rotation")
	collect(http.StatusUnauthorized, f.deliver(ws, secret, tok1, now.Add(-time.Second)), "replay of an older delivery")

	// A throttled delivery: a frozen clock and a one-token budget the
	// handshake spends.
	frozen := time.Now()
	g := newMeshFixtureOn(t, f.pool, true, func(d *api.MeshDeps) {
		d.ResolveLimit = api.CatalogLimit{PerMinute: 1, Burst: 1, Now: func() time.Time { return frozen }}
	})
	gws := uuid.New()
	g.handshakeBound(gws, secret)
	collect(http.StatusUnauthorized, g.deliver(gws, secret, tok1, now), "throttled")

	got, err := f.gateToken(ws)
	if err != nil || got != tok2 {
		t.Fatalf("gate token after rotation: match %v, err %v", got == tok2, err)
	}
	if f.logbuf.Len() == 0 || g.logbuf.Len() == 0 {
		t.Fatal("logger captured nothing; the log check proves nothing")
	}
	for i, s := range append(append(answers, g.logbuf.String()), f.surfaces()...) {
		if c.In(s) {
			t.Fatalf("actor token leaked on surface #%d (%d bytes); the surface is not printed", i, len(s))
		}
	}
}

// Every outcome of POST /mesh/token on the real database and the real vault:
// the token is sealed for its installation only, a newer delivery replaces
// it, and every refusal is the same 401 that changes nothing the gate reads.
func TestMeshTokenDeliveryOutcomes(t *testing.T) {
	f := newMeshFixture(t, true)
	ctx := context.Background()
	secretA, secretB := "a-signing-"+strings.Repeat("1", 40), "b-signing-"+strings.Repeat("2", 40)
	wsA, wsB := uuid.New(), uuid.New()
	now := time.Now()

	// A workspace Keep does not hold gets the same 401 as a bad signature.
	wantStatus(t, f.deliver(wsA, secretA, "ext_first", now), http.StatusUnauthorized, "not connected")
	f.handshakeBound(wsA, secretA)
	f.handshakeBound(wsB, secretB)
	if _, err := f.gateToken(wsA); !errors.Is(err, ErrGateToken) {
		t.Fatalf("handshake alone sealed a token: err %v", err)
	}

	unchanged := func(what string, want string) {
		t.Helper()
		got, err := f.gateToken(wsA)
		if want == "" {
			if !errors.Is(err, ErrGateToken) {
				t.Fatalf("%s: a token appeared (err %v)", what, err)
			}
			return
		}
		if err != nil || got != want {
			t.Fatalf("%s: gate token changed (match %v, err %v)", what, got == want, err)
		}
	}
	refusals := []struct {
		name string
		rec  func() *httptest.ResponseRecorder
	}{
		{"key of another workspace", func() *httptest.ResponseRecorder { return f.deliver(wsA, secretB, "ext_bad", now) }},
		{"handshake secret of nobody", func() *httptest.ResponseRecorder {
			return f.deliver(wsA, "nobody-"+strings.Repeat("9", 40), "ext_bad", now)
		}},
		{"stale timestamp", func() *httptest.ResponseRecorder { return f.deliver(wsA, secretA, "ext_bad", now.Add(-10*time.Minute)) }},
		{"future timestamp", func() *httptest.ResponseRecorder { return f.deliver(wsA, secretA, "ext_bad", now.Add(10*time.Minute)) }},
		{"foreign extension", func() *httptest.ResponseRecorder {
			return f.deliverSigned(meshTokenBody(wsA, "vault", "ext_bad"), secretA, now)
		}},
		{"empty token", func() *httptest.ResponseRecorder { return f.deliver(wsA, secretA, "", now) }},
		{"token too long", func() *httptest.ResponseRecorder {
			return f.deliver(wsA, secretA, strings.Repeat("t", 4097), now)
		}},
		{"signature over another body", func() *httptest.ResponseRecorder {
			tsStr := strconv.FormatInt(now.Unix(), 10)
			return f.post("/mesh/token", "", meshTokenBody(wsA, "keep", "ext_bad"), map[string]string{
				"X-Mesh-Timestamp": tsStr, "X-Mesh-Signature": meshSign(secretA, tsStr, meshTokenBody(wsA, "keep", "ext_other")),
			})
		}},
		{"no signature", func() *httptest.ResponseRecorder {
			return f.post("/mesh/token", "", meshTokenBody(wsA, "keep", "ext_bad"), map[string]string{
				"X-Mesh-Timestamp": strconv.FormatInt(now.Unix(), 10),
			})
		}},
	}
	for _, rc := range refusals {
		wantStatus(t, rc.rec(), http.StatusUnauthorized, rc.name)
		unchanged(rc.name, "")
	}
	// Plain HTTP is refused before anything is read.
	tsStr := strconv.FormatInt(now.Unix(), 10)
	body := meshTokenBody(wsA, "keep", "ext_bad")
	if rec := f.send("/mesh/token", "", body, map[string]string{"X-Mesh-Timestamp": tsStr, "X-Mesh-Signature": meshSign(secretA, tsStr, body)}, false); rec.Code == http.StatusOK {
		t.Fatalf("delivery over plain HTTP accepted")
	}
	unchanged("plain HTTP", "")

	// The delivery is sealed for its own installation, and only there.
	wantStatus(t, f.deliver(wsA, secretA, "ext_first", now.Add(-3*time.Second)), http.StatusOK, "delivery")
	unchanged("after delivery", "ext_first")
	if _, err := f.gateToken(wsB); !errors.Is(err, ErrGateToken) {
		t.Fatalf("token of workspace A is readable as workspace B: err %v", err)
	}
	if n := f.count(`SELECT count(*) FROM keep_envelope WHERE name=$1`, "mesh/"+wsA.String()+"/extension_token"); n != 1 {
		t.Fatalf("sealed versions at the installation's path = %d, want 1", n)
	}

	// A newer delivery replaces the token; an older or equal one is a replay.
	wantStatus(t, f.deliver(wsA, secretA, "ext_second", now.Add(-time.Second)), http.StatusOK, "rotation")
	unchanged("after rotation", "ext_second")
	wantStatus(t, f.deliver(wsA, secretA, "ext_first", now.Add(-2*time.Second)), http.StatusUnauthorized, "older replay")
	wantStatus(t, f.deliver(wsA, secretA, "ext_first", now.Add(-time.Second)), http.StatusUnauthorized, "same-second replay")
	unchanged("after replay", "ext_second")

	// Workspace B's own delivery does not touch A.
	wantStatus(t, f.deliver(wsB, secretB, "ext_of_b", now), http.StatusOK, "delivery to B")
	unchanged("after B's delivery", "ext_second")
	if got, err := f.gateToken(wsB); err != nil || got != "ext_of_b" {
		t.Fatalf("gate token of B: match %v, err %v", got == "ext_of_b", err)
	}

	// The journal holds each accepted delivery with a fingerprint and the
	// length, and each authenticated refusal: the foreign extension, the empty
	// and the oversized token, and the two replays.
	var ok, refused int
	if err := f.pool.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE result_status='ok' AND result_fingerprint LIKE 'kfp1:%' AND result_length IN (9, 10)),
		count(*) FILTER (WHERE result_status='failed')
		FROM audit_records WHERE action='mesh.token' AND actor_id=$1`, wsA.String()).Scan(&ok, &refused); err != nil {
		t.Fatalf("journal: %v", err)
	}
	if ok != 2 || refused != 5 {
		t.Fatalf("journal of A: ok with fingerprint %d (want 2), refused %d (want 5)", ok, refused)
	}
}

// A delivery the journal does not hold is not acknowledged: Mesh delivers
// again with a new timestamp and the token is still the one it sent.
func TestMeshTokenNoAcknowledgementWithoutAuditRecord(t *testing.T) {
	f := newMeshFixture(t, true)
	secret := "j-signing-" + strings.Repeat("3", 40)
	ws := uuid.New()
	f.handshakeBound(ws, secret)
	f.refuseAudit("mesh.token", "ok")
	now := time.Now()
	wantStatus(t, f.deliver(ws, secret, "ext_unjournaled", now.Add(-time.Second)), http.StatusServiceUnavailable, "journal refused")
	f.dropAuditRefusal()
	wantStatus(t, f.deliver(ws, secret, "ext_unjournaled", now), http.StatusOK, "retry")
	if got, err := f.gateToken(ws); err != nil || got != "ext_unjournaled" {
		t.Fatalf("gate token after retry: match %v, err %v", got == "ext_unjournaled", err)
	}

	// An authenticated refusal the journal does not hold, a replay or a
	// signed body Keep refuses, is not answered as a plain refusal either.
	f.refuseAudit("mesh.token", "failed")
	wantStatus(t, f.deliver(ws, secret, "ext_replayed", now), http.StatusServiceUnavailable, "unjournaled replay")
	wantStatus(t, f.deliverSigned(meshTokenBody(ws, "vault", "ext_foreign"), secret, now.Add(time.Second)), http.StatusServiceUnavailable, "unjournaled foreign extension")
	wantStatus(t, f.deliver(ws, secret, "", now.Add(time.Second)), http.StatusServiceUnavailable, "unjournaled empty token")
	f.dropAuditRefusal()
	wantStatus(t, f.deliver(ws, secret, "ext_replayed", now), http.StatusUnauthorized, "journaled replay")
	if got, err := f.gateToken(ws); err != nil || got != "ext_unjournaled" {
		t.Fatalf("gate token after replays: match %v, err %v", got == "ext_unjournaled", err)
	}
}

// Every refusal is the same 401, a body over the limit and a throttled
// delivery included: the answer tells a caller nothing but "no". The
// pre-authentication limit's 429 is outside this contract: its bucket is keyed
// on the client address alone and spent before the body is read, so it answers
// alike for any workspace and any signature (TestMeshPreauthLimitsTokenDelivery).
func TestMeshTokenRefusalsShareOneAnswer(t *testing.T) {
	f := newMeshFixture(t, true)
	secret := "r-signing-" + strings.Repeat("4", 40)
	ws := uuid.New()
	f.handshakeBound(ws, secret)
	now := time.Now()
	huge := meshTokenBody(ws, "keep", strings.Repeat("t", 70<<10))
	wantStatus(t, f.deliverSigned(huge, secret, now), http.StatusUnauthorized, "body over the limit")

	// A frozen clock and a one-token budget: the handshake spends it, so the
	// delivery right after it is throttled.
	frozen := time.Now()
	g := newMeshFixtureOn(t, f.pool, true, func(d *api.MeshDeps) {
		d.ResolveLimit = api.CatalogLimit{PerMinute: 1, Burst: 1, Now: func() time.Time { return frozen }}
	})
	gws := uuid.New()
	g.handshakeBound(gws, secret)
	wantStatus(t, g.deliver(gws, secret, "ext_throttled", now), http.StatusUnauthorized, "throttled delivery")
	if _, err := g.gateToken(gws); !errors.Is(err, ErrGateToken) {
		t.Fatalf("throttled delivery sealed a token: err %v", err)
	}
}

// Bad signatures do not spend the workspace's budget: a caller who knows the
// workspace id but not its key cannot hold off the next rotation.
func TestMeshTokenBadSignaturesDoNotSpendTheBudget(t *testing.T) {
	f := newMeshFixture(t, true)
	secret := "t-signing-" + strings.Repeat("5", 40)
	// A frozen clock and a two-token budget: the handshake spends one, so one
	// delivery is left.
	frozen := time.Now()
	g := newMeshFixtureOn(t, f.pool, true, func(d *api.MeshDeps) {
		d.ResolveLimit = api.CatalogLimit{PerMinute: 1, Burst: 2, Now: func() time.Time { return frozen }}
	})
	ws := uuid.New()
	g.handshakeBound(ws, secret)
	now := time.Now()
	forged := "forged-" + strings.Repeat("8", 40)
	for i := 0; i < 5; i++ {
		wantStatus(t, g.deliver(ws, forged, "ext_forged", now), http.StatusUnauthorized, "forged delivery")
	}
	wantStatus(t, g.deliver(ws, secret, "ext_after_forgeries", now), http.StatusOK, "signed delivery after forgeries")
	if got, err := g.gateToken(ws); err != nil || got != "ext_after_forgeries" {
		t.Fatalf("gate token after forgeries: match %v, err %v", got == "ext_after_forgeries", err)
	}
	// The budget still binds signed deliveries.
	wantStatus(t, g.deliver(ws, secret, "ext_throttled", now.Add(time.Second)), http.StatusUnauthorized, "signed delivery over the budget")
	if got, err := g.gateToken(ws); err != nil || got != "ext_after_forgeries" {
		t.Fatalf("throttled delivery changed the gate token: match %v, err %v", got == "ext_after_forgeries", err)
	}
}

// The replay guard is committed before the token is sealed: a seal that
// fails still spends its timestamp, so no sealed token sits behind a guard
// that rolled back. Deliveries for one installation seal one at a time.
func TestMeshTokenGuardCommitsBeforeSeal(t *testing.T) {
	f := newMeshFixture(t, true)
	ctx := context.Background()
	ws := uuid.New()
	f.handshakeBound(ws, "g-signing-"+strings.Repeat("5", 40))
	org, found, err := f.repo.Owner(ctx, ws)
	if err != nil || !found {
		t.Fatalf("owner: found %v, err %v", found, err)
	}
	ts := time.Now().Unix()
	boom := errors.New("seal failed")
	if err := f.repo.AcceptToken(ctx, ws, org, ts, func(context.Context) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("failing seal: err %v, want the seal's error", err)
	}
	if err := f.repo.AcceptToken(ctx, ws, org, ts, func(context.Context) error { return nil }); !errors.Is(err, meshext.ErrStaleToken) {
		t.Fatalf("a failed seal left its timestamp reusable: err %v", err)
	}

	entered, release := make(chan struct{}), make(chan struct{})
	first, second := make(chan error, 1), make(chan error, 1)
	go func() {
		first <- f.repo.AcceptToken(ctx, ws, org, ts+1, func(context.Context) error { close(entered); <-release; return nil })
	}()
	<-entered
	var sealedSecond atomic.Bool
	go func() {
		second <- f.repo.AcceptToken(ctx, ws, org, ts+2, func(context.Context) error { sealedSecond.Store(true); return nil })
	}()
	time.Sleep(300 * time.Millisecond)
	overlapped := sealedSecond.Load()
	close(release)
	if err := <-first; err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	if err := <-second; err != nil || !sealedSecond.Load() {
		t.Fatalf("second delivery: sealed %v, err %v", sealedSecond.Load(), err)
	}
	if overlapped {
		t.Fatal("a second delivery sealed while the first was still sealing")
	}
}

// Deliveries waiting for the workspace lock cannot exhaust the pool: on a
// two-connection pool, two deliveries queue behind a lock held elsewhere, and
// once it is released both finish, each sealing on a connection of the same
// pool. Holding a connection per waiter and asking for a second one to record
// the delivery would hang here until the deadline.
func TestMeshTokenWaitingDeliveriesDoNotExhaustThePool(t *testing.T) {
	f := newMeshFixture(t, true)
	ctx := context.Background()
	ws := uuid.New()
	f.handshakeBound(ws, "p-signing-"+strings.Repeat("6", 40))
	org, found, err := f.repo.Owner(ctx, ws)
	if err != nil || !found {
		t.Fatalf("owner: found %v, err %v", found, err)
	}
	cfg := f.pool.Config().Copy()
	cfg.MaxConns = 2
	small, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("small pool: %v", err)
	}
	defer small.Close()
	repo := meshext.NewRepo(small)

	held, err := f.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer held.Release()
	lockSQL := `SELECT pg_advisory_lock(hashtextextended('mesh-install:' || $1::text, 0))`
	if _, err := held.Exec(ctx, lockSQL, ws.String()); err != nil {
		t.Fatalf("hold the workspace lock: %v", err)
	}

	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	seal := func(ctx context.Context) error {
		_, err := small.Exec(ctx, `SELECT 1`)
		return err
	}
	ts := time.Now().Unix()
	done := make(chan error, 2)
	for i := int64(1); i <= 2; i++ {
		go func() { done <- repo.AcceptToken(dctx, ws, org, ts+i, seal) }()
	}
	for small.Stat().AcquiredConns() == 0 {
		if dctx.Err() != nil {
			t.Fatal("no delivery reached the lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	if _, err := held.Exec(ctx, `SELECT pg_advisory_unlock(hashtextextended('mesh-install:' || $1::text, 0))`, ws.String()); err != nil {
		t.Fatalf("release the workspace lock: %v", err)
	}
	for range 2 {
		// Deliveries can finish in either order; the later-signed one
		// first makes the other stale, which is still a finish.
		if err := <-done; err != nil && !errors.Is(err, meshext.ErrStaleToken) {
			t.Fatalf("a delivery did not finish: %v", err)
		}
	}
}

// A failed reinstall cannot roll back a token delivered while it ran: the
// reinstall writes the token slot and restores it on failure, so a delivery
// waits for it under the same workspace lock. The reinstall here stops in
// its last step, the installation row, until a signed delivery has arrived,
// then fails; the gate reads the delivered token, not the restored one.
func TestMeshTokenDeliveryWaitsForFailingReinstall(t *testing.T) {
	ctx := context.Background()
	// The handlers run on a pool as small as a CI runner's default; the
	// test's own gate and probes use a pool of their own, so they never
	// take a connection the reinstall or the delivery is waiting for.
	aux := testPool(t)
	cfg := aux.Config().Copy()
	cfg.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	// Registered before the fixture's cleanups, so it runs after them.
	t.Cleanup(pool.Close)
	f := newMeshFixtureOn(t, pool, true)
	ws := uuid.New()
	oldSecret, newSecret := "events-old-"+uuid.NewString(), "events-new-"+uuid.NewString()
	installedKeepSecret(t, f.install(f.admin, ws, "tok-old", oldSecret))

	// The installation-row write of the reinstall blocks on gateKey, then
	// fails. A BEFORE INSERT trigger fires before the upsert locks the row,
	// so a delivery's update of the row is not held up by it.
	conn, err := aux.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	gateKey := "mesh-test-gate:" + ws.String()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended($1, 0))`, gateKey); err != nil {
		t.Fatal(err)
	}
	suffix := strings.ReplaceAll(ws.String(), "-", "")
	fn, trg := "mesh_test_gate_"+suffix, "mesh_test_gate_"+suffix
	if _, err := aux.Exec(ctx, `CREATE FUNCTION `+fn+`() RETURNS trigger AS $$ BEGIN
PERFORM pg_advisory_lock(hashtextextended('`+gateKey+`', 0));
PERFORM pg_advisory_unlock(hashtextextended('`+gateKey+`', 0));
RAISE EXCEPTION 'injected'; END $$ LANGUAGE plpgsql`); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = aux.Exec(ctx, `DROP FUNCTION IF EXISTS `+fn+`()`) }()
	if _, err := aux.Exec(ctx, `CREATE TRIGGER `+trg+` BEFORE INSERT ON mesh_installations FOR EACH ROW WHEN (NEW.workspace_id = '`+ws.String()+`') EXECUTE FUNCTION `+fn+`()`); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = aux.Exec(ctx, `DROP TRIGGER IF EXISTS `+trg+` ON mesh_installations`) }()
	// Opened before the trigger is dropped: the drop waits for a gated insert.
	gated := true
	openGate := func() {
		if gated {
			gated = false
			_, _ = conn.Exec(ctx, `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, gateKey)
		}
	}
	defer openGate()

	// waiting reports whether a session waits for the advisory lock key.
	waiting := func(key string) bool {
		var n int
		_ = aux.QueryRow(ctx, `SELECT count(*) FROM pg_locks l, (SELECT hashtextextended($1, 0) AS k) h
 WHERE l.locktype = 'advisory' AND NOT l.granted AND l.objsubid = 1
   AND ((l.classid::bigint << 32) | l.objid::bigint) = h.k`, key).Scan(&n)
		return n > 0
	}
	deadline := time.Now().Add(10 * time.Second)
	reinstall := make(chan *httptest.ResponseRecorder, 1)
	go func() { reinstall <- f.install(f.admin, ws, "tok-reinstall", newSecret) }()
	for !waiting(gateKey) {
		if time.Now().After(deadline) {
			t.Fatal("the reinstall did not reach its installation-row write")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Mid-reinstall the workspace's events secret is the reinstall's.
	delivered := make(chan *httptest.ResponseRecorder, 1)
	go func() { delivered <- f.deliver(ws, newSecret, "tok-delivered", time.Now()) }()
	var early *httptest.ResponseRecorder
	for early == nil && !waiting(workspaceLockKey(ws)) {
		select {
		case early = <-delivered:
		case <-time.After(10 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("the delivery neither finished nor waited for the workspace lock")
		}
	}
	openGate()
	select {
	case rec := <-reinstall:
		wantStatus(t, rec, http.StatusInternalServerError, "gated reinstall")
	case <-time.After(10 * time.Second):
		t.Fatal("the reinstall did not finish")
	}
	if early == nil {
		select {
		case early = <-delivered:
		case <-time.After(10 * time.Second):
			t.Fatal("the delivery did not finish after the reinstall")
		}
	}
	wantStatus(t, early, http.StatusOK, "delivery during the reinstall")
	got, err := f.gateToken(ws)
	if err != nil || got != "tok-delivered" {
		t.Fatalf("gate token after the failed reinstall: delivered %v, restored %v, err %v", got == "tok-delivered", got == "tok-old", err)
	}
}

// workspaceLockKey is the advisory lock text meshext takes for ws.
func workspaceLockKey(ws uuid.UUID) string { return "mesh-install:" + ws.String() }
