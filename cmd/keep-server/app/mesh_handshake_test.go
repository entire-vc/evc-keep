package app

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/api"
	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/config"
	"github.com/entire-vc/evc-keep/internal/meshext"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// meshInstallRequest is a copy of installRequest in evc-mesh
// internal/extensions/external/handshake.go: same fields, same order, same
// tags, so json.Marshal gives the bytes Mesh sends.
type meshInstallRequest struct {
	ExtensionID   string    `json:"extension_id"`
	Version       string    `json:"version"`
	WorkspaceID   uuid.UUID `json:"workspace_id"`
	SigningSecret string    `json:"signing_secret"`
	Events        []string  `json:"events"`
	EventsPath    string    `json:"events_path"`
}

// meshSign is Sign() of evc-mesh, written independently of the server code:
// hex HMAC-SHA256 of "{timestamp}.{body}", no prefix.
func meshSign(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp + "."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// meshSecretSHA256 is what the admin gives when opening a window: the full
// SHA-256 of the signing secret in lowercase hex.
func meshSecretSHA256(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func meshHandshakeBody(ws uuid.UUID, ext, secret string) []byte {
	b, _ := json.Marshal(meshInstallRequest{
		ExtensionID: ext, Version: "1.0.0", WorkspaceID: ws, SigningSecret: secret,
		Events:     []string{"workspace.member.added", "project.created", "task.gate.decided"},
		EventsPath: "/mesh/events",
	})
	return b
}

// handshakeSigned sends body the way Mesh's Handshaker.install does: no
// Authorization, the timestamp and signature headers, signed with signer.
func (f *meshFixture) handshakeSigned(body []byte, signer string, ts time.Time) *httptest.ResponseRecorder {
	tsStr := strconv.FormatInt(ts.Unix(), 10)
	return f.post("/mesh/install", "", body, map[string]string{
		"Content-Type": "application/json", "User-Agent": "evc-mesh-extension/1.0",
		"X-Mesh-Timestamp": tsStr, "X-Mesh-Signature": meshSign(signer, tsStr, body),
	})
}

// handshake is a well-formed Mesh install of secret for ws.
func (f *meshFixture) handshake(ws uuid.UUID, secret string) *httptest.ResponseRecorder {
	return f.handshakeSigned(meshHandshakeBody(ws, "keep", secret), secret, time.Now())
}

func (f *meshFixture) openWindow(bearer string, ws uuid.UUID, digest string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(map[string]string{"workspace_id": ws.String(), "mesh_url": "https://mesh.example.test", "signing_secret_sha256": digest})
	return f.post("/orgs/"+f.org.ID.String()+"/mesh/pending-installs", bearer, b, nil)
}

func (f *meshFixture) mustOpenWindow(ws uuid.UUID, secret string) {
	f.t.Helper()
	if rec := f.openWindow(f.admin, ws, meshSecretSHA256(secret)); rec.Code != http.StatusCreated {
		f.t.Fatalf("open window: status %d, body %s", rec.Code, answerDiag(rec))
	}
}

func (f *meshFixture) count(q string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		f.t.Fatalf("%s: %v", q, err)
	}
	return n
}

func (f *meshFixture) expireWindow(ws uuid.UUID) {
	f.t.Helper()
	if _, err := f.pool.Exec(context.Background(), `UPDATE mesh_pending_installs SET expires_at = now() - interval '1 minute' WHERE workspace_id=$1`, ws); err != nil {
		f.t.Fatalf("expire window: %v", err)
	}
}

// Leak test (written before the feature): the signing secret Mesh sends in
// the install handshake is on no surface — response, headers, log, audit
// journal, metadata tables, the pending window — in any outcome: the binding,
// a repeat, and every refusal. Neither is the SHA-256 the admin gave for the
// window: it lives only in the window row, which is gone once spent or expired.
func TestMeshHandshakeSecretNeverLeaks(t *testing.T) {
	f := newMeshFixture(t, true)
	c := canary.New()
	if !c.In(hex.EncodeToString([]byte(c.Value(1)))) || !c.In("x"+c.Value(1)) {
		t.Fatal("canary detector is blind; the test proves nothing")
	}
	secret, other := c.Value(1), c.Value(2)
	// digestIn finds the window digest of either secret, whole or cut down
	// to its first 8 bytes: hex in either case, and base64 (standard or URL
	// alphabet; a padded form contains the unpadded one).
	digestIn := func(s string) bool {
		lower := strings.ToLower(s)
		for _, v := range []string{secret, other} {
			sum := sha256.Sum256([]byte(v))
			if strings.Contains(lower, hex.EncodeToString(sum[:8])) ||
				strings.Contains(s, base64.RawStdEncoding.EncodeToString(sum[:9])) ||
				strings.Contains(s, base64.RawURLEncoding.EncodeToString(sum[:9])) {
				return true
			}
		}
		return false
	}
	for _, probe := range []func([]byte) string{
		hex.EncodeToString, func(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) },
		base64.StdEncoding.EncodeToString, base64.RawStdEncoding.EncodeToString, base64.RawURLEncoding.EncodeToString,
		func(b []byte) string { return hex.EncodeToString(b)[:16] },
	} {
		sum := sha256.Sum256([]byte(other))
		if !digestIn("x" + probe(sum[:]) + "x") {
			t.Fatal("digest detector is blind to one encoding; the test proves nothing")
		}
	}
	ws := uuid.New()
	var surfaces []string
	collect := func(want int, rec *httptest.ResponseRecorder) {
		t.Helper()
		if rec.Code != want {
			t.Fatalf("status = %d, want %d, body %s", rec.Code, want, answerDiag(rec))
		}
		surfaces = append(surfaces, rec.Body.String())
		for k, v := range rec.Header() {
			surfaces = append(surfaces, k+": "+strings.Join(v, ","))
		}
	}

	// Refusals before any window: no window, then a window for another secret.
	collect(http.StatusUnauthorized, f.handshake(ws, secret))
	collect(http.StatusCreated, f.openWindow(f.admin, ws, meshSecretSHA256(other)))
	collect(http.StatusUnauthorized, f.handshake(ws, secret)) // fp does not match
	collect(http.StatusCreated, f.openWindow(f.admin, ws, meshSecretSHA256(secret)))
	// Positive control: the digest detector sees the open window's row.
	var row string
	if err := f.pool.QueryRow(context.Background(), `SELECT row_to_json(t)::text FROM mesh_pending_installs t WHERE workspace_id=$1`, ws).Scan(&row); err != nil || !digestIn(row) {
		t.Fatalf("digest detector is blind to the open window (err %v)", err)
	}
	body := meshHandshakeBody(ws, "keep", secret)
	collect(http.StatusUnauthorized, f.handshakeSigned(body, other, time.Now()))                  // bad signature
	collect(http.StatusUnauthorized, f.handshakeSigned(body, secret, time.Now().Add(-time.Hour))) // stale timestamp
	ext := meshHandshakeBody(ws, "vault", secret)
	collect(http.StatusUnauthorized, f.handshakeSigned(ext, secret, time.Now())) // foreign extension
	f.expireWindow(ws)
	collect(http.StatusUnauthorized, f.handshake(ws, secret)) // window expired

	// Binding, repeat, and another secret after the binding.
	collect(http.StatusCreated, f.openWindow(f.admin, ws, meshSecretSHA256(secret)))
	collect(http.StatusOK, f.handshake(ws, secret))
	collect(http.StatusOK, f.handshake(ws, secret))
	collect(http.StatusUnauthorized, f.handshake(ws, other))

	ctx := context.Background()
	for _, q := range []string{
		`SELECT row_to_json(t)::text FROM mesh_installations t`,
		`SELECT row_to_json(t)::text FROM mesh_pending_installs t`,
		`SELECT row_to_json(t)::text FROM audit_records t`,
	} {
		rows, err := f.pool.Query(ctx, q)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			surfaces = append(surfaces, s)
		}
		rows.Close()
	}
	if f.logbuf.Len() == 0 {
		t.Fatal("logger captured nothing; the log check proves nothing")
	}
	for i, s := range append(surfaces, f.logbuf.String()) {
		if c.In(s) {
			t.Fatalf("signing secret leaked on surface #%d (%d bytes); the surface is not printed", i, len(s))
		}
		if digestIn(s) {
			t.Fatalf("window digest leaked on surface #%d (%d bytes); the surface is not printed", i, len(s))
		}
	}
}

// Every outcome of the Mesh flow of POST /mesh/install, on the real database
// and the real vault. A refusal is the same 401 and writes nothing.
func TestMeshHandshakeOutcomes(t *testing.T) {
	f := newMeshFixture(t, true)
	c := canary.New()
	secret, other := c.Value(1), c.Value(2)
	installs := func(ws uuid.UUID) int {
		return f.count(`SELECT count(*) FROM mesh_installations WHERE workspace_id=$1`, ws)
	}
	windows := func(ws uuid.UUID) int {
		return f.count(`SELECT count(*) FROM mesh_pending_installs WHERE workspace_id=$1`, ws)
	}
	audits := func() int {
		return f.count(`SELECT count(*) FROM audit_records WHERE org_id=$1 AND action='mesh.install'`, f.org.ID.String())
	}
	deny := func(name string, rec *httptest.ResponseRecorder) {
		t.Helper()
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: status = %d, want 401, body %s", name, rec.Code, answerDiag(rec))
		}
		var e struct {
			ErrorClass string `json:"error_class"`
			Message    string `json:"message"`
		}
		if json.Unmarshal(rec.Body.Bytes(), &e) != nil || e.ErrorClass != "unauthenticated" || e.Message != "authentication failed" {
			t.Fatalf("%s: refusal is not the uniform 401: %s", name, answerDiag(rec))
		}
	}
	// eventAccepted proves the bound secret became the events secret.
	eventAccepted := func(ws uuid.UUID, s, id string) bool {
		b := eventBody(ws, id, "project.created")
		return f.post("/mesh/events", "", b, signedHeaders(ws, s, time.Now(), b)).Code == http.StatusOK
	}

	t.Run("no window", func(t *testing.T) {
		ws := uuid.New()
		deny("no window", f.handshake(ws, secret))
		if installs(ws) != 0 {
			t.Fatal("refusal wrote an installation")
		}
	})
	t.Run("digest mismatch", func(t *testing.T) {
		ws := uuid.New()
		f.mustOpenWindow(ws, other)
		deny("digest mismatch", f.handshake(ws, secret))
		if installs(ws) != 0 || windows(ws) != 1 {
			t.Fatal("digest mismatch wrote an installation or spent the window")
		}
	})
	t.Run("digest equal only in its prefix or suffix", func(t *testing.T) {
		full := meshSecretSHA256(secret)
		last := "0"
		if full[63] == '0' {
			last = "1"
		}
		for name, d := range map[string]string{
			"first 8 hex":    full[:8] + strings.Repeat("0", 56),
			"first 16 bytes": full[:32] + strings.Repeat("0", 32),
			"last hex off":   full[:63] + last,
		} {
			ws := uuid.New()
			if rec := f.openWindow(f.admin, ws, d); rec.Code != http.StatusCreated {
				t.Fatalf("%s: open window: %d", name, rec.Code)
			}
			deny(name, f.handshake(ws, secret))
			if installs(ws) != 0 || windows(ws) != 1 {
				t.Fatalf("%s: a partial digest bound the workspace or spent the window", name)
			}
		}
	})
	t.Run("expired window", func(t *testing.T) {
		ws := uuid.New()
		f.mustOpenWindow(ws, secret)
		f.expireWindow(ws)
		deny("expired", f.handshake(ws, secret))
		if installs(ws) != 0 {
			t.Fatal("expired window bound the workspace")
		}
		if windows(ws) != 0 {
			t.Fatal("an expired window (and its digest) stayed after the lookup")
		}
		// Opening any window drops every expired one, of any workspace.
		stale := uuid.New()
		f.mustOpenWindow(stale, secret)
		f.expireWindow(stale)
		f.mustOpenWindow(uuid.New(), other)
		if windows(stale) != 0 {
			t.Fatal("opening a window left another workspace's expired window")
		}
		f.mustOpenWindow(stale, secret)
		f.expireWindow(stale)
		if err := meshext.NewRepo(f.pool).DropExpiredPending(context.Background()); err != nil || windows(stale) != 0 {
			t.Fatalf("DropExpiredPending left an expired window (err %v)", err)
		}
	})
	t.Run("timestamp outside window", func(t *testing.T) {
		ws := uuid.New()
		f.mustOpenWindow(ws, secret)
		body := meshHandshakeBody(ws, "keep", secret)
		deny("stale", f.handshakeSigned(body, secret, time.Now().Add(-301*time.Second)))
		deny("future", f.handshakeSigned(body, secret, time.Now().Add(301*time.Second)))
		if installs(ws) != 0 {
			t.Fatal("stale handshake bound the workspace")
		}
		// Positive control: the same window, a fresh timestamp.
		if rec := f.handshakeSigned(body, secret, time.Now().Add(-200*time.Second)); rec.Code != http.StatusOK {
			t.Fatalf("in-window timestamp: status %d", rec.Code)
		}
	})
	t.Run("bad signature", func(t *testing.T) {
		ws := uuid.New()
		f.mustOpenWindow(ws, secret)
		body := meshHandshakeBody(ws, "keep", secret)
		deny("wrong key", f.handshakeSigned(body, other, time.Now()))
		tsStr := strconv.FormatInt(time.Now().Unix(), 10)
		deny("no signature", f.post("/mesh/install", "", body, map[string]string{"X-Mesh-Timestamp": tsStr}))
		deny("prefixed signature", f.post("/mesh/install", "", body, map[string]string{"X-Mesh-Timestamp": tsStr, "X-Mesh-Signature": "v2=" + meshSign(secret, tsStr, body)}))
		tampered := []byte(strings.Replace(string(body), `"1.0.0"`, `"1.0.1"`, 1))
		deny("tampered body", f.post("/mesh/install", "", tampered, map[string]string{"X-Mesh-Timestamp": tsStr, "X-Mesh-Signature": meshSign(secret, tsStr, body)}))
		if installs(ws) != 0 || windows(ws) != 1 {
			t.Fatal("unsigned handshake wrote or spent the window")
		}
	})
	t.Run("foreign extension and bad secret length", func(t *testing.T) {
		ws := uuid.New()
		short := secret[:31]
		f.mustOpenWindow(ws, secret)
		deny("extension", f.handshakeSigned(meshHandshakeBody(ws, "vault", secret), secret, time.Now()))
		if rec := f.openWindow(f.admin, ws, meshSecretSHA256(short)); rec.Code != http.StatusCreated {
			t.Fatalf("reopen: %d", rec.Code)
		}
		deny("short secret", f.handshakeSigned(meshHandshakeBody(ws, "keep", short), short, time.Now()))
		if installs(ws) != 0 {
			t.Fatal("refusal bound the workspace")
		}
	})
	t.Run("bind, repeat, other secret, one-shot window", func(t *testing.T) {
		ws := uuid.New()
		before := audits()
		f.mustOpenWindow(ws, secret)
		// Unknown body fields are a counterparty's addition, not an error.
		extra := []byte(strings.Replace(string(meshHandshakeBody(ws, "keep", secret)), `{`, `{"added_later":1,`, 1))
		rec := f.handshakeSigned(extra, secret, time.Now())
		if rec.Code != http.StatusOK {
			t.Fatalf("bind: status %d, body %s", rec.Code, answerDiag(rec))
		}
		var res map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil || res["ok"] != true || res["request_id"] == "" || len(res) != 2 {
			t.Fatalf("bind response is not {ok, request_id}: %s", answerDiag(rec))
		}
		if installs(ws) != 1 || windows(ws) != 0 || audits() != before+1 {
			t.Fatalf("bind: installs=%d windows=%d audits=%d (before %d)", installs(ws), windows(ws), audits(), before)
		}
		var by, org string
		if err := f.pool.QueryRow(context.Background(), `SELECT installed_by::text, org_id::text FROM mesh_installations WHERE workspace_id=$1`, ws).Scan(&by, &org); err != nil || org != f.org.ID.String() {
			t.Fatalf("installation row: org %q err %v", org, err)
		}
		// Every successful mesh.install of this org (earlier subtests bound
		// workspaces too) names the admin who opened the window.
		okAll := f.count(`SELECT count(*) FROM audit_records WHERE org_id=$1 AND action='mesh.install' AND result_status='ok'`, f.org.ID.String())
		if n := f.count(`SELECT count(*) FROM audit_records WHERE org_id=$1 AND action='mesh.install' AND result_status='ok' AND actor_id=$2`, f.org.ID.String(), by); n == 0 || n != okAll {
			t.Fatalf("mesh.install audit by the admin who opened the window: %d of %d", n, okAll)
		}
		if !eventAccepted(ws, secret, "bind-1") || eventAccepted(ws, other, "bind-2") {
			t.Fatal("the bound secret is not the events secret")
		}
		var updated time.Time
		_ = f.pool.QueryRow(context.Background(), `SELECT updated_at FROM mesh_installations WHERE workspace_id=$1`, ws).Scan(&updated)

		// Repeat with the same secret (Mesh after a restart): 200, nothing written.
		if rec := f.handshake(ws, secret); rec.Code != http.StatusOK {
			t.Fatalf("repeat: status %d", rec.Code)
		}
		var updated2 time.Time
		_ = f.pool.QueryRow(context.Background(), `SELECT updated_at FROM mesh_installations WHERE workspace_id=$1`, ws).Scan(&updated2)
		if audits() != before+1 || !updated2.Equal(updated) {
			t.Fatal("repeat wrote something")
		}
		// Another secret after the binding, with or without a fresh window.
		deny("other secret", f.handshake(ws, other))
		f.mustOpenWindow(ws, other)
		deny("other secret, new window", f.handshake(ws, other))
		if !eventAccepted(ws, secret, "bind-3") || eventAccepted(ws, other, "bind-4") || audits() != before+1 {
			t.Fatal("a refused handshake changed the events secret or wrote an audit record")
		}
	})
	t.Run("bearer flow unchanged", func(t *testing.T) {
		ws := uuid.New()
		installedKeepSecret(t, f.install(f.admin, ws, c.Value(3), c.Value(4)))
		if rec := f.install("", ws, c.Value(3), c.Value(4)); rec.Code != http.StatusUnauthorized {
			t.Fatalf("bearer-shaped body without a bearer: %d", rec.Code)
		}
	})
}

// POST /orgs/{org_id}/mesh/pending-installs: admin only, TLS only, closed
// response fields, a workspace of another organisation refused.
func TestMeshPendingInstallWindow(t *testing.T) {
	f := newMeshFixture(t, true)
	c := canary.New()
	ws := uuid.New()
	fp := meshSecretSHA256(c.Value(1))

	rec := f.openWindow(f.admin, ws, fp)
	if strings.Contains(rec.Body.String(), fp) || strings.Contains(f.logbuf.String(), fp) {
		t.Fatal("the window digest is echoed in the response or the log")
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("admin: status %d, body %s", rec.Code, answerDiag(rec))
	}
	var res map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil || len(res) != 3 || res["workspace_id"] != ws.String() || res["request_id"] == "" {
		t.Fatalf("response fields: %s", answerDiag(rec))
	}
	exp, err := time.Parse(time.RFC3339, res["expires_at"].(string))
	if err != nil || exp.Before(time.Now().Add(14*time.Minute)) || exp.After(time.Now().Add(16*time.Minute)) {
		t.Fatalf("expires_at %v is not about 15 minutes ahead", res["expires_at"])
	}
	if n := f.count(`SELECT count(*) FROM audit_records WHERE org_id=$1 AND action='mesh.install.pending' AND result_status='ok'`, f.org.ID.String()); n != 1 {
		t.Fatalf("mesh.install.pending audit: %d", n)
	}
	// Reopening replaces the window: one per workspace.
	if rec := f.openWindow(f.admin, ws, meshSecretSHA256(c.Value(2))); rec.Code != http.StatusCreated {
		t.Fatalf("reopen: %d", rec.Code)
	}
	if n := f.count(`SELECT count(*) FROM mesh_pending_installs WHERE workspace_id=$1`, ws); n != 1 {
		t.Fatalf("windows for one workspace: %d", n)
	}

	if rec := f.openWindow(f.member, uuid.New(), fp); rec.Code != http.StatusNotFound {
		t.Fatalf("member: status %d", rec.Code)
	}
	if rec := f.openWindow("", uuid.New(), fp); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no bearer: status %d", rec.Code)
	}
	b, _ := json.Marshal(map[string]string{"workspace_id": uuid.NewString(), "mesh_url": "https://mesh.example.test", "signing_secret_sha256": fp})
	if rec := f.send("/orgs/"+f.org.ID.String()+"/mesh/pending-installs", f.admin, b, nil, false); rec.Code != http.StatusNotFound {
		t.Fatalf("plain HTTP: status %d", rec.Code)
	}
	for name, body := range map[string]map[string]string{
		"sha short":   {"workspace_id": uuid.NewString(), "mesh_url": "https://mesh.example.test", "signing_secret_sha256": "abc"},
		"mesh label":  {"workspace_id": uuid.NewString(), "mesh_url": "https://mesh.example.test", "signing_secret_sha256": fp[:8]},
		"sha 63":      {"workspace_id": uuid.NewString(), "mesh_url": "https://mesh.example.test", "signing_secret_sha256": fp[:63]},
		"sha 65":      {"workspace_id": uuid.NewString(), "mesh_url": "https://mesh.example.test", "signing_secret_sha256": fp + "0"},
		"sha upper":   {"workspace_id": uuid.NewString(), "mesh_url": "https://mesh.example.test", "signing_secret_sha256": strings.ToUpper(fp)},
		"sha not hex": {"workspace_id": uuid.NewString(), "mesh_url": "https://mesh.example.test", "signing_secret_sha256": strings.Repeat("g", 64)},
		"old field":   {"workspace_id": uuid.NewString(), "mesh_url": "https://mesh.example.test", "signing_secret_fp": fp[:8]},
		"mesh_url":    {"workspace_id": uuid.NewString(), "mesh_url": "http://mesh.example.test", "signing_secret_sha256": fp},
		"workspace":   {"workspace_id": "nope", "mesh_url": "https://mesh.example.test", "signing_secret_sha256": fp},
		"no sha":      {"workspace_id": uuid.NewString(), "mesh_url": "https://mesh.example.test"},
		"the secret":  {"workspace_id": uuid.NewString(), "mesh_url": "https://mesh.example.test", "signing_secret_sha256": fp, "signing_secret": c.Value(1)},
	} {
		b, _ := json.Marshal(body)
		if rec := f.post("/orgs/"+f.org.ID.String()+"/mesh/pending-installs", f.admin, b, nil); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: status %d", name, rec.Code)
		}
	}

	// A workspace already connected to another organisation.
	g := newMeshFixtureOn(t, f.pool, true)
	taken := uuid.New()
	installedKeepSecret(t, g.install(g.admin, taken, c.Value(3), c.Value(4)))
	if rec := f.openWindow(f.admin, taken, fp); rec.Code != http.StatusConflict {
		t.Fatalf("foreign workspace: status %d", rec.Code)
	}
	// A live window of another organisation is not replaced either.
	free := uuid.New()
	if rec := g.openWindow(g.admin, free, fp); rec.Code != http.StatusCreated {
		t.Fatalf("other org window: %d", rec.Code)
	}
	if rec := f.openWindow(f.admin, free, fp); rec.Code != http.StatusConflict {
		t.Fatalf("live window of another org: status %d", rec.Code)
	}
	g.expireWindow(free)
	if rec := f.openWindow(f.admin, free, fp); rec.Code != http.StatusCreated {
		t.Fatalf("expired window of another org: status %d", rec.Code)
	}
}

// lockProbeVault writes through to the real vault, and on each write of the
// events secret of ws checks from another connection whether the window row
// is locked, i.e. whether the write runs inside the transaction spending it.
type lockProbeVault struct {
	api.MeshVault
	pool   *pgxpool.Pool
	ws     uuid.UUID
	puts   int
	locked bool
}

func (v *lockProbeVault) Put(ctx context.Context, org, workspace, kind, value string) error {
	if workspace == v.ws.String() && kind == builtin.MeshEventsSecret {
		v.puts++
		tx, err := v.pool.Begin(ctx)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `SELECT 1 FROM mesh_pending_installs WHERE workspace_id=$1 FOR UPDATE NOWAIT`, v.ws)
		var pgErr *pgconn.PgError
		v.locked = errors.As(err, &pgErr) && pgErr.Code == "55P03"
		_ = tx.Rollback(ctx)
	}
	return v.MeshVault.Put(ctx, org, workspace, kind, value)
}

// failingPutVault refuses every credential write; everything else is the
// real vault.
type failingPutVault struct{ api.MeshVault }

func (failingPutVault) Put(context.Context, string, string, string, string) error {
	return errors.New("vault write refused")
}

// The events secret is written only inside the transaction that consumes the
// window: a window that expired, was replaced or was spent before the binding
// gets no write at all, and a failed write leaves the window open and nothing
// bound.
func TestMeshHandshakeBindConsumesWindowBeforeSealing(t *testing.T) {
	f := newMeshFixture(t, true)
	ctx := context.Background()
	c := canary.New()
	secret := c.Value(1)
	stored := func(ws uuid.UUID) bool {
		_, err := f.local.MeshVault().SameEventsSecret(ctx, f.org.ID.String(), ws.String(), secret)
		return err == nil
	}
	pending := func(ws uuid.UUID) meshext.Pending {
		t.Helper()
		f.mustOpenWindow(ws, secret)
		p, live, err := f.repo.LivePending(ctx, ws)
		if err != nil || !live {
			t.Fatalf("window not live: %v", err)
		}
		return p
	}
	bind := func(ws uuid.UUID, p meshext.Pending) (bool, error) {
		sealed := false
		err := f.repo.BindPending(ctx, ws, p, meshext.ModeExtension, func(ctx context.Context) error {
			sealed = true
			return f.local.MeshVault().Put(ctx, p.Org.String(), ws.String(), builtin.MeshEventsSecret, secret)
		})
		return sealed, err
	}
	installs := func(ws uuid.UUID) int {
		return f.count(`SELECT count(*) FROM mesh_installations WHERE workspace_id=$1`, ws)
	}

	for name, spoil := range map[string]func(ws uuid.UUID){
		"expired after lookup":  f.expireWindow,
		"replaced after lookup": func(ws uuid.UUID) { f.mustOpenWindow(ws, c.Value(2)) },
		"spent after lookup": func(ws uuid.UUID) {
			if _, err := f.pool.Exec(ctx, `DELETE FROM mesh_pending_installs WHERE workspace_id=$1`, ws); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			ws := uuid.New()
			p := pending(ws)
			spoil(ws)
			// Checked without LivePending, which would delete an expired
			// window itself: here BindPending alone must refuse it.
			if n := f.count(`SELECT count(*) FROM mesh_pending_installs WHERE workspace_id=$1 AND secret_sha256=$2 AND expires_at > now()`, ws, p.SecretSHA256); n != 0 {
				t.Fatalf("the window is still live after %s", name)
			}
			sealed, err := bind(ws, p)
			if !errors.Is(err, meshext.ErrNoWindow) {
				t.Fatalf("bind = %v, want ErrNoWindow", err)
			}
			if sealed || stored(ws) || installs(ws) != 0 {
				t.Fatalf("a window gone before the binding still wrote: sealed=%v stored=%v installs=%d", sealed, stored(ws), installs(ws))
			}
		})
	}

	t.Run("live window binds once", func(t *testing.T) {
		ws := uuid.New()
		p := pending(ws)
		if sealed, err := bind(ws, p); err != nil || !sealed || !stored(ws) || installs(ws) != 1 {
			t.Fatalf("bind = %v sealed=%v stored=%v", err, sealed, stored(ws))
		}
		if sealed, err := bind(ws, p); !errors.Is(err, meshext.ErrNoWindow) || sealed {
			t.Fatalf("second bind of the same window = %v sealed=%v", err, sealed)
		}
	})

	t.Run("handler seals while the window row is being spent", func(t *testing.T) {
		v := &lockProbeVault{pool: f.pool}
		g := newMeshFixtureOn(t, f.pool, true, func(d *api.MeshDeps) { v.MeshVault = d.Vault; d.Vault = v })
		ws := uuid.New()
		v.ws = ws
		g.mustOpenWindow(ws, secret)
		if rec := g.handshake(ws, secret); rec.Code != http.StatusOK {
			t.Fatalf("bind: status %d, body %s", rec.Code, answerDiag(rec))
		}
		if v.puts != 1 || !v.locked {
			t.Fatalf("the events secret was written outside the transaction spending the window: puts=%d locked=%v", v.puts, v.locked)
		}
	})

	t.Run("failed write keeps the window and binds nothing", func(t *testing.T) {
		g := newMeshFixtureOn(t, f.pool, true, func(d *api.MeshDeps) { d.Vault = failingPutVault{d.Vault} })
		ws := uuid.New()
		g.mustOpenWindow(ws, secret)
		if rec := g.handshake(ws, secret); rec.Code != http.StatusInternalServerError {
			t.Fatalf("handshake with a failing vault: status %d", rec.Code)
		}
		if installs(ws) != 0 || g.count(`SELECT count(*) FROM mesh_pending_installs WHERE workspace_id=$1 AND expires_at > now()`, ws) != 1 {
			t.Fatal("a failed write spent the window or bound the workspace")
		}
		if rec := g.handshake(ws, secret); rec.Code != http.StatusInternalServerError {
			t.Fatalf("retry with a failing vault: status %d", rec.Code)
		}
	})
}

// The guards around the handshake and the window route: TLS, the per-
// workspace limiter, the workspace lock, no-store, the org in the path and
// the journal of a refused window.
func TestMeshHandshakeGuards(t *testing.T) {
	f := newMeshFixture(t, true)
	c := canary.New()
	secret := c.Value(1)
	installs := func(ws uuid.UUID) int {
		return f.count(`SELECT count(*) FROM mesh_installations WHERE workspace_id=$1`, ws)
	}

	t.Run("plain HTTP", func(t *testing.T) {
		ws := uuid.New()
		f.mustOpenWindow(ws, secret)
		body := meshHandshakeBody(ws, "keep", secret)
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		rec := f.send("/mesh/install", "", body, map[string]string{"X-Mesh-Timestamp": ts, "X-Mesh-Signature": meshSign(secret, ts, body)}, false)
		if rec.Code != http.StatusNotFound || installs(ws) != 0 {
			t.Fatalf("handshake over plain HTTP: status %d, installs %d", rec.Code, installs(ws))
		}
	})

	t.Run("no-store", func(t *testing.T) {
		ws := uuid.New()
		rec := f.openWindow(f.admin, ws, meshSecretSHA256(secret))
		if rec.Code != http.StatusCreated || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("window: status %d, Cache-Control %q", rec.Code, rec.Header().Get("Cache-Control"))
		}
		rec = f.handshake(ws, secret)
		if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("bind: status %d, Cache-Control %q", rec.Code, rec.Header().Get("Cache-Control"))
		}
	})

	t.Run("org in the path", func(t *testing.T) {
		g := newMeshFixtureOn(t, f.pool, true)
		ws := uuid.New()
		b, _ := json.Marshal(map[string]string{"workspace_id": ws.String(), "mesh_url": "https://mesh.example.test", "signing_secret_sha256": meshSecretSHA256(secret)})
		if rec := f.post("/orgs/"+g.org.ID.String()+"/mesh/pending-installs", f.admin, b, nil); rec.Code != http.StatusNotFound {
			t.Fatalf("admin of another org: status %d", rec.Code)
		}
		if n := f.count(`SELECT count(*) FROM mesh_pending_installs WHERE workspace_id=$1`, ws); n != 0 {
			t.Fatalf("a window was opened through another org's path: %d", n)
		}
	})

	t.Run("poller token", func(t *testing.T) {
		ws := uuid.New()
		if rec := f.openWindow(f.pollerBearer(), ws, meshSecretSHA256(secret)); rec.Code != http.StatusForbidden {
			t.Fatalf("restart:poll token: status %d, want 403 from the role gate", rec.Code)
		}
		if n := f.count(`SELECT count(*) FROM mesh_pending_installs WHERE workspace_id=$1`, ws); n != 0 {
			t.Fatalf("a restart:poll token opened a window: %d", n)
		}
	})

	t.Run("refused window is journaled", func(t *testing.T) {
		before := f.count(`SELECT count(*) FROM audit_records WHERE org_id=$1 AND action='mesh.install.pending' AND result_status='failed'`, f.org.ID.String())
		if rec := f.openWindow(f.member, uuid.New(), meshSecretSHA256(secret)); rec.Code != http.StatusNotFound {
			t.Fatalf("member: status %d", rec.Code)
		}
		if n := f.count(`SELECT count(*) FROM audit_records WHERE org_id=$1 AND action='mesh.install.pending' AND result_status='failed'`, f.org.ID.String()); n != before+1 {
			t.Fatalf("refused window journaled %d times", n-before)
		}
	})

	t.Run("workspace lock", func(t *testing.T) {
		ws := uuid.New()
		f.mustOpenWindow(ws, secret)
		rawUnlock, err := f.repo.LockWorkspace(context.Background(), ws)
		if err != nil {
			t.Fatal(err)
		}
		var once sync.Once
		unlock := func() { once.Do(rawUnlock) }
		defer unlock()
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() { done <- f.handshake(ws, secret) }()
		select {
		case <-done:
			t.Fatal("handshake completed while the workspace lock was held")
		case <-time.After(500 * time.Millisecond):
		}
		if installs(ws) != 0 {
			t.Fatal("handshake bound the workspace while its lock was held")
		}
		unlock()
		select {
		case rec := <-done:
			if rec.Code != http.StatusOK {
				t.Fatalf("after unlock: status %d", rec.Code)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("handshake did not proceed after the lock was released")
		}
	})

	// The workspace's budget bounds authenticated handshakes: the binding
	// one spends it, a repeat with the bound secret is refused once it is out.
	t.Run("limiter", func(t *testing.T) {
		frozen := time.Now()
		g := newMeshFixtureOn(t, f.pool, true, func(d *api.MeshDeps) {
			d.ResolveLimit = api.CatalogLimit{PerMinute: 1, Burst: 1, Now: func() time.Time { return frozen }}
		})
		ws := uuid.New()
		g.mustOpenWindow(ws, secret)
		if rec := g.handshake(ws, secret); rec.Code != http.StatusOK {
			t.Fatalf("binding handshake: status %d", rec.Code)
		}
		rec := g.handshake(ws, secret)
		if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
			t.Fatalf("repeat over the budget: status %d, Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
		}
	})

	// keep-rotator points at the same install_path and Mesh repeats its
	// handshake on every health check: refusing another extension_id must not
	// spend the workspace's budget nor the caller's pre-authentication one,
	// or the keep handshake from the same Mesh is locked out.
	t.Run("foreign extension spends no budget", func(t *testing.T) {
		frozen := time.Now()
		g := newMeshFixtureOn(t, f.pool, true, func(d *api.MeshDeps) {
			d.ResolveLimit = api.CatalogLimit{PerMinute: 1, Burst: 1, Now: func() time.Time { return frozen }}
			d.PreauthLimit = api.CatalogLimit{PerMinute: 1, Burst: 1, Now: func() time.Time { return frozen }}
		})
		ws := uuid.New()
		g.mustOpenWindow(ws, secret)
		rot := meshHandshakeBody(ws, "keep-rotator", secret)
		for i := 0; i < 3; i++ {
			if rec := g.handshakeSigned(rot, secret, time.Now()); rec.Code != http.StatusUnauthorized {
				t.Fatalf("keep-rotator handshake %d: status %d, want 401", i, rec.Code)
			}
		}
		if rec := g.handshake(ws, secret); rec.Code != http.StatusOK || installs(ws) != 1 {
			t.Fatalf("keep handshake after keep-rotator ones: status %d, installs %d", rec.Code, installs(ws))
		}
	})
}

// notModified answers every hierarchy fetch with 304, so a sync round does
// no network work.
type notModified struct{}

func (notModified) FetchHierarchy(context.Context, uuid.UUID, uuid.UUID, string, string) (meshext.Fetched, error) {
	return meshext.Fetched{NotModified: true}, nil
}

// An expired window does not wait for the next window to be opened or looked
// up: the periodic sync round deletes it, and leaves a live one alone.
func TestMeshSyncRoundDropsExpiredWindows(t *testing.T) {
	f := newMeshFixture(t, true)
	c := canary.New()
	stale, live := uuid.New(), uuid.New()
	f.mustOpenWindow(stale, c.Value(1))
	f.mustOpenWindow(live, c.Value(2))
	f.expireWindow(stale)
	meshSyncRound(context.Background(), f.repo, notModified{}, f.logger)
	n := func(ws uuid.UUID) int {
		return f.count(`SELECT count(*) FROM mesh_pending_installs WHERE workspace_id=$1`, ws)
	}
	if n(stale) != 0 || n(live) != 1 {
		t.Fatalf("after a sync round: expired windows %d (want 0), live windows %d (want 1)", n(stale), n(live))
	}
}

// The periodic sync loop runs the cleanup round: an expired window is gone
// right after the loop starts, without any window being opened or looked up.
func TestMeshSyncLoopDropsExpiredWindows(t *testing.T) {
	f := newMeshFixture(t, true)
	stale := uuid.New()
	f.mustOpenWindow(stale, canary.New().Value(1))
	f.expireWindow(stale)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runMeshSync(ctx, config.Config{MeshExtension: true}, f.pool, f.local, f.logger)
	}()
	defer func() { cancel(); <-done }()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if f.count(`SELECT count(*) FROM mesh_pending_installs WHERE workspace_id=$1`, stale) == 0 {
			return
		}
	}
	t.Fatal("the sync loop left an expired window in place")
}
