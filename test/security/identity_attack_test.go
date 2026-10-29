// Package security holds Keep's attack tests: written from the outside of
// the packages they attack, through their exported API only — the view of a
// hostile caller or of careless calling code. Each attack is real (its
// happy-path control passes first) and is proven able to fail by the red
// runs listed in the MR that adds it.
package security

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ---------------------------------------------------------------- harness

func attackDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("KEEP_DATABASE_URL")
	if dsn == "" {
		t.Skip("KEEP_DATABASE_URL not set — see CONTRIBUTING.md")
	}
	pgscratch.WaitReady(t)
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func mustID(t *testing.T) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func exec(t *testing.T, db *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := db.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

// sqlState is the SQLSTATE of a database error, or "" when err carries none —
// an assertion on "the database refused" must name the refusal (an integrity
// violation), not accept any error, or a typo in the statement passes as a
// defence.
func sqlState(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

type world struct {
	db      *pgxpool.Pool
	repo    *identity.Repo
	org     uuid.UUID
	user    uuid.UUID // sponsor
	agent   uuid.UUID
	service uuid.UUID
}

// newWorld seeds one organization with a user (the sponsor), an agent
// sponsored by it, and a service.
func newWorld(t *testing.T, db *pgxpool.Pool) world {
	t.Helper()
	w := world{db: db, repo: identity.NewRepo(db), org: mustID(t), user: mustID(t), agent: mustID(t), service: mustID(t)}
	exec(t, db, `INSERT INTO organizations (id, name) VALUES ($1, $2)`, w.org, "org-"+w.org.String())
	exec(t, db, `INSERT INTO users (id, org_id, email) VALUES ($1, $2, $3)`, w.user, w.org, w.user.String()+"@attack.test")
	exec(t, db, `INSERT INTO agents (id, org_id, sponsor_user_id, name) VALUES ($1, $2, $3, 'agent')`, w.agent, w.org, w.user)
	exec(t, db, `INSERT INTO services (id, org_id, owner_scope, name) VALUES ($1, $2, $3, 'svc')`, w.service, w.org, "org:"+w.org.String())
	return w
}

// issuedToken is an IssueResult plus the token's text. The attacks are the one
// place outside internal/identity that must hold the value: they present it as
// a credential and hunt for it on every surface. Token shadows the embedded
// identity.Token so the text is reachable as .Token, and reveal is the only
// call to Reveal in this package.
type issuedToken struct {
	identity.IssueResult
	Token string
}

func reveal(tok identity.Token) string { return identity.Reveal(tok) }

// generated returns a well-formed token text that was never stored.
func generated(t *testing.T, kind identity.Kind) string {
	t.Helper()
	tok, err := identity.GenerateToken(kind)
	if err != nil {
		t.Fatal(err)
	}
	return reveal(tok)
}

func (w world) issue(t *testing.T, kind identity.Kind, exp *time.Time) issuedToken {
	t.Helper()
	pid := map[identity.Kind]uuid.UUID{identity.KindAgent: w.agent, identity.KindService: w.service, identity.KindUser: w.user}[kind]
	res, err := w.repo.Issue(context.Background(), identity.IssueParams{
		OrgID: w.org, Kind: kind, PrincipalID: pid, Scope: "org:" + w.org.String(), ExpiresAt: exp,
	})
	if err != nil {
		t.Fatalf("issue %s: %v", kind, err)
	}
	return issuedToken{IssueResult: res, Token: reveal(res.Token)}
}

func (w world) setMembership(t *testing.T, scope, role string) {
	t.Helper()
	exec(t, w.db, `DELETE FROM memberships WHERE user_id = $1 AND scope = $2`, w.user, scope)
	if role == "" {
		return
	}
	exec(t, w.db, `INSERT INTO memberships (id, org_id, user_id, scope, role) VALUES ($1, $2, $3, $4, $5)`,
		mustID(t), w.org, w.user, scope, role)
}

func (w world) setGrants(t *testing.T, perms ...string) {
	t.Helper()
	exec(t, w.db, `DELETE FROM agent_grants WHERE agent_id = $1`, w.agent)
	for _, p := range perms {
		exec(t, w.db, `INSERT INTO agent_grants (id, org_id, agent_id, permission) VALUES ($1, $2, $3, $4)`,
			mustID(t), w.org, w.agent, p)
	}
}

// app is the smallest real server: request-id, RequireAuth, RequireOrgMatch,
// and handlers that report only what the Principal in context says.
type app struct {
	h   http.Handler
	log *bytes.Buffer
}

func newApp(repo *identity.Repo) app {
	logs := &bytes.Buffer{}
	logger := slog.New(obs.NewHandler(&lockedWriter{w: logs}, slog.LevelDebug))

	whoami := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := identity.FromContext(r.Context())
		if !ok {
			http.Error(w, "no principal", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"org_id": p.OrgID.String(), "kind": string(p.Kind), "principal_id": p.ID.String(),
		})
	})
	auth := identity.RequireAuth(repo, logger)
	mux := http.NewServeMux()
	mux.Handle("GET /me", auth(whoami))
	mux.Handle("POST /me", auth(whoami))
	mux.Handle("GET /orgs/{org_id}/whoami", auth(identity.RequireOrgMatch("org_id")(whoami)))
	mux.Handle("GET /noauth/orgs/{org_id}/whoami", identity.RequireOrgMatch("org_id")(whoami))

	withRID := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := reqid.FromHeader(r.Header.Get(reqid.HeaderName))
		w.Header().Set(reqid.HeaderName, id)
		mux.ServeHTTP(w, r.WithContext(reqid.WithContext(r.Context(), id)))
	})
	return app{h: withRID, log: logs}
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

type resp struct {
	status int
	header http.Header
	body   string
}

func (a app) do(method, path string, hdr map[string][]string, body string) resp {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, vs := range hdr {
		req.Header.Del(k)
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	a.h.ServeHTTP(rec, req)
	return resp{status: rec.Code, header: rec.Header(), body: rec.Body.String()}
}

func bearer(tok string) map[string][]string {
	return map[string][]string{"Authorization": {"Bearer " + tok}}
}

var ridRe = regexp.MustCompile(`"request_id":"[^"]*"`)

// shape is everything a client can observe of a response except the
// per-request id — the thing two "identical" failures must agree on.
func (r resp) shape() string {
	h := r.header.Clone()
	h.Del(reqid.HeaderName)
	var keys []string
	for k := range h {
		keys = append(keys, k+"="+strings.Join(h[k], ","))
	}
	sort.Strings(keys) // map order is random; two identical responses must compare equal
	return fmt.Sprintf("%d|%v|%s", r.status, keys, ridRe.ReplaceAllString(strings.TrimSpace(r.body), `"request_id":"-"`))
}

// outline is what a failing check may print of a response: the status, the
// names of the headers, the length of the body and the names of its JSON keys.
// Never a value: a distinguishable failure is exactly the case where the body
// or a header may carry the credential in an encoding safe() does not know
// (a base64 of "user:"+token, say), and a message that prints it turns the
// finding into the leak it reports.
func (r resp) outline() string {
	var hdr []string
	for k := range r.header {
		hdr = append(hdr, k)
	}
	sort.Strings(hdr)
	var keys []string
	var body map[string]any
	if json.Unmarshal([]byte(r.body), &body) == nil {
		for k := range body {
			keys = append(keys, printableName(k))
		}
		sort.Strings(keys)
	} else {
		keys = []string{"<not a JSON object>"}
	}
	for i, k := range hdr {
		hdr[i] = printableName(k)
	}
	return fmt.Sprintf("status=%d headers=%v body_bytes=%d body_keys=%v", r.status, hdr, len(r.body), keys)
}

// knownNames is the closed set of header and JSON-key names these attacks
// ever expect to see: the response headers (Content-Type, the request-id
// header), whoami's success body, apperr's error body, and the
// auth-failure log record's own field names. A plain-shape check (short,
// alphanumeric) let up to 32 attacker-chosen characters through — anything
// shaped like a name, including one an attacker picked to look ordinary.
// The closed set has no such gap: a name outside it is reduced to its
// length, whatever it looks like.
var knownNames = map[string]bool{
	"Content-Type": true, reqid.HeaderName: true,
	"org_id": true, "kind": true, "principal_id": true,
	"error_class": true, "message": true, "request_id": true,
	"time": true, "level": true, "msg": true, "auth_reason": true,
}

// printableName is a key or header name that is safe to print: one of the
// closed set this file's attacks actually expect. Anything else — a key
// that is itself a credential, or one shaped to pass as an expected name —
// is reduced to its length.
func printableName(k string) string {
	if knownNames[k] {
		return k
	}
	return fmt.Sprintf("<%d-char name>", len(k))
}

// captureStdout runs fn while everything a careless caller might print to is
// redirected to one pipe — the os.Stdout and os.Stderr variables, the log
// package's writer and slog's default logger (the latter two hold their own
// writers and would otherwise keep the original fds) — and returns what was
// written. Restoration and closing run from t.Cleanup as well, so a t.Fatalf
// inside fn cannot leave the process redirected or leak the pipe.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan string, 1) // buffered: the reader never blocks if nobody collects
	go func() {
		defer func() { _ = rOut.Close() }()
		b, _ := io.ReadAll(rOut)
		done <- string(b)
	}()
	oldOut, oldErr := os.Stdout, os.Stderr
	oldLogW, oldLogFlags, oldSlog := log.Writer(), log.Flags(), slog.Default()
	var once sync.Once
	finish := func() {
		once.Do(func() {
			os.Stdout, os.Stderr = oldOut, oldErr
			slog.SetDefault(oldSlog)
			log.SetOutput(oldLogW)
			log.SetFlags(oldLogFlags)
			_ = wOut.Close()
		})
	}
	t.Cleanup(finish)
	os.Stdout, os.Stderr = wOut, wOut
	slog.SetDefault(slog.New(slog.NewTextHandler(wOut, &slog.HandlerOptions{Level: slog.LevelDebug})))
	log.SetOutput(wOut)
	fn()
	finish()
	return <-done
}

// tokenLike matches the shapes a token can take in text: the full form and
// the bare 52-character body. `{52,}`, not `{52}`: a token glued to other
// [a-z2-7] characters on the left (no word boundary in that alphabet) still
// has a token-shaped run longer than 52, and an exact count would replace
// only its leftmost 52 characters, leaving the token's own trailing bytes
// unmasked — the same bug this round's leak-review found in the shell
// mask() helper's mirror pattern (scripts/check-identity-attack-mutations.sh).
var tokenLike = regexp.MustCompile(`(?i)(keep_[asu]_)?[a-z2-7]{52,}`)

// safe masks anything token-shaped, for messages: a failing attack must not
// print the very thing it found.
func safe(s string) string { return tokenLike.ReplaceAllString(s, "<token-shaped>") }

// closedValue is v as text when it is one of the allowed values, otherwise only
// its length: for a message that must show which closed value was logged
// without ever showing what else a broken logger put there.
func closedValue(v any, allowed ...string) string {
	str, ok := v.(string)
	if !ok {
		return "<not a string>"
	}
	for _, a := range allowed {
		if str == a {
			return fmt.Sprintf("%q", str)
		}
	}
	return fmt.Sprintf("<outside the closed set, %d chars>", len(str))
}

// TestSafe_MasksGluedPrefixRun is the round-3 leak-review's boundary finding
// on the shell mask() helper's mirror pattern (see the comment on tokenLike):
// [a-z2-7] has no word boundary, so a token glued to other alphabet
// characters on its left forms one run longer than 52. An exact `{52}`
// count matches only the leftmost 52 characters of that run, leaving the
// token's own trailing bytes past that point unmasked.
func TestSafe_MasksGluedPrefixRun(t *testing.T) {
	body := strings.Repeat("abcdefg234567", 4) // 52 chars, entirely in [a-z2-7]
	if len(body) != 52 {
		t.Fatalf("test setup: body is %d chars, want 52", len(body))
	}
	// 20 more [a-z2-7] characters glued on, no boundary: long enough that an
	// exact {52} count's leftmost-52 match leaves an unambiguous tail of the
	// body's own bytes past it, not just a character or two a narrower
	// prefix would also leave.
	glued := strings.Repeat("q", 20) + body
	out := safe("leaked: " + glued)
	if tail := body[len(body)-15:]; strings.Contains(out, tail) {
		t.Fatalf("safe() left the token's own trailing bytes visible: %q in %q", tail, out)
	}
	if m := regexp.MustCompile(`(?i)[a-z2-7]{52,}`).FindString(out); m != "" {
		t.Fatalf("safe() output still carries a token-shaped run: %q", m)
	}
}

// dumpDB returns every row of every public table as text — every column of
// every table, not just the ones the author expects a token in. It reads the
// whole database, so it is only safe under `-p 1` (see the Makefile's test
// target and .gitlab-ci.yml): run alongside another package that resets the
// schema mid-test and this either sees a half-migrated table or scans rows
// out from under a DROP.
func dumpDB(t *testing.T, db *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()
	rows, err := db.Query(ctx, `SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close() // a t.Fatal below must not leave the cursor open under t.Cleanup(pool.Close)
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, n)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(tables) < 5 {
		t.Fatalf("dump saw only %d tables — schema not migrated?", len(tables))
	}
	var sb strings.Builder
	for _, tb := range tables {
		func() {
			r, err := db.Query(ctx, fmt.Sprintf(`SELECT x::text FROM %s x`, pgx.Identifier{tb}.Sanitize()))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			for r.Next() {
				var s string
				if err := r.Scan(&s); err != nil {
					t.Fatal(err)
				}
				sb.WriteString(s)
				sb.WriteByte('\n')
			}
			if err := r.Err(); err != nil {
				t.Fatal(err)
			}
		}()
	}
	return sb.String()
}

// ---------------------------------------------------------------- attacks

// namedCanary is one thing that must never surface, with a name that is safe
// to print (an index and a kind of value — never the value itself).
type namedCanary struct {
	name string
	c    canary.Canary
}

// surface is one thing an observer could see, as text, with a label that is
// safe to print.
type surface struct{ label, text string }

// tokenRawBytes decodes the random 32 bytes behind a token's base32 body.
func tokenRawBytes(t *testing.T, tok string) []byte {
	t.Helper()
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(tok[len("keep_a_"):]))
	if err != nil || len(raw) != 32 {
		t.Fatalf("control: token body does not decode to 32 bytes (err=%v, len=%d)", err, len(raw))
	}
	return raw
}

// TestIdentity_TokenNeverEscapesItsIssuance — threat model §4.3/§4.4 and the
// token leak requirement: a token appears in exactly one place, the issuance
// response. The attack issues every token INSIDE the capture window (so output
// on the Issue/GenerateToken path is searched too) and drives every lifecycle
// step (success, expired, revoked, deleted principal, unknown-but-well-formed,
// wrong-shape mutations of a real token, database down, revoke), with real
// minted tokens as canaries — the full text, the body without its prefix, and
// the 32 random bytes behind it — and searches everything an outsider or an
// operator can see: every response body and header, the debug log, fd-level
// stdout/stderr plus the log and slog defaults, every error string, every
// column of every table, and every rendering of the issuance types (each fmt
// verb, each method called directly, JSON, slog) — in six encodings plus
// shifted base64. A hit is reported as a canary name and a surface label,
// never as text.
func TestIdentity_TokenNeverEscapesItsIssuance(t *testing.T) {
	db := attackDB(t)
	w := newWorld(t, db)
	a := newApp(w.repo)
	ctx := context.Background()

	var (
		canaries []namedCanary
		surfaces []surface
		add      = func(label, s string) { surfaces = append(surfaces, surface{label, s}) }
		// canary.Of matches only the string it is given: every token is tracked
		// as its full text, its body (a leak after parsing off the kind), and
		// the raw 32 bytes (a leak of the entropy in another encoding, e.g. %x).
		track = func(name, tok string) {
			raw := tokenRawBytes(t, tok)
			rc := canary.Of(string(raw))
			if !rc.In(fmt.Sprintf("%x", raw)) || !rc.In(base64.StdEncoding.EncodeToString(raw)) {
				t.Fatal("control: the raw-bytes canary is blind to hex/base64 of the bytes")
			}
			canaries = append(canaries,
				namedCanary{name + "/text", canary.Of(tok)},
				namedCanary{name + "/body", canary.Of(tok[len("keep_a_"):])},
				namedCanary{name + "/raw-bytes", rc})
		}
		issued     = map[identity.Kind]issuedToken{}
		expired    issuedToken
		revoked    issuedToken
		gone       issuedToken
		unknownTok string
		deletedSvc = mustID(t)
		err        error
	)

	out := captureStdout(t, func() {
		// Positive controls: the capture sees fd-level stdout/stderr, the log
		// package and slog's default — otherwise "not found" means nothing.
		_, _ = fmt.Fprintln(os.Stdout, "capture-live-stdout")
		_, _ = fmt.Fprintln(os.Stderr, "capture-live-stderr")
		log.Print("capture-live-log")
		slog.Default().Info("capture-live-slog")

		// Tokens are issued inside the window.
		for _, k := range []identity.Kind{identity.KindAgent, identity.KindService, identity.KindUser} {
			issued[k] = w.issue(t, k, nil)
			track(string(k), issued[k].Token)
		}
		past := time.Now().Add(-time.Hour)
		expired = w.issue(t, identity.KindService, &past)
		revoked = w.issue(t, identity.KindService, nil)
		exec(t, db, `INSERT INTO services (id, org_id, owner_scope, name) VALUES ($1,$2,'org:x','gone')`, deletedSvc, w.org)
		goneRes, err := w.repo.Issue(ctx, identity.IssueParams{OrgID: w.org, Kind: identity.KindService, PrincipalID: deletedSvc, Scope: "s"})
		if err != nil {
			t.Fatal(err)
		}
		gone = issuedToken{IssueResult: goneRes, Token: reveal(goneRes.Token)}
		unknownTok = generated(t, identity.KindAgent) // well-formed, never stored
		track("expired", expired.Token)
		track("revoked", revoked.Token)
		track("gone", gone.Token)
		track("unknown", unknownTok)

		// success on every kind
		for _, k := range []identity.Kind{identity.KindAgent, identity.KindService, identity.KindUser} {
			r := a.do("GET", "/me", bearer(issued[k].Token), "")
			if r.status != 200 {
				t.Fatalf("control: valid %s token got %d", k, r.status)
			}
			add("resp-ok", r.body+fmt.Sprint(r.header))
			r = a.do("GET", "/orgs/"+w.org.String()+"/whoami", bearer(issued[k].Token), "")
			add("resp-ok-org", r.body+fmt.Sprint(r.header))
		}
		if err := w.repo.Revoke(ctx, identity.Principal{OrgID: w.org}, revoked.TokenID); err != nil {
			t.Fatal(err)
		}
		exec(t, db, `DELETE FROM services WHERE id = $1`, deletedSvc)

		bad := []string{expired.Token, revoked.Token, gone.Token, unknownTok,
			strings.ToUpper(issued[identity.KindAgent].Token),
			issued[identity.KindAgent].Token + "x",
			issued[identity.KindAgent].Token[:len(issued[identity.KindAgent].Token)-1],
			strings.Replace(issued[identity.KindAgent].Token, "_a_", "_s_", 1),
		}
		for _, tok := range bad {
			r := a.do("GET", "/me", bearer(tok), "")
			if r.status != 401 {
				t.Fatalf("control: bad token must be 401, got %d", r.status)
			}
			add("resp-401", r.body+fmt.Sprint(r.header))
			r = a.do("GET", "/orgs/"+w.org.String()+"/whoami", map[string][]string{
				"Authorization": {"Bearer " + tok}, "X-Request-Id": {"probe-fixed-id"}}, "")
			add("resp-401-org", r.body+fmt.Sprint(r.header))
			_, err := w.repo.Authenticate(ctx, identity.NewToken(tok))
			if err == nil {
				t.Fatal("control: Authenticate accepted a bad token")
			}
			add("authenticate-error", err.Error()+fmt.Sprintf("%v|%+v|%#v", err, err, err))
		}
		// The same real tokens in headers that are not "Bearer <token>": the
		// path that fails before any lookup must not echo or log them either.
		for _, tok := range []string{issued[identity.KindAgent].Token, revoked.Token} {
			for name, h := range map[string]string{
				"bare":            tok,
				"basic":           "Basic " + base64.StdEncoding.EncodeToString([]byte("user:"+tok)),
				"basic-shifted-1": "Basic " + base64.StdEncoding.EncodeToString([]byte("a"+tok)),
				"lowercase":       "bearer " + tok,
				"other-scheme":    "Token " + tok,
			} {
				r := a.do("GET", "/me", map[string][]string{"Authorization": {h}}, "")
				if r.status != 401 {
					t.Fatalf("control: %s header must be 401, got %d", name, r.status)
				}
				add("resp-401-"+name, r.body+fmt.Sprint(r.header))
			}
		}
		// the revoke path's own errors
		for _, id := range []uuid.UUID{revoked.TokenID, mustID(t)} {
			err := w.repo.Revoke(ctx, identity.Principal{OrgID: w.org}, id)
			if err == nil {
				t.Fatal("control: revoke of revoked/unknown must fail")
			}
			add("revoke-error", fmt.Sprintf("%v %+v", err, err))
		}
		// database down: a pool that is already closed
		dead, err := pgxpool.New(context.Background(), os.Getenv("KEEP_DATABASE_URL"))
		if err != nil {
			t.Fatalf("control: cannot build the pool that is then closed to stand in for a dead database: %s", safe(err.Error()))
		}
		dead.Close()
		da := newApp(identity.NewRepo(dead))
		r := da.do("GET", "/me", bearer(issued[identity.KindAgent].Token), "")
		if r.status != http.StatusServiceUnavailable {
			t.Fatalf("control: dead database must answer 503, got %d", r.status)
		}
		add("resp-503", r.body+fmt.Sprint(r.header))
		add("log-503", da.log.String())
		_, err = identity.NewRepo(dead).Authenticate(ctx, issued[identity.KindAgent].IssueResult.Token)
		if err == nil {
			t.Fatal("control: Authenticate on a closed pool must fail, not succeed")
		}
		add("db-down-error", fmt.Sprintf("%v %+v", err, err))

		// every rendering of the issuance types: each fmt verb, each method
		// called directly (fmt never reaches GoString once Format exists), JSON,
		// and slog through both obs and a bare JSON handler.
		res := issued[identity.KindAgent].IssueResult
		resp := res.Response()
		// The token type is redacted on its own, wherever it is placed: bare, in
		// exported and unexported struct fields, slices and maps (fmt reaches
		// unexported fields by reflection and calls no method there).
		tk := res.Token
		type holder struct {
			Pub  identity.Token
			priv identity.Token
		}
		for name, v := range map[string]any{
			"IssueResult": res, "IssueResponse": resp, "Token": tk, "Token.ptr": &tk,
			"holder": holder{Pub: tk, priv: tk}, "holder.ptr": &holder{Pub: tk, priv: tk},
			"Token.slice": []identity.Token{tk}, "Token.map": map[string]identity.Token{"k": tk},
			"Token.any": []any{tk, &tk},
		} {
			for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%q", "%x", "%t"} {
				add(name+".fmt"+verb, fmt.Sprintf(verb, v))
			}
			var lo, lj bytes.Buffer
			slog.New(obs.NewHandler(&lo, slog.LevelDebug)).Info("issued", "token_id", v)
			slog.New(slog.NewJSONHandler(&lj, nil)).Info("issued", "token_id", v)
			add(name+".slog-obs", lo.String())
			add(name+".slog-json", lj.String())
		}
		add("IssueResult.String()", res.String())
		add("IssueResult.GoString()", res.GoString())
		add("IssueResult.LogValue()", res.LogValue().String())
		add("IssueResponse.String()", resp.String())
		add("IssueResponse.GoString()", resp.GoString())
		add("IssueResponse.LogValue()", resp.LogValue().String())
		add("Token.String()", tk.String())
		add("Token.GoString()", tk.GoString())
		add("Token.LogValue()", tk.LogValue().String())
		if b, err := tk.MarshalText(); err == nil {
			add("Token.MarshalText()", string(b))
		}
		if b, err := tk.MarshalJSON(); err == nil {
			add("Token.MarshalJSON()", string(b))
		}
		if b, err := json.Marshal(holder{Pub: tk}); err == nil {
			add("Token.json-in-struct", string(b))
		}
		if b, err := json.Marshal(resp); err == nil {
			add("IssueResponse.json", string(b)) // must refuse: the only wire path is WireJSON
		} else {
			add("IssueResponse.json-error", err.Error())
		}
		if b, err := json.Marshal(res); err == nil {
			add("IssueResult.json", string(b)) // the internal type must refuse; if it doesn't, this is the leak
		} else {
			add("IssueResult.json-error", err.Error())
		}
	})
	add("stdout+stderr+log", out)
	for _, live := range []string{"capture-live-stdout", "capture-live-stderr", "capture-live-log", "capture-live-slog"} {
		if !strings.Contains(out, live) {
			t.Fatalf("control: the capture missed %q — it does not see every output path", live)
		}
	}
	add("debug-log", a.log.String())
	if !strings.Contains(a.log.String(), "auth_reason") {
		t.Fatal("control: debug log must contain the failure reasons — log capture is not live")
	}
	add("database", dumpDB(t, db))

	// Positive control: the detector sees a token where it is, and in the
	// issuance response — the one legitimate copy, which is not in `surfaces`.
	ic := canary.Of(issued[identity.KindAgent].Token)
	issueJSON, err := issued[identity.KindAgent].Response().WireJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !ic.In(string(issueJSON)) {
		t.Fatal("control: the issuance response must carry the token exactly once")
	}
	if b, err := json.Marshal(issued[identity.KindAgent].Response()); err == nil {
		t.Fatalf("a generic encoder serialized the issuance response (%d bytes); only WireJSON may", len(b))
	}
	// base64 groups bytes three at a time, so a token that follows 0, 1 or 2
	// bytes of something else (mod 3) encodes to three different runs of
	// characters: the detector must see all three.
	for _, before := range []string{"", "a", "ab", "user:", "u:"} {
		if !ic.In(base64.StdEncoding.EncodeToString([]byte(before + issued[identity.KindAgent].Token))) {
			t.Fatalf("control: detector blind to base64 of the token after %d leading bytes (offset %d mod 3)", len(before), len(before)%3)
		}
	}

	for _, c := range canaries {
		for _, s := range surfaces {
			if c.c.In(s.text) {
				t.Errorf("canary %s found on surface %q (%d bytes of text; not printed)", c.name, s.label, len(s.text))
			}
		}
	}
}

// TestIdentity_TenantSwap — tenancy model §1/§2 (S-1..): org_id comes only
// from the token. A token of org A can reach nothing of org B and cannot
// tell whether org B (or anything in it) exists.
func TestIdentity_TenantSwap(t *testing.T) {
	db := attackDB(t)
	A, B := newWorld(t, db), newWorld(t, db)
	a := newApp(A.repo)
	tokA := A.issue(t, identity.KindAgent, nil).Token
	tokB := B.issue(t, identity.KindUser, nil)

	t.Run("control: own org resolves", func(t *testing.T) {
		if r := a.do("GET", "/orgs/"+A.org.String()+"/whoami", bearer(tokA), ""); r.status != 200 || !strings.Contains(r.body, A.org.String()) {
			t.Fatalf("got %d %s", r.status, r.outline())
		}
	})
	t.Run("foreign org in URL is 404, indistinguishable from nonexistent", func(t *testing.T) {
		foreign := a.do("GET", "/orgs/"+B.org.String()+"/whoami", bearer(tokA), "")
		ghost := a.do("GET", "/orgs/"+mustID(t).String()+"/whoami", bearer(tokA), "")
		junk := a.do("GET", "/orgs/not-a-uuid/whoami", bearer(tokA), "")
		if foreign.status != 404 {
			t.Fatalf("foreign org: got %d, want 404 (never 403, never 200)", foreign.status)
		}
		if foreign.shape() != ghost.shape() || foreign.shape() != junk.shape() {
			t.Fatalf("existence oracle:\n foreign=%s\n ghost  =%s\n junk   =%s", foreign.outline(), ghost.outline(), junk.outline())
		}
		if strings.Contains(foreign.body, B.org.String()) {
			t.Fatal("foreign org id echoed in the response")
		}
	})
	t.Run("org_id smuggled through header, query and body is ignored", func(t *testing.T) {
		h := bearer(tokA)
		h["X-Org-Id"] = []string{B.org.String()}
		h["X-Org"] = []string{B.org.String()}
		h["Content-Type"] = []string{"application/json"}
		for _, r := range []resp{
			a.do("GET", "/me?org_id="+B.org.String()+"&org="+B.org.String(), h, ""),
			a.do("POST", "/me", h, fmt.Sprintf(`{"org_id":%q}`, B.org.String())),
		} {
			if r.status != 200 || strings.Contains(r.body, B.org.String()) || !strings.Contains(r.body, A.org.String()) {
				t.Fatalf("org taken from the request: %d %s", r.status, r.outline())
			}
		}
	})
	t.Run("unauthenticated request never reaches the org check", func(t *testing.T) {
		r := a.do("GET", "/orgs/"+B.org.String()+"/whoami", nil, "")
		if r.status != 401 {
			t.Fatalf("got %d, want 401", r.status)
		}
	})
	t.Run("org check without authentication fails closed", func(t *testing.T) {
		// The nil UUID is the case that matters: it equals the OrgID of a
		// zero Principal, so a check that lets a missing Principal through
		// to the comparison waves it in.
		for _, org := range []string{A.org.String(), uuid.Nil.String()} {
			if r := a.do("GET", "/noauth/orgs/"+org+"/whoami", nil, ""); r.status != 404 {
				t.Fatalf("RequireOrgMatch without a Principal answered %d for org %s, want 404", r.status, org)
			}
		}
	})
	t.Run("revoke across orgs", func(t *testing.T) {
		errForeign := A.repo.Revoke(context.Background(), identity.Principal{OrgID: A.org}, tokB.TokenID)
		errGhost := A.repo.Revoke(context.Background(), identity.Principal{OrgID: A.org}, mustID(t))
		if errForeign == nil || errGhost == nil {
			t.Fatalf("control: revoking a foreign or a nonexistent token id must fail (foreign nil=%v, ghost nil=%v)", errForeign == nil, errGhost == nil)
		}
		if !errors.Is(errForeign, identity.ErrTokenUnknown) || errForeign.Error() != errGhost.Error() {
			t.Fatalf("foreign revoke: %s; nonexistent: %s — must be the same sentinel", safe(errForeign.Error()), safe(errGhost.Error()))
		}
		if _, err := B.repo.Authenticate(context.Background(), tokB.IssueResult.Token); err != nil {
			t.Fatalf("org B's token was revoked from org A: %T, %d chars", err, len(err.Error()))
		}
	})
	t.Run("issue for a principal of another org or of the wrong kind", func(t *testing.T) {
		ctx := context.Background()
		for name, p := range map[string]identity.IssueParams{
			"B's agent in A":  {OrgID: A.org, Kind: identity.KindAgent, PrincipalID: B.agent},
			"B's user in A":   {OrgID: A.org, Kind: identity.KindUser, PrincipalID: B.user},
			"A's user as svc": {OrgID: A.org, Kind: identity.KindService, PrincipalID: A.user},
			"A's agent as u":  {OrgID: A.org, Kind: identity.KindUser, PrincipalID: A.agent},
			"bad kind x":      {OrgID: A.org, Kind: "x", PrincipalID: A.user},
			"empty kind":      {OrgID: A.org, Kind: "", PrincipalID: A.user},
		} {
			if res, err := A.repo.Issue(ctx, p); err == nil {
				t.Errorf("%s: token issued (%d chars)", name, len(reveal(res.Token)))
			}
		}
	})
	t.Run("database refuses cross-org rows", func(t *testing.T) {
		ctx := context.Background()
		const (
			fkViolation    = "23503" // foreign_key_violation
			checkViolation = "23514" // check_violation
		)
		// Controls: the same statements with rows of the right org go through,
		// so a refusal below is about the row and not about the statement.
		okAgent, okScope := mustID(t), "org:"+A.org.String()
		for _, q := range [][]any{
			{`INSERT INTO agents (id, org_id, sponsor_user_id, name) VALUES ($1,$2,$3,'ctl')`, okAgent, A.org, A.user},
			{`INSERT INTO memberships (id, org_id, user_id, scope, role) VALUES ($1,$2,$3,$4,'viewer')`, mustID(t), A.org, A.user, okScope},
			{`INSERT INTO agent_grants (id, org_id, agent_id, permission) VALUES ($1,$2,$3,'rotate')`, mustID(t), A.org, A.agent},
		} {
			if _, err := db.Exec(ctx, q[0].(string), q[1:]...); err != nil {
				t.Fatalf("control: %q with rows of one org failed: %v", q[0], err)
			}
		}
		for _, c := range []struct {
			name, sql string
			args      []any
			want      string
		}{
			{"agent sponsored by another org's user", `INSERT INTO agents (id, org_id, sponsor_user_id, name) VALUES ($1,$2,$3,'x')`, []any{mustID(t), A.org, B.user}, fkViolation},
			{"membership of another org's user", `INSERT INTO memberships (id, org_id, user_id, scope, role) VALUES ($1,$2,$3,'org:x','admin')`, []any{mustID(t), A.org, B.user}, fkViolation},
			{"grant of another org's agent", `INSERT INTO agent_grants (id, org_id, agent_id, permission) VALUES ($1,$2,$3,'rotate')`, []any{mustID(t), A.org, B.agent}, fkViolation},
			{"role outside the closed set", `INSERT INTO memberships (id, org_id, user_id, scope, role) VALUES ($1,$2,$3,'org:y','root')`, []any{mustID(t), A.org, A.user}, checkViolation},
			{"permission outside the closed set", `INSERT INTO agent_grants (id, org_id, agent_id, permission) VALUES ($1,$2,$3,'read_secret')`, []any{mustID(t), A.org, A.agent}, checkViolation},
			{"delete a sponsor that still has agents", `DELETE FROM users WHERE id = $1`, []any{A.user}, fkViolation},
		} {
			t.Run(c.name, func(t *testing.T) {
				_, err := db.Exec(ctx, c.sql, c.args...)
				if err == nil {
					t.Fatal("database accepted it")
				}
				if got := sqlState(err); got != c.want {
					t.Fatalf("refused for the wrong reason: SQLSTATE %q, want %q (%v)", got, c.want, err)
				}
			})
		}
	})
	t.Run("token row pointing at another org's principal does not authenticate", func(t *testing.T) {
		// Defence in depth: even a token row written with org A and a principal
		// of org B (a bug elsewhere, or a hand-edited row) must not resolve.
		tok, err := identity.GenerateToken(identity.KindUser)
		if err != nil {
			t.Fatal(err)
		}
		exec(t, db, `INSERT INTO tokens (id, org_id, kind, principal_id, token_hash, last4, scope) VALUES ($1,$2,'u',$3,$4,'0000','s')`,
			mustID(t), A.org, B.user, identity.HashToken(tok))
		if p, err := A.repo.Authenticate(context.Background(), tok); err == nil {
			t.Fatalf("authenticated as %+v", p)
		}
	})
}

// TestIdentity_UniformUnauthenticated — the client sees one failure. Every
// way of being unauthenticated yields the same status, headers and body
// (modulo the request id), and none names the reason.
func TestIdentity_UniformUnauthenticated(t *testing.T) {
	db := attackDB(t)
	w := newWorld(t, db)
	a := newApp(w.repo)
	good := w.issue(t, identity.KindAgent, nil)
	past := time.Now().Add(-time.Minute)
	expired := w.issue(t, identity.KindUser, &past)
	revoked := w.issue(t, identity.KindService, nil)
	if err := w.repo.Revoke(context.Background(), identity.Principal{OrgID: w.org}, revoked.TokenID); err != nil {
		t.Fatal(err)
	}
	// deleted principals of each kind: a token that outlives its principal
	// must fail like any other, whichever table the principal lived in.
	gone := map[identity.Kind]string{}
	for _, k := range []identity.Kind{identity.KindAgent, identity.KindService, identity.KindUser} {
		id := mustID(t)
		switch k {
		case identity.KindAgent:
			exec(t, db, `INSERT INTO agents (id, org_id, sponsor_user_id, name) VALUES ($1,$2,$3,'g')`, id, w.org, w.user)
		case identity.KindService:
			exec(t, db, `INSERT INTO services (id, org_id, owner_scope, name) VALUES ($1,$2,'org:x','g')`, id, w.org)
		case identity.KindUser:
			exec(t, db, `INSERT INTO users (id, org_id, email) VALUES ($1,$2,$3)`, id, w.org, id.String()+"@g.test")
		}
		r, err := w.repo.Issue(context.Background(), identity.IssueParams{OrgID: w.org, Kind: k, PrincipalID: id, Scope: "s"})
		if err != nil {
			t.Fatal(err)
		}
		tok := reveal(r.Token)
		if r := a.do("GET", "/me", bearer(tok), ""); r.status != 200 {
			t.Fatalf("control: token of a live %s principal got %d", k, r.status)
		}
		tbl := map[identity.Kind]string{identity.KindAgent: "agents", identity.KindService: "services", identity.KindUser: "users"}[k]
		exec(t, db, fmt.Sprintf(`DELETE FROM %s WHERE id=$1`, tbl), id)
		gone[k] = tok
	}
	unknown := generated(t, identity.KindAgent)

	if r := a.do("GET", "/me", bearer(good.Token), ""); r.status != 200 {
		t.Fatalf("control: valid token got %d", r.status)
	}

	cases := map[string]map[string][]string{
		"no header":                nil,
		"empty bearer":             {"Authorization": {"Bearer "}},
		"bearer only":              {"Authorization": {"Bearer"}},
		"basic":                    {"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("u:"+good.Token))}},
		"lowercase scheme":         {"Authorization": {"bearer " + good.Token}},
		"token without scheme":     {"Authorization": {good.Token}},
		"garbage":                  bearer("garbage"),
		"well-formed unknown":      bearer(unknown),
		"expired":                  bearer(expired.Token),
		"revoked":                  bearer(revoked.Token),
		"deleted agent":            bearer(gone[identity.KindAgent]),
		"deleted service":          bearer(gone[identity.KindService]),
		"deleted user":             bearer(gone[identity.KindUser]),
		"kind swapped":             bearer(strings.Replace(good.Token, "_a_", "_u_", 1)),
		"uppercase":                bearer(strings.ToUpper(good.Token)),
		"trailing junk":            bearer(good.Token + "0"),
		"garbage first, real next": {"Authorization": {"Bearer garbage", "Bearer " + good.Token}},
	}
	baseline := a.do("GET", "/me", bearer("garbage"), "")
	want := baseline.shape()
	if !strings.HasPrefix(want, "401|") || !strings.Contains(want, "unauthenticated") {
		t.Fatalf("control: baseline failure is not the unauthenticated shape: %s", baseline.outline())
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			r := a.do("GET", "/me", h, "")
			if r.shape() != want {
				t.Errorf("distinguishable failure (values are not printed: a body or header may carry the credential)\n got  %s\n want %s", r.outline(), baseline.outline())
			}
			for _, word := range []string{"expired", "revoked", "unknown", "malformed", "deleted", "principal", "sponsor"} {
				if strings.Contains(strings.ToLower(r.body), word) {
					t.Errorf("response names a reason (%q): %s", word, r.outline())
				}
			}
		})
	}
}

// TestIdentity_HeaderFuzz — mutations and junk in Authorization never
// authenticate as anyone but the token's owner, and never produce a 5xx or a
// panic. Whitespace around a real token is the one tolerated variant.
func TestIdentity_HeaderFuzz(t *testing.T) {
	db := attackDB(t)
	w := newWorld(t, db)
	a := newApp(w.repo)
	tok := w.issue(t, identity.KindAgent, nil).Token

	inputs := map[string]string{
		"sqli quote":        "keep_a_' OR '1'='1",
		"sqli in body":      strings.Replace(tok, tok[len(tok)-5:], "';--x", 1),
		"nul byte":          tok + "\x00",
		"crlf":              tok + "\r\nX-Injected: 1",
		"tab":               "\t" + tok,
		"fullwidth k":       "ｋeep" + tok[4:],
		"turkish i":         strings.Replace(tok, "e", "ė", 1),
		"padded base32":     tok + "====",
		"urlencoded":        strings.ReplaceAll(tok, "_", "%5F"),
		"1 MiB":             "keep_a_" + strings.Repeat("a", 1<<20),
		"only prefix":       "keep_a_",
		"prefix twice":      "keep_a_" + tok,
		"other kind prefix": "keep_x_" + tok[7:],
		"empty":             "",
		"long spaces":       strings.Repeat(" ", 4096),
	}
	for name, in := range inputs {
		t.Run(name, func(t *testing.T) {
			var r resp
			func() {
				defer func() {
					if p := recover(); p != nil {
						t.Fatalf("panic: %T (%d chars)", p, len(fmt.Sprint(p)))
					}
				}()
				r = a.do("GET", "/me", map[string][]string{"Authorization": {"Bearer " + in}}, "")
			}()
			if r.status >= 500 {
				t.Fatalf("server error %d on junk input", r.status)
			}
			if r.status == 200 && !strings.Contains(r.body, w.agent.String()) {
				t.Fatalf("authenticated as someone else: %s", r.outline())
			}
			// Whitespace around the token is the one tolerated variant: anything
			// else that authenticates is a token the server invented.
			if r.status == 200 && strings.TrimSpace(in) != tok {
				t.Fatalf("input that is not the token authenticated")
			}
		})
	}
	if r := a.do("GET", "/me", bearer(tok), ""); r.status != 200 {
		t.Fatalf("control: real token got %d", r.status)
	}
}

// TestIdentity_AgentNeverExceedsSponsor — tenancy model §4, C-agent-⊆-sponsor.
// An agent's permissions are the intersection of its sponsor's role in the
// scope and its own grants, recomputed every call. The expected values below
// are this test's own table, written from the model, not read from the
// package under attack.
func TestIdentity_AgentNeverExceedsSponsor(t *testing.T) {
	db := attackDB(t)
	ctx := context.Background()
	rolePerms := map[string][]string{
		"":       {},
		"viewer": {"read_metadata"},
		"member": {"read_metadata", "deploy"},
		"admin":  {"read_metadata", "deploy", "rotate", "create_ref"},
	}
	agentHas := func(grants []string) map[string]bool { // defaults + explicit
		m := map[string]bool{"read_metadata": true, "deploy": true}
		for _, g := range grants {
			m[g] = true
		}
		return m
	}
	grantSets := [][]string{nil, {"rotate"}, {"create_ref"}, {"rotate", "create_ref"}}
	const scope = "ws:attack"

	for role, sp := range rolePerms {
		for _, grants := range grantSets {
			t.Run(fmt.Sprintf("role=%q grants=%v", role, grants), func(t *testing.T) {
				w := newWorld(t, db)
				w.setMembership(t, scope, role)
				w.setGrants(t, grants...)
				p := authenticate(t, w, w.issue(t, identity.KindAgent, nil).Token)
				got, err := w.repo.EffectiveAgentPermissions(ctx, p, scope)
				if err != nil {
					t.Fatal(err)
				}
				want := map[string]bool{}
				ag := agentHas(grants)
				for _, perm := range sp {
					if ag[perm] {
						want[perm] = true
					}
				}
				gotS := map[string]bool{}
				for k, v := range got {
					if v {
						gotS[string(k)] = true
					}
				}
				if fmt.Sprint(gotS) != fmt.Sprint(want) {
					t.Fatalf("effective %v, want %v", gotS, want)
				}
				for perm := range gotS {
					in := false
					for _, s := range sp {
						in = in || s == perm
					}
					if !in {
						t.Fatalf("agent holds %q that its sponsor (%q) does not", perm, role)
					}
				}
			})
		}
	}

	effective := func(t *testing.T, w world, p identity.Principal, scope string) map[identity.Permission]bool {
		t.Helper()
		got, err := w.repo.EffectiveAgentPermissions(ctx, p, scope)
		if err != nil {
			t.Fatalf("EffectiveAgentPermissions(%s): %v", scope, err)
		}
		return got
	}

	t.Run("sponsor demoted: the agent's very next call loses it", func(t *testing.T) {
		w := newWorld(t, db)
		w.setMembership(t, scope, "admin")
		w.setGrants(t, "rotate", "create_ref")
		p := authenticate(t, w, w.issue(t, identity.KindAgent, nil).Token)
		before := effective(t, w, p, scope)
		if !before[identity.PermRotate] {
			t.Fatal("control: admin sponsor + rotate grant must allow rotate")
		}
		w.setMembership(t, scope, "viewer")
		after := effective(t, w, p, scope) // same Principal, no re-auth
		if !after[identity.PermReadMetadata] {
			t.Fatal("control: a viewer sponsor still lets the agent read metadata")
		}
		if after[identity.PermRotate] || after[identity.PermCreateRef] || after[identity.PermDeploy] {
			t.Fatalf("stale rights after demotion: %v", after)
		}
		w.setMembership(t, scope, "")
		if none := effective(t, w, p, scope); len(none) != 0 {
			t.Fatalf("stale rights after membership removed: %v", none)
		}
	})
	t.Run("rights in one scope do not leak into another", func(t *testing.T) {
		w := newWorld(t, db)
		w.setMembership(t, "ws:one", "admin")
		w.setGrants(t, "rotate")
		p := authenticate(t, w, w.issue(t, identity.KindAgent, nil).Token)
		// Control: the rights exist where the membership is. An empty answer
		// for ws:two means nothing unless ws:one is not empty.
		if own := effective(t, w, p, "ws:one"); !own[identity.PermRotate] || !own[identity.PermDeploy] {
			t.Fatalf("control: the admin sponsor's scope gives the agent no rights: %v", own)
		}
		if got := effective(t, w, p, "ws:two"); len(got) != 0 {
			t.Fatalf("scope leak: %v", got)
		}
	})
	t.Run("another agent's grants are not mine", func(t *testing.T) {
		w := newWorld(t, db)
		w.setMembership(t, scope, "admin")
		other := mustID(t)
		exec(t, db, `INSERT INTO agents (id, org_id, sponsor_user_id, name) VALUES ($1,$2,$3,'other')`, other, w.org, w.user)
		exec(t, db, `INSERT INTO agent_grants (id, org_id, agent_id, permission) VALUES ($1,$2,$3,'rotate')`, mustID(t), w.org, other)
		p := authenticate(t, w, w.issue(t, identity.KindAgent, nil).Token)
		got := effective(t, w, p, scope)
		if !got[identity.PermDeploy] {
			t.Fatalf("control: the agent has no default rights in its sponsor's scope: %v", got)
		}
		if got[identity.PermRotate] {
			t.Fatal("agent inherited a sibling agent's rotate grant")
		}
	})
	t.Run("forged principals get nothing", func(t *testing.T) {
		A, B := newWorld(t, db), newWorld(t, db)
		B.setMembership(t, scope, "admin")
		B.setGrants(t, "rotate", "create_ref")
		A.setMembership(t, scope, "admin")
		A.setGrants(t, "rotate", "create_ref")
		pa := authenticate(t, A, A.issue(t, identity.KindAgent, nil).Token)
		pu := authenticate(t, A, A.issue(t, identity.KindUser, nil).Token)
		// Control: a genuine agent in this very scope holds the permissions the
		// forgeries below try to reach — otherwise "no rotate" would hold for
		// every principal and prove nothing.
		if real := effective(t, A, pa, scope); !real[identity.PermRotate] || !real[identity.PermCreateRef] {
			t.Fatalf("control: the genuine agent lacks its explicit grants: %v", real)
		}
		sponsorA, sponsorB := A.user, B.user
		forged := map[string]identity.Principal{
			"user token as agent":         pu,
			"service kind":                {Kind: identity.KindService, ID: A.service, OrgID: A.org},
			"service kind with a sponsor": {Kind: identity.KindService, ID: A.service, OrgID: A.org, SponsorUserID: &sponsorA},
			"user kind with a sponsor":    {Kind: identity.KindUser, ID: A.user, OrgID: A.org, SponsorUserID: &sponsorA},
			"agent without sponsor":       {Kind: identity.KindAgent, ID: A.agent, OrgID: A.org},
			"A agent, sponsor from B":     {Kind: identity.KindAgent, ID: pa.ID, OrgID: A.org, SponsorUserID: &sponsorB},
			"B agent claimed under org A": {Kind: identity.KindAgent, ID: B.agent, OrgID: A.org, SponsorUserID: &sponsorA},
			"A agent claimed under org B": {Kind: identity.KindAgent, ID: pa.ID, OrgID: B.org, SponsorUserID: &sponsorB},
		}
		// The forged principals with no sponsor of their own kind or org get
		// nothing at all; the two "claimed under" ones may keep the defaults a
		// real sponsor's role gives (a caller-built Principal is the caller's
		// own claim), but never an explicit grant of another organization.
		mustBeEmpty := map[string]bool{
			"user token as agent": true, "service kind": true, "service kind with a sponsor": true,
			"user kind with a sponsor": true, "agent without sponsor": true, "A agent, sponsor from B": true,
		}
		for name, p := range forged {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("%s: EffectiveAgentPermissions panicked: %T (%d chars)", name, r, len(fmt.Sprint(r)))
					}
				}()
				// Refusing outright (err != nil) is a valid answer to a forged
				// principal, but a backend error must not excuse a result that
				// leaks a grant alongside it — got is checked below regardless
				// of err; a nil map (the error path) denies everything by
				// definition, so this adds no false failure on the clean-refusal
				// path.
				got, _ := A.repo.EffectiveAgentPermissions(ctx, p, scope)
				if got[identity.PermRotate] || got[identity.PermCreateRef] {
					t.Errorf("%s: forged principal holds an explicit-grant permission: %v", name, got)
				}
				if mustBeEmpty[name] && len(got) != 0 {
					t.Errorf("%s: got rights %v, want none", name, got)
				}
			}()
		}
	})
}

func authenticate(t *testing.T, w world, tok string) identity.Principal {
	t.Helper()
	p, err := w.repo.Authenticate(context.Background(), identity.NewToken(tok))
	if err != nil {
		t.Fatalf("control: authenticate: %T, %d chars", err, len(err.Error()))
	}
	return p
}

// TestIdentity_RevocationAndDeletionAreImmediate — no cache, no grace: the
// request after Revoke / expiry / principal deletion is refused, for every
// token kind, including under concurrent load.
func TestIdentity_RevocationAndDeletionAreImmediate(t *testing.T) {
	db := attackDB(t)
	ctx := context.Background()

	for _, kind := range []identity.Kind{identity.KindAgent, identity.KindService, identity.KindUser} {
		t.Run("delete principal kind="+string(kind), func(t *testing.T) {
			w := newWorld(t, db)
			// a dedicated principal so deleting it does not disturb the world
			pid := mustID(t)
			switch kind {
			case identity.KindAgent:
				exec(t, db, `INSERT INTO agents (id, org_id, sponsor_user_id, name) VALUES ($1,$2,$3,'d')`, pid, w.org, w.user)
			case identity.KindService:
				exec(t, db, `INSERT INTO services (id, org_id, owner_scope, name) VALUES ($1,$2,'org:x','d')`, pid, w.org)
			case identity.KindUser:
				exec(t, db, `INSERT INTO users (id, org_id, email) VALUES ($1,$2,$3)`, pid, w.org, pid.String()+"@d.test")
			}
			res, err := w.repo.Issue(ctx, identity.IssueParams{OrgID: w.org, Kind: kind, PrincipalID: pid, Scope: "s"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.repo.Authenticate(ctx, res.Token); err != nil {
				t.Fatalf("control: %T, %d chars", err, len(err.Error()))
			}
			tbl := map[identity.Kind]string{identity.KindAgent: "agents", identity.KindService: "services", identity.KindUser: "users"}[kind]
			exec(t, db, fmt.Sprintf(`DELETE FROM %s WHERE id = $1`, tbl), pid)
			if p, err := w.repo.Authenticate(ctx, res.Token); err == nil {
				t.Fatalf("token of a deleted %s still authenticates as %+v", tbl, p)
			}
		})
	}

	t.Run("expiry set to the past takes effect on the next call", func(t *testing.T) {
		w := newWorld(t, db)
		future := time.Now().Add(time.Hour)
		res := w.issue(t, identity.KindService, &future)
		authenticate(t, w, res.Token)
		exec(t, db, `UPDATE tokens SET expires_at = now() - interval '1 second' WHERE id = $1`, res.TokenID)
		if p, err := w.repo.Authenticate(ctx, res.IssueResult.Token); !errors.Is(err, identity.ErrUnauthenticated) {
			if err == nil {
				t.Fatalf("expired token still authenticates as %+v", p)
			}
			t.Fatalf("expired token: %T, %d chars", err, len(err.Error()))
		}
	})
	t.Run("revoke under concurrent load: nothing authenticates after Revoke returns", func(t *testing.T) {
		w := newWorld(t, db)
		res := w.issue(t, identity.KindService, nil)
		stop := make(chan struct{})
		var stopOnce sync.Once
		stopAll := func() { stopOnce.Do(func() { close(stop) }) }
		var wg sync.WaitGroup
		var revoked atomic.Bool
		var staleSuccesses atomic.Int64
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					// The flag is read BEFORE the call, not after: a call already
					// in flight when Revoke commits may legitimately have read
					// pre-revoke state and still succeed. Only a call that starts
					// after the flag is set and still succeeds is a violation.
					startedAfterRevoke := revoked.Load()
					if _, err := w.repo.Authenticate(ctx, res.IssueResult.Token); err == nil && startedAfterRevoke {
						staleSuccesses.Add(1)
					}
				}
			}()
		}
		// Whatever happens below (including a t.Fatal, which runs Goexit and
		// skips the rest of this closure), the goroutines must be told to stop
		// and be waited on exactly once — otherwise they spin on Authenticate
		// forever, past this subtest and past t.Cleanup(pool.Close) on the
		// world's own pool.
		t.Cleanup(func() {
			stopAll()
			wg.Wait()
		})
		time.Sleep(50 * time.Millisecond)
		if err := w.repo.Revoke(ctx, identity.Principal{OrgID: w.org}, res.TokenID); err != nil {
			t.Fatal(err)
		}
		revoked.Store(true)
		for i := 0; i < 200; i++ {
			if _, err := w.repo.Authenticate(ctx, res.IssueResult.Token); err == nil {
				t.Fatalf("authenticated %d calls after Revoke returned", i)
			}
		}
		stopAll()
		wg.Wait()
		// The goroutines' own results are the point of "under load": a success
		// any of them observed after the revoked flag was set is a real window
		// where a concurrent caller was still authenticating a revoked token,
		// not just the sequential probe above.
		if n := staleSuccesses.Load(); n != 0 {
			t.Fatalf("%d concurrent Authenticate calls succeeded after Revoke set the revoked flag", n)
		}
		if err := w.repo.Revoke(ctx, identity.Principal{OrgID: w.org}, res.TokenID); !errors.Is(err, identity.ErrTokenUnknown) {
			t.Fatalf("second revoke: %s", safe(err.Error()))
		}
	})
}

// TestIdentity_NoForgedPrincipal — nothing outside RequireAuth can put a
// Principal into a context: the attack is a context the caller builds, with
// foreign key types and with the key names a guesser would try for a
// string-keyed context value.
func TestIdentity_NoForgedPrincipal(t *testing.T) {
	db := attackDB(t)
	w := newWorld(t, db)
	a := newApp(w.repo)
	tok := w.issue(t, identity.KindAgent, nil).Token

	t.Run("control: RequireAuth does put a Principal in the context", func(t *testing.T) {
		r := a.do("GET", "/me", bearer(tok), "")
		if r.status != 200 || !strings.Contains(r.body, w.agent.String()) {
			t.Fatalf("got %d %s", r.status, r.outline())
		}
	})

	forged := identity.Principal{Kind: identity.KindUser, ID: w.user, OrgID: w.org}
	type structKey struct{}
	type namedKey string
	t.Run("contexts built by the caller carry none", func(t *testing.T) {
		ctxs := map[string]context.Context{
			"empty":                context.Background(),
			"struct key":           context.WithValue(context.Background(), structKey{}, forged),
			"request id":           reqid.WithContext(context.Background(), "x"),
			"typed key principal":  context.WithValue(context.Background(), namedKey("principal"), forged),
			"principal as its key": context.WithValue(context.Background(), forged, forged),
		}
		// The names a guesser would try when the value is stored under a plain
		// string: what a Principal is called in this codebase, in a few spellings.
		for _, name := range []string{"principal", "Principal", "identity.principal", "identity.Principal", "principalCtxKey", "keep.principal", "org_id"} {
			// A plain string key is what the lint rule forbids and what the attack needs.
			ctxs["string key "+name] = context.WithValue(context.Background(), name, forged) //nolint:staticcheck // SA1029: the attack is a guessable plain-string key
		}
		for name, ctx := range ctxs {
			t.Run(name, func(t *testing.T) {
				if p, ok := identity.FromContext(ctx); ok {
					t.Fatalf("FromContext returned a Principal: %+v", p)
				}
			})
		}
	})
}

// TestIdentity_ParseKindIsStrict — a token's kind is read from its text, and
// only from text of exactly the issued shape: the anchors of the shape are
// what keep a longer string with a token inside it (or a token with something
// after it) from being routed to a lookup as if it were one. The database
// lookup that follows hashes the whole text, so an unanchored pattern would
// still not authenticate anything today; this attack pins the parser itself,
// because nothing else does.
func TestIdentity_ParseKindIsStrict(t *testing.T) {
	agent := generated(t, identity.KindAgent)
	for kind, tok := range map[identity.Kind]string{
		identity.KindAgent:   agent,
		identity.KindService: generated(t, identity.KindService),
		identity.KindUser:    generated(t, identity.KindUser),
	} {
		t.Run("control: a well-formed "+string(kind)+" token", func(t *testing.T) {
			got, err := identity.ParseKind(identity.NewToken(tok))
			if err != nil {
				t.Fatalf("a well-formed token is refused: %T, %d chars", err, len(err.Error()))
			}
			if got != kind {
				t.Fatalf("got kind %s, want %q", closedValue(string(got), string(identity.KindAgent), string(identity.KindService), string(identity.KindUser)), kind)
			}
		})
	}
	for name, in := range map[string]string{
		"junk before the token": "x" + agent,
		"junk after the token":  agent + "0",
		// "0" is outside the alphabet, so the character class alone stops the
		// case above; a character inside it is stopped only by the end anchor
		// and by the fixed length.
		"an in-alphabet character after the token": agent + "a",
		"newline after":           agent + "\n",
		"newline before":          "\n" + agent,
		"space around":            " " + agent + " ",
		"token twice":             agent + agent,
		"one character short":     agent[:len(agent)-1],
		"digit outside base32":    agent[:len(agent)-1] + "1",
		"upper-case body":         strings.ToUpper(agent),
		"unknown kind letter":     "keep_x_" + agent[len("keep_a_"):],
		"missing separator":       "keep_a" + agent[len("keep_a_"):],
		"empty":                   "",
		"prefix only":             "keep_a_",
		"a token inside a header": "Bearer " + agent,
	} {
		t.Run(name, func(t *testing.T) {
			kind, err := identity.ParseKind(identity.NewToken(in))
			if err == nil {
				t.Fatalf("parsed as kind %s", closedValue(string(kind), string(identity.KindAgent), string(identity.KindService), string(identity.KindUser)))
			}
			// The content check comes first: nothing below prints an error
			// that has not been shown token-free.
			if strings.Contains(err.Error(), agent[len("keep_a_"):]) {
				t.Fatal("the error carries the token")
			}
			// Exact identity, not errors.Is: a wrapped sentinel (say,
			// fmt.Errorf("%w: %x", ErrMalformedToken, identity.Reveal(token))) still
			// satisfies errors.Is while its own text can carry the token in an
			// encoding the content check above does not recognize as the same
			// bytes (hex, unlike the base32 substring checked for) — only ==
			// on the sentinel itself rules that construction out. The failure
			// message below prints the error's type and length, never its
			// text, since a mismatch here is exactly the case that text might
			// carry the token.
			if err != identity.ErrMalformedToken {
				t.Fatalf("error is not exactly ErrMalformedToken: %T, %d chars", err, len(err.Error()))
			}
		})
	}
}

// TestIdentity_TokenRowKindMustMatch — the kind stored beside a token's hash
// is part of what the token is: a row whose kind column disagrees with the
// kind written in the token's own text (a bug elsewhere, a hand-edited row)
// must not authenticate, even when its principal is a real one of the kind the
// token claims. The hash alone cannot decide this — the row was written by
// whoever wrote it.
func TestIdentity_TokenRowKindMustMatch(t *testing.T) {
	db := attackDB(t)
	w := newWorld(t, db)
	ctx := context.Background()
	principals := map[identity.Kind]uuid.UUID{identity.KindAgent: w.agent, identity.KindService: w.service, identity.KindUser: w.user}
	insert := func(t *testing.T, tok identity.Token, rowKind identity.Kind, principal uuid.UUID) {
		t.Helper()
		exec(t, db, `INSERT INTO tokens (id, org_id, kind, principal_id, token_hash, last4, scope) VALUES ($1,$2,$3,$4,$5,'0000','s')`,
			mustID(t), w.org, string(rowKind), principal, identity.HashToken(tok))
	}
	for tokKind, principal := range principals {
		t.Run("control: row kind "+string(tokKind)+" matches", func(t *testing.T) {
			tok, err := identity.GenerateToken(tokKind)
			if err != nil {
				t.Fatal(err)
			}
			insert(t, tok, tokKind, principal)
			if _, err := w.repo.Authenticate(ctx, tok); err != nil {
				t.Fatalf("a consistent row does not authenticate: %T, %d chars", err, len(err.Error()))
			}
		})
		for rowKind := range principals {
			if rowKind == tokKind {
				continue
			}
			t.Run("token kind "+string(tokKind)+" row kind "+string(rowKind), func(t *testing.T) {
				tok, err := identity.GenerateToken(tokKind)
				if err != nil {
					t.Fatal(err)
				}
				insert(t, tok, rowKind, principal)
				p, err := w.repo.Authenticate(ctx, tok)
				if err == nil {
					t.Fatalf("a row of kind %q authenticated a token of kind %q as %+v", rowKind, tokKind, p)
				}
				// Any error would do for "does not authenticate" — a database
				// error included, which RequireAuth answers as 503 and which is
				// not an authentication verdict. The mismatch must be the
				// verdict itself.
				if !errors.Is(err, identity.ErrUnauthenticated) {
					t.Fatalf("a kind mismatch is not an authentication verdict: %T, %d chars", err, len(err.Error()))
				}
			})
		}
	}
}

// TestIdentity_AuthFailureLog — the operator's view of a failed
// authentication (threat model §4.4): every way of failing, on every path
// through RequireAuth, leaves exactly one line, with the closed reason and
// the request's own id and nothing else — no header, no token, no error text.
// The absence of the line matters as much as its content: a path that fails
// silently is a path an operator cannot see being probed.
func TestIdentity_AuthFailureLog(t *testing.T) {
	db := attackDB(t)
	w := newWorld(t, db)
	ctx := context.Background()
	good := w.issue(t, identity.KindAgent, nil).Token
	past := time.Now().Add(-time.Minute)
	expired := w.issue(t, identity.KindUser, &past).Token
	revoked := w.issue(t, identity.KindService, nil)
	if err := w.repo.Revoke(ctx, identity.Principal{OrgID: w.org}, revoked.TokenID); err != nil {
		t.Fatal(err)
	}
	dead, err := pgxpool.New(ctx, os.Getenv("KEEP_DATABASE_URL"))
	if err != nil {
		t.Fatalf("control: cannot build the pool that is then closed to stand in for a dead database: %s", safe(err.Error()))
	}
	dead.Close()

	basic := base64.StdEncoding.EncodeToString([]byte("u:" + good))
	cases := []struct {
		name, reason string
		hdr          []string // Authorization values; none = header absent
		repo         *identity.Repo
	}{
		{"no header", "malformed", nil, w.repo},
		{"token without scheme", "malformed", []string{good}, w.repo},
		{"basic with the token inside", "malformed", []string{"Basic " + basic}, w.repo},
		{"lowercase scheme", "malformed", []string{"bearer " + good}, w.repo},
		{"empty bearer", "malformed", []string{"Bearer "}, w.repo},
		{"garbage bearer", "malformed", []string{"Bearer " + good + "0"}, w.repo},
		{"well-formed unknown", "unknown", []string{"Bearer " + generated(t, identity.KindAgent)}, w.repo},
		{"expired", "expired", []string{"Bearer " + expired}, w.repo},
		{"revoked", "revoked", []string{"Bearer " + revoked.Token}, w.repo},
		{"database down", "backend", []string{"Bearer " + good}, identity.NewRepo(dead)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := newApp(c.repo)
			const rid = "req-authlog-0001"
			hdr := map[string][]string{reqid.HeaderName: {rid}}
			if c.hdr != nil {
				hdr["Authorization"] = c.hdr
			}
			if r := a.do("GET", "/me", hdr, ""); r.status != 401 && r.status != 503 {
				t.Fatalf("control: the request must fail, got %d", r.status)
			}
			lines := strings.Split(strings.TrimSpace(a.log.String()), "\n")
			if len(lines) != 1 || lines[0] == "" {
				// Counts only: the log is the thing that must not carry the
				// header, and a failing check must not print it either.
				t.Fatalf("want exactly one log line for a failed authentication, got %d lines, %d bytes", len(lines), a.log.Len())
			}
			var rec map[string]any
			if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
				t.Fatalf("log line is not JSON (%d bytes): %s", len(lines[0]), safe(err.Error()))
			}
			for k := range rec {
				switch k {
				case "time", "level", "msg", "auth_reason", "request_id":
				default:
					t.Errorf("log line carries key %s beyond the closed set", printableName(k))
				}
			}
			if rec["msg"] != "identity: authentication failed" || rec["auth_reason"] != c.reason || rec["request_id"] != rid {
				// The closed values only; anything outside them is reduced to
				// its length, and the line itself is never printed.
				t.Fatalf("log line is not the closed shape: msg=%s auth_reason=%s (want %q) request_id_matches=%v, %d bytes",
					closedValue(rec["msg"], "identity: authentication failed"), closedValue(rec["auth_reason"], "malformed", "unknown", "expired", "revoked", "backend"),
					c.reason, rec["request_id"] == rid, len(lines[0]))
			}
			if canary.Of(good).In(a.log.String()) || strings.Contains(a.log.String(), "Basic") || strings.Contains(a.log.String(), basic) {
				t.Fatal("the log line carries the credential or its header")
			}
		})
	}
}
