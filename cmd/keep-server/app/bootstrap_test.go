package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type bootstrapRun struct {
	code           int
	stdout, stderr string
	log            string
}

func testBootstrapDeps(t *testing.T, pool *pgxpool.Pool, logBuf *bytes.Buffer) bootstrapDeps {
	t.Helper()
	root := make([]byte, 32)
	if _, err := rand.Read(root); err != nil {
		t.Fatal(err)
	}
	local, err := builtin.NewLocal(pool, "test-v1", root, nil, func(builtin.KeyEvent) {})
	if err != nil {
		t.Fatalf("local: %v", err)
	}
	return bootstrapDeps{pool: pool, local: local, logger: obs.New(logBuf)}
}

func runBootstrap(t *testing.T, pool *pgxpool.Pool, args ...string) bootstrapRun {
	t.Helper()
	var out, errb, logb bytes.Buffer
	code := bootstrapOrg(context.Background(), testBootstrapDeps(t, pool, &logb), args, &out, &errb)
	return bootstrapRun{code: code, stdout: out.String(), stderr: errb.String(), log: logb.String()}
}

// tokenForms are the shapes a token can leave in: as is, hex, base64 (three
// shifts: the encoding works on byte triples), URL-escaped, reversed.
func tokenForms(tok string) []string {
	rev := []byte(tok)
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	forms := []string{tok, hex.EncodeToString([]byte(tok)), url.QueryEscape(tok), string(rev)}
	for _, p := range []string{"", "x", "xx"} {
		forms = append(forms, base64.StdEncoding.EncodeToString([]byte(p+tok)), base64.RawURLEncoding.EncodeToString([]byte(p+tok)))
	}
	return forms
}

func tokenIn(tok, text string) bool {
	for _, f := range tokenForms(tok) {
		// A base64 shift leaves partial leading/trailing quads; match the middle.
		if len(f) > 24 {
			f = f[8 : len(f)-8]
		}
		if strings.Contains(strings.ToLower(text), strings.ToLower(f)) {
			return true
		}
	}
	return false
}

func readToken(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: path is the test's own temp file
	if err != nil {
		t.Fatalf("read token file: %v", err)
	}
	return strings.TrimSpace(string(b))
}

// The token is only in --token-file: not in stdout, stderr, the log, the
// audit journal, nor any other file in the directory. Positive controls make
// sure the detector and every interception are alive.
func TestBootstrapOrg_TokenOnlyInFile(t *testing.T) {
	pool := testPool(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "admin.token")

	res := runBootstrap(t, pool, "--ttl", "24h", "--name", "acme", "--admin-email", "admin@acme.test", "--token-file", path)
	if res.code != 0 {
		t.Fatalf("exit %d, stderr %q", res.code, res.stderr)
	}
	tok := readToken(t, path)
	if !strings.HasPrefix(tok, "keep_u_") {
		t.Fatalf("token file does not hold a user token")
	}
	if !tokenIn(tok, "prefix "+tok) || !tokenIn(tok, base64.StdEncoding.EncodeToString([]byte("xx"+tok))) || tokenIn(tok, "nothing here") {
		t.Fatal("token detector is blind or trigger-happy; the test proves nothing")
	}
	if res.log == "" || res.stdout == "" {
		t.Fatalf("interception empty (log %d bytes, stdout %d bytes)", len(res.log), len(res.stdout))
	}
	var audit string
	if err := pool.QueryRow(context.Background(), `SELECT coalesce(string_agg(to_jsonb(a)::text, E'\n'), '') FROM audit_records a`).Scan(&audit); err != nil || audit == "" {
		t.Fatalf("read journal: %v (len %d)", err, len(audit))
	}
	for name, text := range map[string]string{"stdout": res.stdout, "stderr": res.stderr, "log": res.log, "audit": audit} {
		if tokenIn(tok, text) {
			t.Errorf("token leaked into %s", name)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("directory of --token-file holds %d entries, want only the token file", len(entries))
	}
	if !strings.Contains(res.stdout, "org_id=") || !strings.Contains(res.stdout, path) {
		t.Errorf("stdout %q must carry org_id and the file path", res.stdout)
	}
}

func TestBootstrapOrg_FileMode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	pool := testPool(t)
	path := filepath.Join(t.TempDir(), "admin.token")
	if res := runBootstrap(t, pool, "--ttl", "24h", "--name", "acme", "--admin-email", "a@acme.test", "--token-file", path); res.code != 0 {
		t.Fatalf("exit %d: %s", res.code, res.stderr)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("token file mode %o, want 600", st.Mode().Perm())
	}
}

// Org, CA, admin membership and a working admin token are all there, as with
// an ordinary organization creation.
func TestBootstrapOrg_CreatesOrgCAAdminAndJournal(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "admin.token")
	res := runBootstrap(t, pool, "--ttl", "24h", "--name", "acme", "--admin-email", "a@acme.test", "--token-file", path)
	if res.code != 0 {
		t.Fatalf("exit %d: %s", res.code, res.stderr)
	}
	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM organizations WHERE name = 'acme'`).Scan(&orgID); err != nil {
		t.Fatalf("org row: %v", err)
	}
	if !strings.Contains(res.stdout, orgID.String()) {
		t.Errorf("stdout %q does not name the org id", res.stdout)
	}
	var expires time.Time
	if err := pool.QueryRow(ctx, `SELECT expires_at FROM tokens WHERE org_id = $1`, orgID).Scan(&expires); err != nil {
		t.Fatalf("token expiry: %v", err)
	}
	if d := time.Until(expires); d < 23*time.Hour || d > 25*time.Hour {
		t.Errorf("token expires in %v, want --ttl 24h", d)
	}
	if want := "org_id=" + orgID.String() + "\ntoken_file=" + path + "\n"; res.stdout != want {
		t.Errorf("stdout %q, want exactly %q: only org_id and the file path", res.stdout, want)
	}
	var caRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM org_ca WHERE org_id = $1`, orgID).Scan(&caRows); err != nil || caRows != 1 {
		t.Errorf("org CA rows = %d (err %v), want 1", caRows, err)
	}
	p, err := identity.NewRepo(pool).Authenticate(ctx, identity.NewToken(readToken(t, path)))
	if err != nil {
		t.Fatalf("token does not authenticate: %v", err)
	}
	if p.Kind != identity.KindUser || p.OrgID != orgID {
		t.Errorf("principal %v/%v, want user of org %v", p.Kind, p.OrgID, orgID)
	}
	var role string
	if err := pool.QueryRow(ctx, `SELECT role FROM memberships WHERE org_id = $1 AND user_id = $2 AND scope = $3`, orgID, p.ID, "org:"+orgID.String()).Scan(&role); err != nil || role != "admin" {
		t.Errorf("admin membership at org scope: role=%q err=%v", role, err)
	}
	var email string
	if err := pool.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, p.ID).Scan(&email); err != nil || email != "a@acme.test" {
		t.Errorf("admin email = %q (err %v), want a@acme.test", email, err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_records WHERE org_id = $1 AND scope = $2 AND action = 'org.bootstrap' AND result_status = 'ok'`, orgID.String(), "org:"+orgID.String()).Scan(&n); err != nil || n != 1 {
		t.Errorf("org.bootstrap journal records = %d (err %v), want 1", n, err)
	}
}

func TestBootstrapOrg_RepeatedNameRefused(t *testing.T) {
	pool := testPool(t)
	dir := t.TempDir()
	if res := runBootstrap(t, pool, "--ttl", "24h", "--name", "acme", "--admin-email", "a@acme.test", "--token-file", filepath.Join(dir, "one")); res.code != 0 {
		t.Fatalf("first run exit %d: %s", res.code, res.stderr)
	}
	second := filepath.Join(dir, "two")
	res := runBootstrap(t, pool, "--ttl", "24h", "--name", "acme", "--admin-email", "b@acme.test", "--token-file", second)
	if res.code == 0 || !strings.Contains(res.stderr, "already_exists") {
		t.Errorf("second run exit %d stderr %q, want failure with class already_exists", res.code, res.stderr)
	}
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM organizations WHERE name = 'acme'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("organizations named acme = %d (err %v), want 1", n, err)
	}
	if _, err := os.Stat(second); err == nil {
		t.Error("second run left a token file")
	}
}

func TestBootstrapOrg_ExistingTokenFileKeptAndNoOrg(t *testing.T) {
	pool := testPool(t)
	path := filepath.Join(t.TempDir(), "admin.token")
	if err := os.WriteFile(path, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := runBootstrap(t, pool, "--ttl", "24h", "--name", "acme", "--admin-email", "a@acme.test", "--token-file", path)
	if res.code == 0 {
		t.Fatal("overwriting an existing file must fail")
	}
	if got := readToken(t, path); got != "precious" {
		t.Errorf("existing file changed to %q", got)
	}
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM organizations`).Scan(&n); err != nil || n != 0 {
		t.Errorf("organizations = %d (err %v), want 0: refuse before creating anything", n, err)
	}
}

func TestBootstrapOrg_RelativeTokenFileRefused(t *testing.T) {
	pool := testPool(t)
	res := runBootstrap(t, pool, "--ttl", "24h", "--name", "acme", "--admin-email", "a@acme.test", "--token-file", "admin.token")
	if res.code == 0 {
		t.Fatal("relative --token-file must be refused")
	}
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM organizations`).Scan(&n); err != nil || n != 0 {
		t.Errorf("organizations = %d (err %v), want 0", n, err)
	}
}

func TestBootstrapOrg_UndeliveredTokenRevoked(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	orig := writeTokenFile
	writeTokenFile = func(string, identity.Token) error { return errors.New("disk full") }
	t.Cleanup(func() { writeTokenFile = orig })

	res := runBootstrap(t, pool, "--ttl", "24h", "--name", "acme", "--admin-email", "a@acme.test", "--token-file", filepath.Join(t.TempDir(), "admin.token"))
	if res.code == 0 {
		t.Fatal("a failed token write must fail the command")
	}
	var live, revoked int
	if err := pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE revoked_at IS NULL), count(*) FILTER (WHERE revoked_at IS NOT NULL) FROM tokens`).Scan(&live, &revoked); err != nil {
		t.Fatal(err)
	}
	if live != 0 || revoked != 1 {
		t.Errorf("tokens live=%d revoked=%d, want 0 and 1: an undelivered token must not stay valid", live, revoked)
	}
	if !strings.Contains(res.stderr, "token is revoked") {
		t.Errorf("stderr does not say the token is revoked: %q", res.stderr)
	}
}

// --ttl is required, positive and at most 720h; a refusal creates nothing.
func TestBootstrapOrg_TTLRequiredAndBounded(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	for _, ttl := range []string{"", "0s", "-1h", "721h", "abc", "30d"} {
		args := []string{"--name", "acme", "--admin-email", "a@acme.test", "--token-file", filepath.Join(t.TempDir(), "admin.token")}
		if ttl != "" {
			args = append(args, "--ttl", ttl)
		}
		res := runBootstrap(t, pool, args...)
		if res.code == 0 || !strings.Contains(res.stderr, "error_class=invalid_argument") {
			t.Errorf("--ttl %q: exit %d, stderr %q; want a refusal with class invalid_argument", ttl, res.code, res.stderr)
		}
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM organizations`).Scan(&n); err != nil || n != 0 {
		t.Errorf("organizations = %d (err %v), want 0 after refusals", n, err)
	}
	if res := runBootstrap(t, pool, "--ttl", "720h", "--name", "acme", "--admin-email", "a@acme.test", "--token-file", filepath.Join(t.TempDir(), "admin.token")); res.code != 0 {
		t.Errorf("--ttl 720h (the limit) refused: %s", res.stderr)
	}
}

// A creation of the same name that is still in flight in another transaction
// is waited for, not raced: the name check runs under a table lock.
func TestBootstrapOrg_ConcurrentSameNameRefused(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `INSERT INTO organizations (id, name, key_level) VALUES ($1, 'acme', 'user')`, uuid.New()); err != nil {
		t.Fatal(err)
	}

	var logb, out, errb bytes.Buffer
	d := testBootstrapDeps(t, pool, &logb)
	done := make(chan int, 1)
	go func() {
		done <- bootstrapOrg(ctx, d, []string{"--ttl", "24h", "--name", "acme", "--admin-email", "a@acme.test", "--token-file", filepath.Join(t.TempDir(), "admin.token")}, &out, &errb)
	}()
	// Let the command reach the database and block on the lock (or, without
	// one, finish).
	waiting := false
	for i := 0; i < 50 && !waiting; i++ {
		time.Sleep(100 * time.Millisecond)
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE NOT granted AND relation = 'organizations'::regclass)`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if len(done) > 0 {
			break
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	code := <-done
	if code == 0 || !strings.Contains(errb.String(), "error_class=already_exists") {
		t.Errorf("concurrent same name: exit %d, stderr %q; want already_exists", code, errb.String())
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM organizations WHERE name = 'acme'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("organizations named acme = %d (err %v), want 1", n, err)
	}
}
