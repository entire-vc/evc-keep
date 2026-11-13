package app

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func runIssue(t *testing.T, pool *pgxpool.Pool, args ...string) bootstrapRun {
	t.Helper()
	var out, errb, logb bytes.Buffer
	code := issueAdminToken(context.Background(), pool, obs.New(&logb), args, &out, &errb)
	return bootstrapRun{code: code, stdout: out.String(), stderr: errb.String(), log: logb.String()}
}

// issueFixture is an organization made by bootstrap-org: its admin user holds
// an admin token in a file, as an organization whose token expired would.
type issueFixture struct {
	org, admin uuid.UUID
	oldToken   string
}

func newIssueFixture(t *testing.T, pool *pgxpool.Pool, name string) issueFixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "first.token")
	if res := runBootstrap(t, pool, "--ttl", "24h", "--name", name, "--admin-email", "a@"+name+".test", "--token-file", path); res.code != 0 {
		t.Fatalf("bootstrap %s: exit %d: %s", name, res.code, res.stderr)
	}
	f := issueFixture{oldToken: readToken(t, path)}
	if err := pool.QueryRow(context.Background(), `SELECT org_id, user_id FROM memberships m JOIN organizations o ON o.id = m.org_id WHERE o.name = $1`, name).Scan(&f.org, &f.admin); err != nil {
		t.Fatal(err)
	}
	return f
}

func issueArgs(f issueFixture, path string, extra ...string) []string {
	return append([]string{"--org-id", f.org.String(), "--admin-user-id", f.admin.String(), "--ttl", "24h", "--token-file", path}, extra...)
}

type dbCounts struct {
	orgs, users, memberships, tokens, audit int
}

func counts(t *testing.T, pool *pgxpool.Pool) dbCounts {
	t.Helper()
	var c dbCounts
	if err := pool.QueryRow(context.Background(), `SELECT
		(SELECT count(*) FROM organizations), (SELECT count(*) FROM users), (SELECT count(*) FROM memberships),
		(SELECT count(*) FROM tokens), (SELECT count(*) FROM audit_records)`).Scan(&c.orgs, &c.users, &c.memberships, &c.tokens, &c.audit); err != nil {
		t.Fatal(err)
	}
	return c
}

// The token is only in --token-file: not in stdout, stderr, the log, the
// journal, nor any other file in the directory. Positive controls make sure
// the detector and every interception are alive.
func TestIssueAdminToken_TokenOnlyInFile(t *testing.T) {
	pool := testPool(t)
	f := newIssueFixture(t, pool, "acme")
	dir := t.TempDir()
	path := filepath.Join(dir, "admin.token")

	res := runIssue(t, pool, issueArgs(f, path)...)
	if res.code != 0 {
		t.Fatalf("exit %d, stderr %q", res.code, res.stderr)
	}
	tok := readToken(t, path)
	if !strings.HasPrefix(tok, "keep_u_") || tok == f.oldToken {
		t.Fatalf("token file does not hold a new user token")
	}
	if !tokenIn(tok, "prefix "+tok) || tokenIn(tok, "nothing here") {
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
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("directory of --token-file holds %d entries, want only the token file", len(entries))
	}
}

func TestIssueAdminToken_FileMode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	pool := testPool(t)
	f := newIssueFixture(t, pool, "acme")
	path := filepath.Join(t.TempDir(), "admin.token")
	if res := runIssue(t, pool, issueArgs(f, path)...); res.code != 0 {
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

// The token authenticates as the admin of that organization, expires after
// --ttl, is journaled with its id before delivery, and leaves the old token
// and everything else alone.
func TestIssueAdminToken_IssuesForTheAdminAndJournals(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	f := newIssueFixture(t, pool, "acme")
	other := newIssueFixture(t, pool, "other")
	before := counts(t, pool)
	path := filepath.Join(t.TempDir(), "admin.token")

	res := runIssue(t, pool, issueArgs(f, path)...)
	if res.code != 0 {
		t.Fatalf("exit %d: %s", res.code, res.stderr)
	}
	var tokenID uuid.UUID
	var expires time.Time
	if err := pool.QueryRow(ctx, `SELECT id, expires_at FROM tokens WHERE org_id = $1 AND token_hash = $2`, f.org, identity.HashToken(identity.NewToken(readToken(t, path)))).Scan(&tokenID, &expires); err != nil {
		t.Fatalf("new token row: %v", err)
	}
	if d := time.Until(expires); d < 23*time.Hour || d > 25*time.Hour {
		t.Errorf("token expires in %v, want --ttl 24h", d)
	}
	if want := "org_id=" + f.org.String() + "\ntoken_id=" + tokenID.String() + "\nexpires_at=" + expires.UTC().Format(time.RFC3339) + "\ntoken_file=" + path + "\n"; res.stdout != want {
		t.Errorf("stdout %q, want exactly %q", res.stdout, want)
	}
	p, err := identity.NewRepo(pool).Authenticate(ctx, identity.NewToken(readToken(t, path)))
	if err != nil || p.Kind != identity.KindUser || p.OrgID != f.org || p.ID != f.admin || p.Scope != "org:"+f.org.String() {
		t.Errorf("principal %+v (err %v), want the admin user of org %v", p, err, f.org)
	}
	if _, err := identity.NewRepo(pool).Authenticate(ctx, identity.NewToken(f.oldToken)); err != nil {
		t.Errorf("the earlier token stopped working: %v", err)
	}
	after := counts(t, pool)
	if after.orgs != before.orgs || after.users != before.users || after.memberships != before.memberships || after.tokens != before.tokens+1 || after.audit != before.audit+1 {
		t.Errorf("counts %+v -> %+v; want exactly one new token and one journal record", before, after)
	}
	var reason string
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*), coalesce(max(intent_reason), '') FROM audit_records WHERE org_id = $1 AND scope = $2 AND action = 'identity.token_issue' AND result_status = 'ok' AND actor_id = 'keep-server-issue-admin-token' AND actor_type = 'system'`,
		f.org.String(), "org:"+f.org.String()).Scan(&n, &reason); err != nil || n != 1 {
		t.Fatalf("token_issue journal records = %d (err %v), want 1", n, err)
	}
	for _, want := range []string{"admin_user_id=" + f.admin.String(), "token_id=" + tokenID.String(), "expires_at="} {
		if !strings.Contains(reason, want) {
			t.Errorf("journal reason %q lacks %q", reason, want)
		}
	}
	var otherTokens int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tokens WHERE org_id = $1`, other.org).Scan(&otherTokens); err != nil || otherTokens != 1 {
		t.Errorf("another organization holds %d tokens (err %v), want its 1", otherTokens, err)
	}
}

// Refusals name a class and change nothing: no token, no journal record, no
// file, no new organization or user.
func TestIssueAdminToken_Refusals(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	f := newIssueFixture(t, pool, "acme")
	other := newIssueFixture(t, pool, "other")
	tn := tenancy.New(pool)
	viewer, err := tn.CreateUser(ctx, f.org, "viewer@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tn.CreateMembership(ctx, f.org, viewer.ID, tenancy.Org(f.org), string(identity.RoleViewer)); err != nil {
		t.Fatal(err)
	}
	nobody, err := tn.CreateUser(ctx, f.org, "nobody@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	removed, err := tn.CreateUser(ctx, f.org, "gone@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tn.CreateMembership(ctx, f.org, removed.ID, tenancy.Org(f.org), string(identity.RoleAdmin)); err != nil {
		t.Fatal(err)
	}
	if err := tn.RemoveUser(ctx, f.org, removed.ID); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		org   uuid.UUID
		user  uuid.UUID
		class string
	}{
		{"unknown org", uuid.New(), f.admin, "not_found"},
		{"unknown user", f.org, uuid.New(), "not_found"},
		{"admin of another org", f.org, other.admin, "not_found"},
		{"viewer", f.org, viewer.ID, "permission_denied"},
		{"user without membership", f.org, nobody.ID, "permission_denied"},
		{"removed admin", f.org, removed.ID, "permission_denied"},
	}
	before := counts(t, pool)
	for _, c := range cases {
		path := filepath.Join(t.TempDir(), "admin.token")
		res := runIssue(t, pool, "--org-id", c.org.String(), "--admin-user-id", c.user.String(), "--ttl", "24h", "--token-file", path)
		if res.code == 0 || !strings.Contains(res.stderr, "error_class="+c.class) {
			t.Errorf("%s: exit %d, stderr %q; want a refusal with class %s", c.name, res.code, res.stderr, c.class)
		}
		if _, err := os.Stat(path); err == nil {
			t.Errorf("%s: a token file was created", c.name)
		}
		if got := counts(t, pool); got != before {
			t.Errorf("%s: counts changed %+v -> %+v", c.name, before, got)
		}
	}
}

func TestIssueAdminToken_ExistingFileKeptAndNothingIssued(t *testing.T) {
	pool := testPool(t)
	f := newIssueFixture(t, pool, "acme")
	path := filepath.Join(t.TempDir(), "admin.token")
	if err := os.WriteFile(path, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := counts(t, pool)
	res := runIssue(t, pool, issueArgs(f, path)...)
	if res.code == 0 || !strings.Contains(res.stderr, "already_exists") {
		t.Fatalf("overwriting an existing file: exit %d stderr %q; want already_exists", res.code, res.stderr)
	}
	if got := readToken(t, path); got != "precious" {
		t.Errorf("existing file changed to %q", got)
	}
	if got := counts(t, pool); got != before {
		t.Errorf("counts changed %+v -> %+v", before, got)
	}
}

func TestIssueAdminToken_RelativeTokenFileRefused(t *testing.T) {
	pool := testPool(t)
	f := newIssueFixture(t, pool, "acme")
	before := counts(t, pool)
	res := runIssue(t, pool, issueArgs(f, "admin.token")...)
	if res.code == 0 || !strings.Contains(res.stderr, "error_class=invalid_argument") {
		t.Errorf("relative --token-file: exit %d stderr %q; want invalid_argument", res.code, res.stderr)
	}
	if got := counts(t, pool); got != before {
		t.Errorf("counts changed %+v -> %+v", before, got)
	}
}

// --ttl is required, positive and at most 720h; a refusal issues nothing.
func TestIssueAdminToken_TTLRequiredAndBounded(t *testing.T) {
	pool := testPool(t)
	f := newIssueFixture(t, pool, "acme")
	before := counts(t, pool)
	for _, ttl := range []string{"", "0s", "-1h", "721h", "abc", "30d"} {
		args := []string{"--org-id", f.org.String(), "--admin-user-id", f.admin.String(), "--token-file", filepath.Join(t.TempDir(), "admin.token")}
		if ttl != "" {
			args = append(args, "--ttl", ttl)
		}
		res := runIssue(t, pool, args...)
		if res.code == 0 || !strings.Contains(res.stderr, "error_class=invalid_argument") {
			t.Errorf("--ttl %q: exit %d, stderr %q; want invalid_argument", ttl, res.code, res.stderr)
		}
	}
	if got := counts(t, pool); got != before {
		t.Errorf("counts changed %+v -> %+v after refusals", before, got)
	}
	if res := runIssue(t, pool, "--org-id", f.org.String(), "--admin-user-id", f.admin.String(), "--ttl", "720h", "--token-file", filepath.Join(t.TempDir(), "admin.token")); res.code != 0 {
		t.Errorf("--ttl 720h (the limit) refused: %s", res.stderr)
	}
}

func TestIssueAdminToken_UsageAndBadIDs(t *testing.T) {
	pool := testPool(t)
	f := newIssueFixture(t, pool, "acme")
	path := filepath.Join(t.TempDir(), "admin.token")
	if res := runIssue(t, pool, "--org-id", f.org.String(), "--ttl", "24h", "--token-file", path); res.code != 2 || !strings.Contains(res.stderr, "usage:") {
		t.Errorf("missing --admin-user-id: exit %d stderr %q; want usage and 2", res.code, res.stderr)
	}
	if res := runIssue(t, pool, "--org-id", "nope", "--admin-user-id", f.admin.String(), "--ttl", "24h", "--token-file", path); res.code == 0 || !strings.Contains(res.stderr, "invalid_argument") {
		t.Errorf("bad --org-id: exit %d stderr %q", res.code, res.stderr)
	}
}

func TestIssueAdminToken_UndeliveredTokenRevoked(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	f := newIssueFixture(t, pool, "acme")
	orig := writeTokenFile
	writeTokenFile = func(string, identity.Token) error { return errors.New("disk full") }
	t.Cleanup(func() { writeTokenFile = orig })

	res := runIssue(t, pool, issueArgs(f, filepath.Join(t.TempDir(), "admin.token"))...)
	if res.code == 0 || !strings.Contains(res.stderr, "token is revoked") {
		t.Fatalf("a failed token write: exit %d stderr %q; want failure saying the token is revoked", res.code, res.stderr)
	}
	var live, revoked int
	if err := pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE revoked_at IS NULL), count(*) FILTER (WHERE revoked_at IS NOT NULL) FROM tokens WHERE org_id = $1`, f.org).Scan(&live, &revoked); err != nil {
		t.Fatal(err)
	}
	if live != 1 || revoked != 1 {
		t.Errorf("tokens live=%d revoked=%d, want the earlier one live and the undelivered one revoked", live, revoked)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_records WHERE org_id = $1 AND action = 'identity.token_revoke' AND intent_reason LIKE '%undelivered%'`, f.org.String()).Scan(&n); err != nil || n != 1 {
		t.Errorf("revocation journal records = %d (err %v), want 1", n, err)
	}
}

// The revocation of an undelivered token must be journaled; when that record
// cannot be written the operator is told, not left with a bare "revoked".
func TestIssueAdminToken_UndeliveredRevocationJournalFailureReported(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	f := newIssueFixture(t, pool, "acme")
	origWrite := writeTokenFile
	writeTokenFile = func(string, identity.Token) error { return errors.New("disk full") }
	t.Cleanup(func() { writeTokenFile = origWrite })
	origAppend := issueAppend
	calls := 0
	issueAppend = func(ctx context.Context, p *pgxpool.Pool, l *slog.Logger, r audit.Record) error {
		calls++
		if calls == 2 {
			return errors.New("journal down")
		}
		return origAppend(ctx, p, l, r)
	}
	t.Cleanup(func() { issueAppend = origAppend })

	res := runIssue(t, pool, issueArgs(f, filepath.Join(t.TempDir(), "admin.token"))...)
	if res.code == 0 || !strings.Contains(res.stderr, "could not be journaled") {
		t.Fatalf("revocation journal failure: exit %d stderr %q; want failure saying the revocation could not be journaled", res.code, res.stderr)
	}
	if calls != 2 {
		t.Errorf("journal appends = %d, want 2 (issue, revoke)", calls)
	}
	var revoked int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tokens WHERE org_id = $1 AND revoked_at IS NOT NULL`, f.org).Scan(&revoked); err != nil || revoked != 1 {
		t.Errorf("revoked tokens = %d (err %v), want the undelivered one revoked", revoked, err)
	}
}

// No journal record, no token: when the record cannot be written nothing is
// issued and no file appears.
func TestIssueAdminToken_JournalFailureIssuesNothing(t *testing.T) {
	pool := testPool(t)
	f := newIssueFixture(t, pool, "acme")
	orig := issueAppend
	issueAppend = func(context.Context, *pgxpool.Pool, *slog.Logger, audit.Record) error {
		return errors.New("journal down")
	}
	t.Cleanup(func() { issueAppend = orig })
	before := counts(t, pool)
	path := filepath.Join(t.TempDir(), "admin.token")

	res := runIssue(t, pool, issueArgs(f, path)...)
	if res.code == 0 || !strings.Contains(res.stderr, "audit record") {
		t.Fatalf("journal failure: exit %d stderr %q; want failure naming the audit record", res.code, res.stderr)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("a token file was created without a journal record")
	}
	if got := counts(t, pool); got != before {
		t.Errorf("counts changed %+v -> %+v", before, got)
	}
}

// A token file in a directory that cannot be written is refused before the
// database is touched.
func TestIssueAdminToken_UnwritableDirectoryRefused(t *testing.T) {
	pool := testPool(t)
	f := newIssueFixture(t, pool, "acme")
	before := counts(t, pool)
	res := runIssue(t, pool, issueArgs(f, filepath.Join(t.TempDir(), "missing", "admin.token"))...)
	if res.code == 0 || !strings.Contains(res.stderr, "error_class=invalid_argument") {
		t.Errorf("missing directory: exit %d stderr %q; want invalid_argument", res.code, res.stderr)
	}
	if got := counts(t, pool); got != before {
		t.Errorf("counts changed %+v -> %+v", before, got)
	}
}
