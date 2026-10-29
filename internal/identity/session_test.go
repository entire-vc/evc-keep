package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func openSessionFixture(t *testing.T, kind Kind) (*Repo, Token, Principal, func(string) string) {
	t.Helper()
	db := testDB(t)
	org := seedOrg(t, db)
	user := seedUser(t, db, org)
	id := user
	if kind == KindAgent {
		id = seedAgent(t, db, org, user)
	}
	repo := NewRepo(db)
	res, err := repo.Issue(context.Background(), IssueParams{OrgID: org, Kind: kind, PrincipalID: id, Scope: "org:" + org.String()})
	if err != nil {
		t.Fatal("issue token")
	}
	p, err := repo.Authenticate(context.Background(), res.Token)
	if err != nil {
		t.Fatal("authenticate")
	}
	exec := func(sql string) string {
		if _, err := db.Exec(context.Background(), sql, org); err != nil {
			t.Fatalf("exec: %v", err)
		}
		return ""
	}
	return repo, res.Token, p, exec
}

func TestSessionOpensFromValidTokenAndStoresOnlyHashes(t *testing.T) {
	repo, token, p, _ := openSessionFixture(t, KindUser)
	handle, s, err := repo.OpenSession(context.Background(), token)
	if err != nil || s.Principal.ID != p.ID || s.CSRF == "" || handle == "" {
		t.Fatal("session did not open")
	}
	got, err := repo.LookupSession(context.Background(), handle)
	if err != nil || got.Principal.ID != p.ID || got.CSRF != s.CSRF {
		t.Fatal("session did not resolve to the same principal and csrf")
	}
	var leaked int
	if err = repo.db.QueryRow(context.Background(), `SELECT count(*) FROM console_sessions s WHERE s::text LIKE '%'||$1||'%'`, handle).Scan(&leaked); err != nil {
		t.Fatalf("leak query failed: %v", err)
	}
	if leaked != 0 {
		t.Fatal("session handle stored in the clear")
	}
	// positive control: the same query finds the CSRF token that IS stored.
	if err = repo.db.QueryRow(context.Background(), `SELECT count(*) FROM console_sessions s WHERE s::text LIKE '%'||$1||'%'`, s.CSRF).Scan(&leaked); err != nil || leaked != 1 {
		t.Fatal("leak query is blind")
	}
	if _, err = repo.LookupSession(context.Background(), handle+"x"); !errors.Is(err, ErrNoSession) {
		t.Fatal("altered handle resolved")
	}
	if err = repo.CloseSession(context.Background(), handle); err != nil {
		t.Fatal("close")
	}
	if _, err = repo.LookupSession(context.Background(), handle); !errors.Is(err, ErrNoSession) {
		t.Fatal("closed session still resolves")
	}
}

func TestSessionRefusesInvalidTokenAndEndsWithToken(t *testing.T) {
	repo, token, p, _ := openSessionFixture(t, KindUser)
	if _, _, err := repo.OpenSession(context.Background(), NewToken("keep_u_"+strings.Repeat("a", 52))); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("session opened from an unknown token")
	}
	handle, _, err := repo.OpenSession(context.Background(), token)
	if err != nil {
		t.Fatal("open")
	}
	if _, err = repo.db.Exec(context.Background(), `UPDATE tokens SET revoked_at=now() WHERE principal_id=$1`, p.ID); err != nil {
		t.Fatal("revoke")
	}
	if _, err = repo.LookupSession(context.Background(), handle); !errors.Is(err, ErrNoSession) {
		t.Fatal("session outlived its revoked token")
	}
}

func TestSessionDiesWithItsExpiredToken(t *testing.T) {
	repo, token, p, _ := openSessionFixture(t, KindUser)
	handle, _, err := repo.OpenSession(context.Background(), token)
	if err != nil {
		t.Fatal("open")
	}
	if _, err = repo.LookupSession(context.Background(), handle); err != nil {
		t.Fatal("control: a live session must resolve")
	}
	if _, err = repo.db.Exec(context.Background(), `UPDATE tokens SET expires_at=now()-interval '1 minute' WHERE principal_id=$1`, p.ID); err != nil {
		t.Fatal("expire token")
	}
	if _, err = repo.LookupSession(context.Background(), handle); !errors.Is(err, ErrNoSession) {
		t.Fatal("session outlived its expired token")
	}
}

func TestSessionDiesWithItsPrincipal(t *testing.T) {
	repo, token, p, _ := openSessionFixture(t, KindUser)
	handle, _, err := repo.OpenSession(context.Background(), token)
	if err != nil {
		t.Fatal("open")
	}
	if _, err = repo.db.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, p.ID); err != nil {
		t.Fatalf("delete principal: %v", err)
	}
	if _, err = repo.LookupSession(context.Background(), handle); !errors.Is(err, ErrNoSession) && !errors.Is(err, ErrTokenUnknown) {
		t.Fatalf("session outlived its deleted principal: %v", err)
	}
}

func TestSessionExpires(t *testing.T) {
	repo, token, _, _ := openSessionFixture(t, KindUser)
	handle, _, err := repo.OpenSession(context.Background(), token)
	if err != nil {
		t.Fatal("open")
	}
	if _, err = repo.db.Exec(context.Background(), `UPDATE console_sessions SET created_at=now()-interval '2 hours',expires_at=$1`, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal("backdate")
	}
	if _, err = repo.LookupSession(context.Background(), handle); !errors.Is(err, ErrNoSession) {
		t.Fatal("expired session resolved")
	}
}

func TestSessionCarriesAgentKindSoCallersCanRefuseIt(t *testing.T) {
	repo, token, _, _ := openSessionFixture(t, KindAgent)
	handle, s, err := repo.OpenSession(context.Background(), token)
	if err != nil || s.Principal.Kind != KindAgent || s.Principal.SponsorUserID == nil {
		t.Fatal("agent session lost its kind or sponsor")
	}
	if got, err := repo.LookupSession(context.Background(), handle); err != nil || got.Principal.Kind != KindAgent {
		t.Fatal("agent session lookup lost its kind")
	}
}
