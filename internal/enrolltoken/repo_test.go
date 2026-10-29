package enrolltoken

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// testDB opens a pool against a real, already-migrated PostgreSQL instance —
// see CONTRIBUTING.md: the database layer is never mocked. Mirrors
// internal/identity's and internal/builtin/orgpki's own testDB: it does not
// run migrations itself (see that doc for why).
func testDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("KEEP_DATABASE_URL")
	if dsn == "" {
		t.Skip("KEEP_DATABASE_URL not set — see CONTRIBUTING.md")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func seedOrg(t *testing.T, db *pgxpool.Pool) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuid.NewV7: %v", err)
	}
	_, err = db.Exec(context.Background(), `INSERT INTO organizations (id, name) VALUES ($1, $2)`, id, "org-"+id.String())
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	return id
}

func seedUser(t *testing.T, db *pgxpool.Pool, org uuid.UUID) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuid.NewV7: %v", err)
	}
	_, err = db.Exec(context.Background(), `INSERT INTO users (id, org_id, email) VALUES ($1, $2, $3)`,
		id, org, id.String()+"@example.test")
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

const testPolicySHA256 = "aaaabbbbccccddddeeeeffff00001111222233334444555566667777888899aa"

func newRepo(t *testing.T) (*Repo, *pgxpool.Pool) {
	db := testDB(t)
	return NewRepo(db), db
}

func TestIssueGeneratesRedeemableToken(t *testing.T) {
	repo, db := newRepo(t)
	ctx := context.Background()
	org := seedOrg(t, db)
	admin := seedUser(t, db, org)

	res, err := repo.Issue(ctx, IssueParams{OrgID: org, Host: "runner-1.example.test", PolicySHA256: testPolicySHA256, CreatedBy: admin})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if res.Token.IsZero() {
		t.Fatal("Issue returned a zero token")
	}
	if res.Last4 != Last4(res.Token) {
		t.Errorf("Last4 = %q, want %q", res.Last4, Last4(res.Token))
	}
	if !res.ExpiresAt.After(time.Now()) || res.ExpiresAt.After(time.Now().Add(MaxTTL+time.Second)) {
		t.Errorf("ExpiresAt = %v, want within (now, now+%v]", res.ExpiresAt, MaxTTL)
	}

	redeemed, err := repo.Redeem(ctx, res.Token, RedeemParams{Host: "runner-1.example.test", PolicySHA256: testPolicySHA256})
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if redeemed.OrgID != org {
		t.Errorf("Redeem OrgID = %s, want %s", redeemed.OrgID, org)
	}
}

func TestIssueRejectsEmptyHost(t *testing.T) {
	repo, db := newRepo(t)
	org := seedOrg(t, db)
	admin := seedUser(t, db, org)
	_, err := repo.Issue(context.Background(), IssueParams{OrgID: org, Host: "", PolicySHA256: testPolicySHA256, CreatedBy: admin})
	if err != ErrInvalidHost {
		t.Fatalf("Issue with empty host: err = %v, want ErrInvalidHost", err)
	}
}

func TestIssueRejectsMalformedPolicyHash(t *testing.T) {
	repo, db := newRepo(t)
	org := seedOrg(t, db)
	admin := seedUser(t, db, org)
	for _, bad := range []string{"", "not-hex", testPolicySHA256[:63], testPolicySHA256 + "a", "AAAA" + testPolicySHA256[4:]} {
		_, err := repo.Issue(context.Background(), IssueParams{OrgID: org, Host: "h", PolicySHA256: bad, CreatedBy: admin})
		if err != ErrInvalidPolicyHash {
			t.Errorf("Issue with policy_sha256=%q: err = %v, want ErrInvalidPolicyHash", bad, err)
		}
	}
}

func TestIssueRejectsTTLAboveMax(t *testing.T) {
	repo, db := newRepo(t)
	org := seedOrg(t, db)
	admin := seedUser(t, db, org)
	_, err := repo.Issue(context.Background(), IssueParams{OrgID: org, Host: "h", PolicySHA256: testPolicySHA256, CreatedBy: admin, TTL: MaxTTL + time.Minute})
	if err != ErrTTLTooLong {
		t.Fatalf("Issue with TTL > MaxTTL: err = %v, want ErrTTLTooLong", err)
	}
}

func TestIssueRejectsUnknownOrg(t *testing.T) {
	repo, db := newRepo(t)
	org := seedOrg(t, db)
	admin := seedUser(t, db, org)
	unknownOrg, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	_, err = repo.Issue(context.Background(), IssueParams{OrgID: unknownOrg, Host: "h", PolicySHA256: testPolicySHA256, CreatedBy: admin})
	if err != ErrOrgNotFound {
		t.Fatalf("Issue for unknown org: err = %v, want ErrOrgNotFound", err)
	}
}

func TestIssueRejectsIssuerFromAnotherOrg(t *testing.T) {
	repo, db := newRepo(t)
	orgA := seedOrg(t, db)
	orgB := seedOrg(t, db)
	adminOfB := seedUser(t, db, orgB)
	_, err := repo.Issue(context.Background(), IssueParams{OrgID: orgA, Host: "h", PolicySHA256: testPolicySHA256, CreatedBy: adminOfB})
	if err != ErrIssuerNotFound {
		t.Fatalf("Issue with a creator from a different org: err = %v, want ErrIssuerNotFound", err)
	}
}

// TestRedeemRefusesReuse is the spec's red-run requirement, case 1: reusing
// a token must be refused.
func TestRedeemRefusesReuse(t *testing.T) {
	repo, db := newRepo(t)
	ctx := context.Background()
	org := seedOrg(t, db)
	admin := seedUser(t, db, org)
	res, err := repo.Issue(ctx, IssueParams{OrgID: org, Host: "h", PolicySHA256: testPolicySHA256, CreatedBy: admin})
	if err != nil {
		t.Fatal(err)
	}
	params := RedeemParams{Host: "h", PolicySHA256: testPolicySHA256}
	if _, err := repo.Redeem(ctx, res.Token, params); err != nil {
		t.Fatalf("first Redeem: %v", err)
	}
	if _, err := repo.Redeem(ctx, res.Token, params); err != ErrTokenRejected {
		t.Fatalf("second Redeem (reuse): err = %v, want ErrTokenRejected", err)
	}
}

// TestRedeemRefusesAfterExpiry is the spec's red-run requirement, case 2: a
// token past its TTL must be refused. Since MaxTTL is 15 minutes, this
// backdates expires_at directly rather than sleeping in the test.
func TestRedeemRefusesAfterExpiry(t *testing.T) {
	repo, db := newRepo(t)
	ctx := context.Background()
	org := seedOrg(t, db)
	admin := seedUser(t, db, org)
	res, err := repo.Issue(ctx, IssueParams{OrgID: org, Host: "h", PolicySHA256: testPolicySHA256, CreatedBy: admin})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE enroll_tokens SET expires_at = now() - interval '1 second' WHERE id = $1`, res.TokenID); err != nil {
		t.Fatalf("backdate expires_at: %v", err)
	}
	if _, err := repo.Redeem(ctx, res.Token, RedeemParams{Host: "h", PolicySHA256: testPolicySHA256}); err != ErrTokenRejected {
		t.Fatalf("Redeem an expired token: err = %v, want ErrTokenRejected", err)
	}
}

// TestRedeemRefusesWrongHost is the spec's red-run requirement, case 3: a
// token presented for a different host must be refused.
func TestRedeemRefusesWrongHost(t *testing.T) {
	repo, db := newRepo(t)
	ctx := context.Background()
	org := seedOrg(t, db)
	admin := seedUser(t, db, org)
	res, err := repo.Issue(ctx, IssueParams{OrgID: org, Host: "expected-host", PolicySHA256: testPolicySHA256, CreatedBy: admin})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Redeem(ctx, res.Token, RedeemParams{Host: "different-host", PolicySHA256: testPolicySHA256}); err != ErrTokenRejected {
		t.Fatalf("Redeem against the wrong host: err = %v, want ErrTokenRejected", err)
	}
}

func TestRedeemRefusesWrongPolicyHash(t *testing.T) {
	repo, db := newRepo(t)
	ctx := context.Background()
	org := seedOrg(t, db)
	admin := seedUser(t, db, org)
	res, err := repo.Issue(ctx, IssueParams{OrgID: org, Host: "h", PolicySHA256: testPolicySHA256, CreatedBy: admin})
	if err != nil {
		t.Fatal(err)
	}
	other := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if _, err := repo.Redeem(ctx, res.Token, RedeemParams{Host: "h", PolicySHA256: other}); err != ErrTokenRejected {
		t.Fatalf("Redeem with the wrong policy hash: err = %v, want ErrTokenRejected", err)
	}
}

func TestRedeemRefusesUnknownToken(t *testing.T) {
	repo, db := newRepo(t)
	seedOrg(t, db) // just to touch db; unrelated to the redeemed token
	fake, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Redeem(context.Background(), fake, RedeemParams{Host: "h", PolicySHA256: testPolicySHA256}); err != ErrTokenRejected {
		t.Fatalf("Redeem an unknown token: err = %v, want ErrTokenRejected", err)
	}
}

// TestRedeemConcurrentAttemptsOnlyOneWins directly exercises the
// "WHERE used_at IS NULL" race guard: many goroutines racing to redeem the
// same token must see exactly one success.
func TestRedeemConcurrentAttemptsOnlyOneWins(t *testing.T) {
	repo, db := newRepo(t)
	ctx := context.Background()
	org := seedOrg(t, db)
	admin := seedUser(t, db, org)
	res, err := repo.Issue(ctx, IssueParams{OrgID: org, Host: "h", PolicySHA256: testPolicySHA256, CreatedBy: admin})
	if err != nil {
		t.Fatal(err)
	}

	const n = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := repo.Redeem(ctx, res.Token, RedeemParams{Host: "h", PolicySHA256: testPolicySHA256})
			if err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			} else if err != ErrTokenRejected {
				t.Errorf("unexpected error from concurrent Redeem: %v", err)
			}
		}()
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("concurrent Redeem successes = %d, want exactly 1", successes)
	}
}

// TestRedeemRaceGuardIsLoadBearing exercises the same "UPDATE ... WHERE
// used_at IS NULL" guard as TestRedeemConcurrentAttemptsOnlyOneWins, but
// deterministically: it forces one Redeem call to reach the point right
// after its own validity checks pass and park there — the exact window the
// guard exists for — while a second Redeem call for the same token runs to
// completion, before letting the first one attempt its UPDATE. Unlike the
// goroutine race above (which only caught a removed guard 1 run in 20 —
// crypto-review finding), this never depends on scheduling.
func TestRedeemRaceGuardIsLoadBearing(t *testing.T) {
	repo, db := newRepo(t)
	ctx := context.Background()
	org := seedOrg(t, db)
	admin := seedUser(t, db, org)
	res, err := repo.Issue(ctx, IssueParams{OrgID: org, Host: "h", PolicySHA256: testPolicySHA256, CreatedBy: admin})
	if err != nil {
		t.Fatal(err)
	}

	parked := make(chan struct{})
	release := make(chan struct{})
	repo.redeemTestHook = func() {
		close(parked)
		<-release
	}

	var lateErr error
	lateDone := make(chan struct{})
	go func() {
		_, lateErr = repo.Redeem(ctx, res.Token, RedeemParams{Host: "h", PolicySHA256: testPolicySHA256})
		close(lateDone)
	}()

	<-parked
	// The goroutine above has passed every validity check and is now
	// parked before its own UPDATE. Redeem the same token to completion
	// here first.
	repo.redeemTestHook = nil
	if _, err := repo.Redeem(ctx, res.Token, RedeemParams{Host: "h", PolicySHA256: testPolicySHA256}); err != nil {
		t.Fatalf("first Redeem (winner): %v", err)
	}
	close(release)
	<-lateDone

	if lateErr != ErrTokenRejected {
		t.Fatalf("second Redeem (loser) = %v, want ErrTokenRejected — the mark-used UPDATE's guard did not catch the race", lateErr)
	}
}

// ── response field allowlist (keep-api-surface §4.3) ────────────────────────
//
// issueWire is the one wire shape in Keep that carries an enrollment
// token's plaintext (WireJSON's own doc comment). "token" is therefore the
// single sanctioned exception to the closed field list; every other field
// must still be one of the plain metadata fields keep-api-surface allows.

func issueWireAllowlistViolations(allowed map[string]bool) []string {
	var violations []string
	typ := reflect.TypeOf(issueWire{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		tag := f.Tag.Get("json")
		name, _, _ := bytes.Cut([]byte(tag), []byte(","))
		if !allowed[string(name)] {
			violations = append(violations, fmt.Sprintf("issueWire.%s has json tag %q, not in the response-field allowlist", f.Name, tag))
		}
	}
	return violations
}

func TestIssueWireFieldsWithinAllowlist(t *testing.T) {
	allowed := map[string]bool{
		"token_id": true, "token": true /* sanctioned: the one-time disclosure */, "last4": true,
		"org_id": true, "host": true, "policy_sha256": true, "expires_at": true, "created_at": true,
	}
	for _, v := range issueWireAllowlistViolations(allowed) {
		t.Error(v)
	}
}

// TestIssueWireAllowlistCanFail is this guard's own red run: dropping
// "token" from the allowed set must make the check above fail, proving it
// actually inspects issueWire's fields rather than passing vacuously.
func TestIssueWireAllowlistCanFail(t *testing.T) {
	allowed := map[string]bool{
		"token_id": true, "last4": true, "org_id": true, "host": true,
		"policy_sha256": true, "expires_at": true, "created_at": true,
	}
	violations := issueWireAllowlistViolations(allowed)
	if len(violations) == 0 {
		t.Fatal("issueWireAllowlistViolations did not flag the removal of \"token\" from the allowlist — the guard cannot fail")
	}
}
