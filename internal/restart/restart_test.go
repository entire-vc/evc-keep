package restart

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const testFP = "kfp1:k1:abcdefghijklmnop"

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
	id := uuid.New()
	if _, err := db.Exec(context.Background(), `INSERT INTO organizations (id, name) VALUES ($1, $2)`, id, "org-"+id.String()); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	return id
}

// clock is a movable time source for the TTL and lease tests.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// claimed is Claim that fails the test on an error: a claim that errors out
// returns nothing, which must never pass for "nothing to hand out".
func claimed(t *testing.T, r *Repo, org uuid.UUID) []Request {
	t.Helper()
	got, err := r.Claim(context.Background(), org, 10)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	return got
}

func newRepo(t *testing.T) (*Repo, uuid.UUID, *clock) {
	db := testDB(t)
	r := NewRepo(db)
	c := &clock{t: time.Now().UTC().Truncate(time.Millisecond)}
	r.now = c.now
	return r, seedOrg(t, db), c
}

func TestClaimGivesARequestOnce(t *testing.T) {
	r, org, _ := newRepo(t)
	ctx := context.Background()
	id, err := r.Enqueue(ctx, org, "Hugh", "key-1", testFP)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Claim(ctx, org, 10)
	if err != nil || len(got) != 1 || got[0].RequestID != id || got[0].Lane != "Hugh" || got[0].KeyVersion != "key-1" || got[0].Fingerprint != testFP {
		t.Fatalf("first claim: %+v, %v", got, err)
	}
	again, err := r.Claim(ctx, org, 10)
	if err != nil || len(again) != 0 {
		t.Fatalf("second claim must be empty while the lease holds: %+v, %v", again, err)
	}
}

func TestExpiredLeaseReturnsToPending(t *testing.T) {
	r, org, c := newRepo(t)
	ctx := context.Background()
	id, _ := r.Enqueue(ctx, org, "Test", "key-1", testFP)
	if got := claimed(t, r, org); len(got) != 1 {
		t.Fatal("no first claim")
	}
	c.add(Lease - time.Second)
	if got := claimed(t, r, org); len(got) != 0 {
		t.Fatal("lease not over yet, nothing may be handed out")
	}
	c.add(2 * time.Second)
	got, err := r.Claim(ctx, org, 10)
	if err != nil || len(got) != 1 || got[0].RequestID != id {
		t.Fatalf("after the lease the request must come back: %+v, %v", got, err)
	}
}

func TestPendingExpiresAfterTTL(t *testing.T) {
	r, org, c := newRepo(t)
	ctx := context.Background()
	id, _ := r.Enqueue(ctx, org, "Hugh", "key-1", testFP)
	c.add(PendingTTL + time.Second)
	if got := claimed(t, r, org); len(got) != 0 {
		t.Fatalf("an expired request was handed out: %+v", got)
	}
	var state string
	if err := r.db.QueryRow(ctx, `SELECT state FROM restart_requests WHERE request_id = $1`, id).Scan(&state); err != nil || state != "expired" {
		t.Fatalf("stored state %q (%v), want expired", state, err)
	}
	applied, final, err := r.Outcome(ctx, org, id)
	if err != nil || applied || !final {
		t.Fatalf("expired request: applied=%v final=%v err=%v, want not applied, final", applied, final, err)
	}
	if err := r.Ack(ctx, org, id, strings.Repeat("ab", tokenBytes), ResultOK); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ack of an expired request: %v, want ErrNotFound", err)
	}
}

func TestLeaseReturnedPastTTLExpires(t *testing.T) {
	r, org, c := newRepo(t)
	ctx := context.Background()
	_, _ = r.Enqueue(ctx, org, "Hugh", "key-1", testFP)
	if got := claimed(t, r, org); len(got) != 1 {
		t.Fatal("no first claim")
	}
	c.add(PendingTTL + time.Minute)
	if got := claimed(t, r, org); len(got) != 0 {
		t.Fatalf("a request past its TTL came back from a lease: %+v", got)
	}
}

func TestAckIdempotentAndFinal(t *testing.T) {
	r, org, _ := newRepo(t)
	ctx := context.Background()
	id, _ := r.Enqueue(ctx, org, "Hugh", "key-1", testFP)
	if err := r.Ack(ctx, org, id, strings.Repeat("ab", tokenBytes), ResultOK); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ack before claim: %v, want ErrNotFound", err)
	}
	tok := claimed(t, r, org)[0].ClaimToken
	if _, final, _ := r.Outcome(ctx, org, id); final {
		t.Fatal("a claimed request is not final")
	}
	for i := 0; i < 2; i++ {
		if err := r.Ack(ctx, org, id, tok, ResultOK); err != nil {
			t.Fatalf("ack #%d: %v", i, err)
		}
	}
	if err := r.Ack(ctx, org, id, tok, ResultFailed); !errors.Is(err, ErrConflict) {
		t.Fatalf("another result: %v, want ErrConflict", err)
	}
	if applied, final, _ := r.Outcome(ctx, org, id); !applied || !final {
		t.Fatal("ok must count as applied")
	}
}

func TestOutcomeByResult(t *testing.T) {
	r, org, _ := newRepo(t)
	ctx := context.Background()
	for res, want := range map[Result]bool{ResultOK: true, ResultNothingRunning: true, ResultFailed: false} {
		id, _ := r.Enqueue(ctx, org, "Hugh", "key-1", testFP)
		tok := claimed(t, r, org)[0].ClaimToken
		if err := r.Ack(ctx, org, id, tok, res); err != nil {
			t.Fatal(err)
		}
		if applied, final, _ := r.Outcome(ctx, org, id); applied != want || !final {
			t.Fatalf("%s: applied=%v final=%v, want applied=%v", res, applied, final, want)
		}
	}
}

func TestLaneOutsideAllowlistRefused(t *testing.T) {
	r, org, _ := newRepo(t)
	for _, lane := range []string{"Calvin", "hugh", "", "Hugh ", "Hugh;x"} {
		if _, err := r.Enqueue(context.Background(), org, lane, "key-1", testFP); !errors.Is(err, ErrLane) {
			t.Fatalf("lane %q: %v, want ErrLane", lane, err)
		}
	}
	var n int
	if err := r.db.QueryRow(context.Background(), `SELECT count(*) FROM restart_requests WHERE org_id = $1`, org).Scan(&n); err != nil || n != 0 {
		t.Fatalf("a refused lane left %d rows (%v)", n, err)
	}
}

func TestOtherOrganizationSeesNothing(t *testing.T) {
	r, org, _ := newRepo(t)
	ctx := context.Background()
	other := seedOrg(t, r.db)
	id, _ := r.Enqueue(ctx, org, "Hugh", "key-1", testFP)
	if got := claimed(t, r, other); len(got) != 0 {
		t.Fatalf("foreign claim got %+v", got)
	}
	tok := claimed(t, r, org)[0].ClaimToken
	if err := r.Ack(ctx, other, id, tok, ResultOK); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign ack: %v, want ErrNotFound", err)
	}
	if err := r.Ack(ctx, org, uuid.New(), tok, ResultOK); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown ack: %v, want ErrNotFound", err)
	}
}

func TestConcurrentClaimsNeverShareARequest(t *testing.T) {
	r, org, _ := newRepo(t)
	ctx := context.Background()
	for i := 0; i < 6; i++ {
		_, _ = r.Enqueue(ctx, org, "Hugh", "key-1", testFP)
	}
	var mu sync.Mutex
	seen := map[uuid.UUID]int{}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := r.Claim(ctx, org, 3)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			for _, x := range got {
				seen[x.RequestID]++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	if len(seen) != 6 {
		t.Fatalf("claimed %d of 6 requests", len(seen))
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("request %s handed out %d times", id, n)
		}
	}
}

// TestInvalidInputNeverEchoed: a value-shaped string in any field is refused
// and its text is in no error and no stored row.
func TestInvalidInputNeverEchoed(t *testing.T) {
	r, org, _ := newRepo(t)
	c := canary.New()
	ctx := context.Background()
	if !c.In("x"+c.Value(1)) || !c.In(strings.ToUpper(c.Value(1))) {
		t.Fatal("canary detector is blind")
	}
	for _, in := range [][3]string{
		{c.Value(1), "key-1", testFP},
		{"Hugh", c.Value(1) + "!", testFP},
		{"Hugh", "key-1", "kfp1:k1:" + c.Value(1)},
	} {
		_, err := r.Enqueue(ctx, org, in[0], in[1], in[2])
		if err != nil && c.In(err.Error()) {
			t.Fatalf("error echoes the input: %v", err)
		}
	}
	got, err := r.Claim(ctx, org, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range got {
		if x.Lane != "Hugh" || x.Fingerprint != testFP {
			t.Fatalf("an invalid request got through: %+v", x)
		}
	}
}

// TestEnqueueRefusesBadShapesBeforeTheDatabase pins the Go-side checks; the
// table's CHECK constraints are a second layer (migration test), so without
// this a weakened check here would go unseen. No database: a refusal returns
// before any query.
func TestEnqueueRefusesBadShapesBeforeTheDatabase(t *testing.T) {
	r := NewRepo(nil)
	org := uuid.New()
	for _, c := range []struct{ version, fp string }{
		{"", testFP},
		{"has space", testFP},
		{strings.Repeat("a", 65), testFP},
		{"key-1", ""},
		{"key-1", "sha256:abc"},
		{"key-1", "kfp1:k1:abc"},
		{"key-1", "KFP1:k1:abcdefghijklmnop"},
	} {
		if _, err := r.Enqueue(context.Background(), org, "Hugh", c.version, c.fp); !errors.Is(err, ErrInvalid) {
			t.Errorf("version %q fingerprint %q: %v, want ErrInvalid", c.version, c.fp, err)
		}
	}
}

// A poller that claims and then dies leaves the request claimed: no later
// Claim moves it. Outcome must still settle it once the lease and the TTL
// are both over, so self-rotation reaches the failed path instead of waiting.
func TestAbandonedClaimSettlesWithoutAnotherPoll(t *testing.T) {
	r, org, c := newRepo(t)
	ctx := context.Background()
	id, _ := r.Enqueue(ctx, org, "Hugh", "key-1", testFP)
	if got := claimed(t, r, org); len(got) != 1 {
		t.Fatal("no claim")
	}
	c.add(Lease)
	if applied, final, err := r.Outcome(ctx, org, id); err != nil || applied || final {
		t.Fatalf("lease over, TTL not: applied=%v final=%v err=%v, want still open", applied, final, err)
	}
	c.add(PendingTTL)
	if applied, final, err := r.Outcome(ctx, org, id); err != nil || applied || !final {
		t.Fatalf("lease and TTL over: applied=%v final=%v err=%v, want not applied, final", applied, final, err)
	}
}

// A lease still running keeps the request open past the TTL: the holder may
// still ack it.
func TestLiveLeaseKeepsRequestOpenPastTTL(t *testing.T) {
	r, org, c := newRepo(t)
	ctx := context.Background()
	id, _ := r.Enqueue(ctx, org, "Hugh", "key-1", testFP)
	c.add(PendingTTL - time.Minute)
	tok := claimed(t, r, org)[0].ClaimToken
	c.add(2 * time.Minute)
	if _, final, err := r.Outcome(ctx, org, id); err != nil || final {
		t.Fatalf("live lease past the TTL: final=%v err=%v, want open", final, err)
	}
	if err := r.Ack(ctx, org, id, tok, ResultOK); err != nil {
		t.Fatalf("ack inside the lease: %v", err)
	}
	if applied, final, _ := r.Outcome(ctx, org, id); !applied || !final {
		t.Fatal("acked request is not applied")
	}
}

func TestAckAfterLeaseLapseIsRefused(t *testing.T) {
	r, org, c := newRepo(t)
	ctx := context.Background()
	id, _ := r.Enqueue(ctx, org, "Hugh", "key-1", testFP)
	a := claimed(t, r, org)[0].ClaimToken
	c.add(Lease)
	if err := r.Ack(ctx, org, id, a, ResultOK); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ack at lease end: %v, want ErrNotFound", err)
	}
	if applied, final, _ := r.Outcome(ctx, org, id); applied || final {
		t.Fatal("a refused late ack must not finish the request")
	}
	// The request goes to the next claim, which may ack it.
	got, err := r.Claim(ctx, org, 10)
	if err != nil || len(got) != 1 || got[0].RequestID != id {
		t.Fatalf("reclaim after the lapse: %+v, %v", got, err)
	}
	if got[0].ClaimToken == a {
		t.Fatal("a reissued claim kept the old token")
	}
	if err := r.Ack(ctx, org, id, got[0].ClaimToken, ResultOK); err != nil {
		t.Fatalf("ack by the new claim: %v", err)
	}
	// A finished request keeps answering a repeat of the same result.
	c.add(2 * Lease)
	if err := r.Ack(ctx, org, id, got[0].ClaimToken, ResultOK); err != nil {
		t.Fatalf("idempotent repeat after lease time: %v", err)
	}
	if err := r.Ack(ctx, org, id, got[0].ClaimToken, ResultFailed); !errors.Is(err, ErrConflict) {
		t.Fatalf("other result: %v, want ErrConflict", err)
	}
	// The stale holder cannot touch the finished request either.
	if err := r.Ack(ctx, org, id, a, ResultOK); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale token on a finished request: %v, want ErrNotFound", err)
	}
}

// TestStaleHolderCannotCloseAReissuedClaim is the scenario of the review:
// claim A, the lease lapses, claim B of the same request, then A acks inside
// B's lease. Without a token the lease check passes again and A closes B.
func TestStaleHolderCannotCloseAReissuedClaim(t *testing.T) {
	r, org, c := newRepo(t)
	ctx := context.Background()
	id, _ := r.Enqueue(ctx, org, "Hugh", "key-1", testFP)
	a := claimed(t, r, org)[0].ClaimToken
	c.add(Lease + time.Second)
	b := claimed(t, r, org)
	if len(b) != 1 || b[0].RequestID != id {
		t.Fatalf("no reissue: %+v", b)
	}
	if err := r.Ack(ctx, org, id, a, ResultOK); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ack by the stale holder: %v, want ErrNotFound", err)
	}
	if _, final, _ := r.Outcome(ctx, org, id); final {
		t.Fatal("the stale holder closed the reissued claim")
	}
	for _, bad := range []string{"", "zz", strings.Repeat("0", 2*tokenBytes), strings.Repeat("ab", tokenBytes+1)} {
		if err := r.Ack(ctx, org, id, bad, ResultOK); !errors.Is(err, ErrNotFound) {
			t.Fatalf("token %q: %v, want ErrNotFound", bad, err)
		}
	}
	if err := r.Ack(ctx, org, id, b[0].ClaimToken, ResultFailed); err != nil {
		t.Fatalf("ack by the current holder: %v", err)
	}
}

// The table keeps the digest of the claim token, never the token: a reader of
// the row cannot acknowledge in the poller's name.
func TestClaimTokenIsStoredAsADigest(t *testing.T) {
	r, org, _ := newRepo(t)
	ctx := context.Background()
	id, _ := r.Enqueue(ctx, org, "Hugh", "key-1", testFP)
	tok := claimed(t, r, org)[0].ClaimToken
	var stored []byte
	if err := r.db.QueryRow(ctx, `SELECT claim_token FROM restart_requests WHERE request_id = $1`, id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(tok)
	if err != nil || len(raw) != tokenBytes {
		t.Fatalf("positive control: the handed-out token is not %d hex bytes", tokenBytes)
	}
	if len(stored) != sha256.Size || bytes.Contains(stored, raw) {
		t.Fatalf("stored claim_token: %d bytes, the token itself must not be stored", len(stored))
	}
	if sum := sha256.Sum256(raw); !bytes.Equal(stored, sum[:]) {
		t.Fatal("stored value is not the digest of the token")
	}
}
