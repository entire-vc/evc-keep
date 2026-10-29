package api

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/google/uuid"
)

// clock is a settable time source for the limiter.
type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

type limitFixture struct {
	*routeFixture
	clk    *clock
	lastID string
}

func newLimitFixture(t *testing.T, perMinute, burst int) *limitFixture {
	t.Helper()
	f := newRouteFixture(t)
	clk := &clock{now: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)}
	f.router = NewRouter(obs.New(f.logbuf), f.pool, Deps{Catalog: CatalogLimit{PerMinute: perMinute, Burst: burst, Now: clk.Now}})
	return &limitFixture{routeFixture: f, clk: clk}
}

func (f *limitFixture) missing(bearer string) (int, http.Header, string) {
	f.t.Helper()
	f.lastID = uuid.NewString()
	rec := f.do(http.MethodGet, fmt.Sprintf("/orgs/%s/secrets/%s", f.org.ID, f.lastID), bearer, nil)
	return rec.Code, rec.Header(), rec.Body.String()
}

// The boundary: burst requests pass (missing ids included: probing ids is the
// thing being limited), the next one is refused with a closed 429 and a
// Retry-After; waiting for a token lets one more through.
func TestCatalogLimit_BoundaryAndRefill(t *testing.T) {
	f := newLimitFixture(t, 6, 3)
	bearer := f.mustToken(identity.KindUser, f.mustAdmin("a").ID, "org:"+f.org.ID.String())
	for i := 1; i <= 3; i++ {
		if code, _, body := f.missing(bearer); code != http.StatusNotFound {
			t.Fatalf("request %d of the burst: %d %s", i, code, body)
		}
	}
	code, hdr, body := f.missing(bearer)
	if code != http.StatusTooManyRequests || !strings.Contains(body, `"error_class":"rate_limited"`) {
		t.Fatalf("request over the burst: %d %s", code, body)
	}
	if hdr.Get("Retry-After") != "10" {
		t.Fatalf("Retry-After %q, want 10 (one token per 10 s)", hdr.Get("Retry-After"))
	}
	if strings.Contains(body, f.lastID) {
		t.Fatalf("a refusal must name nothing: %s", body)
	}
	f.clk.now = f.clk.now.Add(10 * time.Second)
	if code, _, _ := f.missing(bearer); code != http.StatusNotFound {
		t.Fatalf("after one token was refilled: %d", code)
	}
	if code, _, _ := f.missing(bearer); code != http.StatusTooManyRequests {
		t.Fatalf("the refill gave more than one token: %d", code)
	}
}

// Another principal of the same tenant and a principal of another tenant keep
// their own budgets: neither is slowed down by the one that is being refused.
func TestCatalogLimit_IsPerPrincipalAndTenant(t *testing.T) {
	f := newLimitFixture(t, 6, 2)
	a := f.mustToken(identity.KindUser, f.mustAdmin("a").ID, "org:"+f.org.ID.String())
	b := f.mustToken(identity.KindUser, f.mustAdmin("b").ID, "org:"+f.org.ID.String())
	for i := 0; i < 3; i++ {
		f.missing(a)
	}
	if code, _, _ := f.missing(a); code != http.StatusTooManyRequests {
		t.Fatalf("control: the exhausted principal must be refused: %d", code)
	}
	if code, _, _ := f.missing(b); code != http.StatusNotFound {
		t.Fatalf("another principal of the tenant was refused: %d", code)
	}
	// Another tenant.
	other, err := f.tr.CreateOrganization(f.ctx, "other-"+t.Name(), "")
	if err != nil {
		t.Fatal(err)
	}
	u, err := f.tr.CreateUser(f.ctx, other.ID, "o@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.tr.CreateMembership(f.ctx, other.ID, u.ID, tenancy.Org(other.ID), string(identity.RoleAdmin)); err != nil {
		t.Fatal(err)
	}
	res, err := f.ir.Issue(f.ctx, identity.IssueParams{OrgID: other.ID, Kind: identity.KindUser, PrincipalID: u.ID, Scope: "org:" + other.ID.String()})
	if err != nil {
		t.Fatal(err)
	}
	rec := f.do(http.MethodGet, fmt.Sprintf("/orgs/%s/secrets/%s", other.ID, uuid.New()), identity.Reveal(res.Token), nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("a principal of another tenant was refused: %d", rec.Code)
	}
}

// Two tokens of one principal share the principal's budget, so minting more
// tokens does not buy more attempts.
func TestCatalogLimit_TokensOfOnePrincipalShareABudget(t *testing.T) {
	f := newLimitFixture(t, 6, 2)
	u := f.mustAdmin("a")
	t1 := f.mustToken(identity.KindUser, u.ID, "org:"+f.org.ID.String())
	t2 := f.mustToken(identity.KindUser, u.ID, "org:"+f.org.ID.String())
	f.missing(t1)
	f.missing(t2)
	if code, _, _ := f.missing(t1); code != http.StatusTooManyRequests {
		t.Fatalf("a second token gave the principal a fresh budget: %d", code)
	}
}

// Policy and tenant refusals count like missing ids, and every catalog route
// is inside the limit.
func TestCatalogLimit_CoversEveryCatalogRouteAndRefusal(t *testing.T) {
	routes := []struct{ method, path string }{
		{http.MethodGet, "/orgs/{org}/secrets"},
		{http.MethodGet, "/orgs/{org}/secrets/" + uuid.NewString()},
		{http.MethodGet, "/orgs/{org}/secrets/" + uuid.NewString() + "/versions"},
		{http.MethodPost, "/orgs/{org}/secrets"},
		// Routes that resolve a secret by name spend the same budget.
		{http.MethodPost, "/v1/deployments"},
		{http.MethodGet, "/v1/deployments/" + uuid.NewString()},
		{http.MethodPost, "/v1/input-links"},
		{http.MethodGet, "/v1/input-links/" + uuid.NewString()},
	}
	for _, rt := range routes {
		f := newLimitFixture(t, 6, 2)
		bearer := f.mustToken(identity.KindUser, f.mustAdmin("a").ID, "org:"+f.org.ID.String())
		path := strings.ReplaceAll(rt.path, "{org}", f.org.ID.String())
		for i := 0; i < 2; i++ {
			f.do(rt.method, path, bearer, map[string]any{})
		}
		if rec := f.do(rt.method, path, bearer, map[string]any{}); rec.Code != http.StatusTooManyRequests {
			t.Fatalf("%s %s is outside the limit: %d", rt.method, rt.path, rec.Code)
		}
	}
	// A request for another tenant's path is a refusal and counts too.
	f := newLimitFixture(t, 6, 2)
	bearer := f.mustToken(identity.KindUser, f.mustAdmin("a").ID, "org:"+f.org.ID.String())
	foreign := fmt.Sprintf("/orgs/%s/secrets/%s", uuid.New(), uuid.New())
	f.do(http.MethodGet, foreign, bearer, nil)
	f.do(http.MethodGet, foreign, bearer, nil)
	if rec := f.do(http.MethodGet, foreign, bearer, nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("probing another tenant is not limited: %d", rec.Code)
	}
}

// Without configuration the limit is 60 a minute with a burst of 20.
func TestCatalogLimit_Defaults(t *testing.T) {
	f := newLimitFixture(t, 0, 0)
	bearer := f.mustToken(identity.KindUser, f.mustAdmin("a").ID, "org:"+f.org.ID.String())
	for i := 1; i <= 20; i++ {
		if code, _, _ := f.missing(bearer); code != http.StatusNotFound {
			t.Fatalf("request %d of the default burst: %d", i, code)
		}
	}
	code, hdr, _ := f.missing(bearer)
	if code != http.StatusTooManyRequests || hdr.Get("Retry-After") != "1" {
		t.Fatalf("request 21: %d Retry-After %q", code, hdr.Get("Retry-After"))
	}
	f.clk.now = f.clk.now.Add(time.Minute)
	for i := 1; i <= 20; i++ {
		if code, _, _ := f.missing(bearer); code != http.StatusNotFound {
			t.Fatalf("request %d after a minute: %d", i, code)
		}
	}
	if code, _, _ := f.missing(bearer); code != http.StatusTooManyRequests {
		t.Fatalf("a minute of refill gave more than the burst: %d", code)
	}
}

// Idle buckets are dropped once the table is full, so the limiter's memory
// is bounded by the callers active within the refill period.
func TestLimiterDropsIdleBuckets(t *testing.T) {
	clk := &clock{now: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)}
	l := newLimiter(CatalogLimit{PerMinute: 60, Burst: 2, Now: clk.Now})
	for i := 0; i < limiterMaxBuckets; i++ {
		var k bucketKey
		k.id = [16]byte(uuid.New())
		l.take(k)
	}
	clk.now = clk.now.Add(time.Hour)
	l.take(bucketKey{id: [16]byte(uuid.New())})
	if n := len(l.buckets); n > 10 {
		t.Fatalf("idle buckets were kept: %d", n)
	}
}

// The health probes and unauthenticated routes are not charged to anyone.
func TestCatalogLimit_LeavesProbesAlone(t *testing.T) {
	f := newLimitFixture(t, 6, 1)
	for i := 0; i < 5; i++ {
		if rec := f.do(http.MethodGet, "/healthz", "", nil); rec.Code != http.StatusOK {
			t.Fatalf("healthz: %d", rec.Code)
		}
	}
}

// A refusal leaves one log line with the closed key set and no path id.
func TestCatalogLimit_RefusalIsLogged(t *testing.T) {
	f := newLimitFixture(t, 6, 1)
	bearer := f.mustToken(identity.KindUser, f.mustAdmin("a").ID, "org:"+f.org.ID.String())
	f.missing(bearer)
	f.logbuf.Reset()
	if code, _, _ := f.missing(bearer); code != http.StatusTooManyRequests {
		t.Fatalf("control: %d", code)
	}
	line := f.logbuf.String()
	if !strings.Contains(line, `"status":429`) || !strings.Contains(line, `"error_class":"rate_limited"`) ||
		!strings.Contains(line, `"route":"/orgs/{org_id}/secrets/{secret_id}"`) {
		t.Fatalf("refusal not logged as expected: %s", line)
	}
	if strings.Contains(line, f.lastID) {
		t.Fatalf("log line names the requested id: %s", line)
	}
}

// Without a principal the middleware refuses; it never lets a request through
// uncharged.
func TestLimitMiddlewareFailsClosed(t *testing.T) {
	l := newLimiter(CatalogLimit{})
	called := false
	h := limitMiddleware(l, obs.New(&bytes.Buffer{}), "/x")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if called || rec.Code != http.StatusUnauthorized {
		t.Fatalf("called=%v status=%d", called, rec.Code)
	}
}

// The table never outgrows its cap, even when every caller is active.
func TestLimiterHardCap(t *testing.T) {
	clk := &clock{now: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)}
	l := newLimiter(CatalogLimit{PerMinute: 60, Burst: 2, Now: clk.Now})
	for i := 0; i < limiterMaxBuckets+50; i++ {
		clk.now = clk.now.Add(time.Microsecond)
		l.take(bucketKey{id: [16]byte(uuid.New())})
	}
	if n := len(l.buckets); n > limiterMaxBuckets {
		t.Fatalf("table grew past its cap: %d", n)
	}
}

// unlimitedCatalog keeps the limit out of the way of tests that make many
// requests with one principal; the limit has its own tests above.
var unlimitedCatalog = CatalogLimit{PerMinute: 600000, Burst: 1000000}

// When the table is full of active callers the one idle the longest goes; a
// caller that is being refused right now keeps its empty bucket, so
// flooding the table with new principals does not reset an enumerator.
func TestLimiterHardCapEvictsTheOldestBucket(t *testing.T) {
	clk := &clock{now: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)}
	l := newLimiter(CatalogLimit{PerMinute: 60, Burst: 2, Now: clk.Now})
	for i := 0; i < limiterMaxBuckets-1; i++ {
		clk.now = clk.now.Add(time.Microsecond)
		l.take(bucketKey{id: [16]byte(uuid.New())})
	}
	attacker := bucketKey{id: [16]byte(uuid.New())}
	clk.now = clk.now.Add(time.Microsecond)
	for i := 0; i < 3; i++ {
		l.take(attacker)
	}
	if ok, _ := l.take(attacker); ok {
		t.Fatal("control: the attacker must be refused before the table overflows")
	}
	clk.now = clk.now.Add(time.Microsecond)
	l.take(bucketKey{id: [16]byte(uuid.New())})
	if len(l.buckets) > limiterMaxBuckets {
		t.Fatalf("table grew past its cap: %d", len(l.buckets))
	}
	if ok, _ := l.take(attacker); ok {
		t.Fatal("an active refused caller lost its bucket to a flood of new principals")
	}
}

// The key is the whole (tenant, kind, id) triple: the same id under another
// tenant or kind is a different caller with its own budget.
func TestLimiterKeyIsTenantKindAndID(t *testing.T) {
	clk := &clock{now: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)}
	l := newLimiter(CatalogLimit{PerMinute: 60, Burst: 1, Now: clk.Now})
	base := bucketKey{org: [16]byte(uuid.New()), kind: identity.KindUser, id: [16]byte(uuid.New())}
	l.take(base)
	if ok, _ := l.take(base); ok {
		t.Fatal("control: the same key must be refused")
	}
	otherOrg := base
	otherOrg.org = [16]byte(uuid.New())
	if ok, _ := l.take(otherOrg); !ok {
		t.Fatal("the same id under another tenant shares a budget")
	}
	otherKind := base
	otherKind.kind = identity.KindAgent
	if ok, _ := l.take(otherKind); !ok {
		t.Fatal("the same id of another kind shares a budget")
	}
}

// Retry-After is rounded up: a caller told to wait that long finds a token.
func TestLimiterRetryAfterRoundsUp(t *testing.T) {
	clk := &clock{now: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)}
	l := newLimiter(CatalogLimit{PerMinute: 40, Burst: 1, Now: clk.Now}) // 1 token per 1.5 s
	k := bucketKey{id: [16]byte(uuid.New())}
	l.take(k)
	ok, wait := l.take(k)
	if ok || wait != 2 {
		t.Fatalf("want a refusal with Retry-After 2, got ok=%v wait=%d", ok, wait)
	}
	clk.now = clk.now.Add(time.Duration(wait) * time.Second)
	if ok, _ := l.take(k); !ok {
		t.Fatal("no token after the advertised wait")
	}
}
