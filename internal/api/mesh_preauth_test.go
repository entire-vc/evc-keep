package api

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/meshext"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/google/uuid"
)

// touchVault is a vault every method of which panics (the embedded interface
// is nil), like the repository over no pool: a request that reaches storage
// panics, and the test counts it.
type touchVault struct{ MeshVault }

// preauthRoutes are the Mesh routes over storage that panics on first use,
// with a pre-authentication budget of burst calls and no refill.
func preauthRoutes(burst int, trusted ...netip.Prefix) *meshRoutes {
	frozen := time.Now()
	return &meshRoutes{
		deps:    MeshDeps{Vault: touchVault{}, Repo: meshext.NewRepo(nil), TrustedProxies: trusted},
		now:     time.Now,
		resolve: newLimiter(CatalogLimit{}), install: newLimiter(CatalogLimit{}),
		preauth: newLimiter(CatalogLimit{PerMinute: 1, Burst: burst, Now: func() time.Time { return frozen }}),
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// serve runs h and reports whether it reached storage (panicked).
func serve(h http.HandlerFunc, r *http.Request) (rec *httptest.ResponseRecorder, touched bool) {
	rec = httptest.NewRecorder()
	func() {
		defer func() { touched = recover() != nil }()
		h(rec, r)
	}()
	return rec, touched
}

// Each unauthenticated Mesh request, well-formed but badly signed: it passes
// every check that needs no storage.
func preauthRequests(m *meshRoutes) map[string]func(peer string) (http.HandlerFunc, *http.Request) {
	ws := uuid.New()
	ts := func() string { return strconv.FormatInt(time.Now().Unix(), 10) }
	badSig := strings.Repeat("ab", meshSigSize)
	signed := func(method, path string) func(string) (http.HandlerFunc, *http.Request) {
		return func(peer string) (http.HandlerFunc, *http.Request) {
			r := httptest.NewRequest(method, path, nil)
			r.RemoteAddr, r.TLS = peer, &tls.ConnectionState{}
			r.Header.Set(meshHeaderWS, ws.String())
			r.Header.Set(meshHeaderTS, ts())
			r.Header.Set(meshHeaderNonce, "nonce-"+strconv.FormatInt(time.Now().UnixNano(), 10))
			r.Header.Set(meshHeaderSig, meshSigPrefix+badSig)
			r.SetPathValue("org_id", uuid.NewString())
			r.SetPathValue("ref", "db.password")
			if method == http.MethodPut {
				return m.handlePutSecret, r
			}
			return m.handleResolveSecret, r
		}
	}
	return map[string]func(string) (http.HandlerFunc, *http.Request){
		"events": func(peer string) (http.HandlerFunc, *http.Request) {
			r := httptest.NewRequest(http.MethodPost, "/mesh/events", strings.NewReader(`{}`))
			r.RemoteAddr = peer
			r.Header.Set(meshHeaderWS, ws.String())
			r.Header.Set(meshHeaderTS, ts())
			r.Header.Set(meshHeaderSig, badSig)
			return m.handleEvents, r
		},
		"secret put":     signed(http.MethodPut, "/orgs/o/mesh/secrets/db.password"),
		"secret resolve": signed(http.MethodPost, "/orgs/o/mesh/secrets/db.password/resolve"),
		"handshake": func(peer string) (http.HandlerFunc, *http.Request) {
			body, _ := json.Marshal(map[string]string{"extension_id": meshext.ExtensionID,
				"workspace_id": ws.String(), "signing_secret": strings.Repeat("s", meshMinSigningSecret)})
			r := httptest.NewRequest(http.MethodPost, "/mesh/install", bytes.NewReader(body))
			r.RemoteAddr, r.TLS = peer, &tls.ConnectionState{}
			r.Header.Set(meshHeaderTS, ts())
			r.Header.Set(meshHeaderSig, hex.EncodeToString(make([]byte, meshSigSize)))
			return m.handleHandshake, r
		},
		"token": func(peer string) (http.HandlerFunc, *http.Request) {
			body, _ := json.Marshal(map[string]string{"extension_id": meshext.ExtensionID,
				"workspace_id": ws.String(), "extension_token": "ext_token"})
			r := httptest.NewRequest(http.MethodPost, "/mesh/token", bytes.NewReader(body))
			r.RemoteAddr = peer
			r.Header.Set(meshHeaderTS, ts())
			r.Header.Set(meshHeaderSig, badSig)
			return m.handleToken, r
		},
	}
}

// A flood of bad signatures from one address past its pre-authentication
// budget is answered 429 before any storage or vault call; another address
// keeps its own budget, whatever workspace either names.
func TestMeshPreauthLimitStopsBadSignaturesBeforeStorage(t *testing.T) {
	const burst, flood = 3, 10
	for name := range preauthRequests(preauthRoutes(burst)) {
		t.Run(name, func(t *testing.T) {
			m := preauthRoutes(burst)
			req := preauthRequests(m)[name]
			touched, limited := 0, 0
			for i := 0; i < flood; i++ {
				rec, hit := serve(req("198.51.100.7:4000"))
				switch {
				case hit:
					touched++
				case rec.Code == http.StatusTooManyRequests && rec.Header().Get("Retry-After") != "":
					limited++
				default:
					t.Fatalf("request %d: status %d without reaching storage", i, rec.Code)
				}
			}
			if touched != burst || limited != flood-burst {
				t.Fatalf("storage reached %d times, %d limited; want %d and %d", touched, limited, burst, flood-burst)
			}
			// positive control: the harness does see storage being reached.
			if _, hit := serve(req("203.0.113.9:4000")); !hit {
				t.Fatal("another address was limited too, or the harness cannot see storage")
			}
		})
	}
}

// A forged X-Forwarded-For from a peer that is not a trusted proxy changes
// nothing: the flood stays on the peer's budget.
func TestMeshPreauthIgnoresForwardedForFromUntrustedPeer(t *testing.T) {
	m := preauthRoutes(1, netip.MustParsePrefix("127.0.0.1/32"))
	req := preauthRequests(m)["events"]
	for i := 0; i < 3; i++ {
		h, r := req("198.51.100.7:4000")
		r.Header.Set("X-Forwarded-For", "203.0.113."+strconv.Itoa(i+1))
		rec, hit := serve(h, r)
		if i > 0 && (hit || rec.Code != http.StatusTooManyRequests) {
			t.Fatalf("forged X-Forwarded-For %d bought a new budget: touched=%v status %d", i, hit, rec.Code)
		}
	}
	// positive control: from the trusted proxy the header does name the client.
	h, r := req("127.0.0.1:5000")
	r.Header.Set("X-Forwarded-For", "203.0.113.50")
	if _, hit := serve(h, r); !hit {
		t.Fatal("a client behind the trusted proxy was limited")
	}
}

func TestClientAddr(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("10.0.0.0/8")}
	for _, c := range []struct {
		name, peer string
		xff        []string
		want       string
	}{
		{"peer only", "198.51.100.7:4000", nil, "198.51.100.7"},
		{"untrusted peer, forged header", "198.51.100.7:4000", []string{"203.0.113.1"}, "198.51.100.7"},
		{"ipv4-mapped peer", "[::ffff:198.51.100.7]:4000", nil, "198.51.100.7"},
		{"ipv6 /64", "[2001:db8:1:2:aaaa:bbbb:cccc:dddd]:4000", nil, "2001:db8:1:2::"},
		{"ipv6 zone dropped", "[fe80::1%eth0]:4000", nil, "fe80::"},
		{"trusted proxy names the client", "127.0.0.1:5000", []string{"203.0.113.1"}, "203.0.113.1"},
		{"rightmost untrusted", "127.0.0.1:5000", []string{"192.0.2.66, 203.0.113.1, 10.1.1.1"}, "203.0.113.1"},
		{"headers joined in order", "127.0.0.1:5000", []string{"192.0.2.66", "203.0.113.1, 10.1.1.1"}, "203.0.113.1"},
		{"mapped hop", "127.0.0.1:5000", []string{"::ffff:203.0.113.1"}, "203.0.113.1"},
		{"ipv6 hop /64", "127.0.0.1:5000", []string{"2001:db8:9:9::1"}, "2001:db8:9:9::"},
		{"garbage on the right keeps the peer", "127.0.0.1:5000", []string{"203.0.113.1, garbage"}, "127.0.0.1"},
		{"garbage behind a trusted hop keeps the peer", "127.0.0.1:5000", []string{"192.0.2.66, nonsense, 10.1.1.1"}, "127.0.0.1"},
		{"no header keeps the peer", "127.0.0.1:5000", nil, "127.0.0.1"},
		{"empty element keeps the peer", "127.0.0.1:5000", []string{"203.0.113.1,"}, "127.0.0.1"},
		{"address with port is not an address", "127.0.0.1:5000", []string{"203.0.113.1:80"}, "127.0.0.1"},
		{"all trusted: the leftmost", "127.0.0.1:5000", []string{"10.2.2.2, 10.1.1.1"}, "10.2.2.2"},
	} {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r.RemoteAddr = c.peer
		for _, v := range c.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := clientAddr(r, trusted).String(); got != c.want {
			t.Errorf("%s: client %s, want %s", c.name, got, c.want)
		}
	}
	// An unparsable peer is one shared bucket, not a panic or a bypass.
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = "pipe"
	if a := clientAddr(r, trusted); a.IsValid() || addrKey(a) != addrKey(netip.Addr{}) {
		t.Errorf("unparsable peer: %v", a)
	}
}

// A refund returns the token take spent and never lifts a bucket over burst.
func TestLimiterRefund(t *testing.T) {
	frozen := time.Now()
	l := newLimiter(CatalogLimit{PerMinute: 1, Burst: 2, Now: func() time.Time { return frozen }})
	k := bucketKey{id: [16]byte{1}}
	l.refund(k) // no bucket yet: nothing to refund
	for i := 0; i < 5; i++ {
		if ok, _ := l.take(k); !ok {
			t.Fatalf("take %d after refund refused", i)
		}
		l.refund(k)
		l.refund(k)
	}
	l.take(k)
	l.take(k)
	if ok, _ := l.take(k); ok {
		t.Fatal("refunds lifted the bucket over its burst")
	}
}

// A loopback peer with no trusted proxy is a local reverse proxy hiding every
// client: the server says so once, through the closed-key logger, and not at
// all once the proxy is trusted.
func TestMeshPreauthWarnsOnceOnLoopbackWithoutProxies(t *testing.T) {
	for _, c := range []struct {
		name    string
		trusted []netip.Prefix
		want    int
	}{
		{"no proxies", nil, 1},
		{"proxy trusted", []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, 0},
	} {
		var buf bytes.Buffer
		m := preauthRoutes(10, c.trusted...)
		m.logger = obs.New(&buf)
		req := preauthRequests(m)["events"]
		for _, peer := range []string{"127.0.0.1:5000", "[::1]:5000", "127.0.0.1:5001"} {
			serve(req(peer))
		}
		serve(req("198.51.100.7:4000"))
		if n := strings.Count(buf.String(), "set KEEP_TRUSTED_PROXIES"); n != c.want {
			t.Errorf("%s: %d warnings, want %d: %s", c.name, n, c.want, buf.String())
		}
		if strings.Contains(buf.String(), "dropped disallowed log attribute") {
			t.Errorf("%s: the warning carries a key the logger drops", c.name)
		}
	}
}
