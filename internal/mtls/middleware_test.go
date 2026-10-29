package mtls

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/registry"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
)

// testCA is an in-memory Ed25519 certificate authority — deliberately not
// internal/builtin/orgpki, which this package may not import
// (zone-internals) and which this test does not need: only the shape of a
// real org CA and runner leaf certificate matters here, not sealed storage.
type testCA struct {
	cert    *x509.Certificate
	certDER []byte
	priv    ed25519.PrivateKey
}

func newTestCA(t *testing.T, orgID uuid.UUID) *testCA {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{orgID.String()}, CommonName: "test CA " + orgID.String()},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, certDER: der, priv: priv}
}

// issueLeaf signs a client certificate for (orgID, runnerID, host) under ca
// — mirrors internal/builtin/orgpki.Repo.IssueRunnerCert's template exactly,
// since this test's whole point is exercising how RequireMTLS reads it.
func (ca *testCA) issueLeaf(t *testing.T, orgID, runnerID uuid.UUID, host string, serial int64) *x509.Certificate {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{Organization: []string{orgID.String()}, CommonName: runnerID.String()},
		DNSNames:              []string{host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.priv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// issueLeafWithEKU is issueLeaf with a caller-chosen ExtKeyUsage list, for
// TestRequireMTLS_RejectsNonClientAuthCertificate: RequireMTLS must enforce
// ClientAuth itself, not merely rely on orgpki never issuing anything else.
func (ca *testCA) issueLeafWithEKU(t *testing.T, orgID, runnerID uuid.UUID, host string, serial int64, eku []x509.ExtKeyUsage) *x509.Certificate {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{Organization: []string{orgID.String()}, CommonName: runnerID.String()},
		DNSNames:              []string{host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           eku,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.priv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

type fakeCA map[uuid.UUID][]byte

func (f fakeCA) CACert(_ context.Context, orgID uuid.UUID) ([]byte, bool, error) {
	der, ok := f[orgID]
	return der, ok, nil
}

type failingCA struct{ err error }

func (f failingCA) CACert(context.Context, uuid.UUID) ([]byte, bool, error) {
	return nil, false, f.err
}

func TestRequireMTLS_CAErrorNeverLeaks(t *testing.T) {
	org, runner := uuid.New(), uuid.New()
	ca := newTestCA(t, org)
	leaf := ca.issueLeaf(t, org, runner, "h", 1)
	c := canary.New()
	probe := c.Value(1)
	if !c.In("CA storage: " + probe) {
		t.Fatal("canary control failed")
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	rec := httptest.NewRecorder()
	req := withPeerCert(httptest.NewRequest(http.MethodPost, "/runners/renew", nil), leaf)
	RequireMTLS(failingCA{err: fmt.Errorf("CA storage: %s", probe)}, fakeRunners{}, logger)(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("failed CA lookup reached handler") }),
	).ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || c.In(rec.Body.String()) || c.In(logs.String()) {
		t.Fatal("CA lookup error escaped into response or log")
	}
}

type fakeRunners struct {
	reject bool
	err    error
}

func (f fakeRunners) CheckActive(_ context.Context, _, _ uuid.UUID, _ string) error {
	if f.err != nil {
		return f.err
	}
	if f.reject {
		return errFakeRejected
	}
	return nil
}

var errFakeRejected = registry.ErrRunnerRejected

func TestRequireMTLS_RegistryFailureClassification(t *testing.T) {
	org, runner := uuid.New(), uuid.New()
	ca := newTestCA(t, org)
	leaf := ca.issueLeaf(t, org, runner, "h", 1)
	c := canary.New()
	diagnostic := c.Value(1)
	if !c.In(fmt.Sprintf("registry: %s", diagnostic)) {
		t.Fatal("canary detector did not detect the planted error text")
	}
	for _, tc := range []struct {
		name   string
		err    error
		status int
		class  apperr.Class
		reason string
	}{
		{"backend", fmt.Errorf("registry: %s", diagnostic), http.StatusServiceUnavailable, apperr.ClassNotReady, "backend"},
		{"wrapped-backend", fmt.Errorf("wrapped: %w", fmt.Errorf("registry: %s", diagnostic)), http.StatusServiceUnavailable, apperr.ClassNotReady, "backend"},
		{"rejected", registry.ErrRunnerRejected, http.StatusUnauthorized, apperr.ClassUnauthenticated, "runner_rejected"},
		{"wrapped-rejected", fmt.Errorf("%s: %w", diagnostic, registry.ErrRunnerRejected), http.StatusUnauthorized, apperr.ClassUnauthenticated, "runner_rejected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			called := false
			handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
			mw := RequireMTLS(fakeCA{org: ca.certDER}, fakeRunners{err: tc.err}, logger)
			rec := httptest.NewRecorder()
			req := withPeerCert(httptest.NewRequest(http.MethodPost, "/runners/renew", nil), leaf)
			requestID := reqid.New()
			req = req.WithContext(reqid.WithContext(req.Context(), requestID))
			mw(handler).ServeHTTP(rec, req)
			if called {
				t.Error("handler ran after registry rejection or failure")
			}
			if c.In(rec.Body.String()) || c.In(logs.String()) {
				t.Error("registry error text escaped into the response or log")
			}
			for _, values := range rec.Header() {
				for _, value := range values {
					if c.In(value) {
						t.Error("registry error text escaped into a response header")
					}
				}
			}
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d", rec.Code, tc.status)
			}
			var body apperr.Body
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.ErrorClass != string(tc.class) {
				t.Errorf("error class = %s, want %s", body.ErrorClass, tc.class)
			}
			if body.RequestID != requestID {
				t.Error("response lost its request id")
			}
			message := "authentication failed"
			if tc.status == http.StatusServiceUnavailable {
				message = "database not reachable"
			}
			if body.Message != message {
				t.Error("response did not use the static error message")
			}
			var entry struct {
				Reason    string `json:"auth_reason"`
				RequestID string `json:"request_id"`
			}
			if err := json.Unmarshal(logs.Bytes(), &entry); err != nil {
				t.Fatal(err)
			}
			if entry.Reason != tc.reason {
				t.Error("log did not use the expected closed-set auth reason")
			}
			if entry.RequestID != requestID {
				t.Error("log lost its request id")
			}
		})
	}
}

func withPeerCert(r *http.Request, cert *x509.Certificate) *http.Request {
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	return r
}

func newCapturingHandler(t *testing.T) (http.Handler, *Principal) {
	t.Helper()
	var captured Principal
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := FromContext(r.Context())
		if !ok {
			t.Fatal("handler ran without a Principal in context")
		}
		captured = p
		w.WriteHeader(http.StatusOK)
	})
	return h, &captured
}

func TestRequireMTLS_ValidCertificateAttachesPrincipalFromCertOnly(t *testing.T) {
	org, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	runner, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	ca := newTestCA(t, org)
	leaf := ca.issueLeaf(t, org, runner, "runner-1.example.test", 42)

	handler, captured := newCapturingHandler(t)
	mw := RequireMTLS(fakeCA{org: ca.certDER}, fakeRunners{}, nil)

	req := withPeerCert(httptest.NewRequest(http.MethodPost, "/runners/renew", nil), leaf)
	rec := httptest.NewRecorder()
	mw(handler).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if captured.OrgID != org || captured.RunnerID != runner || captured.Host != "runner-1.example.test" {
		t.Fatalf("Principal = %+v, want org=%s runner=%s host=runner-1.example.test", captured, org, runner)
	}
}

// TestRequireMTLS_BodyAndHeaderOrgIDAreIgnored is the spec's red-run
// requirement, case 2: a request with a valid certificate for organization A
// and organization B's org_id in the body and a header still operates as A —
// the middleware never even looks at the body or that header when deciding
// identity.
func TestRequireMTLS_BodyAndHeaderOrgIDAreIgnored(t *testing.T) {
	orgA, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	orgB, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	runner, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	caA := newTestCA(t, orgA)
	leaf := caA.issueLeaf(t, orgA, runner, "h", 1)

	handler, captured := newCapturingHandler(t)
	mw := RequireMTLS(fakeCA{orgA: caA.certDER}, fakeRunners{}, nil)

	body := strings.NewReader(`{"org_id":"` + orgB.String() + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/runners/renew", body)
	req = withPeerCert(req, leaf)
	req.Header.Set("X-Org-Id", orgB.String())

	rec := httptest.NewRecorder()
	mw(handler).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if captured.OrgID != orgA {
		t.Fatalf("Principal.OrgID = %s, want %s (the certificate's org, not the header/body's)", captured.OrgID, orgA)
	}
	if captured.OrgID == orgB {
		t.Fatal("Principal.OrgID must never equal the body/header-supplied org")
	}
}

// TestRequireMTLS_ForgedOrgClaimFailsChainVerification: a certificate whose
// Subject *claims* organization A but was actually signed by organization
// B's CA never verifies against A's real CA — the claim in the Subject
// carries no weight on its own, only a chain that actually verifies does.
func TestRequireMTLS_ForgedOrgClaimFailsChainVerification(t *testing.T) {
	orgA, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	orgB, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	runner, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	caA := newTestCA(t, orgA)
	caB := newTestCA(t, orgB)
	// Forged: Subject.Organization says orgA, but caB actually signed it.
	forged := caB.issueLeaf(t, orgA, runner, "h", 7)

	handler, _ := newCapturingHandler(t)
	mw := RequireMTLS(fakeCA{orgA: caA.certDER, orgB: caB.certDER}, fakeRunners{}, nil)

	req := withPeerCert(httptest.NewRequest(http.MethodPost, "/runners/renew", nil), forged)
	rec := httptest.NewRecorder()
	mw(handler).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a forged org claim", rec.Code)
	}
}

// TestRequireMTLS_RejectsNonClientAuthCertificate proves RequireMTLS enforces
// ExtKeyUsageClientAuth on the verify call itself (crypto-review finding: no
// test presented a certificate without it). orgpki only ever issues
// ClientAuth leaves, so this never fires in production — the point is that
// RequireMTLS does not rely on that being true.
func TestRequireMTLS_RejectsNonClientAuthCertificate(t *testing.T) {
	org, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	runner, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	ca := newTestCA(t, org)
	leaf := ca.issueLeafWithEKU(t, org, runner, "h", 99, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

	handler, _ := newCapturingHandler(t)
	mw := RequireMTLS(fakeCA{org: ca.certDER}, fakeRunners{}, nil)

	req := withPeerCert(httptest.NewRequest(http.MethodPost, "/runners/renew", nil), leaf)
	rec := httptest.NewRecorder()
	mw(handler).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a certificate without ClientAuth", rec.Code)
	}
}

// TestRequireMTLS_RevokedRunnerRejected is the spec's red-run requirement,
// case 3's middleware half: RunnerChecker rejecting a runner refuses the
// request even with an otherwise perfectly valid certificate.
func TestRequireMTLS_RevokedRunnerRejected(t *testing.T) {
	org, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	runner, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	ca := newTestCA(t, org)
	leaf := ca.issueLeaf(t, org, runner, "h", 1)

	handler, _ := newCapturingHandler(t)
	mw := RequireMTLS(fakeCA{org: ca.certDER}, fakeRunners{reject: true}, nil)

	req := withPeerCert(httptest.NewRequest(http.MethodPost, "/runners/renew", nil), leaf)
	rec := httptest.NewRecorder()
	mw(handler).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a revoked runner", rec.Code)
	}
}

func TestRequireMTLS_NoCertificateRejected(t *testing.T) {
	handler, _ := newCapturingHandler(t)
	mw := RequireMTLS(fakeCA{}, fakeRunners{}, nil)

	req := httptest.NewRequest(http.MethodPost, "/runners/renew", nil)
	rec := httptest.NewRecorder()
	mw(handler).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 with no client certificate", rec.Code)
	}
}

func TestRequireMTLS_UnknownOrgRejected(t *testing.T) {
	org, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	runner, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	ca := newTestCA(t, org)
	leaf := ca.issueLeaf(t, org, runner, "h", 1)

	handler, _ := newCapturingHandler(t)
	mw := RequireMTLS(fakeCA{}, fakeRunners{}, nil) // no CA on file for org

	req := withPeerCert(httptest.NewRequest(http.MethodPost, "/runners/renew", nil), leaf)
	rec := httptest.NewRecorder()
	mw(handler).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for an org with no CA on file", rec.Code)
	}
}

func TestRequireMTLS_MissingCAAndBadChainShareAuthenticationReason(t *testing.T) {
	org, runner := uuid.New(), uuid.New()
	ca := newTestCA(t, org)
	leaf := ca.issueLeaf(t, org, runner, "h", 1)
	other := newTestCA(t, uuid.New())
	for _, tc := range []struct {
		name string
		ca   fakeCA
	}{
		{"missing", fakeCA{}},
		{"bad-chain", fakeCA{org: other.certDER}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			rec := httptest.NewRecorder()
			req := withPeerCert(httptest.NewRequest(http.MethodPost, "/runners/renew", nil), leaf)
			RequireMTLS(tc.ca, fakeRunners{}, logger)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("untrusted certificate reached handler")
			})).ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatal("untrusted certificate was not refused")
			}
			var entry struct {
				Reason string `json:"auth_reason"`
			}
			if err := json.Unmarshal(logs.Bytes(), &entry); err != nil {
				t.Fatal(err)
			}
			if entry.Reason != "chain_verification_failed" {
				t.Fatal("CA absence disclosed a distinct authentication reason")
			}
		})
	}
}

// The chain is valid at issuance, but request-time verification must reject
// an expired leaf even when the runner registry would accept its identity.
func TestRequireMTLS_RejectsExpiredCertificate(t *testing.T) {
	org, runnerID := uuid.New(), uuid.New()
	ca := newTestCA(t, org)
	tmpl := ca.issueLeaf(t, org, runnerID, "host.example", 123)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.NotBefore = time.Now().Add(-30 * time.Minute)
	tmpl.NotAfter = time.Now().Add(-15 * time.Minute)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.priv)
	if err != nil {
		t.Fatal("expired fixture signing failed")
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal("expired fixture parse failed")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: leaf.NotBefore.Add(time.Second), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal("expired fixture was not valid at issuance")
	}
	for name, cert := range map[string]*x509.Certificate{"expired": leaf, "valid": ca.issueLeaf(t, org, runnerID, "host.example", 124)} {
		t.Run(name, func(t *testing.T) {
			called := false
			handler := RequireMTLS(fakeCA{org: ca.certDER}, fakeRunners{}, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(http.StatusNoContent) }))
			req := httptest.NewRequest(http.MethodGet, "https://keep.example/runner", nil)
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if name == "expired" && (called || response.Code != http.StatusUnauthorized) {
				t.Fatal("expired client certificate accepted")
			}
			if name == "valid" && (!called || response.Code != http.StatusNoContent) {
				t.Fatal("valid client certificate rejected")
			}
		})
	}
}
