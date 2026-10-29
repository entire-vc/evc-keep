package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/enrolltoken"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/registry"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ── seeding ──────────────────────────────────────────────────────────────
//
// internal/api may not import internal/builtin/orgpki (zone-internals) — the
// real sealed-CA implementation is exercised at the process level in
// cmd/keep-server's own test suite instead (see its doc). These tests use a
// fake [CertIssuer]/[mtls.CAResolver] pair built below, and drive every
// other dependency ([enrolltoken.Repo], [registry.Repo], [identity.Repo])
// against the real database, same convention as this package's other tests.

func seedOrg(t *testing.T, db *pgxpool.Pool) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuid.NewV7: %v", err)
	}
	if _, err := db.Exec(context.Background(), `INSERT INTO organizations (id, name) VALUES ($1, $2)`,
		id, "org-"+id.String()); err != nil {
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
	if _, err := db.Exec(context.Background(), `INSERT INTO users (id, org_id, email) VALUES ($1, $2, $3)`,
		id, org, id.String()+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

func seedMembership(t *testing.T, db *pgxpool.Pool, org, user uuid.UUID, scope string, role identity.Role) {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuid.NewV7: %v", err)
	}
	if _, err := db.Exec(context.Background(), `INSERT INTO memberships (id, org_id, user_id, scope, role) VALUES ($1, $2, $3, $4, $5)`,
		id, org, user, scope, string(role)); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
}

// adminToken seeds an org admin (a user with PermManageRunners via
// [identity.RoleAdmin]) and returns a bearer token authenticating as them.
func adminToken(t *testing.T, db *pgxpool.Pool, org uuid.UUID) string {
	t.Helper()
	idr := identity.NewRepo(db)
	user := seedUser(t, db, org)
	seedMembership(t, db, org, user, tenancy.Org(org).String(), identity.RoleAdmin)
	res, err := idr.Issue(context.Background(), identity.IssueParams{
		OrgID: org, Kind: identity.KindUser, PrincipalID: user, Scope: tenancy.Org(org).String(),
	})
	if err != nil {
		t.Fatalf("issue admin token: %v", err)
	}
	return identity.Reveal(res.Token)
}

// nonAdminToken seeds a user with no membership at all in org — the
// baseline "authenticated but not authorized" principal requirePermission
// must reject.
func nonAdminToken(t *testing.T, db *pgxpool.Pool, org uuid.UUID) string {
	t.Helper()
	idr := identity.NewRepo(db)
	user := seedUser(t, db, org)
	res, err := idr.Issue(context.Background(), identity.IssueParams{
		OrgID: org, Kind: identity.KindUser, PrincipalID: user, Scope: tenancy.Org(org).String(),
	})
	if err != nil {
		t.Fatalf("issue non-admin token: %v", err)
	}
	return identity.Reveal(res.Token)
}

func validPolicySHA256() string {
	return hex.EncodeToString(make([]byte, 32)) // 64 lowercase hex chars — enrolltoken's own shape check
}

// ── fake CertIssuer / CAResolver ────────────────────────────────────────
//
// Mirrors internal/builtin/orgpki's real template exactly (organization CA,
// leaf Subject carrying org_id/runner_id, host in DNSNames) — enough for
// this package's own routing, registry-wiring and mtls-integration
// properties, which don't depend on the CA being sealed. The sealed-storage
// and CSR-cryptography properties themselves are internal/builtin/orgpki's
// and internal/mtls's own tests, not this package's.
type fakeOrgCA struct {
	certDER []byte
	priv    ed25519.PrivateKey
}

type fakeOrgPKI struct {
	t       *testing.T
	mu      sync.Mutex
	cas     map[uuid.UUID]*fakeOrgCA
	serial  int64
	signPub ed25519.PublicKey

	// failNext, once set, makes the next IssueRunnerCert call return this
	// error instead of issuing — TestEnrollRunner_TokenReleasedOnCertIssuanceFailure's
	// own way to simulate an infrastructure failure downstream of a
	// successful Redeem, with no other test affected (cleared after firing
	// once).
	failNext error
}

func newFakeOrgPKI(t *testing.T) *fakeOrgPKI {
	t.Helper()
	signPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate sign key: %v", err)
	}
	return &fakeOrgPKI{t: t, cas: map[uuid.UUID]*fakeOrgCA{}, signPub: signPub}
}

func (f *fakeOrgPKI) ensureCA(orgID uuid.UUID) *fakeOrgCA {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ca, ok := f.cas[orgID]; ok {
		return ca
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.t.Fatalf("generate CA key: %v", err)
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
		f.t.Fatalf("create CA cert: %v", err)
	}
	ca := &fakeOrgCA{certDER: der, priv: priv}
	f.cas[orgID] = ca
	return ca
}

// IssueRunnerCert implements [CertIssuer]. It lazily mints an org's CA on
// first use, exactly like orgpki.Repo.Ensure/IssueRunnerCert — never on a
// mere CACert lookup (see [fakeOrgPKI.CACert]).
func (f *fakeOrgPKI) IssueRunnerCert(_ context.Context, orgID, runnerID uuid.UUID, host string, csrDER []byte) (RunnerCertIssued, error) {
	f.mu.Lock()
	if f.failNext != nil {
		err := f.failNext
		f.failNext = nil
		f.mu.Unlock()
		return RunnerCertIssued{}, err
	}
	f.mu.Unlock()

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return RunnerCertIssued{}, ErrCertIssuerInvalidCSR
	}
	if err := csr.CheckSignature(); err != nil {
		return RunnerCertIssued{}, ErrCertIssuerInvalidCSR
	}
	pub, ok := csr.PublicKey.(ed25519.PublicKey)
	if !ok {
		return RunnerCertIssued{}, ErrCertIssuerInvalidCSR
	}

	ca := f.ensureCA(orgID)
	serial := atomic.AddInt64(&f.serial, 1)
	notAfter := time.Now().Add(30 * 24 * time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{Organization: []string{orgID.String()}, CommonName: runnerID.String()},
		DNSNames:              []string{host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	caCert, err := x509.ParseCertificate(ca.certDER)
	if err != nil {
		f.t.Fatalf("parse own CA cert: %v", err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, pub, ca.priv)
	if err != nil {
		f.t.Fatalf("issue leaf cert: %v", err)
	}
	return RunnerCertIssued{
		CertDER:    leafDER,
		CACertDER:  ca.certDER,
		SignKeyID:  "test-sign-key",
		SignPubKey: []byte(f.signPub),
		NotAfter:   notAfter,
	}, nil
}

// CACert implements [mtls.CAResolver] over the same fakeOrgPKI — but,
// mirroring orgpki.Repo.Lookup's own contract, never mints: an org with no
// CA yet (nobody has enrolled into it) resolves ok=false, never a
// freshly-generated CA for an org an attacker merely claims to belong to.
func (f *fakeOrgPKI) CACert(_ context.Context, orgID uuid.UUID) ([]byte, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ca, ok := f.cas[orgID]
	if !ok {
		return nil, false, nil
	}
	return ca.certDER, true, nil
}

// ── router construction ─────────────────────────────────────────────────

func fullRouter(t *testing.T) (http.Handler, *pgxpool.Pool, *fakeOrgPKI, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	logger := obs.New(&buf)
	pool := testPool(t)
	pki := newFakeOrgPKI(t)
	deps := Deps{
		Identity: identity.NewRepo(pool),
		Tokens:   enrolltoken.NewRepo(pool),
		Runners:  registry.NewRepo(pool),
		Certs:    pki,
		CA:       pki,
	}
	return NewRouter(logger, pool, deps), pool, pki, &buf
}

// tlsRequest marks req as having arrived over the TLS listener (requireTLS
// checks r.TLS != nil) and, when cert is non-nil, attaches it as the
// presented client certificate for internal/mtls.RequireMTLS to read.
func tlsRequest(req *http.Request, cert *x509.Certificate) *http.Request {
	cs := &tls.ConnectionState{}
	if cert != nil {
		cs.PeerCertificates = []*x509.Certificate{cert}
	}
	req.TLS = cs
	return req
}

func doJSON(t *testing.T, handler http.Handler, method, path string, body any, bearer string, mtlsCert *x509.Certificate) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Buffer
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		reader = bytes.NewBuffer(b)
	} else {
		reader = &bytes.Buffer{}
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req = tlsRequest(req, mtlsCert)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func runnerCSR(t *testing.T) (csrDER []byte, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate runner key: %v", err)
	}
	// Subject deliberately does not match anything real — the server must
	// never trust it (card's red-run test #2's underlying property, at the
	// CSR layer rather than the certificate layer covered in
	// internal/mtls's own tests).
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "attacker-supplied"}, PublicKey: pub}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return der, priv
}

func nonEd25519CSR(t *testing.T) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, priv)
	if err != nil {
		t.Fatalf("create RSA CSR: %v", err)
	}
	return der
}

func decodeCertResponse(t *testing.T, rec *httptest.ResponseRecorder) runnerCertResponse {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var res runnerCertResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode response: %v\nbody: %s", err, rec.Body.String())
	}
	return res
}

func errorClass(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		ErrorClass string `json:"error_class"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body: %v\nbody: %s", err, rec.Body.String())
	}
	return body.ErrorClass
}

// issueEnrollToken drives POST /runners/enroll-tokens as org's admin and
// returns the plaintext token plus the host/policy it was issued for.
func issueEnrollToken(t *testing.T, handler http.Handler, org uuid.UUID, admin, host, policy string) string {
	t.Helper()
	rec := doJSON(t, handler, http.MethodPost, "/runners/enroll-tokens",
		enrollTokenIssueRequest{Host: host, PolicySHA256: policy}, admin, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue enroll token: status = %d, body length = %d (body suppressed)", rec.Code, rec.Body.Len())
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode enroll token response: %v", err)
	}
	return body.Token
}

// ── admin route: issue enroll token ─────────────────────────────────────

func TestIssueEnrollToken_AdminSucceeds(t *testing.T) {
	handler, db, _, _ := fullRouter(t)
	org := seedOrg(t, db)
	admin := adminToken(t, db, org)

	rec := doJSON(t, handler, http.MethodPost, "/runners/enroll-tokens",
		enrollTokenIssueRequest{Host: "runner-1.example.test", PolicySHA256: validPolicySHA256()}, admin, nil)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body length = %d (body suppressed)", rec.Code, rec.Body.Len())
	}
	// This response body carries the one-time enrollment token itself — a
	// cache (browser, proxy, admin's own client) must never be allowed to
	// store it (leak-review finding).
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want %q", got, "no-store")
	}
	var body struct {
		Token string `json:"token"`
		Host  string `json:"host"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Token == "" {
		t.Fatal("expected a non-empty token in the issuance response")
	}
	if body.Host != "runner-1.example.test" {
		t.Fatalf("host = %q, want runner-1.example.test", body.Host)
	}
}

func TestIssueEnrollToken_NonAdminForbidden(t *testing.T) {
	handler, db, _, _ := fullRouter(t)
	org := seedOrg(t, db)
	nonAdmin := nonAdminToken(t, db, org)

	rec := doJSON(t, handler, http.MethodPost, "/runners/enroll-tokens",
		enrollTokenIssueRequest{Host: "h", PolicySHA256: validPolicySHA256()}, nonAdmin, nil)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body length = %d (body suppressed)", rec.Code, rec.Body.Len())
	}
}

func TestNewRouterFallbackIdentityGuardsRunnerAdminRoutes(t *testing.T) {
	pool := testPool(t)
	org := seedOrg(t, pool)
	viewer := nonAdminToken(t, pool, org)
	admin := adminToken(t, pool, org)
	handler := NewRouter(obs.New(io.Discard), pool, Deps{
		Tokens:  enrolltoken.NewRepo(pool),
		Runners: registry.NewRepo(pool),
	})
	body := enrollTokenIssueRequest{Host: "fallback.example.test", PolicySHA256: validPolicySHA256()}
	for _, path := range []string{"/runners/enroll-tokens", "/runners/" + uuid.NewString() + "/revoke"} {
		t.Run(path, func(t *testing.T) {
			rec := doJSON(t, handler, http.MethodPost, path, body, viewer, nil)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", rec.Code)
			}
		})
	}
	// A deny-all replacement must not pass the negative cases above.
	rec := doJSON(t, handler, http.MethodPost, "/runners/enroll-tokens", body, admin, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("admin status = %d, want 201", rec.Code)
	}
}

func TestIssueEnrollToken_UnauthenticatedRejected(t *testing.T) {
	handler, _, _, _ := fullRouter(t)

	rec := doJSON(t, handler, http.MethodPost, "/runners/enroll-tokens",
		enrollTokenIssueRequest{Host: "h", PolicySHA256: validPolicySHA256()}, "", nil)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body length = %d (body suppressed)", rec.Code, rec.Body.Len())
	}
}

func TestIssueEnrollToken_RequiresTLSListener(t *testing.T) {
	handler, db, _, _ := fullRouter(t)
	org := seedOrg(t, db)
	admin := adminToken(t, db, org)

	req := httptest.NewRequest(http.MethodPost, "/runners/enroll-tokens", bytes.NewBufferString(`{}`))
	req.Header.Set("Authorization", "Bearer "+admin)
	// No req.TLS set — as if this arrived on the plain listener.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for a runner route reached over the plain listener", rec.Code)
	}
}

// ── enroll ───────────────────────────────────────────────────────────────

func TestEnrollRunner_ValidTokenSucceeds(t *testing.T) {
	handler, db, _, _ := fullRouter(t)
	org := seedOrg(t, db)
	admin := adminToken(t, db, org)
	host, policy := "runner-1.example.test", validPolicySHA256()
	token := issueEnrollToken(t, handler, org, admin, host, policy)
	csr, _ := runnerCSR(t)

	rec := doJSON(t, handler, http.MethodPost, "/runners/enroll",
		runnerEnrollRequest{Token: token, Host: host, PolicySHA256: policy, CSR: csr}, "", nil)

	res := decodeCertResponse(t, rec)
	if res.RunnerID == uuid.Nil {
		t.Fatal("expected a non-nil runner_id")
	}
	if len(res.Certificate) == 0 || len(res.CACertificate) == 0 {
		t.Fatal("expected non-empty certificate and ca_certificate")
	}
}

// TestEnrollRunner_TokenReuseRejected is the card's red-run test #1, case
// "reuse": a second enroll with the same token must fail, even against the
// same host/policy/CSR that succeeded the first time.
func TestEnrollRunner_TokenReuseRejected(t *testing.T) {
	handler, db, _, _ := fullRouter(t)
	org := seedOrg(t, db)
	admin := adminToken(t, db, org)
	host, policy := "runner-1.example.test", validPolicySHA256()
	token := issueEnrollToken(t, handler, org, admin, host, policy)
	csr1, _ := runnerCSR(t)
	csr2, _ := runnerCSR(t)

	first := doJSON(t, handler, http.MethodPost, "/runners/enroll",
		runnerEnrollRequest{Token: token, Host: host, PolicySHA256: policy, CSR: csr1}, "", nil)
	if first.Code != http.StatusOK {
		t.Fatalf("first enroll: status = %d: %s", first.Code, first.Body.String())
	}

	second := doJSON(t, handler, http.MethodPost, "/runners/enroll",
		runnerEnrollRequest{Token: token, Host: host, PolicySHA256: policy, CSR: csr2}, "", nil)
	if second.Code != http.StatusUnauthorized {
		t.Fatalf("second enroll (reused token): status = %d, want 401: %s", second.Code, second.Body.String())
	}
}

// TestEnrollRunner_TokenReleasedOnCertIssuanceFailure is the crypto
// reviewer's own atomicity finding, turned into a red-run test: Redeem
// necessarily happens before cert issuance (only Redeem reveals which org's
// CA to sign with), so an infrastructure failure in IssueRunnerCert must not
// permanently burn the operator's one-time token. If it did, this test's
// second attempt — the same token, unchanged, after the first attempt's
// injected failure — would come back 401 (token already used) instead of
// 200.
func TestEnrollRunner_TokenReleasedOnCertIssuanceFailure(t *testing.T) {
	handler, db, pki, _ := fullRouter(t)
	org := seedOrg(t, db)
	admin := adminToken(t, db, org)
	host, policy := "runner-1.example.test", validPolicySHA256()
	token := issueEnrollToken(t, handler, org, admin, host, policy)
	csr, _ := runnerCSR(t)

	pki.mu.Lock()
	pki.failNext = fmt.Errorf("simulated cert issuer failure")
	pki.mu.Unlock()

	first := doJSON(t, handler, http.MethodPost, "/runners/enroll",
		runnerEnrollRequest{Token: token, Host: host, PolicySHA256: policy, CSR: csr}, "", nil)
	if first.Code != http.StatusServiceUnavailable {
		t.Fatalf("first enroll (simulated issuer failure): status = %d, want 503: %s", first.Code, first.Body.String())
	}

	second := doJSON(t, handler, http.MethodPost, "/runners/enroll",
		runnerEnrollRequest{Token: token, Host: host, PolicySHA256: policy, CSR: csr}, "", nil)
	res := decodeCertResponse(t, second)
	if res.RunnerID == uuid.Nil {
		t.Fatal("expected the released token to succeed on retry with a non-nil runner_id")
	}
}

// TestEnrollRunner_ExpiredTokenRejected is the card's red-run test #1, case
// "TTL": a token past its expires_at is refused. enrolltoken.MaxTTL is 15
// minutes, too long to actually sleep through in a unit test, so this backdates
// the row directly — the same shortcut internal/enrolltoken's own
// TestRedeemRefusesAfterExpiry test uses for this exact case.
func TestEnrollRunner_ExpiredTokenRejected(t *testing.T) {
	handler, db, _, _ := fullRouter(t)
	org := seedOrg(t, db)
	admin := adminToken(t, db, org)
	host, policy := "runner-1.example.test", validPolicySHA256()
	token := issueEnrollToken(t, handler, org, admin, host, policy)

	if _, err := db.Exec(context.Background(),
		`UPDATE enroll_tokens SET expires_at = $1 WHERE token_hash = $2`,
		time.Now().Add(-time.Minute), enrolltoken.HashToken(enrolltoken.NewToken(token))); err != nil {
		t.Fatalf("backdate token expiry: %v", err)
	}

	csr, _ := runnerCSR(t)
	rec := doJSON(t, handler, http.MethodPost, "/runners/enroll",
		runnerEnrollRequest{Token: token, Host: host, PolicySHA256: policy, CSR: csr}, "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for an expired token: %s", rec.Code, rec.Body.String())
	}
}

// TestEnrollRunner_WrongHostRejected is the card's red-run test #1, case
// "wrong host".
func TestEnrollRunner_WrongHostRejected(t *testing.T) {
	handler, db, _, _ := fullRouter(t)
	org := seedOrg(t, db)
	admin := adminToken(t, db, org)
	policy := validPolicySHA256()
	token := issueEnrollToken(t, handler, org, admin, "expected-host.example.test", policy)

	csr, _ := runnerCSR(t)
	rec := doJSON(t, handler, http.MethodPost, "/runners/enroll",
		runnerEnrollRequest{Token: token, Host: "different-host.example.test", PolicySHA256: policy, CSR: csr}, "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a token redeemed against the wrong host: %s", rec.Code, rec.Body.String())
	}
}

func TestEnrollRunner_InvalidCSRRejected(t *testing.T) {
	handler, db, _, _ := fullRouter(t)
	org := seedOrg(t, db)
	admin := adminToken(t, db, org)
	host, policy := "runner-1.example.test", validPolicySHA256()
	token := issueEnrollToken(t, handler, org, admin, host, policy)

	rec := doJSON(t, handler, http.MethodPost, "/runners/enroll",
		runnerEnrollRequest{Token: token, Host: host, PolicySHA256: policy, CSR: []byte("not a csr")}, "", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a malformed CSR: %s", rec.Code, rec.Body.String())
	}
	if got := errorClass(t, rec); got != "invalid_argument" {
		t.Fatalf("error_class = %q, want invalid_argument", got)
	}
}

// TestEnrollRunner_NonEd25519CSRRejectedWithoutBurningToken is the red-run
// for keep-leak-reviewer's finding that a syntactically-valid, correctly
// self-signed CSR carrying a non-Ed25519 key must be rejected by the same
// cheap pre-check as a malformed CSR, before the one-time token is
// redeemed — otherwise the operator's only token is spent on a request
// CertIssuer.IssueRunnerCert was always going to refuse anyway.
func TestEnrollRunner_NonEd25519CSRRejectedWithoutBurningToken(t *testing.T) {
	handler, db, _, _ := fullRouter(t)
	org := seedOrg(t, db)
	admin := adminToken(t, db, org)
	host, policy := "runner-1.example.test", validPolicySHA256()
	token := issueEnrollToken(t, handler, org, admin, host, policy)

	rejected := doJSON(t, handler, http.MethodPost, "/runners/enroll",
		runnerEnrollRequest{Token: token, Host: host, PolicySHA256: policy, CSR: nonEd25519CSR(t)}, "", nil)
	if rejected.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a non-Ed25519 CSR: %s", rejected.Code, rejected.Body.String())
	}

	csr, _ := runnerCSR(t)
	retry := doJSON(t, handler, http.MethodPost, "/runners/enroll",
		runnerEnrollRequest{Token: token, Host: host, PolicySHA256: policy, CSR: csr}, "", nil)
	if retry.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: the token must still be usable after the non-Ed25519 CSR was rejected: %s", retry.Code, retry.Body.String())
	}
}

// ── renew / mTLS ─────────────────────────────────────────────────────────

func enrollForTest(t *testing.T, handler http.Handler, db *pgxpool.Pool, org uuid.UUID, admin, host string) runnerCertResponse {
	t.Helper()
	policy := validPolicySHA256()
	token := issueEnrollToken(t, handler, org, admin, host, policy)
	csr, _ := runnerCSR(t)
	rec := doJSON(t, handler, http.MethodPost, "/runners/enroll",
		runnerEnrollRequest{Token: token, Host: host, PolicySHA256: policy, CSR: csr}, "", nil)
	return decodeCertResponse(t, rec)
}

func parseCert(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func TestRenewRunner_ValidCertificateSucceeds(t *testing.T) {
	handler, db, _, _ := fullRouter(t)
	org := seedOrg(t, db)
	admin := adminToken(t, db, org)
	enrolled := enrollForTest(t, handler, db, org, admin, "runner-1.example.test")
	leaf := parseCert(t, enrolled.Certificate)

	csr, _ := runnerCSR(t)
	rec := doJSON(t, handler, http.MethodPost, "/runners/renew", runnerRenewRequest{CSR: csr}, "", leaf)

	res := decodeCertResponse(t, rec)
	if res.RunnerID != enrolled.RunnerID {
		t.Fatalf("runner_id = %s, want %s (renew must not change identity)", res.RunnerID, enrolled.RunnerID)
	}
}

func TestRenewRunner_NoCertificateRejected(t *testing.T) {
	handler, db, _, _ := fullRouter(t)
	org := seedOrg(t, db)
	admin := adminToken(t, db, org)
	_ = enrollForTest(t, handler, db, org, admin, "runner-1.example.test")

	csr, _ := runnerCSR(t)
	rec := doJSON(t, handler, http.MethodPost, "/runners/renew", runnerRenewRequest{CSR: csr}, "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 with no client certificate: %s", rec.Code, rec.Body.String())
	}
}

// TestRenewRunner_BodyOrgIDIgnored is the card's red-run test #2 at the full
// HTTP-routing level (internal/mtls's own tests already cover the
// middleware in isolation): a request presenting organization A's valid
// certificate, with organization B's id smuggled into the JSON body and a
// header, must not operate as B and must not disclose anything about B.
// runnerRenewRequest carries no org_id field, and decodeJSON's
// DisallowUnknownFields means the smuggled field itself makes this the
// "refusal" branch the spec explicitly allows as an alternative to
// "proceeds as A" — this test accepts either outcome, but requires no
// leak and requires A's own runner to work normally afterward either way.
func TestRenewRunner_BodyOrgIDIgnored(t *testing.T) {
	handler, db, _, _ := fullRouter(t)
	orgA := seedOrg(t, db)
	orgB := seedOrg(t, db)
	adminA := adminToken(t, db, orgA)
	adminB := adminToken(t, db, orgB)
	enrolledA := enrollForTest(t, handler, db, orgA, adminA, "runner-a.example.test")
	enrolledB := enrollForTest(t, handler, db, orgB, adminB, "runner-b.example.test")
	leafA := parseCert(t, enrolledA.Certificate)

	csr, _ := runnerCSR(t)
	smuggled := struct {
		CSR   []byte `json:"csr"`
		OrgID string `json:"org_id"`
	}{CSR: csr, OrgID: orgB.String()}
	smuggledBody, err := json.Marshal(smuggled)
	if err != nil {
		t.Fatalf("marshal smuggled body: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/runners/renew", bytes.NewBuffer(smuggledBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-Id", orgB.String())
	req = tlsRequest(req, leafA)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK && rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 200 (proceeded as org A) or 400 (refused): %s", rec.Code, rec.Body.String())
	}
	if rec.Code == http.StatusOK {
		res := decodeCertResponse(t, rec)
		if res.RunnerID != enrolledA.RunnerID {
			t.Fatalf("runner_id = %s, want %s (org A's own runner, never B's)", res.RunnerID, enrolledA.RunnerID)
		}
	}
	if bytes.Contains(rec.Body.Bytes(), []byte(orgB.String())) {
		t.Fatalf("response leaked org B's id: %s", rec.Body.String())
	}
	if bytes.Contains(rec.Body.Bytes(), enrolledB.Certificate) {
		t.Fatal("response leaked org B's certificate material")
	}

	// Whatever the smuggling attempt did, org A's own runner must still work
	// normally on a clean follow-up request over the same certificate.
	csr2, _ := runnerCSR(t)
	clean := doJSON(t, handler, http.MethodPost, "/runners/renew", runnerRenewRequest{CSR: csr2}, "", leafA)
	res := decodeCertResponse(t, clean)
	if res.RunnerID != enrolledA.RunnerID {
		t.Fatalf("runner_id = %s, want %s after the smuggling attempt", res.RunnerID, enrolledA.RunnerID)
	}
}

// TestRenewRunner_RevokedCertificateRejected is the card's red-run test #3
// at the full HTTP-routing level: revoke via the admin route, then the
// runner's next request over its still-cryptographically-valid certificate
// is refused.
func TestRenewRunner_RevokedCertificateRejected(t *testing.T) {
	handler, db, _, _ := fullRouter(t)
	org := seedOrg(t, db)
	admin := adminToken(t, db, org)
	enrolled := enrollForTest(t, handler, db, org, admin, "runner-1.example.test")
	leaf := parseCert(t, enrolled.Certificate)

	revokeRec := doJSON(t, handler, http.MethodPost, "/runners/"+enrolled.RunnerID.String()+"/revoke", nil, admin, nil)
	if revokeRec.Code != http.StatusOK {
		t.Fatalf("revoke: status = %d: %s", revokeRec.Code, revokeRec.Body.String())
	}

	csr, _ := runnerCSR(t)
	rec := doJSON(t, handler, http.MethodPost, "/runners/renew", runnerRenewRequest{CSR: csr}, "", leaf)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a revoked runner's next request: %s", rec.Code, rec.Body.String())
	}
}

// ── revoke ───────────────────────────────────────────────────────────────

func TestRevokeRunner_CrossOrgNotFound(t *testing.T) {
	handler, db, _, _ := fullRouter(t)
	orgA := seedOrg(t, db)
	orgB := seedOrg(t, db)
	adminA := adminToken(t, db, orgA)
	adminB := adminToken(t, db, orgB)
	enrolledB := enrollForTest(t, handler, db, orgB, adminB, "runner-b.example.test")

	// adminA tries to revoke a runner_id that only exists in org B.
	rec := doJSON(t, handler, http.MethodPost, "/runners/"+enrolledB.RunnerID.String()+"/revoke", nil, adminA, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for a runner_id from another organization: %s", rec.Code, rec.Body.String())
	}

	// Confirm B's own runner is untouched: it can still renew.
	leafB := parseCert(t, enrolledB.Certificate)
	csr, _ := runnerCSR(t)
	renewRec := doJSON(t, handler, http.MethodPost, "/runners/renew", runnerRenewRequest{CSR: csr}, "", leafB)
	if renewRec.Code != http.StatusOK {
		t.Fatalf("org B's runner should still be active after A's failed cross-org revoke: status = %d: %s", renewRec.Code, renewRec.Body.String())
	}
}

func TestRevokeRunner_UnknownRunnerNotFound(t *testing.T) {
	handler, db, _, _ := fullRouter(t)
	org := seedOrg(t, db)
	admin := adminToken(t, db, org)
	unknown := uuid.Must(uuid.NewV7())

	rec := doJSON(t, handler, http.MethodPost, "/runners/"+unknown.String()+"/revoke", nil, admin, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for an unknown runner_id: %s", rec.Code, rec.Body.String())
	}
}

// ── leak canary: enrollment token and CA private key ──────────────────────
//
// Card's red-run test #4, this package's own half: a canary standing in for
// the enrollment token's plaintext, and one standing in for an org's CA
// private key, must never appear in any response body or log line this
// package produces — across success and every failure path exercised
// above. The process-level half (stdout/stderr of the actual compiled
// keep-server binary) lives in cmd/keep-server's own test suite, per
// internal/builtin/orgpki.TestCAPrivateKeyNeverLeaksThroughReturnValuesOrErrors's
// own doc.
func TestRunnerRoutesNeverLeakTokenOrCAKey(t *testing.T) {
	handler, db, pki, logbuf := fullRouter(t)
	org := seedOrg(t, db)
	admin := adminToken(t, db, org)
	host, policy := "runner-1.example.test", validPolicySHA256()

	tokenRec := doJSON(t, handler, http.MethodPost, "/runners/enroll-tokens",
		enrollTokenIssueRequest{Host: host, PolicySHA256: policy}, admin, nil)
	var tokenBody struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(tokenRec.Body.Bytes(), &tokenBody); err != nil {
		t.Fatalf("decode: %v", err)
	}
	tokenCanary := canary.Of(tokenBody.Token)

	csr, _ := runnerCSR(t)
	enrollRec := doJSON(t, handler, http.MethodPost, "/runners/enroll",
		runnerEnrollRequest{Token: tokenBody.Token, Host: host, PolicySHA256: policy, CSR: csr}, "", nil)
	enrolled := decodeCertResponse(t, enrollRec)

	// Force the CA into existence, then probe its private key — never
	// generated with the canary's own bytes (it's the org's own random
	// Ed25519 key), so this is canary.Of on the real secret value, same
	// idiom as orgpki_test.go's TestCAPrivateKeyNeverLeaksThroughReturnValuesOrErrors.
	ca, ok := pki.cas[org]
	if !ok {
		t.Fatal("expected enroll to have minted a CA for org")
	}
	// Two canaries: one over the key's hex text (catches %x and hex-string
	// leaks), one over the raw bytes themselves (catches a []byte field
	// leaking as JSON, which encoding/json base64-encodes from the raw
	// bytes, not from their hex text — a leak in that shape would slip past
	// a hex-only canary entirely).
	keyCanary := canary.Of(hex.EncodeToString(ca.priv))
	keyCanaryRaw := canary.Of(string(ca.priv))

	// Reuse the same token (a failure path) and try to revoke an unknown
	// runner (another failure path) to exercise error text too.
	reuseRec := doJSON(t, handler, http.MethodPost, "/runners/enroll",
		runnerEnrollRequest{Token: tokenBody.Token, Host: host, PolicySHA256: policy, CSR: csr}, "", nil)
	revokeUnknownRec := doJSON(t, handler, http.MethodPost, "/runners/"+uuid.Must(uuid.NewV7()).String()+"/revoke", nil, admin, nil)

	// The enroll-token issuance response is the ONE spec-sanctioned place
	// the token's plaintext appears (keep-api-surface's own closed list:
	// "enrollment token, except for the one-time issuance to the admin at
	// runner registration") — the admin must have it to hand to the
	// runner. Every other surface, including this same token reappearing
	// anywhere else, is a leak.
	tokenSurfaces := map[string]string{
		"enroll response":         enrollRec.Body.String(),
		"reused-token response":   reuseRec.Body.String(),
		"revoke-unknown response": revokeUnknownRec.Body.String(),
		"log":                     logbuf.String(),
	}
	for name, out := range tokenSurfaces {
		if tokenCanary.In(out) {
			t.Errorf("enrollment token leaked into %s (content suppressed)", name)
		}
	}

	allSurfaces := map[string]string{
		"enroll-token response":   tokenRec.Body.String(),
		"enroll response":         enrollRec.Body.String(),
		"reused-token response":   reuseRec.Body.String(),
		"revoke-unknown response": revokeUnknownRec.Body.String(),
		"log":                     logbuf.String(),
	}
	for name, out := range allSurfaces {
		if keyCanary.In(out) || keyCanaryRaw.In(out) {
			t.Errorf("CA private key leaked into %s (content suppressed)", name)
		}
	}
	if len(enrolled.Certificate) == 0 {
		t.Fatal("sanity: enroll did not actually succeed")
	}
	// Positive control: the canary itself must be capable of detecting a
	// leak, and the one sanctioned disclosure is really happening — an
	// always-empty tokenBody.Token would make every check above vacuous.
	if !tokenCanary.In(tokenRec.Body.String()) {
		t.Fatal("sanity: the enroll-token issuance response no longer discloses the token at all")
	}
}

// ── response field allowlist ─────────────────────────────────────────────
//
// Local copy of the keep-api-surface response-field guard (card's own
// requirement) until the shared reflection-based sentinel covering every
// response type in the binary lands. Every json field name below must be
// in the threat model's §4.3 closed list for "Result" / "Carrier" — none
// of them may ever be a plaintext value, key material, or an enrollment
// token.
// allowlistViolations returns, for each field of typ whose json tag is not
// in allowed, a description of the offending field. Both
// TestRunnerResponseFieldsWithinAllowlist and its own red run below call
// this same function, so the red run actually proves the check can fail
// rather than asserting something else next to it.
func allowlistViolations(typ reflect.Type, allowed map[string]bool) []string {
	var violations []string
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		tag := f.Tag.Get("json")
		name, _, _ := bytes.Cut([]byte(tag), []byte(","))
		if !allowed[string(name)] {
			violations = append(violations, fmt.Sprintf("%s.%s has json tag %q, not in the response-field allowlist", typ.Name(), f.Name, tag))
		}
	}
	return violations
}

func TestRunnerResponseFieldsWithinAllowlist(t *testing.T) {
	allowed := map[string]bool{
		"runner_id": true, "certificate": true, "ca_certificate": true,
		"sign_key_id": true, "sign_pub_key": true, "not_after": true,
		"ok": true, "request_id": true,
	}
	for _, typ := range []reflect.Type{
		reflect.TypeOf(runnerCertResponse{}),
		reflect.TypeOf(revokeResult{}),
	} {
		for _, v := range allowlistViolations(typ, allowed) {
			t.Error(v)
		}
	}
}

// TestRunnerResponseFieldsAllowlistCanFail is this guard's own red run
// (keep-redrun-checker): a hypothetical response type carrying a forbidden
// field must be caught by allowlistViolations, the same function
// TestRunnerResponseFieldsWithinAllowlist calls, proving the allowlist
// check actually verifies something rather than vacuously passing.
func TestRunnerResponseFieldsAllowlistCanFail(t *testing.T) {
	type leaky struct {
		Value string `json:"value"`
	}
	violations := allowlistViolations(reflect.TypeOf(leaky{}), map[string]bool{"runner_id": true})
	if len(violations) == 0 {
		t.Fatal("allowlistViolations did not flag a response field outside the allowlist — the guard cannot fail")
	}
}

func TestRunnerEnrollmentWritesIssueAndUseAudit(t *testing.T) {
	handler, db, _, _ := fullRouter(t)
	org := seedOrg(t, db)
	admin := adminToken(t, db, org)
	enrolled := enrollForTest(t, handler, db, org, admin, "audited.example.test")
	for _, action := range []string{"runner.enroll_token_issue", "runner.enroll"} {
		var count int
		if err := db.QueryRow(context.Background(), `SELECT count(*) FROM audit_records WHERE org_id=$1 AND action=$2`, org.String(), action).Scan(&count); err != nil {
			t.Fatal("read enrollment audit")
		}
		if count != 1 {
			t.Fatalf("action %s count=%d, want 1", action, count)
		}
	}
	var recordedRunner string
	if err := db.QueryRow(context.Background(), `SELECT actor_id FROM audit_records WHERE org_id=$1 AND action='runner.enroll'`, org.String()).Scan(&recordedRunner); err != nil {
		t.Fatal("read enrolled runner actor")
	}
	if recordedRunner != enrolled.RunnerID.String() {
		t.Fatal("use event is not bound to registered runner")
	}
}

type unavailableEnrollAudit struct{}

func (unavailableEnrollAudit) Append(context.Context, audit.Record) (audit.Record, error) {
	return audit.Record{}, errors.New("journal unavailable")
}

func TestRunnerEnrollmentFailsClosedWithoutAudit(t *testing.T) {
	good, db, pki, _ := fullRouter(t)
	org := seedOrg(t, db)
	admin := adminToken(t, db, org)
	bad := NewRouter(obs.New(io.Discard), db, Deps{Audit: unavailableEnrollAudit{}, Identity: identity.NewRepo(db), Tokens: enrolltoken.NewRepo(db), Runners: registry.NewRepo(db), Certs: pki, CA: pki})
	failedIssue := doJSON(t, bad, http.MethodPost, "/runners/enroll-tokens", enrollTokenIssueRequest{Host: "audited.example.test", PolicySHA256: validPolicySHA256()}, admin, nil)
	if failedIssue.Code != http.StatusInternalServerError || bytes.Contains(failedIssue.Body.Bytes(), []byte("keep_renr_")) {
		t.Fatal("issuance returned a token without its audit event")
	}
	token := issueEnrollToken(t, good, org, admin, "audited.example.test", validPolicySHA256())
	csr, _ := runnerCSR(t)
	failedUse := doJSON(t, bad, http.MethodPost, "/runners/enroll", runnerEnrollRequest{Token: token, Host: "audited.example.test", PolicySHA256: validPolicySHA256(), CSR: csr}, "", nil)
	if failedUse.Code != http.StatusServiceUnavailable || bytes.Contains(failedUse.Body.Bytes(), []byte("certificate")) {
		t.Fatal("enrollment returned a certificate without its audit event")
	}
	var active int
	if err := db.QueryRow(context.Background(), `SELECT count(*) FROM runners WHERE org_id=$1 AND revoked_at IS NULL`, org).Scan(&active); err != nil {
		t.Fatal("check runner registry")
	}
	if active != 0 {
		t.Fatal("unaudited enrollment left an active runner")
	}
}

// renewalBarrier stops both requests after mTLS authentication but before
// updating the registry, reproducing concurrent renewals without sleeps.
type renewalBarrier struct {
	*fakeOrgPKI
	arrived chan struct{}
	release chan struct{}
}

func (b *renewalBarrier) IssueRunnerCert(ctx context.Context, org, runner uuid.UUID, host string, csr []byte) (RunnerCertIssued, error) {
	b.arrived <- struct{}{}
	select {
	case <-b.release:
		return b.fakeOrgPKI.IssueRunnerCert(ctx, org, runner, host, csr)
	case <-ctx.Done():
		return RunnerCertIssued{}, ctx.Err()
	}
}

func TestRenewRunner_ConcurrentAuthenticatedRequests(t *testing.T) {
	handler, db, pki, _ := fullRouter(t)
	org := seedOrg(t, db)
	enrolled := enrollForTest(t, handler, db, org, adminToken(t, db, org), "renew.example.test")
	leaf := parseCert(t, enrolled.Certificate)
	barrier := &renewalBarrier{fakeOrgPKI: pki, arrived: make(chan struct{}, 2), release: make(chan struct{})}
	repo := registry.NewRepo(db)
	concurrent := NewRouter(obs.New(io.Discard), db, Deps{
		Identity: identity.NewRepo(db), Tokens: enrolltoken.NewRepo(db), Runners: repo, Certs: barrier, CA: pki,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	results := make(chan *httptest.ResponseRecorder, 2)
	for range 2 {
		csr, _ := runnerCSR(t)
		body, err := json.Marshal(runnerRenewRequest{CSR: csr})
		if err != nil {
			t.Fatal("encode renewal request failed")
		}
		req := tlsRequest(httptest.NewRequest(http.MethodPost, "/runners/renew", bytes.NewReader(body)).WithContext(ctx), leaf)
		req.Header.Set("Content-Type", "application/json")
		go func() {
			rec := httptest.NewRecorder()
			concurrent.ServeHTTP(rec, req)
			results <- rec
		}()
	}
	for range 2 {
		select {
		case <-barrier.arrived:
		case <-ctx.Done():
			t.Fatal("both requests did not reach the post-authentication barrier")
		}
	}
	close(barrier.release)
	var winner *httptest.ResponseRecorder
	successes, rejected := 0, 0
	for range 2 {
		select {
		case rec := <-results:
			switch rec.Code {
			case http.StatusOK:
				successes++
				winner = rec
			case http.StatusUnauthorized:
				rejected++
			default:
				t.Errorf("unexpected renewal status: %d", rec.Code)
			}
		case <-ctx.Done():
			t.Fatal("concurrent renewal did not finish")
		}
	}
	if successes != 1 || rejected != 1 {
		t.Fatalf("concurrent renewals: successes=%d rejected=%d, want one of each", successes, rejected)
	}
	renewed := decodeCertResponse(t, winner)
	cert := parseCert(t, renewed.Certificate)
	if err := repo.CheckActive(ctx, org, enrolled.RunnerID, cert.SerialNumber.String()); err != nil {
		t.Fatal("successful renewal returned a stale certificate")
	}
	if err := repo.CheckActive(ctx, org, enrolled.RunnerID, leaf.SerialNumber.String()); err != registry.ErrRunnerRejected {
		t.Fatal("original certificate remained active after renewal")
	}
	assertRunnerAudit(t, db, org, "runner.renew", "ok", "", "", 1)
	assertRunnerAudit(t, db, org, "runner.renew", "failed", "", "", 1)
	// The winner must be usable on its next mTLS request, including renewal.
	csr, _ := runnerCSR(t)
	rec := doJSON(t, handler, http.MethodPost, "/runners/renew", runnerRenewRequest{CSR: csr}, "", cert)
	if rec.Code != http.StatusOK {
		t.Fatalf("winner cannot renew again: status=%d", rec.Code)
	}
}
