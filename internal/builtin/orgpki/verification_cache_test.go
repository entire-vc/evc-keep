package orgpki

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	"github.com/entire-vc/evc-keep/internal/mtls"
	"github.com/google/uuid"
)

type countedRoot struct {
	sealer.RootKey
	opens atomic.Int64
}

type cachedCAResolver struct{ repo *Repo }

func (r cachedCAResolver) CACert(_ context.Context, id uuid.UUID) ([]byte, bool, error) {
	der, ok := r.repo.CachedCACert(id)
	return der, ok, nil
}

type acceptingRunner struct{}

func (acceptingRunner) CheckActive(context.Context, uuid.UUID, uuid.UUID, string) error {
	return nil
}

func (r *countedRoot) Unwrap(wrapped, aad []byte) ([]byte, error) {
	r.opens.Add(1)
	return r.RootKey.Unwrap(wrapped, aad)
}

func TestVerificationCacheNeverOpensKeysForClaimedOrganization(t *testing.T) {
	db := testDB(t)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	root, err := sealer.NewLocalRootKey("test-root", key)
	clear(key)
	if err != nil {
		t.Fatal(err)
	}
	counted := &countedRoot{RootKey: root}
	repo := NewRepo(db, sealer.New(counted, noopAuditor{}, builtin.NewKeyStore(db)))
	org := seedOrg(t, db)
	want, err := repo.Ensure(context.Background(), org)
	if err != nil {
		t.Fatal(err)
	}
	counted.opens.Store(0)
	got, ok := repo.CachedCACert(org)
	if !ok || !bytes.Equal(got, want.CACertDER) {
		t.Fatal("authenticated CA was not cached")
	}
	if _, ok := repo.CachedCACert(uuid.New()); ok {
		t.Fatal("unknown organization was accepted")
	}
	if counted.opens.Load() != 0 {
		t.Fatal("verification CA lookup opened a sealed private key")
	}
	foreignOrg := seedOrg(t, db)
	if _, err := repo.Ensure(context.Background(), foreignOrg); err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(want.CACertDER)
	if err != nil {
		t.Fatal(err)
	}
	caPrivate, err := repo.unsealCAKey(context.Background(), org)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		wipe(caPrivate)
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{Organization: []string{foreignOrg.String()}, CommonName: uuid.New().String()},
		DNSNames:     []string{"h"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, pub, ed25519.PrivateKey(caPrivate))
	wipe(caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	counted.opens.Store(0)
	request := httptest.NewRequest(http.MethodPost, "https://keep.example/runners/renew", nil)
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	response := httptest.NewRecorder()
	mtls.RequireMTLS(cachedCAResolver{repo}, acceptingRunner{}, nil)(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("forged certificate reached handler") }),
	).ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || counted.opens.Load() != 0 {
		t.Fatal("untrusted organization claim opened a private key or passed authentication")
	}
}

func TestVerificationCacheIsolatesCorruptOrganization(t *testing.T) {
	repo, db := newRepo(t)
	good, bad := seedOrg(t, db), seedOrg(t, db)
	ctx := context.Background()
	want, err := repo.Ensure(ctx, good)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Ensure(ctx, bad); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE org_ca SET ca_ciphertext=$1 WHERE org_id=$2`, []byte("synthetic-corruption"), bad); err != nil {
		t.Fatal(err)
	}
	restarted := NewRepo(db, repo.sealer)
	var failures []uuid.UUID
	if err := restarted.PrimeVerificationCache(ctx, func(id uuid.UUID) { failures = append(failures, id) }); err != nil {
		t.Fatal(err)
	}
	badReported := false
	for _, id := range failures {
		if id == good {
			t.Fatal("healthy organization was reported as corrupt")
		}
		if id == bad {
			badReported = true
		}
	}
	if !badReported {
		t.Fatal("corrupt organization was not reported")
	}
	got, ok := restarted.CachedCACert(good)
	if !ok || !bytes.Equal(got, want.CACertDER) {
		t.Fatal("healthy organization lost its verification CA")
	}
	if _, ok := restarted.CachedCACert(bad); ok {
		t.Fatal("corrupt organization retained a verification CA")
	}
	csr, _ := runnerCSR(t, pkix.Name{})
	issued, err := restarted.IssueRunnerCert(ctx, good, uuid.New(), "healthy.example.test", csr)
	if err != nil {
		t.Fatal("healthy organization could not issue a runner certificate")
	}
	leaf, err := x509.ParseCertificate(issued.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://keep.example/runners/renew", nil)
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	response := httptest.NewRecorder()
	mtls.RequireMTLS(cachedCAResolver{restarted}, acceptingRunner{}, nil)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }),
	).ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatal("healthy organization was blocked by another organization's corrupt CA")
	}
}
