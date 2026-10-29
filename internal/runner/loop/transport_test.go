//go:build unix

package loop

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/runner"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

// mtlsServer is a stand-in for the runner listener: it demands a client
// certificate from the test CA and serves what handler gives it.
func mtlsServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, runner.Credential, *x509.CertPool) {
	t.Helper()
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caPub, caPriv)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "runner-1"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, pub, caPriv)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	serverPool := x509.NewCertPool()
	serverPool.AddCert(srv.Certificate())
	return srv, runner.Credential{Key: priv, CertDER: der, CACertDER: caDER}, serverPool
}

func TestHTTPTransportRoutesAndBodies(t *testing.T) {
	id := newID(t)
	var seen []string
	srv, cred, pool := mtlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = append(seen, r.Method+" "+r.URL.Path+" "+string(b))
		switch r.URL.Path {
		case "/runners/jobs/next":
			if len(seen) == 1 {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			_, _ = w.Write([]byte(`{"key_id":"org1","payload":"AQI=","sig":"AwQ="}`))
		case "/runners/jobs/value":
			_, _ = w.Write([]byte(`{"job_id":"` + id + `","sealed":"AQ==","sealed_fingerprint_key":"Ag=="}`))
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	})
	tr, err := NewHTTPTransport(srv.URL, cred, pool)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if sj, err := tr.NextJob(ctx); sj != nil || err != nil {
		t.Fatalf("204: %v %v", sj, err)
	}
	if sj, err := tr.NextJob(ctx); err != nil || sj == nil || sj.KeyID != "org1" {
		t.Fatalf("200: %v %v", sj, err)
	}
	if env, err := tr.FetchValue(ctx, id); err != nil || env.JobID != id {
		t.Fatalf("value: %v", err)
	}
	if err := tr.SendResult(ctx, id, runnerproto.Result{ErrorClass: runnerproto.ErrClassInternal}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"GET /runners/jobs/next ",
		"GET /runners/jobs/next ",
		`POST /runners/jobs/value {"job_id":"` + id + `"}`,
		"POST /runners/jobs/" + id + `/result {"ok":false,"error_class":"internal"}`,
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("request %d = %q, want %q", i, seen[i], want[i])
		}
	}
}

func TestHTTPTransportNeedsClientCertificate(t *testing.T) {
	srv, cred, pool := mtlsServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	cred.CertDER = nil // no usable certificate
	tr, err := NewHTTPTransport(srv.URL, cred, pool)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.NextJob(context.Background()); !errors.Is(err, ErrTransport) {
		t.Fatalf("connected without a client certificate: %v", err)
	}
	if _, err := NewHTTPTransport("http://127.0.0.1:1", cred, pool); err == nil {
		t.Fatal("plain http server accepted")
	}
}

func TestHTTPTransportStatusMapping(t *testing.T) {
	id := newID(t)
	for code, want := range map[int]error{404: ErrRefused, 401: ErrTransport, 500: ErrTransport, 302: ErrTransport} {
		followed := false
		srv, cred, pool := mtlsServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/elsewhere" {
				followed = true
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.Header().Set("Location", "/elsewhere")
			w.WriteHeader(code)
		})
		tr, _ := NewHTTPTransport(srv.URL, cred, pool)
		err := tr.SendResult(context.Background(), id, runnerproto.Result{ErrorClass: runnerproto.ErrClassInternal})
		if !errors.Is(err, want) || followed {
			t.Fatalf("status %d: %v (redirect followed: %v), want %v", code, err, followed, want)
		}
	}
}

func TestHTTPTransportErrorsNeverEchoTheBody(t *testing.T) {
	c := canary.New()
	srv, cred, pool := mtlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error_class":"x","message":"` + c.Value(1) + `"}`))
	})
	tr, _ := NewHTTPTransport(srv.URL, cred, pool)
	id := newID(t)
	_, e1 := tr.NextJob(context.Background())
	_, e2 := tr.FetchValue(context.Background(), id)
	e3 := tr.SendResult(context.Background(), id, runnerproto.Result{ErrorClass: runnerproto.ErrClassInternal})
	for _, e := range []error{e1, e2, e3} {
		if e == nil || canary.Of(c.Value(1)).In(e.Error()) || strings.Contains(e.Error(), srv.URL) {
			t.Fatalf("error text: %v", e)
		}
	}
}

func TestHTTPTransportRefusesOpenSchema(t *testing.T) {
	id := newID(t)
	for name, body := range map[string]string{
		"unknown-field": `{"key_id":"org1","payload":"AQI=","sig":"AwQ=","extra":1}`,
		"trailing":      `{"key_id":"org1","payload":"AQI=","sig":"AwQ="} {}`,
		"oversize":      `{"key_id":"org1","payload":"AQI=","sig":"AwQ="}` + strings.Repeat(" ", maxJobBody),
	} {
		srv, cred, pool := mtlsServer(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) })
		tr, _ := NewHTTPTransport(srv.URL, cred, pool)
		if sj, err := tr.NextJob(context.Background()); err == nil || sj != nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// A job id that is not a UUIDv7 never reaches a URL.
	srv, cred, pool := mtlsServer(t, func(w http.ResponseWriter, r *http.Request) { t.Error("request sent") })
	tr, _ := NewHTTPTransport(srv.URL, cred, pool)
	if err := tr.SendResult(context.Background(), "../x", runnerproto.Result{}); !errors.Is(err, ErrRefused) {
		t.Fatal(err)
	}
	_ = json.Marshal
	_ = id
}

// The largest valid builtin value (1 MiB) arrives as a sealed, base64 JSON
// envelope; the body limit must admit it and still refuse something larger.
func TestHTTPTransportValueBodyLimit(t *testing.T) {
	id := newID(t)
	for name, tc := range map[string]struct {
		sealed  int
		wantErr bool
	}{
		"empty-value-envelope": {48, false},
		"64k":                  {64<<10 + 48, false},
		"max-value":            {1<<20 + 48, false},
		"oversized":            {3 << 20, true},
	} {
		t.Run(name, func(t *testing.T) {
			sealed := base64.StdEncoding.EncodeToString(make([]byte, tc.sealed))
			srv, cred, pool := mtlsServer(t, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"job_id":"` + id + `","sealed":"` + sealed + `","sealed_fingerprint_key":"Ag=="}`))
			})
			tr, err := NewHTTPTransport(srv.URL, cred, pool)
			if err != nil {
				t.Fatal(err)
			}
			env, err := tr.FetchValue(context.Background(), id)
			if tc.wantErr != (err != nil) || (err == nil && len(env.Sealed) != tc.sealed) {
				t.Fatalf("err = %v, sealed = %d", err, len(env.Sealed))
			}
		})
	}
}
