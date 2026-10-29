package api

import (
	"bytes"
	"context"
	"fmt"
	"github.com/entire-vc/evc-keep/internal/enrolltoken"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/registry"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
	"net/http"
	"testing"
)

type hookCertIssuer struct {
	pki    *fakeOrgPKI
	before func()
	err    error
}

func (h hookCertIssuer) IssueRunnerCert(ctx context.Context, org, runner uuid.UUID, host string, csr []byte) (RunnerCertIssued, error) {
	if h.before != nil {
		h.before()
	}
	if h.err != nil {
		return RunnerCertIssued{}, h.err
	}
	return h.pki.IssueRunnerCert(ctx, org, runner, host, csr)
}
func TestEnrollRunner_BackendClassification(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
	}{{"token-read", 503}, {"token-update", 503}, {"issuer", 503}, {"registry", 503}, {"rejected", 401}, {"invalid-csr", 400}, {"ok", 200}} {
		t.Run(tc.name, func(t *testing.T) {
			handler, db, pki, _ := fullRouter(t)
			org := seedOrg(t, db)
			admin := adminToken(t, db, org)
			token := issueEnrollToken(t, handler, org, admin, "h", validPolicySHA256())
			tokenDB, runnerDB := testPool(t), testPool(t)
			c := canary.New()
			diagnostic := c.Value(1)
			if !c.In(diagnostic) {
				t.Fatal("canary positive control failed")
			}
			issuer := hookCertIssuer{pki: pki}
			host := "h"
			switch tc.name {
			case "token-read":
				tokenDB.Close()
			case "token-update":
				_, err := db.Exec(context.Background(), `CREATE FUNCTION reject_token_use() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'token store unavailable'; END $$;
					CREATE TRIGGER reject_token_use BEFORE UPDATE ON enroll_tokens FOR EACH ROW EXECUTE FUNCTION reject_token_use()`)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					_, _ = db.Exec(context.Background(), `DROP TRIGGER reject_token_use ON enroll_tokens; DROP FUNCTION reject_token_use()`)
				})
			case "issuer":
				issuer.err = fmt.Errorf("issuer: %s", diagnostic)
			case "registry":
				issuer.before = runnerDB.Close
			case "rejected":
				host = "wrong"
			case "invalid-csr":
				issuer.err = fmt.Errorf("%s: %w", diagnostic, ErrCertIssuerInvalidCSR)
			}
			var logs bytes.Buffer
			handler = NewRouter(obs.New(&logs), db, Deps{Identity: identity.NewRepo(db), Tokens: enrolltoken.NewRepo(tokenDB), Runners: registry.NewRepo(runnerDB), Certs: issuer, CA: pki})
			csr, _ := runnerCSR(t)
			rec := doJSON(t, handler, http.MethodPost, "/runners/enroll", runnerEnrollRequest{Token: token, Host: host, PolicySHA256: validPolicySHA256(), CSR: csr}, "", nil)
			if c.In(rec.Body.String()) || c.In(logs.String()) {
				t.Error("backend diagnostic escaped into response or logs")
			}
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d", rec.Code, tc.status)
			}
		})
	}
}
func TestRenewRunner_BackendClassification(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
	}{{"issuer", 503}, {"registry", 503}, {"revoked", 401}, {"invalid-csr", 400}} {
		t.Run(tc.name, func(t *testing.T) {
			handler, db, pki, _ := fullRouter(t)
			org := seedOrg(t, db)
			admin := adminToken(t, db, org)
			enrolled := enrollForTest(t, handler, db, org, admin, "h")
			leaf := parseCert(t, enrolled.Certificate)
			runnerDB := testPool(t)
			runners := registry.NewRepo(runnerDB)
			c := canary.New()
			diagnostic := c.Value(1)
			if !c.In(diagnostic) {
				t.Fatal("canary positive control failed")
			}
			issuer := hookCertIssuer{pki: pki}
			switch tc.name {
			case "issuer":
				issuer.err = fmt.Errorf("issuer: %s", diagnostic)
			case "registry":
				issuer.before = runnerDB.Close
			case "revoked":
				issuer.before = func() {
					if err := runners.Revoke(context.Background(), org, enrolled.RunnerID); err != nil {
						t.Fatal(err)
					}
				}
			case "invalid-csr":
				issuer.err = fmt.Errorf("%s: %w", diagnostic, ErrCertIssuerInvalidCSR)
			}
			var logs bytes.Buffer
			handler = NewRouter(obs.New(&logs), db, Deps{Identity: identity.NewRepo(db), Tokens: enrolltoken.NewRepo(db), Runners: runners, Certs: issuer, CA: pki})
			csr, _ := runnerCSR(t)
			rec := doJSON(t, handler, http.MethodPost, "/runners/renew", runnerRenewRequest{CSR: csr}, "", leaf)
			if c.In(rec.Body.String()) || c.In(logs.String()) {
				t.Error("backend diagnostic escaped into response or logs")
			}
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d", rec.Code, tc.status)
			}
		})
	}
}
func TestRevokeRunner_BackendClassification(t *testing.T) {
	for _, closed := range []bool{false, true} {
		t.Run(map[bool]string{false: "unknown", true: "backend"}[closed], func(t *testing.T) {
			_, db, pki, _ := fullRouter(t)
			org := seedOrg(t, db)
			admin := adminToken(t, db, org)
			runnerDB := testPool(t)
			if closed {
				runnerDB.Close()
			}
			var logs bytes.Buffer
			handler := NewRouter(obs.New(&logs), db, Deps{Identity: identity.NewRepo(db), Tokens: enrolltoken.NewRepo(db), Runners: registry.NewRepo(runnerDB), Certs: pki, CA: pki})
			rec := doJSON(t, handler, http.MethodPost, "/runners/"+uuid.NewString()+"/revoke", nil, admin, nil)
			want := 404
			if closed {
				want = 503
			}
			if rec.Code != want {
				t.Fatalf("status = %d, want %d", rec.Code, want)
			}
		})
	}
}
