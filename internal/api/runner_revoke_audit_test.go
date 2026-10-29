package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/enrolltoken"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/registry"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

func TestRevokeRunner_WritesAuditWithoutCredentials(t *testing.T) {
	handler, db, _, logs := fullRouter(t)
	org := seedOrg(t, db)
	admin := adminToken(t, db, org)
	principal, err := identity.NewRepo(db).Authenticate(context.Background(), identity.NewToken(admin))
	if err != nil {
		t.Fatal("authenticate test administrator")
	}
	enrollToken := issueEnrollToken(t, handler, org, admin, "audit-revoke.example.test", validPolicySHA256())
	csr, privateKey := runnerCSR(t)
	enrolled := decodeCertResponse(t, doJSON(t, handler, http.MethodPost, "/runners/enroll",
		runnerEnrollRequest{Token: enrollToken, Host: "audit-revoke.example.test", PolicySHA256: validPolicySHA256(), CSR: csr}, "", nil))
	const requestID = "runner-revoke-audit-request"
	req := tlsRequest(httptest.NewRequest(http.MethodPost, "/runners/"+enrolled.RunnerID.String()+"/revoke", nil), nil)
	req.Header.Set("Authorization", "Bearer "+admin)
	req.Header.Set("X-Request-Id", requestID)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status=%d, want 200", rec.Code)
	}
	var records [][]byte
	rows, err := db.Query(context.Background(), `SELECT row_to_json(r)::text FROM audit_records r WHERE org_id=$1 AND action='runner.revoke'`, org.String())
	if err != nil {
		t.Fatal("read revoke audit")
	}
	defer rows.Close()
	for rows.Next() {
		var body string
		if err := rows.Scan(&body); err != nil {
			t.Fatal("scan revoke audit")
		}
		records = append(records, []byte(body))
	}
	if rows.Err() != nil {
		t.Fatal("iterate revoke audit")
	}
	if len(records) != 1 {
		t.Fatalf("revoke audit count=%d, want 1", len(records))
	}
	var fields map[string]any
	if err := json.Unmarshal(records[0], &fields); err != nil {
		t.Fatal("decode revoke audit")
	}
	for field, want := range map[string]string{
		"action": "runner.revoke", "org_id": org.String(), "scope": principal.Scope,
		"actor_type": "user", "actor_id": principal.ID.String(), "actor_via": "api",
		"target_runner_id": enrolled.RunnerID.String(), "request_id": requestID,
		"policy_decision": "allow", "result_status": "ok", "result_error_class": "",
	} {
		if fields[field] != want {
			t.Errorf("revoke audit field %s does not match", field)
		}
	}
	for _, value := range []string{admin, enrollToken, string(privateKey)} {
		c := canary.Of(value)
		if !c.In(value) {
			t.Fatal("credential canary positive control failed")
		}
		for _, surface := range []string{string(records[0]), logs.String(), rec.Body.String()} {
			if c.In(surface) {
				t.Fatal("credential leaked during revoke")
			}
		}
		for _, values := range rec.Header() {
			for _, header := range values {
				if c.In(header) {
					t.Fatal("credential leaked in response header")
				}
			}
		}
	}
	verified, err := audit.Verify(context.Background(), db, org.String())
	if err != nil || !verified.OK || verified.Checked != 3 {
		t.Fatal("audit verify did not accept enrollment and revoke chain")
	}
	if rec.Header().Get("X-Request-Id") != requestID {
		t.Fatal("revoke response lost request id")
	}
}

func TestRevokeRunner_DeniedDoesNotWriteSuccessAudit(t *testing.T) {
	handler, db, _, _ := fullRouter(t)
	org := seedOrg(t, db)
	otherOrg := seedOrg(t, db)
	admin := adminToken(t, db, org)
	enrolled := enrollForTest(t, handler, db, org, admin, "denied-revoke.example.test")
	for _, tc := range []struct {
		name, token string
		status      int
	}{
		{"foreign organization", adminToken(t, db, otherOrg), http.StatusNotFound},
		{"non administrator", nonAdminToken(t, db, org), http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := doJSON(t, handler, http.MethodPost, "/runners/"+enrolled.RunnerID.String()+"/revoke", nil, tc.token, nil)
			if rec.Code != tc.status {
				t.Fatalf("status=%d, want %d", rec.Code, tc.status)
			}
		})
	}
	var successes int
	if err := db.QueryRow(context.Background(), `SELECT count(*) FROM audit_records WHERE org_id IN ($1,$2) AND action='runner.revoke' AND result_status='ok'`, org.String(), otherOrg.String()).Scan(&successes); err != nil {
		t.Fatal("read denied revoke audit")
	}
	if successes != 0 {
		t.Fatal("denied revoke wrote a success audit")
	}
	csr, _ := runnerCSR(t)
	rec := doJSON(t, handler, http.MethodPost, "/runners/renew", runnerRenewRequest{CSR: csr}, "", parseCert(t, enrolled.Certificate))
	if rec.Code != http.StatusOK {
		t.Fatal("denied revoke changed the runner registry")
	}
}

type failingRevokeAudit struct{ message string }

func (f failingRevokeAudit) Append(context.Context, audit.Record) (audit.Record, error) {
	return audit.Record{}, errors.New(f.message)
}

func TestRevokeRunner_AuditFailureDoesNotReportSuccess(t *testing.T) {
	handler, db, pki, logs := fullRouter(t)
	org := seedOrg(t, db)
	admin := adminToken(t, db, org)
	enrolled := enrollForTest(t, handler, db, org, admin, "failed-audit-revoke.example.test")
	c := canary.New()
	bad := NewRouter(obs.New(logs), db, Deps{
		Audit: failingRevokeAudit{message: c.Value(1)}, Identity: identity.NewRepo(db),
		Tokens: enrolltoken.NewRepo(db), Runners: registry.NewRepo(db), Certs: pki, CA: pki,
	})
	rec := doJSON(t, bad, http.MethodPost, "/runners/"+enrolled.RunnerID.String()+"/revoke", nil, admin, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("audit failure status=%d, want 500", rec.Code)
	}
	if !c.In(c.Value(1)) || c.In(rec.Body.String()) || c.In(logs.String()) {
		t.Fatal("audit error redaction failed")
	}
	var result revokeResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil || result.OK {
		t.Fatal("audit failure response claims success")
	}
	csr, _ := runnerCSR(t)
	renew := doJSON(t, handler, http.MethodPost, "/runners/renew", runnerRenewRequest{CSR: csr}, "", parseCert(t, enrolled.Certificate))
	if renew.Code != http.StatusUnauthorized {
		t.Fatal("audit failure reactivated revoked runner")
	}
}
