package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/enrolltoken"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/registry"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func assertRunnerAudit(t *testing.T, db *pgxpool.Pool, org uuid.UUID, action, status, token, serial string, want int) {
	t.Helper()
	rows, err := db.Query(context.Background(), `SELECT row_to_json(a)::text FROM audit_records a WHERE org_id=$1 AND action=$2 AND result_status=$3`, org.String(), action, status)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if (token != "" && strings.Contains(raw, token)) || (serial != "" && strings.Contains(raw, `"`+serial+`"`)) {
			t.Fatal("credential escaped into runner audit")
		}
		var fields map[string]any
		if err := json.Unmarshal([]byte(raw), &fields); err != nil {
			t.Fatal(err)
		}
		decision := "allow"
		if status == "failed" {
			decision = "deny"
		}
		if fields["policy_decision"] != decision {
			t.Fatal("audit lacks closed policy decision")
		}
		if status == "failed" && fields["result_error_class"] != "permission_denied" {
			t.Fatal("denial lacks closed error_class")
		}
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("%s %s audit count=%d, want %d", action, status, count, want)
	}
}

func TestRunnerAuditFourOutcomes(t *testing.T) {
	handler, db, _, logs := fullRouter(t)
	org := seedOrg(t, db)
	admin := adminToken(t, db, org)
	host := "audit.example.test"
	_ = issueEnrollToken(t, handler, org, admin, host, validPolicySHA256())
	c := canary.New()
	token := c.Value(1)
	for _, prefix := range []string{"", "x", "xx"} {
		planted := base64.StdEncoding.EncodeToString([]byte(prefix + token))
		if !c.In(planted) {
			t.Fatal("token canary positive control failed")
		}
	}
	hash := sha256.Sum256([]byte(token))
	if _, err := db.Exec(context.Background(), `UPDATE enroll_tokens SET token_hash=$1 WHERE org_id=$2`, hash[:], org); err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate CSR key")
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: token}}, key)
	if err != nil {
		t.Fatal("create canary CSR")
	}
	rec := doJSON(t, handler, http.MethodPost, "/runners/enroll", runnerEnrollRequest{Token: token, Host: host, PolicySHA256: validPolicySHA256(), CSR: csr}, "", nil)
	if rec.Code != 200 {
		t.Fatalf("enroll status=%d", rec.Code)
	}
	assertAuditCanaryAbsent(t, db, org, c, logs, rec.Body.String()) // enroll-ok canary
	enrolled := decodeCertResponse(t, rec)
	leaf := parseCert(t, enrolled.Certificate)
	assertRunnerAudit(t, db, org, "runner.enroll", "ok", token, leaf.SerialNumber.String(), 1)
	rec = doJSON(t, handler, http.MethodPost, "/runners/enroll", runnerEnrollRequest{Token: token, Host: host, PolicySHA256: validPolicySHA256(), CSR: csr}, "", nil)
	if rec.Code != 401 {
		t.Fatalf("denied enroll status=%d", rec.Code)
	}
	assertAuditCanaryAbsent(t, db, org, c, logs, rec.Body.String()) // enroll-denied canary
	assertRunnerAudit(t, db, org, "runner.enroll", "failed", token, "", 1)
	rec = doJSON(t, handler, http.MethodPost, "/runners/renew", runnerRenewRequest{CSR: csr}, "", leaf)
	if rec.Code != 200 {
		t.Fatalf("renew status=%d", rec.Code)
	}
	assertAuditCanaryAbsent(t, db, org, c, logs, rec.Body.String()) // renew-ok canary
	renewed := decodeCertResponse(t, rec)
	assertRunnerAudit(t, db, org, "runner.renew", "ok", token, parseCert(t, renewed.Certificate).SerialNumber.String(), 1)
	rec = doJSON(t, handler, http.MethodPost, "/runners/renew", runnerRenewRequest{CSR: csr}, "", leaf)
	if rec.Code != 401 {
		t.Fatalf("stale renew status=%d", rec.Code)
	}
	assertAuditCanaryAbsent(t, db, org, c, logs, rec.Body.String()) // renew-denied canary
	assertRunnerAudit(t, db, org, "runner.renew", "failed", token, leaf.SerialNumber.String(), 1)
}

func TestRunnerAuditEnrollmentDenials(t *testing.T) {
	for _, name := range []string{"expired", "host", "policy"} {
		t.Run(name, func(t *testing.T) {
			handler, db, _, _ := fullRouter(t)
			org := seedOrg(t, db)
			host := "audit.example.test"
			token := issueEnrollToken(t, handler, org, adminToken(t, db, org), host, validPolicySHA256())
			req := runnerEnrollRequest{Token: token, Host: host, PolicySHA256: validPolicySHA256()}
			req.CSR, _ = runnerCSR(t)
			switch name {
			case "expired":
				_, err := db.Exec(context.Background(), `UPDATE enroll_tokens SET expires_at=now()-interval '1 hour' WHERE org_id=$1`, org)
				if err != nil {
					t.Fatal(err)
				}
			case "host":
				req.Host = "other.example.test"
			case "policy":
				req.PolicySHA256 = strings.Repeat("a", 64)
			}
			rec := doJSON(t, handler, http.MethodPost, "/runners/enroll", req, "", nil)
			if rec.Code != 401 {
				t.Fatalf("status=%d", rec.Code)
			}
			assertRunnerAudit(t, db, org, "runner.enroll", "failed", token, "", 1)
		})
	}
}

func TestRunnerAuditSuccessRollback(t *testing.T) {
	for _, action := range []string{"enroll", "renew"} {
		t.Run(action, func(t *testing.T) {
			db := scratchPool(t)
			pki := newFakeOrgPKI(t)
			good := NewRouter(obs.New(io.Discard), db, Deps{Identity: identity.NewRepo(db), Tokens: enrolltoken.NewRepo(db), Runners: registry.NewRepo(db), Certs: pki, CA: pki})
			org := seedOrg(t, db)
			admin := adminToken(t, db, org)
			// The real journal rejects its INSERT, after the runner INSERT/UPDATE.
			// Rollback must cover both, including the chain head.
			enrolled := enrollForTest(t, good, db, org, admin, "audit.example.test")
			leaf := parseCert(t, enrolled.Certificate)
			token := issueEnrollToken(t, good, org, admin, "audit.example.test", validPolicySHA256())
			sql := `CREATE FUNCTION reject_runner_audit_` + strings.ReplaceAll(org.String(), "-", "") + `() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.org_id='` + org.String() + `' AND NEW.action='runner.` + action + `' THEN RAISE EXCEPTION 'journal unavailable'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_runner_audit_` + strings.ReplaceAll(org.String(), "-", "") + ` BEFORE INSERT ON audit_records FOR EACH ROW EXECUTE FUNCTION reject_runner_audit_` + strings.ReplaceAll(org.String(), "-", "") + `()`
			if _, err := db.Exec(context.Background(), sql); err != nil {
				t.Fatal(err)
			}
			bad := NewRouter(obs.New(io.Discard), db, Deps{Audit: audit.NewJournal(db), Identity: identity.NewRepo(db), Tokens: enrolltoken.NewRepo(db), Runners: registry.NewRepo(db), Certs: pki, CA: pki})
			csr, _ := runnerCSR(t)
			var before int
			var headBefore, headAfter string
			const chainHead = `SELECT position::text || ':' || hash FROM audit_chain_heads WHERE org_id=$1`
			if err := db.QueryRow(context.Background(), chainHead, org.String()).Scan(&headBefore); err != nil {
				t.Fatal("read chain before failure")
			}
			if err := db.QueryRow(context.Background(), `SELECT count(*) FROM runners WHERE org_id=$1`, org).Scan(&before); err != nil {
				t.Fatal(err)
			}
			var rec *httptest.ResponseRecorder
			if action == "renew" {
				rec = doJSON(t, bad, http.MethodPost, "/runners/renew", runnerRenewRequest{CSR: csr}, "", leaf)
			}
			if action == "enroll" {
				rec = doJSON(t, bad, http.MethodPost, "/runners/enroll", runnerEnrollRequest{Token: token, Host: "audit.example.test", PolicySHA256: validPolicySHA256(), CSR: csr}, "", nil)
			}
			if rec.Code != 503 || bytes.Contains(rec.Body.Bytes(), []byte("certificate")) {
				t.Fatalf("audit failure status=%d or credential returned", rec.Code)
			}
			var after int
			if err := db.QueryRow(context.Background(), `SELECT count(*) FROM runners WHERE org_id=$1`, org).Scan(&after); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRow(context.Background(), chainHead, org.String()).Scan(&headAfter); err != nil {
				t.Fatal("read chain after failure")
			}
			if headBefore != headAfter {
				t.Fatal("audit chain head survived failed transaction")
			}
			if before != after {
				t.Fatal("runner INSERT survived audit failure")
			}
			if action == "renew" {
				if err := registry.NewRepo(db).CheckActive(context.Background(), org, enrolled.RunnerID, leaf.SerialNumber.String()); err != nil {
					t.Fatal("serial UPDATE survived audit failure")
				}
			}
		})
	}
}

func TestRunnerAuditDenialFailureKeeps401(t *testing.T) {
	good, db, pki, logs := fullRouter(t)
	org := seedOrg(t, db)
	admin := adminToken(t, db, org)
	enrolled := enrollForTest(t, good, db, org, admin, "audit.example.test")
	leaf := parseCert(t, enrolled.Certificate)
	token := issueEnrollToken(t, good, org, admin, "audit.example.test", validPolicySHA256())
	if err := registry.NewRepo(db).Revoke(context.Background(), org, enrolled.RunnerID); err != nil {
		t.Fatal(err)
	}
	c := canary.New()
	failure := &runnerDenialAuditFailure{message: c.Value(2)}
	bad := NewRouter(obs.New(logs), db, Deps{Audit: failure, Identity: identity.NewRepo(db), Tokens: enrolltoken.NewRepo(db), Runners: registry.NewRepo(db), Certs: pki, CA: pki})
	csr, _ := runnerCSR(t)
	for _, rec := range []int{doJSON(t, bad, http.MethodPost, "/runners/enroll", runnerEnrollRequest{Token: token, Host: "wrong.example.test", PolicySHA256: validPolicySHA256(), CSR: csr}, "", nil).Code, doJSON(t, bad, http.MethodPost, "/runners/renew", runnerRenewRequest{CSR: csr}, "", leaf).Code} {
		if rec != 401 {
			t.Fatalf("denial journal failure status=%d", rec)
		}
	}
	if failure.calls != 2 {
		t.Fatal("denials did not attempt both audit writes")
	}
	if !strings.Contains(logs.String(), "runner denial journal unavailable") || c.In(logs.String()) {
		t.Fatal("denial failure observation missing or leaks error text")
	}
}

type runnerDenialAuditFailure struct {
	message string
	calls   int
}

func (f *runnerDenialAuditFailure) Append(context.Context, audit.Record) (audit.Record, error) {
	f.calls++
	return audit.Record{}, errors.New(f.message)
}

func assertAuditCanaryAbsent(t *testing.T, db *pgxpool.Pool, org uuid.UUID, c canary.Canary, logs *bytes.Buffer, response string) {
	t.Helper()
	if logs.Len() == 0 {
		t.Fatal("log capture is empty")
	}
	if c.In(logs.String()) || c.In(response) {
		t.Fatal("token canary escaped into response or log")
	}
	rows, err := db.Query(context.Background(), `SELECT row_to_json(a)::text FROM audit_records a WHERE org_id=$1`, org.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if c.In(raw) {
			t.Fatal("token canary escaped into journal")
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestRunnerAuditUnauthenticatedDoesNotAppend(t *testing.T) {
	handler, db, _, _ := fullRouter(t)
	org := seedOrg(t, db)
	admin := adminToken(t, db, org)
	enrolled := enrollForTest(t, handler, db, org, admin, "audit.example.test")
	leaf := parseCert(t, enrolled.Certificate)
	csr, _ := runnerCSR(t)
	rec := doJSON(t, handler, http.MethodPost, "/runners/enroll", runnerEnrollRequest{Token: canary.New().Value(1), Host: "audit.example.test", PolicySHA256: validPolicySHA256(), CSR: csr}, "", nil)
	if rec.Code != 401 {
		t.Fatalf("unknown token status=%d", rec.Code)
	}
	forged := *leaf
	forged.Signature = append([]byte(nil), leaf.Signature...)
	forged.Signature[0] ^= 1
	for _, cert := range []*x509.Certificate{nil, &forged} {
		rec := doJSON(t, handler, http.MethodPost, "/runners/renew", runnerRenewRequest{CSR: csr}, "", cert)
		if rec.Code != 401 {
			t.Fatalf("unauthenticated certificate status=%d", rec.Code)
		}
	}
	assertRunnerAudit(t, db, org, "runner.enroll", "failed", "", "", 0)
	assertRunnerAudit(t, db, org, "runner.renew", "failed", "", "", 0)
}
