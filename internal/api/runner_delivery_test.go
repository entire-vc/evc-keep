package api

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/entire-vc/evc-keep/internal/enrolltoken"
	"github.com/entire-vc/evc-keep/internal/registry"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

func deliveryPublicKey(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate delivery key")
	}
	return key.PublicKey().Bytes(), key.Bytes()
}

func TestEnrollBindsDeliveryTrustFromIssuer(t *testing.T) {
	handler, db, _, _ := fullRouter(t)
	org := seedOrg(t, db)
	admin := adminToken(t, db, org)
	f := false
	attrs := &enrolltoken.HostAttrs{UIDShared: &f, Labels: map[string]string{"platform": "linux"}}
	host, policy := "delivery.example.test", validPolicySHA256()
	issued := doJSON(t, handler, http.MethodPost, "/runners/enroll-tokens",
		enrollTokenIssueRequest{Host: host, PolicySHA256: policy, HostAttrs: attrs}, admin, nil)
	if issued.Code != http.StatusCreated {
		t.Fatal("issue token with host attributes")
	}
	var tokenBody struct {
		Token string `json:"token"`
	}
	if json.Unmarshal(issued.Body.Bytes(), &tokenBody) != nil {
		t.Fatal("decode token response")
	}
	csr, _ := runnerCSR(t)
	public, private := deliveryPublicKey(t)
	bad := doJSON(t, handler, http.MethodPost, "/runners/enroll",
		map[string]any{"token": tokenBody.Token, "host": host, "policy_sha256": policy, "csr": csr,
			"hpke_public_key": public, "host_attrs": map[string]any{"uid_shared": true}}, "", nil)
	if bad.Code != http.StatusBadRequest {
		t.Fatal("runner-supplied host attributes were accepted")
	}
	short := doJSON(t, handler, http.MethodPost, "/runners/enroll",
		runnerEnrollRequest{Token: tokenBody.Token, Host: host, PolicySHA256: policy, CSR: csr, HPKEPublicKey: public[:16]}, "", nil)
	if short.Code != http.StatusBadRequest {
		t.Fatal("short X25519 public key was accepted")
	}
	good := doJSON(t, handler, http.MethodPost, "/runners/enroll",
		runnerEnrollRequest{Token: tokenBody.Token, Host: host, PolicySHA256: policy, CSR: csr, HPKEPublicKey: public}, "", nil)
	res := decodeCertResponse(t, good)
	if len(res.Certificate) == 0 || good.Body.String() == "" {
		t.Fatal("enrollment response missing certificate")
	}
	if canary.Of(string(private)).In(good.Body.String()) {
		t.Fatal("delivery private key appeared in enrollment response")
	}
	trust, err := registry.NewRepo(db).GetDeliveryTrust(context.Background(), org, res.RunnerID)
	if err != nil || !trust.AttrsKnown || trust.UIDShared || trust.HostLabels["platform"] != "linux" || string(trust.HPKEPublicKey) != string(public) {
		t.Fatal("enrollment did not bind issuer attributes and runner delivery key")
	}

	leaf := parseCert(t, res.Certificate)
	renewCSR, _ := runnerCSR(t)
	tamper := doJSON(t, handler, http.MethodPost, "/runners/renew",
		map[string]any{"csr": renewCSR, "hpke_public_key": public}, "", leaf)
	if tamper.Code != http.StatusBadRequest {
		t.Fatal("renewal accepted delivery key replacement")
	}
	renewed := doJSON(t, handler, http.MethodPost, "/runners/renew", runnerRenewRequest{CSR: renewCSR}, "", leaf)
	if renewed.Code != http.StatusOK {
		t.Fatal("ordinary renewal failed")
	}
	after, err := registry.NewRepo(db).GetDeliveryTrust(context.Background(), org, res.RunnerID)
	if err != nil || string(after.HPKEPublicKey) != string(public) || !after.AttrsKnown || after.UIDShared || after.HostLabels["platform"] != "linux" {
		t.Fatal("renewal changed delivery trust")
	}
}

func TestEnrollLegacyWithoutDeliveryKeyCannotBeReleased(t *testing.T) {
	handler, db, _, _ := fullRouter(t)
	org := seedOrg(t, db)
	admin := adminToken(t, db, org)
	enrolled := enrollForTest(t, handler, db, org, admin, "legacy.example.test")
	if _, err := registry.NewRepo(db).GetDeliveryTrust(context.Background(), org, enrolled.RunnerID); err != registry.ErrDeliveryUnavailable {
		t.Fatal("legacy runner was eligible for value delivery")
	}
}
