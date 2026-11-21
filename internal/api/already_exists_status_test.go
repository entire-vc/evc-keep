package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/tenancy"
)

// already_exists is a client conflict, not a server fault: the class is
// 409 on the wire, the same fixed mapping for every handler that raises it.
func TestHTTPStatusAlreadyExistsIsConflict(t *testing.T) {
	if got := httpStatus(apperr.ClassAlreadyExists); got != http.StatusConflict {
		t.Fatalf("httpStatus(already_exists) = %d, want %d", got, http.StatusConflict)
	}
}

// A second create of the same (scope, name) answers 409 already_exists with
// the closed body; a caller from another org still gets the same 404 as
// before, so the 409 is no existence oracle across tenants (threat model §4.3).
func TestSecretRoutes_DuplicateCreateIs409(t *testing.T) {
	f := newRouteFixture(t)
	admin := f.mustAdmin("admin")
	bearer := f.mustToken(identity.KindUser, admin.ID, "org:"+f.org.ID.String())
	f.mustStore("default", tenancy.Org(f.org.ID))
	path := "/orgs/" + f.org.ID.String() + "/secrets"
	body := map[string]any{
		"scope_level": "org", "scope_id": f.org.ID.String(),
		"name": "db-password", "class": "credential", "type": "generic",
		"provider_ref": "builtin://default/db-password",
	}
	if first := f.do(http.MethodPost, path, bearer, body); first.Code != http.StatusCreated {
		t.Fatalf("first create: status = %d, body = %s", first.Code, first.Body.String())
	}
	second := f.do(http.MethodPost, path, bearer, body)
	if second.Code != http.StatusConflict {
		t.Fatalf("second create: status = %d, want 409, body = %s", second.Code, second.Body.String())
	}
	var b apperr.Body
	if err := json.Unmarshal(second.Body.Bytes(), &b); err != nil || b.ErrorClass != string(apperr.ClassAlreadyExists) {
		t.Fatalf("second create body: %v %+v", err, b)
	}
	var fields map[string]any
	if err := json.Unmarshal(second.Body.Bytes(), &fields); err != nil || len(fields) != 3 {
		t.Fatalf("409 body is not the closed three fields: %v", fields)
	}
	if strings.Contains(second.Body.String(), "db-password") || strings.Contains(f.logbuf.String(), "db-password") {
		t.Fatal("the secret name surfaced in the 409 body or the log")
	}

	// Another org's caller probing this org's path: unchanged 404 whether or
	// not the name exists here.
	other, err := f.tr.CreateOrganization(f.ctx, t.Name()+"-other", "")
	if err != nil {
		t.Fatal(err)
	}
	ou, err := f.tr.CreateUser(f.ctx, other.ID, "x@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.tr.CreateMembership(f.ctx, other.ID, ou.ID, tenancy.Org(other.ID), string(identity.RoleAdmin)); err != nil {
		t.Fatal(err)
	}
	res, err := f.ir.Issue(f.ctx, identity.IssueParams{OrgID: other.ID, Kind: identity.KindUser, PrincipalID: ou.ID, Scope: "org:" + other.ID.String()})
	if err != nil {
		t.Fatal(err)
	}
	foreign := f.do(http.MethodPost, path, identity.Reveal(res.Token), body)
	body["name"] = "never-created"
	foreignFresh := f.do(http.MethodPost, path, identity.Reveal(res.Token), body)
	if foreign.Code != foreignFresh.Code || foreign.Code == http.StatusConflict || foreign.Code >= 500 {
		t.Fatalf("cross-org probe: existing name %d vs fresh name %d", foreign.Code, foreignFresh.Code)
	}
	t.Logf("cross-org probe status: %d", foreign.Code)
}

// A member's ref in their own user scope that reuses the locator of an org
// secret in the org's store would share the org secret's value (the
// built-in provider keys a value by store and locator): refused with 409
// provider_ref_in_use and the closed body, which names neither the locator
// nor the secret holding it; the log does not carry the locator either. The
// refusal is journaled as a policy denial.
func TestSecretRoutes_ProviderRefInUseIs409(t *testing.T) {
	f := newRouteFixture(t)
	admin := f.mustAdmin("admin")
	adminBearer := f.mustToken(identity.KindUser, admin.ID, "org:"+f.org.ID.String())
	f.mustStore("default", tenancy.Org(f.org.ID))
	path := "/orgs/" + f.org.ID.String() + "/secrets"
	const locator = "builtin://default/org-db-marker-qzx"
	if first := f.do(http.MethodPost, path, adminBearer, map[string]any{
		"scope_level": "org", "scope_id": f.org.ID.String(),
		"name": "org-db-name-marker", "class": "credential", "type": "generic", "provider_ref": locator,
	}); first.Code != http.StatusCreated {
		t.Fatalf("org secret: status = %d, body = %s", first.Code, first.Body.String())
	}

	member := f.mustUser("member")
	memberBearer := f.mustToken(identity.KindUser, member.ID, "user:"+member.ID.String())
	shadow := map[string]any{
		"scope_level": "user", "scope_id": member.ID.String(),
		"name": "shadow", "class": "credential", "type": "generic", "provider_ref": locator,
	}
	audits := f.auditRowCount()
	resp := f.do(http.MethodPost, path, memberBearer, shadow)
	if resp.Code != http.StatusConflict {
		t.Fatalf("member reusing the org secret's locator: status = %d, want 409, body = %s", resp.Code, resp.Body.String())
	}
	var b apperr.Body
	if err := json.Unmarshal(resp.Body.Bytes(), &b); err != nil || b.ErrorClass != "provider_ref_in_use" {
		t.Fatalf("refusal body: %v %+v", err, b)
	}
	var fields map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &fields); err != nil || len(fields) != 3 {
		t.Fatalf("409 body is not the closed three fields: %v", fields)
	}
	// Positive control for the log check below: the request line of this
	// refusal is in the buffer (not just some other line carrying its id).
	logged := false
	for _, line := range strings.Split(f.logbuf.String(), "\n") {
		logged = logged || (b.RequestID != "" && strings.Contains(line, `"http_request"`) && strings.Contains(line, b.RequestID))
	}
	if !logged {
		t.Fatal("the refused request left no http_request log line; the log check below would prove nothing")
	}
	for _, marker := range []string{"org-db-marker-qzx", "builtin://", "org-db-name-marker"} {
		if strings.Contains(resp.Body.String(), marker) {
			t.Fatalf("refusal body carries %q: %s", marker, resp.Body.String())
		}
		if strings.Contains(f.logbuf.String(), marker) {
			t.Fatalf("log carries %q", marker)
		}
	}
	if f.auditRowCount() != audits+1 {
		t.Fatal("the refusal was not journaled")
	}
	var errClass string
	if err := f.pool.QueryRow(f.ctx, `SELECT result_error_class FROM audit_records WHERE org_id=$1 AND action='secret.create_ref' ORDER BY org_seq DESC LIMIT 1`, f.org.ID.String()).Scan(&errClass); err != nil || errClass != "policy_denied" {
		t.Fatalf("journaled error class = %q (%v), want policy_denied", errClass, err)
	}

	// Positive control: a fresh locator from the same member is accepted.
	shadow["provider_ref"] = "builtin://default/member-own"
	if ok := f.do(http.MethodPost, path, memberBearer, shadow); ok.Code != http.StatusCreated {
		t.Fatalf("fresh locator: status = %d, body = %s", ok.Code, ok.Body.String())
	}
}
