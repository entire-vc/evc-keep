package api

import (
	"context"
	"crypto/sha256"
	"net/http"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/intake"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/google/uuid"
)

type inputServiceProbe struct{ calls int }

func (p *inputServiceProbe) Issue(context.Context, tenancy.SecretRef, catalog.Store, audit.Actor, time.Duration) (intake.Issued, error) {
	p.calls++
	return intake.Issued{URL: "https://keep.example.invalid/input/test", RequestID: uuid.NewString(), ExpiresAt: time.Now().Add(time.Minute)}, nil
}

func TestInputLinkStatusRechecksCredentialRights(t *testing.T) {
	f := newRouteFixture(t)
	user := f.mustAdmin("status-issuer")
	st := f.mustStore("store", tenancy.Org(f.org.ID))
	ref, err := f.cat.CreateRef(f.ctx, catalog.CreateRefInput{Org: f.org.ID, Scope: tenancy.Org(f.org.ID), Name: "status-secret", Class: "dev", Type: "generic", ProviderRef: "builtin://store/status-secret"})
	if err != nil {
		t.Fatal("status reference")
	}
	request := uuid.Must(uuid.NewV7())
	requestHash := sha256.Sum256(request[:])
	_, err = f.pool.Exec(f.ctx, `INSERT INTO intake_links(request_id,org_id,secret_id,store_id,provider_ref,token_hash,actor_type,actor_id,public_key,signing_key,signature,expires_at,state,version,fingerprint) VALUES($1,$2,$3,$4,$5,$6,'user',$7,$8,$8,$9,clock_timestamp()+interval '1 hour','completed','1','kfp1:test:abcdefghijklmnop')`, request, f.org.ID, ref.ID, st.ID, ref.ProviderRef, requestHash[:], user.ID.String(), make([]byte, 32), make([]byte, 64))
	if err != nil {
		t.Fatal("status fixture")
	}
	svc := intake.New(f.pool, nil, nil, "https://keep.example.invalid")
	f.router = NewRouter(obs.New(f.logbuf), f.pool, Deps{Input: svc})
	token := f.mustToken(identity.KindUser, user.ID, "")
	path := "/v1/input-links/" + request.String()
	if w := f.do(http.MethodGet, path, token, nil); w.Code != http.StatusOK {
		t.Fatal("authorized issuer could not read status")
	}
	scoped := f.mustToken(identity.KindUser, user.ID, "ws:"+uuid.NewString())
	if w := f.do(http.MethodGet, path, scoped, nil); w.Code != http.StatusGone {
		t.Fatal("foreign-scope credential read intake status")
	}
	if _, err = f.pool.Exec(f.ctx, `DELETE FROM memberships WHERE org_id=$1 AND user_id=$2`, f.org.ID, user.ID); err != nil {
		t.Fatal("revoke membership")
	}
	if w := f.do(http.MethodGet, path, token, nil); w.Code != http.StatusGone {
		t.Fatal("revoked issuer membership read intake status")
	}
}
func (p *inputServiceProbe) IssueRotation(ctx context.Context, ref tenancy.SecretRef, st catalog.Store, a audit.Actor, ttl time.Duration) (intake.Issued, error) {
	return p.Issue(ctx, ref, st, a, ttl)
}

func (*inputServiceProbe) Read(context.Context, string) (intake.View, error) {
	return intake.View{}, intake.ErrGone
}
func (*inputServiceProbe) Complete(context.Context, string, intake.Envelope) (intake.Result, error) {
	return intake.Result{}, intake.ErrRejected
}
func (*inputServiceProbe) Status(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (intake.Result, error) {
	return intake.Result{}, intake.ErrGone
}
func TestInputLinkAuthorizationAndClosedRequest(t *testing.T) {
	f := newRouteFixture(t)
	user := f.mustAdmin("issuer")
	f.mustStore("store", tenancy.Org(f.org.ID))
	if _, err := f.cat.CreateRef(f.ctx, catalog.CreateRefInput{Org: f.org.ID, Scope: tenancy.Org(f.org.ID), Name: "sample", Class: "dev", Type: "generic", ProviderRef: "builtin://store/sample"}); err != nil {
		t.Fatal("secret")
	}
	token := f.mustToken(identity.KindUser, user.ID, "")
	probe := &inputServiceProbe{}
	f.router = NewRouter(obs.New(f.logbuf), f.pool, Deps{Input: probe})
	cases := []struct {
		body   map[string]string
		status int
	}{{map[string]string{"secret": "sample"}, http.StatusCreated}, {map[string]string{"secret": "sample", "value": "synthetic unwanted input"}, http.StatusBadRequest}, {map[string]string{"secret": "sample", "ttl": "25h"}, http.StatusBadRequest}, {map[string]string{"secret": "sample", "ttl": "0s"}, http.StatusBadRequest}}
	for _, c := range cases {
		w := f.do(http.MethodPost, "/v1/input-links", token, c.body)
		if w.Code != c.status {
			t.Fatalf("issue status %d, want %d", w.Code, c.status)
		}
	}
	scoped := f.mustToken(identity.KindUser, user.ID, "ws:"+uuid.NewString())
	if w := f.do(http.MethodPost, "/v1/input-links", scoped, map[string]string{"secret": "sample"}); w.Code != http.StatusNotFound {
		t.Fatal("foreign-scope credential issued link")
	}
	if probe.calls != 1 {
		t.Fatal("invalid input reached issuer")
	}
	reader := f.mustUser("reader")
	if _, err := f.tr.CreateMembership(f.ctx, f.org.ID, reader.ID, tenancy.Org(f.org.ID), string(identity.RoleViewer)); err != nil {
		t.Fatal("reader role")
	}
	readerToken := f.mustToken(identity.KindUser, reader.ID, "")
	if w := f.do(http.MethodPost, "/v1/input-links", readerToken, map[string]string{"secret": "sample"}); w.Code != http.StatusNotFound {
		t.Fatalf("read-only principal issued input: status %d", w.Code)
	}
	if probe.calls != 1 {
		t.Fatal("unauthorized input reached issuer")
	}
}
