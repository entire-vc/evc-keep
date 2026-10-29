package builtin

import (
	"context"
	"testing"

	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	"github.com/entire-vc/evc-keep/pkg/provider/svctoken"
	"github.com/google/uuid"
)

// A successful svctoken Activate crypto-erases every staged version on the
// builtin store, also those a restarted Store no longer remembers, and leaves
// the main name active: the live service token has one readable sealed copy.
func TestServiceTokenActivateErasesStagedEnvelopes(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	seal, _ := testSealer(t, pool)
	scope := sealer.Scope{Org: randID(t, "org")}
	p := New(pool, seal, scope, nil)
	s, err := svctoken.New(p, "mesh-service-token")
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.NewString()
	for range 2 { // a retried stage leaves two versions
		if err := s.Stage(ctx, id, secretOf("new-token")); err != nil {
			t.Fatal(err)
		}
	}
	// A restart: the new Store learns the staged versions from the provider.
	if s, err = svctoken.New(p, "mesh-service-token"); err != nil {
		t.Fatal(err)
	}
	staged := "builtin://mesh-service-token-staged-" + id
	if r, err := p.db.byVersion(ctx, scope, staged, 2); err != nil || r.status != "active" {
		t.Fatalf("positive control: staged v2 is not active before Activate: %q %v", r.status, err)
	}
	if err := s.Activate(ctx, id); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int64{1, 2} {
		r, err := p.db.byVersion(ctx, scope, staged, n)
		if err != nil {
			t.Fatal(err)
		}
		if r.status != "erased" || r.wrapped != nil || r.kekID != "" {
			t.Fatalf("staged v%d: status %q, wrapped DEK kept %v, kek %q", n, r.status, r.wrapped != nil, r.kekID)
		}
	}
	main, err := p.db.byVersion(ctx, scope, "builtin://mesh-service-token", 1)
	if err != nil || main.status != "active" {
		t.Fatalf("main token: %q %v", main.status, err)
	}
	if tok, err := s.Token(ctx); err != nil || tok != "new-token" {
		t.Fatalf("token after Activate: %q %v", tok, err)
	}
}
