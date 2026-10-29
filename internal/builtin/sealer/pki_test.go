package sealer

import (
	"context"
	"errors"
	"testing"

	"github.com/entire-vc/evc-keep/pkg/secret"
)

func TestPKIDomainAndEnvelopeIsolation(t *testing.T) {
	s, _ := newSealer(t)
	ctx := context.Background()
	scope := Scope{Org: "org", PKI: true}
	if scope.key() != "pki:3:org" || scope.key() == (Scope{Org: "org"}).key() {
		t.Fatal("PKI shares a value domain")
	}
	for _, level := range []Level{LevelUser, LevelProject, LevelWorkspace, LevelOrg} {
		if Domain(scope, level) != scope {
			t.Fatal("value key level changes PKI domain")
		}
	}
	if err := (Scope{Org: "org", PKI: true, User: "user"}).validate(); !errors.Is(err, ErrInvalidScope) {
		t.Fatal("PKI accepted a value owner scope")
	}
	ref := Ref{Store: scope, SecretID: "key", Name: "key", Version: "v2"}
	value := secret.New([]byte("synthetic-domain-control"))
	defer value.Wipe()
	env, err := s.Seal(ctx, ref, value)
	if err != nil {
		t.Fatal("PKI seal failed")
	}
	opened, err := s.Open(ctx, ref, env)
	if err != nil {
		t.Fatal("PKI positive control failed")
	}
	opened.Wipe()
	ref.Store.PKI = false
	opened, err = s.Open(ctx, ref, env)
	opened.Wipe()
	if err == nil {
		t.Fatal("PKI envelope opened in value domain")
	}
}

func TestValuePurgeKeepsRetiredPKIKey(t *testing.T) {
	s, _ := newSealer(t)
	ctx := context.Background()
	ref := Ref{Store: Scope{Org: "org", PKI: true}, SecretID: "key", Name: "key", Version: "v2"}
	v := secret.New([]byte("synthetic-purge-control"))
	defer v.Wipe()
	pki, err := s.Seal(ctx, ref, v)
	if err != nil {
		t.Fatal("PKI seal failed")
	}
	valueRef := ref
	valueRef.Store.PKI = false
	value, err := s.Seal(ctx, valueRef, v)
	if err != nil {
		t.Fatal("value seal failed")
	}
	if err := s.store.Retire(ctx, "org", []string{pki.KEKID, value.KEKID}); err != nil {
		t.Fatal("retire fixture failed")
	}
	n, err := s.Purge(ctx, "org", "admin", newMemStore())
	if err != nil || n != 1 {
		t.Fatal("value purge touched a PKI key or did not purge a value key")
	}
	opened, err := s.Open(ctx, ref, pki)
	opened.Wipe()
	if err != nil {
		t.Fatal("value purge destroyed PKI")
	}
	opened, err = s.Open(ctx, valueRef, value)
	opened.Wipe()
	if err == nil {
		t.Fatal("value purge positive control did not destroy value key")
	}
}
