package sealer

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func rewrapRoot(t *testing.T, id string) RootKey {
	t.Helper()
	key := make([]byte, 32)
	defer wipe(key)
	if _, err := rand.Read(key); err != nil {
		t.Fatal("cannot generate test root")
	}
	r, err := NewLocalRootKey(id, key)
	if err != nil {
		t.Fatal("cannot construct test root")
	}
	return r
}

func rewrapRecord(t *testing.T, root RootKey) (KEKRecord, []byte) {
	t.Helper()
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal("cannot generate test KEK")
	}
	t.Cleanup(func() { wipe(kek) })
	r := KEKRecord{ID: "kek-1", Org: "partner", Domain: Scope{Org: "partner", Workspace: "workspace-1"}, RootKeyID: root.ID()}
	var err error
	r.Wrapped, err = root.Wrap(kek, kekAAD(r.ID, r.Org, r.Domain.key(), r.RootKeyID))
	if err != nil {
		t.Fatal("cannot wrap test KEK")
	}
	return r, kek
}

func TestRewrapKEKIndependentRoots(t *testing.T) {
	for _, targetID := range []string{"partner-root", "local-v1"} {
		t.Run(targetID, func(t *testing.T) {
			source, target := rewrapRoot(t, "local-v1"), rewrapRoot(t, targetID)
			r, kek := rewrapRecord(t, source)
			original := r
			original.Wrapped = bytes.Clone(r.Wrapped)
			out, err := RewrapKEK(r.Org, r, source, target)
			if err != nil {
				t.Fatal("independent-root positive control failed")
			}
			if !reflect.DeepEqual(r, original) {
				t.Fatal("source record mutated")
			}
			if out.ID != r.ID || out.Org != r.Org || out.Domain != r.Domain || out.RootKeyID != target.ID() {
				t.Fatal("rewrap changed immutable identity or missed target root")
			}
			opened, err := target.Unwrap(out.Wrapped, kekAAD(out.ID, out.Org, out.Domain.key(), out.RootKeyID))
			defer wipe(opened)
			if err != nil || !bytes.Equal(opened, kek) {
				t.Fatal("target did not recover the original KEK")
			}
			wrong, err := source.Unwrap(out.Wrapped, kekAAD(out.ID, out.Org, out.Domain.key(), out.RootKeyID))
			defer wipe(wrong)
			if err == nil {
				t.Fatal("new wrapping still authenticates under source root")
			}
			// The original remains readable for rollback; no source key rotation.
			old, err := source.Unwrap(r.Wrapped, kekAAD(r.ID, r.Org, r.Domain.key(), r.RootKeyID))
			defer wipe(old)
			if err != nil || !bytes.Equal(old, kek) {
				t.Fatal("source rollback positive control failed")
			}
		})
	}
}

func TestRewrapKEKRefusesWrongScopeAndAuthentication(t *testing.T) {
	source, target := rewrapRoot(t, "source"), rewrapRoot(t, "target")
	for _, tc := range []struct {
		name   string
		change func(*KEKRecord, *string)
	}{
		{"foreign-org", func(_ *KEKRecord, org *string) { *org = "foreign" }},
		{"empty-org", func(_ *KEKRecord, org *string) { *org = "" }},
		{"foreign-domain", func(r *KEKRecord, _ *string) { r.Domain.Org = "foreign" }},
		{"invalid-domain", func(r *KEKRecord, _ *string) { r.Domain.User = "user" }},
		{"changed-domain", func(r *KEKRecord, _ *string) { r.Domain.Workspace = "other" }},
		{"changed-id", func(r *KEKRecord, _ *string) { r.ID = "other" }},
		{"empty-id", func(r *KEKRecord, _ *string) { r.ID = "" }},
		{"wrong-root-id", func(r *KEKRecord, _ *string) { r.RootKeyID = "other" }},
		{"tampered-wrapping", func(r *KEKRecord, _ *string) { r.Wrapped[len(r.Wrapped)-1] ^= 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := rewrapRecord(t, source)
			org := r.Org
			tc.change(&r, &org)
			out, err := RewrapKEK(org, r, source, target)
			if !errors.Is(err, ErrRewrapKEK) || !reflect.DeepEqual(out, KEKRecord{}) {
				t.Fatal("invalid input returned material or lacked a safe refusal")
			}
		})
	}
	r, _ := rewrapRecord(t, source)
	for _, pair := range [][2]RootKey{{nil, target}, {source, nil}, {rewrapRoot(t, "source"), target}, {source, rewrapRoot(t, "")}} {
		out, err := RewrapKEK(r.Org, r, pair[0], pair[1])
		if !errors.Is(err, ErrRewrapKEK) || !reflect.DeepEqual(out, KEKRecord{}) {
			t.Fatal("invalid root returned material or lacked a safe refusal")
		}
	}
}

// mock: external boundary — a KMS backend can attach key material to errors
// and return a partially populated buffer on failure. No persistence is mocked.
type failingRewrapKMS struct {
	RootKey
	failUnwrap bool
	observed   []byte
}

func (r *failingRewrapKMS) Unwrap(wrapped, aad []byte) ([]byte, error) {
	if !r.failUnwrap {
		return r.RootKey.Unwrap(wrapped, aad)
	}
	r.observed = bytes.Repeat([]byte{17}, 32)
	return r.observed, fmt.Errorf("external key backend: %x", r.observed)
}

func (r *failingRewrapKMS) Wrap(plain, _ []byte) ([]byte, error) {
	r.observed = plain
	return bytes.Clone(plain), fmt.Errorf("external key backend: %x", plain)
}

func TestRewrapKEKNoMaterialInErrors(t *testing.T) {
	source, target := rewrapRoot(t, "source"), rewrapRoot(t, "target")
	r, _ := rewrapRecord(t, source)
	for _, unwrap := range []bool{true, false} {
		backend := &failingRewrapKMS{RootKey: target}
		src, dst := source, RootKey(backend)
		if unwrap {
			backend.RootKey, backend.failUnwrap = source, true
			src, dst = backend, target
		}
		out, err := RewrapKEK(r.Org, r, src, dst)
		if err != ErrRewrapKEK || !reflect.DeepEqual(out, KEKRecord{}) {
			t.Fatal("foreign backend error or partial material escaped")
		}
		if !bytes.Equal(backend.observed, make([]byte, 32)) {
			t.Fatal("temporary plaintext KEK was not wiped on failure")
		}
	}
}

// mock: external boundary — this root backend decrypts into its input buffer.
// It delegates authentication to the real root implementation.
type inPlaceRewrapRoot struct{ RootKey }

func (r inPlaceRewrapRoot) Unwrap(wrapped, aad []byte) ([]byte, error) {
	plain, err := r.RootKey.Unwrap(wrapped, aad)
	if err != nil {
		return nil, err
	}
	defer wipe(plain)
	copy(wrapped, plain)
	return wrapped[:len(plain)], nil
}

func TestRewrapKEKPreservesSourceWithInPlaceBackend(t *testing.T) {
	source, target := rewrapRoot(t, "source"), rewrapRoot(t, "target")
	r, _ := rewrapRecord(t, source)
	original := bytes.Clone(r.Wrapped)
	if _, err := RewrapKEK(r.Org, r, inPlaceRewrapRoot{source}, target); err != nil {
		t.Fatal("in-place backend positive control failed")
	}
	if !bytes.Equal(r.Wrapped, original) {
		t.Fatal("backend mutation or temporary wipe changed the source wrapping")
	}
}

// mock: external boundary — a KMS adapter may reuse the caller's buffer for
// wrapping. Authentication still uses the real root implementation.
type aliasingRewrapRoot struct {
	RootKey
	observed []byte
}

func (r *aliasingRewrapRoot) Wrap(plain, aad []byte) ([]byte, error) {
	wrapped, err := r.RootKey.Wrap(plain, aad)
	if err != nil {
		return nil, err
	}
	defer wipe(wrapped)
	if cap(plain) < len(wrapped) {
		return nil, errors.New("test backend needs an in-place source buffer")
	}
	r.observed = plain[:len(wrapped)]
	copy(r.observed, wrapped)
	return r.observed, nil
}

func TestRewrapKEKOwnsResultAndWipesSuccessfulBackendBuffer(t *testing.T) {
	source, target := rewrapRoot(t, "source"), rewrapRoot(t, "target")
	r, kek := rewrapRecord(t, source)
	backend := &aliasingRewrapRoot{RootKey: target}
	out, err := RewrapKEK(r.Org, r, inPlaceRewrapRoot{source}, backend)
	if err != nil {
		t.Fatal("aliased backend positive control failed")
	}
	if len(backend.observed) == 0 || !bytes.Equal(backend.observed, make([]byte, len(backend.observed))) {
		t.Fatal("successful backend temporary buffer was not wiped")
	}
	opened, err := target.Unwrap(out.Wrapped, kekAAD(out.ID, out.Org, out.Domain.key(), out.RootKeyID))
	defer wipe(opened)
	if err != nil || !bytes.Equal(opened, kek) {
		t.Fatal("temporary buffer cleanup corrupted the owned result")
	}
}
