package sealer

import (
	"bytes"
	"testing"
)

func TestRootKeyRejectsZero(t *testing.T) {
	key := make([]byte, 32)
	if _, err := NewLocalRootKey("test-root", key); err == nil {
		t.Fatal("accepted an all-zero root key")
	}
	key[0] = 1
	if _, err := NewLocalRootKey("test-root", key); err != nil {
		t.Fatal("nonzero root positive control failed")
	}
}

func TestKEKRootIdentity(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	defer clear(key)
	root, err := NewLocalRootKey("root-one", key)
	if err != nil {
		t.Fatal(err)
	}
	rec := KEKRecord{ID: "kek-test", Org: "org", Domain: Scope{Org: "org"}, RootKeyID: root.ID()}
	plain := bytes.Repeat([]byte{2}, 32)
	defer clear(plain)
	rec.Wrapped, err = root.Wrap(plain, kekAAD(rec.ID, rec.Org, rec.Domain.key(), rec.RootKeyID))
	if err != nil {
		t.Fatal(err)
	}
	s := &Sealer{root: root}
	opened, err := s.unwrapKEK(rec)
	defer clear(opened)
	if err != nil || !bytes.Equal(opened, plain) {
		t.Fatal("same root positive control failed")
	}
	other, err := NewLocalRootKey("root-two", key)
	if err != nil {
		t.Fatal(err)
	}
	s.root = other
	opened, err = s.unwrapKEK(rec)
	defer clear(opened)
	if err == nil {
		t.Fatal("KEK opened under a different root identifier")
	}
}
