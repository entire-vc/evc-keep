package builtin

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"

	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

func newRoot(t *testing.T, id string) (sealer.RootKey, []byte) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	root, err := sealer.NewLocalRootKey(id, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	return root, key
}

type xferStore struct {
	mu     sync.Mutex
	recs   map[string]sealer.KEKRecord
	active map[string]string
}

func newXferStore() *xferStore {
	return &xferStore{recs: map[string]sealer.KEKRecord{}, active: map[string]string{}}
}
func (m *xferStore) Level(context.Context, string) (sealer.Level, error) {
	return sealer.DefaultLevel, nil
}
func (m *xferStore) SetLevel(context.Context, string, sealer.Level, string) error { return nil }
func (m *xferStore) Lock(context.Context, string, bool) (sealer.Store, func(context.Context) error, error) {
	return m, func(context.Context) error { return nil }, nil
}
func (m *xferStore) ActiveFor(_ context.Context, org, dk string) (sealer.KEKRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.active[org+"\x00"+dk]
	if !ok {
		return sealer.KEKRecord{}, sealer.ErrNoActiveKEK
	}
	return m.recs[id], nil
}
func (m *xferStore) Create(_ context.Context, dk string, want sealer.KEKRecord) (sealer.KEKRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := want.Org + "\x00" + dk
	if id, ok := m.active[k]; ok {
		return m.recs[id], nil
	}
	m.recs[want.ID] = want
	m.active[k] = want.ID
	return want, nil
}
func (m *xferStore) Get(_ context.Context, org, id string) (sealer.KEKRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.recs[id]
	if !ok || r.Org != org {
		return sealer.KEKRecord{}, errors.New("not found")
	}
	return r, nil
}
func (m *xferStore) ActiveList(_ context.Context, org string) ([]sealer.KEKRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []sealer.KEKRecord
	for _, r := range m.recs {
		if r.Org == org {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func (m *xferStore) RetiredList(context.Context, string) ([]sealer.KEKRecord, error) { return nil, nil }
func (m *xferStore) Retire(context.Context, string, []string) error                  { return nil }
func (m *xferStore) Purge(context.Context, string, []string) error                   { return nil }

type xferAudit struct{}

func (xferAudit) Record(sealer.Event) {}

// kekRecords makes n real KEKs of org under src by sealing a value for n
// different users through the sealer, then reading the KEK records back.
func kekRecords(t *testing.T, org string, src sealer.RootKey, n int) []sealer.KEKRecord {
	t.Helper()
	st := newXferStore()
	s := sealer.New(src, xferAudit{}, st)
	for i := 0; i < n; i++ {
		ref := sealer.Ref{Store: sealer.Scope{Org: org, User: fmt.Sprintf("user-%d", i)}, SecretID: "s", Name: "n", Version: "v1"}
		if _, err := s.Seal(context.Background(), ref, secret.New([]byte("fixture-value-not-real"))); err != nil {
			t.Fatalf("fixture seal: %v", err)
		}
	}
	recs, err := st.ActiveList(context.Background(), org)
	if err != nil || len(recs) != n {
		t.Fatalf("fixture KEKs: %v (%d)", err, len(recs))
	}
	return recs
}

func TestRewrapKEKsForTransfer(t *testing.T) {
	src, _ := newRoot(t, "root")
	dst, _ := newRoot(t, "root") // same ID, independent key material
	recs := kekRecords(t, "org-1", src, 3)

	out, err := rewrapKEKsForTransfer("org-1", recs, src, dst)
	if err != nil || len(out) != len(recs) {
		t.Fatalf("positive control failed: %v", err)
	}
	for i := range recs {
		if out[i].ID != recs[i].ID || out[i].Org != recs[i].Org || out[i].Domain != recs[i].Domain {
			t.Fatal("KEK identity or domain changed")
		}
		if bytes.Equal(out[i].Wrapped, recs[i].Wrapped) {
			t.Fatal("wrapping not changed")
		}
		// the target root must open the result, the source must not
		if _, err := sealer.RewrapKEK("org-1", out[i], dst, src); err != nil {
			t.Fatal("target-wrapped record does not round-trip")
		}
	}
	// source records are untouched
	if _, err := sealer.RewrapKEK("org-1", recs[0], src, dst); err != nil {
		t.Fatal("source record modified")
	}

	other, _ := newRoot(t, "other")
	wrongOrg := append([]sealer.KEKRecord(nil), recs...)
	wrongOrg[1].Org = "org-2"
	dup := append(append([]sealer.KEKRecord(nil), recs...), recs[0])
	foreignRoot := kekRecords(t, "org-1", other, 1)
	cases := map[string]struct {
		org      string
		recs     []sealer.KEKRecord
		src, dst sealer.RootKey
	}{
		"same root":        {"org-1", recs, src, src},
		"empty":            {"org-1", nil, src, dst},
		"empty org":        {"", recs, src, dst},
		"wrong org in set": {"org-1", wrongOrg, src, dst},
		"duplicate":        {"org-1", dup, src, dst},
		"foreign wrapped":  {"org-1", append(append([]sealer.KEKRecord(nil), recs...), foreignRoot...), src, dst},
		"nil target":       {"org-1", recs, src, nil},
		"too many":         {"org-1", make([]sealer.KEKRecord, MaxTransferKEKs+1), src, dst},
	}
	for name, c := range cases {
		got, err := rewrapKEKsForTransfer(c.org, c.recs, c.src, c.dst)
		if err != ErrTransferRewrap || got != nil {
			t.Errorf("%s: want refusal with no partial result, got %v (%d records)", name, err, len(got))
		}
	}
}

// The PKI KEK is part of the closure and must keep its domain unchanged.
func TestRewrapKEKsForTransferKeepsPKIDomain(t *testing.T) {
	src, _ := newRoot(t, "root")
	dst, _ := newRoot(t, "root")
	st := newXferStore()
	s := sealer.New(src, xferAudit{}, st)
	ref := sealer.Ref{Store: sealer.Scope{Org: "org-1", PKI: true}, SecretID: "org-ca", Name: "private_key", Version: "v2:00"}
	if _, err := s.Seal(context.Background(), ref, secret.New([]byte("fixture-value-not-real"))); err != nil {
		t.Fatal(err)
	}
	recs, err := st.ActiveList(context.Background(), "org-1")
	if err != nil || len(recs) != 1 || !recs[0].Domain.PKI {
		t.Fatalf("fixture: %v", err)
	}
	out, err := rewrapKEKsForTransfer("org-1", recs, src, dst)
	if err != nil || !out[0].Domain.PKI || out[0].ID != recs[0].ID {
		t.Fatalf("PKI KEK not carried with its domain: %v", err)
	}
}
