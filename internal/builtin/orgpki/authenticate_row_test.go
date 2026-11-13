package orgpki

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"testing"

	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	"github.com/google/uuid"
)

// memStore is a minimal in-memory sealer.Store so AuthenticateRow is proved
// without a database.
type memStore struct {
	mu     sync.Mutex
	recs   map[string]sealer.KEKRecord
	active map[string]string
}

func newMemStore() *memStore {
	return &memStore{recs: map[string]sealer.KEKRecord{}, active: map[string]string{}}
}
func (m *memStore) Level(context.Context, string) (sealer.Level, error) {
	return sealer.DefaultLevel, nil
}
func (m *memStore) SetLevel(context.Context, string, sealer.Level, string) error { return nil }
func (m *memStore) Lock(context.Context, string, bool) (sealer.Store, func(context.Context) error, error) {
	return m, func(context.Context) error { return nil }, nil
}
func (m *memStore) ActiveFor(_ context.Context, org, dk string) (sealer.KEKRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.active[org+"\x00"+dk]
	if !ok {
		return sealer.KEKRecord{}, sealer.ErrNoActiveKEK
	}
	return m.recs[id], nil
}
func (m *memStore) Create(_ context.Context, dk string, want sealer.KEKRecord) (sealer.KEKRecord, error) {
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
func (m *memStore) Get(_ context.Context, org, id string) (sealer.KEKRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.recs[id]
	if !ok || r.Org != org {
		return sealer.KEKRecord{}, errors.New("not found")
	}
	return r, nil
}
func (m *memStore) ActiveList(context.Context, string) ([]sealer.KEKRecord, error)  { return nil, nil }
func (m *memStore) RetiredList(context.Context, string) ([]sealer.KEKRecord, error) { return nil, nil }
func (m *memStore) Retire(context.Context, string, []string) error                  { return nil }
func (m *memStore) Purge(context.Context, string, []string) error                   { return nil }

func rowFor(t *testing.T) (*sealer.Sealer, uuid.UUID, Row) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	root, err := sealer.NewLocalRootKey("test-root", key)
	if err != nil {
		t.Fatal(err)
	}
	s := sealer.New(root, noopAuditor{}, newMemStore())
	org := uuid.New()
	rec, err := generate(context.Background(), org, s)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return s, org, Row{CACertDER: rec.caCertDER, CAEnv: rec.caEnv, SignKeyID: rec.signKeyID, SignPubKey: rec.signPubKey, SignEnv: rec.signEnv}
}

func flip(b []byte) []byte { c := append([]byte(nil), b...); c[len(c)-1] ^= 1; return c }

func TestAuthenticateRow(t *testing.T) {
	ctx := context.Background()
	s, org, row := rowFor(t)
	if err := AuthenticateRow(ctx, s, org, row); err != nil {
		t.Fatalf("positive control: authentic row rejected: %v", err)
	}
	mut := func(f func(*Row)) Row { r := row; f(&r); return r }
	cases := map[string]struct {
		org uuid.UUID
		row Row
	}{
		"foreign org":       {uuid.New(), row},
		"tampered ca ct":    {org, mut(func(r *Row) { r.CAEnv.Ciphertext = flip(r.CAEnv.Ciphertext) })},
		"tampered sign ct":  {org, mut(func(r *Row) { r.SignEnv.Ciphertext = flip(r.SignEnv.Ciphertext) })},
		"tampered wrapped":  {org, mut(func(r *Row) { r.CAEnv.WrappedDEK = flip(r.CAEnv.WrappedDEK) })},
		"swapped cert":      {org, mut(func(r *Row) { r.CACertDER = flip(r.CACertDER) })},
		"swapped pub":       {org, mut(func(r *Row) { r.SignPubKey = flip(r.SignPubKey) })},
		"swapped key id":    {org, mut(func(r *Row) { r.SignKeyID += "x" })},
		"missing ca env":    {org, mut(func(r *Row) { r.CAEnv = sealer.Envelope{} })},
		"missing sign env":  {org, mut(func(r *Row) { r.SignEnv = sealer.Envelope{} })},
		"envelopes swapped": {org, mut(func(r *Row) { r.CAEnv, r.SignEnv = r.SignEnv, r.CAEnv })},
		"empty row":         {org, Row{}},
	}
	for name, c := range cases {
		err := AuthenticateRow(ctx, s, c.org, c.row)
		if !errors.Is(err, ErrRowNotAuthentic) || err.Error() != ErrRowNotAuthentic.Error() {
			t.Errorf("%s: want bare ErrRowNotAuthentic, got %v", name, err)
		}
	}
	if err := AuthenticateRow(ctx, nil, org, row); !errors.Is(err, ErrRowNotAuthentic) {
		t.Errorf("nil sealer: %v", err)
	}
}
