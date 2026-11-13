package builtin

import (
	"context"
	"errors"

	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	kstore "github.com/entire-vc/evc-keep/internal/store"
)

// ErrTransferAuth carries no key, identifier or backend text.
var ErrTransferAuth = errors.New("builtin: transferred key material cannot be opened")

// NewTransferSealer returns a read-only Sealer over the KEK rows of a transfer
// that were already rewrapped to target. It can open envelopes whose KEKs are
// in rows and nothing else: it creates no KEK, changes no level and writes
// nowhere. The caller uses it to authenticate the organisation CA before any
// row is inserted.
func NewTransferSealer(rows []kstore.KEKRow, target TransferRoot) (*sealer.Sealer, error) {
	if target.k == nil {
		return nil, ErrTransferAuth
	}
	st := &transferKEKs{byID: make(map[string]sealer.KEKRecord, len(rows))}
	for _, r := range rows {
		sc, ok := kekScope(r)
		if !ok {
			return nil, ErrTransferAuth
		}
		st.byID[r.ID] = sealer.KEKRecord{
			ID: r.ID, Org: r.OrgID, RootKeyID: r.RootKeyID, Wrapped: r.Wrapped, Domain: sc,
		}
	}
	return sealer.New(target.k, silentAuditor{}, st), nil
}

type silentAuditor struct{}

func (silentAuditor) Record(sealer.Event) {}

// transferKEKs serves Get from the transferred rows. Every mutating call fails.
type transferKEKs struct{ byID map[string]sealer.KEKRecord }

var errReadOnlyTransfer = errors.New("builtin: transfer key store is read-only")

func (s *transferKEKs) Get(_ context.Context, org, id string) (sealer.KEKRecord, error) {
	if r, ok := s.byID[id]; ok && r.Org == org {
		return r, nil
	}
	return sealer.KEKRecord{}, sealer.ErrKEKNotFound
}
func (s *transferKEKs) ActiveFor(context.Context, string, string) (sealer.KEKRecord, error) {
	return sealer.KEKRecord{}, sealer.ErrNoActiveKEK
}
func (s *transferKEKs) Create(context.Context, string, sealer.KEKRecord) (sealer.KEKRecord, error) {
	return sealer.KEKRecord{}, errReadOnlyTransfer
}
func (s *transferKEKs) ActiveList(context.Context, string) ([]sealer.KEKRecord, error) {
	return nil, errReadOnlyTransfer
}
func (s *transferKEKs) RetiredList(context.Context, string) ([]sealer.KEKRecord, error) {
	return nil, errReadOnlyTransfer
}
func (s *transferKEKs) Retire(context.Context, string, []string) error { return errReadOnlyTransfer }
func (s *transferKEKs) Purge(context.Context, string, []string) error  { return errReadOnlyTransfer }
func (s *transferKEKs) Level(context.Context, string) (sealer.Level, error) {
	return sealer.DefaultLevel, nil
}
func (s *transferKEKs) SetLevel(context.Context, string, sealer.Level, string) error {
	return errReadOnlyTransfer
}
func (s *transferKEKs) Lock(context.Context, string, bool) (sealer.Store, func(context.Context) error, error) {
	return nil, nil, errReadOnlyTransfer
}
