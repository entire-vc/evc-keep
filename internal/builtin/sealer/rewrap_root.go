package sealer

import (
	"bytes"
	"errors"
)

// ErrRewrapKEK carries no backend error, key material or partial result.
var ErrRewrapKEK = errors.New("sealer: cannot rewrap kek")

// RewrapKEK returns a copy of rec wrapped under target, preserving its KEK
// bytes, ID, organisation and domain. Envelopes and their AAD remain valid.
// The source record and root are unchanged. Root IDs may be identical on
// independent installations; authentication, not an ID comparison, proves
// which root can open a wrapping.
//
// This is a cryptographic primitive, not a migration or authorisation API.
// Its caller must authorise org, freeze the source snapshot, select the full
// dependency closure, and commit the destination atomically. It must not use
// this function to weaken key levels or copy another organisation's keys.
// Only temporary KEK bytes are unwrapped; secret values are never opened.
func RewrapKEK(org string, rec KEKRecord, source, target RootKey) (KEKRecord, error) {
	if source == nil || target == nil || org == "" || rec.ID == "" ||
		rec.Org != org || rec.Domain.Org != org || rec.Domain.validate() != nil {
		return KEKRecord{}, ErrRewrapKEK
	}
	sourceID, targetID := source.ID(), target.ID()
	if sourceID == "" || targetID == "" || rec.RootKeyID != sourceID {
		return KEKRecord{}, ErrRewrapKEK
	}
	// A backend may decrypt in place. Never let it modify the source snapshot,
	// and wipe this buffer too in case it has held plaintext on return.
	sourceWrapped := bytes.Clone(rec.Wrapped)
	defer wipe(sourceWrapped)
	plain, err := source.Unwrap(sourceWrapped, kekAAD(rec.ID, rec.Org, rec.Domain.key(), sourceID))
	defer wipe(plain) // backends may return a populated buffer even on error
	if err != nil || len(plain) != 32 {
		return KEKRecord{}, ErrRewrapKEK
	}
	wrapped, err := target.Wrap(plain, kekAAD(rec.ID, rec.Org, rec.Domain.key(), targetID))
	defer wipe(wrapped)
	if err != nil || len(wrapped) == 0 {
		return KEKRecord{}, ErrRewrapKEK
	}
	out := rec
	out.RootKeyID = targetID
	// Own the result even if the backend reused the temporary KEK buffer.
	out.Wrapped = bytes.Clone(wrapped)
	return out, nil
}
