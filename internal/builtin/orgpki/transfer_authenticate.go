package orgpki

import (
	"context"
	"strings"

	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/google/uuid"
)

// AuthenticateTransferCA proves, before anything is inserted, that the
// organisation CA row of a transfer opens under the target root: both v2
// envelopes must authenticate through KEKs that are the organisation's own PKI
// domain KEKs, already rewrapped to target. A transfer without an org_ca row
// has nothing to prove. Legacy, tampered, foreign or mis-domained material
// fails with [ErrRowNotAuthentic]; nothing is generated or written.
func AuthenticateTransferCA(ctx context.Context, org uuid.UUID, rows *store.TransferRows, target builtin.TransferRoot) error {
	if rows == nil {
		return ErrRowNotAuthentic
	}
	if len(rows.OrgCAs) == 0 {
		return nil
	}
	if len(rows.OrgCAs) != 1 || rows.OrgCAs[0].OrgID != org {
		return ErrRowNotAuthentic
	}
	ca := rows.OrgCAs[0]
	for _, id := range []string{ca.CAKEKID, ca.SignKEKID} {
		if !isOrgPKIKEK(rows.KEKs, id, org) {
			return ErrRowNotAuthentic
		}
	}
	s, err := builtin.NewTransferSealer(rows.KEKs, target)
	if err != nil {
		return ErrRowNotAuthentic
	}
	return AuthenticateRow(ctx, s, org, Row{
		CACertDER: ca.CACertDER, CAEnv: sealer.Envelope{KEKID: ca.CAKEKID, WrappedDEK: ca.CAWrappedDEK, Ciphertext: ca.CACiphertext},
		SignKeyID: ca.SignKeyID, SignPubKey: ca.SignPubKey,
		SignEnv: sealer.Envelope{KEKID: ca.SignKEKID, WrappedDEK: ca.SignWrappedDEK, Ciphertext: ca.SignCiphertext},
	})
}

// isOrgPKIKEK reports whether id names a KEK of exactly org's PKI domain.
func isOrgPKIKEK(keks []store.KEKRow, id string, org uuid.UUID) bool {
	for _, k := range keks {
		if k.ID == id {
			return k.OrgID == org.String() && k.DomainOrg == org.String() && strings.HasPrefix(k.DomainKey, "pki:") &&
				k.DomainWorkspace == "" && k.DomainProject == "" && k.DomainUser == ""
		}
	}
	return false
}
