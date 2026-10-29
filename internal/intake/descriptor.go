package intake

import (
	"crypto/ed25519"

	"github.com/entire-vc/evc-keep/internal/intake/descriptor"
)

func validDescriptor(v View) bool {
	return len(v.PublicKey) == 32 && len(v.SigningKey) == ed25519.PublicKeySize && len(v.Signature) == ed25519.SignatureSize && ed25519.Verify(v.SigningKey, descriptor.Message(v.RequestID, v.PublicKey, v.metadata()), v.Signature)
}
func (v View) metadata() descriptor.Metadata {
	return descriptor.Metadata{SecretName: v.SecretName, Scope: v.Scope, StoreName: v.StoreName, Class: v.Class, RequestedBy: v.RequestedBy, Sponsor: v.Sponsor}
}
