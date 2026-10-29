package intake

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/entire-vc/evc-keep/internal/intake/descriptor"
)

func TestDescriptorRejectsLegacyAndTampering(t *testing.T) {
	signing, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal("generate fixture signer")
	}
	defer clear(private)
	v := View{RequestID: "request", PublicKey: make([]byte, 32), SigningKey: signing, SecretName: "name", Scope: "scope", StoreName: "store", Class: "dev", RequestedBy: "user requester", Sponsor: "sponsor"}
	v.Signature = ed25519.Sign(private, descriptor.Message(v.RequestID, v.PublicKey, v.metadata()))
	if !validDescriptor(v) {
		t.Fatal("honest v2 descriptor rejected")
	}
	for _, name := range []string{"request", "name", "scope", "store", "class", "requester", "sponsor", "legacy-v1"} {
		t.Run(name, func(t *testing.T) {
			bad := v
			switch name {
			case "request":
				bad.RequestID += "other"
			case "name":
				bad.SecretName += "other"
			case "scope":
				bad.Scope += "other"
			case "store":
				bad.StoreName += "other"
			case "class":
				bad.Class += "other"
			case "requester":
				bad.RequestedBy += "other"
			case "sponsor":
				bad.Sponsor = ""
			case "legacy-v1":
				bad.Signature = ed25519.Sign(private, []byte("keep/intake-key/v1\x00"+v.RequestID+"\x00"+base64.StdEncoding.EncodeToString(v.PublicKey)))
			}
			if validDescriptor(bad) {
				t.Fatal("untrusted descriptor accepted")
			}
		})
	}
}
