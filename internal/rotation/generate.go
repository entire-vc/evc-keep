package rotation

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"

	prot "github.com/entire-vc/evc-keep/pkg/rotation"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/google/uuid"
)

// generatorKeys names the keys a Generator reports for a subject. It is a
// fixed namespace: a key id is a public name, never derived from a value.
var generatorKeys = uuid.MustParse("6d0b3b8e-0c1a-4a52-9a0e-2f1f7c1d9e11")

// generatedBytes is the entropy of one generated value (256 bits).
const generatedBytes = 32

// Generator is the RotationProvider of a secret that has no credential on
// another system: the new value is random bytes and nothing else stands
// behind it. Revoking the old version is the store's job (the Revoker disables
// it), so the provider holds no key and every Check says inactive.
type Generator struct {
	// Entropy is the source of the random bytes; nil means crypto/rand. Tests
	// set it to know the value without reading it back.
	Entropy io.Reader
}

var _ prot.RotationProvider = Generator{}

func (Generator) Kind() string { return "generated" }

// Capabilities: the old value stays valid in the store until the Revoker
// disables it, so a failed run rolls back by doing nothing.
func (Generator) Capabilities() prot.Capabilities { return prot.Capabilities{DualKey: true} }

func (g Generator) Issue(_ context.Context, _ prot.IssueRequest) (prot.Issued, error) {
	raw := make([]byte, generatedBytes)
	defer clear(raw)
	src := g.Entropy
	if src == nil {
		src = rand.Reader
	}
	if _, err := io.ReadFull(src, raw); err != nil {
		return prot.Issued{}, prot.ErrUnavailable
	}
	enc := make([]byte, base64.RawURLEncoding.EncodedLen(len(raw)))
	defer clear(enc)
	base64.RawURLEncoding.Encode(enc, raw)
	return prot.Issued{KeyID: uuid.NewString(), Value: secret.New(enc)}, nil
}

func (Generator) Check(context.Context, string) (prot.Status, error) {
	return prot.Status{Active: false}, nil
}

// Current names the single stand-in key of a subject, so the run knows what
// "the original key" is and does not open an unknown-key incident for a
// provider that has none.
func (Generator) Current(_ context.Context, subject string) (string, bool, error) {
	return uuid.NewSHA1(generatorKeys, []byte(subject)).String(), true, nil
}

func (Generator) Revoke(context.Context, string) error { return nil }
