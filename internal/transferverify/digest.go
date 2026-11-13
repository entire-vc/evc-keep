package transferverify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/entire-vc/evc-keep/internal/store"
)

// ErrDigest is returned when the rows cannot be encoded.
var ErrDigest = errors.New("transferverify: cannot digest rows")

// ClosureDigest is "sha256:<hex>" over the canonical JSON of every copied
// row. The wrapped bytes and root id of KEK rows are zeroed first: they are
// rewrapped in transit, so the source and the target must agree on the digest
// without them. Everything else, including every ciphertext envelope, is
// covered, so any change of a copied row changes the digest.
func ClosureDigest(r *store.TransferRows) (string, error) {
	if r == nil {
		return "", ErrDigest
	}
	cp := *r
	cp.KEKs = make([]store.KEKRow, len(r.KEKs))
	for i, k := range r.KEKs {
		k.Wrapped, k.RootKeyID = nil, ""
		cp.KEKs[i] = k
	}
	raw, err := json.Marshal(&cp)
	if err != nil {
		return "", ErrDigest
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
