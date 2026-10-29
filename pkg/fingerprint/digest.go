package fingerprint

import (
	"crypto/sha256"
	"crypto/subtle"

	"github.com/entire-vc/evc-keep/pkg/secret"
)

// MatchSHA256 reports whether want is the plain SHA-256 of v, compared in
// constant time over all 32 bytes. It exists for a counterparty that names a
// secret by its unkeyed digest (the Mesh install window, where an admin
// supplies the SHA-256 of the signing secret). As with VerifyMAC there is no
// exported function that returns the digest: it is computed and compared
// here, inside the zone, and only a bool leaves.
func MatchSHA256(v secret.Value, want [sha256.Size]byte) bool {
	var sum [sha256.Size]byte
	defer clear(sum[:])
	secret.Expose(v, func(b []byte) { sum = sha256.Sum256(b) })
	return subtle.ConstantTimeCompare(sum[:], want[:]) == 1
}
