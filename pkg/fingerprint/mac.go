package fingerprint

import (
	"crypto/hmac"
	"crypto/sha256"

	"github.com/entire-vc/evc-keep/pkg/secret"
)

// VerifyMAC reports whether tag is HMAC-SHA256 of msg keyed by the shared
// secret v, compared in constant time. It is plain HMAC so the other side of a
// signed message (Mesh events) can compute the tag with any standard library.
// There is deliberately no exported function that returns the tag: a MAC of
// a caller-chosen message would be a digest of the value (threat model 4.1),
// so the comparison happens here, inside the zone, and only a bool leaves.
func VerifyMAC(v secret.Value, msg, tag []byte) bool {
	return hmac.Equal(tag, mac(v, msg))
}

func mac(v secret.Value, msg []byte) []byte {
	var out []byte
	secret.Expose(v, func(key []byte) {
		m := hmac.New(sha256.New, key)
		m.Write(msg)
		out = m.Sum(nil)
	})
	return out
}
