package api

import (
	"crypto/sha256"
	"encoding/hex"
)

// meshBodyDigest is the hex SHA-256 of a signed request body, the last line
// of the string a Mesh secret request signs. It is the only digest in the
// Mesh files of this package: the rule mesh-handshake-digest keeps digest and
// comparison packages out of every other internal/api/mesh*.go, so a Mesh
// secret cannot be hashed or compared next to the handlers.
func meshBodyDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
