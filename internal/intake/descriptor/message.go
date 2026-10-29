package descriptor

import (
	"encoding/binary"
)

// Metadata is the ordered, closed set of fields displayed on the input page.
// Empty Sponsor is encoded too, so adding or removing it changes the signature.
type Metadata struct {
	SecretName, Scope, StoreName, Class, RequestedBy, Sponsor string
}

// Message binds a receiver key to the request and its visible text.
// The fixed NUL-terminated domain is followed by length-prefixed request,
// raw receiver key and UTF-8 metadata. Strings are not normalized or trimmed.
func Message(requestID string, public []byte, m Metadata) []byte {
	out := []byte("keep/intake-key/v2\x00")
	for _, field := range []string{requestID, string(public), m.SecretName, m.Scope, m.StoreName, m.Class, m.RequestedBy, m.Sponsor} {
		out = binary.BigEndian.AppendUint32(out, uint32(len(field))) // #nosec G115 -- catalog metadata and public keys have bounded sizes
		out = append(out, field...)
	}
	return out
}
