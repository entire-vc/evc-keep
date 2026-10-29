package api

import (
	"crypto/subtle"

	"github.com/entire-vc/evc-keep/internal/identity"
)

// csrfValue reports, in constant time, whether got is the session's CSRF
// token. Kept apart from mesh_ui.go for the rule mesh-handshake-digest.
func csrfValue(got string, s identity.Session) bool {
	return got != "" && len(got) == len(s.CSRF) && subtle.ConstantTimeCompare([]byte(got), []byte(s.CSRF)) == 1
}
