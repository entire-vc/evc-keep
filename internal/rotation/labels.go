package rotation

import (
	"regexp"

	"github.com/google/uuid"
)

// Carrier ids and versions are public identifiers and carry no value. The
// grammar narrows what a collaborator can smuggle through them (no free text,
// no long base32/base64/hex strings, at most nine digits for a version) and
// fails the run as prepare_failed for anything else; the rejected string is
// never stored or echoed. It cannot tell a random UUID from a secret that
// happens to be UUID-shaped, so the rest of the contract is on the
// collaborator: an id or a version never derives from a secret value.
var versionRe = regexp.MustCompile(`^[1-9][0-9]{0,8}$`)

func validCarrierID(s string) bool {
	u, err := uuid.Parse(s)
	return err == nil && u.String() == s
}

func validVersion(s string) bool { return versionRe.MatchString(s) }

// validOldVersion also allows "": the first rotation of a secret has no
// previous version.
func validOldVersion(s string) bool { return s == "" || validVersion(s) }
