package tenancy

import (
	"fmt"

	"github.com/entire-vc/evc-keep/internal/apperr"
)

// NotFoundError builds the *apperr.Error Resolve returns whenever a name
// does not resolve — whether because it truly is not defined anywhere in
// the principal's chain, or because it is defined only at a scope the
// principal's context never visits. Both cases go through this one
// constructor so their message can never drift apart — see
// [apperr.ClassSecretNotFound]'s doc for why that would itself be an
// oracle.
//
// Exported so internal/catalog's rights check (tenancy model §3 step 5,
// see internal/catalog.ResolveAuthorized) can answer "found the name, but
// the principal has no rights there" with the exact same text a name that
// resolves nowhere gets — a third case this constructor's callers must
// keep indistinguishable from the first two, for the same reason.
//
// checked lists the level KINDS of the request's own context (e.g.
// "org, ws, proj"), never scope ids and never anything the server derived
// while resolving (an OverrideLock's position, a sponsor's status, a
// missing role): the caller already supplied whichever org/ws/proj ids it
// used, so naming the kinds back is not new information — the message is
// exactly the name and the levels of the request, nothing more. See
// [CheckedLevels].
func NotFoundError(name string, checked []Level) *apperr.Error {
	return apperr.New(apperr.ClassSecretNotFound,
		fmt.Sprintf("secret %q not found (checked: %s)", name, joinLevels(checked)))
}

func joinLevels(levels []Level) string {
	s := ""
	for i, l := range levels {
		if i > 0 {
			s += ", "
		}
		s += string(l)
	}
	return s
}

// ErrAmbiguousContext is returned by Resolve when the context omits a
// workspace and the principal belongs to more than one in the org (tenancy
// model §7 scenario C3).
var ErrAmbiguousContext = apperr.New(apperr.ClassAmbiguousContext,
	"workspace not specified and principal belongs to more than one — ambiguous_context")

// invalidContextError is returned when the caller's own org/workspace/
// project ids don't relate to each other (e.g. a workspace id that does not
// belong to the given org). The caller already possesses these ids — this
// is a caller bug, not a secret-existence oracle, so it is reported plainly.
func invalidContextError(reason string) *apperr.Error {
	return apperr.New(apperr.ClassInvalidArgument, "invalid context: "+reason)
}
