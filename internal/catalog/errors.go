package catalog

import (
	"fmt"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/google/uuid"
)

// notFoundByID is Meta's not-found shape: used both when no secret with id
// exists in the org at all, and when one does but its scope is outside the
// caller's reach (tenancy model §7 scenario C2, the lookup-by-id case). Both go
// through this one constructor so the text can never drift between them;
// see internal/tenancy's NotFoundError for the equivalent by-name rule.
func notFoundByID(id uuid.UUID) *apperr.Error {
	return apperr.New(apperr.ClassSecretNotFound, fmt.Sprintf("secret %s not found", id))
}

// NotFoundByID exposes notFoundByID for a caller outside this package
// (internal/api's get-by-id route) that must render the exact same
// not-found shape after its OWN rights check denies access to a secret
// [Catalog.Meta] already found — see [ResolveAuthorized]'s doc for why a
// rights failure and a true miss must be indistinguishable, and must
// therefore share this one text, not a second copy of the template that
// could drift from it.
func NotFoundByID(id uuid.UUID) *apperr.Error { return notFoundByID(id) }

// storeNotUsableError is the one answer for an explicitly chosen store that
// cannot back a record in the target scope, whatever the reason (missing,
// disabled, owned outside the scope's chain, another organisation's): the
// text carries neither the store id nor anything about who owns it.
func storeNotUsableError() *apperr.Error {
	return apperr.New(apperr.ClassInvalidArgument, "store is not available for this scope")
}

// alreadyBoundError is CreateStoreBinding's answer to a race on the
// schema's one-binding-per-scope UNIQUE constraint: the text names neither
// the store already bound nor who created it, only that the scope already
// has one — the caller already knows the scope, which is all it is told.
func alreadyBoundError() *apperr.Error {
	return apperr.New(apperr.ClassAlreadyExists, "a store binding already exists at this scope")
}

// duplicateNameError is CreateRef's answer to a race on the schema's
// (org_id, scope_level, scope_id, name) UNIQUE constraint: the text names
// neither the store the racing insert chose nor its provider_ref, only that
// the name is already taken at this scope — the caller already knows both.
func duplicateNameError() *apperr.Error {
	return apperr.New(apperr.ClassAlreadyExists, "a secret with this name already exists at this scope")
}
