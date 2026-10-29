package api

import (
	"errors"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/rotation"
)

// rotationAppError turns an engine error into the *apperr.Error a handler
// writes with writeAppError. Only the sentinel is matched (errors.Is); the
// text of the error, which may wrap a collaborator's message, is dropped.
// Every other error is returned as is, so writeAppError answers an opaque 500.
func rotationAppError(err error) error {
	if errors.Is(err, rotation.ErrRevokePending) {
		return apperr.New(apperr.ClassRevokePending, "the old key has not been revoked yet; retry the same rotation run")
	}
	return err
}
