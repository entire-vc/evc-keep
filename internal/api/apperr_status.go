package api

import (
	"errors"
	"net/http"

	"github.com/entire-vc/evc-keep/internal/apperr"
)

// httpStatus maps an apperr.Class to the HTTP status a handler answers with
// — the same fixed mapping every route in this file uses, so a class always
// gets the same status regardless of which handler raised it.
func httpStatus(class apperr.Class) int {
	switch class {
	case apperr.ClassInvalidArgument, apperr.ClassAmbiguousContext:
		return http.StatusBadRequest
	case apperr.ClassNotReady:
		return http.StatusServiceUnavailable
	case apperr.ClassUnauthenticated:
		return http.StatusUnauthorized
	case apperr.ClassNotFound, apperr.ClassSecretNotFound:
		return http.StatusNotFound
	case apperr.ClassOverrideLocked, apperr.ClassNoStoreBound, apperr.ClassRevokePending, apperr.ClassAlreadyExists:
		return http.StatusConflict
	case apperr.ClassPayloadTooLarge:
		return http.StatusRequestEntityTooLarge
	default:
		return http.StatusInternalServerError
	}
}

// writeAppError renders err onto the wire: an *apperr.Error keeps its own
// class and template message (never a wrapped database error's own text —
// see apperr's package doc), anything else becomes the same opaque 500 the
// panic-recovery path in middleware.go answers, so a handler can never
// accidentally let an unclassified error's message reach a caller.
func writeAppError(w http.ResponseWriter, err error, requestID string) {
	var ae *apperr.Error
	if errors.As(err, &ae) {
		writeError(w, httpStatus(ae.Class), ae.Class, ae.Message, requestID)
		return
	}
	writeError(w, http.StatusInternalServerError, apperr.ClassInternal, "internal error", requestID)
}
