package api

import (
	"encoding/json"
	"net/http"

	"github.com/entire-vc/evc-keep/internal/apperr"
)

// writeError writes the closed error shape from the threat model's §4.3:
// {error_class, message, request_id}. message must already be a template
// naming things, never a raw wrapped error's text — see apperr's doc.
func writeError(w http.ResponseWriter, status int, class apperr.Class, message, requestID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(apperr.Body{
		ErrorClass: string(class),
		Message:    message,
		RequestID:  requestID,
	})
}
