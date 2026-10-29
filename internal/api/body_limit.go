package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/entire-vc/evc-keep/internal/apperr"
)

// Request-body ceilings for the two handlers that decode a free-form JSON
// document. The largest legitimate secret-create body is a few KiB (name 128,
// description 1024, provider_ref 1024 bytes, each at worst six bytes per
// character once \u-escaped); a token-issue body is three short fields.
const (
	maxSecretBodyBytes = 64 << 10
	maxTokenBodyBytes  = 4 << 10
)

// bodyRefusal describes a request body readBoundedBody already answered:
// the status and class it wrote and how many bytes it had read by then.
type bodyRefusal struct {
	Status int
	Class  apperr.Class
	N      int
}

// readBoundedBody reads r's whole body under limit bytes. It answers the
// request itself on failure (413 payload_too_large past the limit, 400
// invalid_argument for a read error) and returns a non-nil refusal; the body
// is never echoed. The ceiling applies to the stream, not to Content-Length,
// so a chunked upload stops at limit+1 bytes read too. Callers decode the
// bytes with [decodeStrict], which rejects an unknown field, a second value
// and trailing garbage.
func readBoundedBody(w http.ResponseWriter, r *http.Request, limit int64, requestID string) ([]byte, *bodyRefusal) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, apperr.ClassPayloadTooLarge, "request body is too large", requestID)
			return nil, &bodyRefusal{http.StatusRequestEntityTooLarge, apperr.ClassPayloadTooLarge, len(body)}
		}
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "request body is not valid JSON", requestID)
		return nil, &bodyRefusal{http.StatusBadRequest, apperr.ClassInvalidArgument, len(body)}
	}
	return body, nil
}

// decodeStrict decodes the single JSON document raw into dst and refuses any
// field dst does not declare, so a caller cannot pass a field this server
// would silently ignore (a typo, or a value parked in a field that no code
// path reads). The error carries no part of raw: encoding/json names the
// offending field in its message, and a caller must answer with its own
// fixed text instead.
func decodeStrict(raw []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return errInvalidBody
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return errInvalidBody
	}
	return nil
}

var errInvalidBody = errors.New("request body is not a valid document for this route")

// logRejected records a body refused by [decodeStrict] as a log event, not an
// audit record: nothing was created, so there is no action to journal. Only
// the event name, request id and error class are written, never the body.
func logRejected(ctx context.Context, logger *slog.Logger, event, requestID string) {
	if logger != nil {
		logger.WarnContext(ctx, event, slog.String("request_id", requestID), slog.String("error_class", "invalid_argument"))
	}
}
