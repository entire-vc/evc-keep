package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/rotation"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

func rotationAnswer(t *testing.T, err error) (int, apperr.Body, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	writeAppError(rec, rotationAppError(err), "req-1")
	var b apperr.Body
	if jerr := json.Unmarshal(rec.Body.Bytes(), &b); jerr != nil {
		t.Fatal(jerr)
	}
	return rec.Code, b, rec.Body.String()
}

// A new run while the old version is still not revoked answers 409 with the
// closed body {error_class,message,request_id}; whatever the wrapped error
// says (a collaborator's text may carry a key) never reaches the wire.
func TestRotationRevokePendingMapsToRevokePending(t *testing.T) {
	c := canary.New()
	wrapped := fmt.Errorf("revoke of %s refused: %w", c.Value(1), rotation.ErrRevokePending)
	code, b, raw := rotationAnswer(t, wrapped)
	if code != http.StatusConflict || b.ErrorClass != string(apperr.ClassRevokePending) || b.RequestID != "req-1" || b.Message == "" {
		t.Fatalf("got %d %+v", code, b)
	}
	if c.In(raw) {
		t.Fatalf("the canary surfaced in the response: %s", raw)
	}
	known := false
	for _, k := range apperr.Classes() {
		known = known || k == apperr.ClassRevokePending
	}
	if !known {
		t.Fatal("revoke_pending is not in apperr.Classes()")
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil || len(m) != 3 {
		t.Fatalf("body fields are not the closed three: %v", m)
	}
}

// Anything else from the engine is an opaque 500, including a lookalike that
// is not ErrRevokePending: the mapping must not be a prefix or text match.
func TestRotationOtherErrorsStayInternal(t *testing.T) {
	c := canary.New()
	for _, err := range []error{errors.New("rotation: old version not revoked yet " + c.Value(2)), rotation.ErrFailed, rotation.ErrIncident, errors.New("x")} {
		code, b, raw := rotationAnswer(t, err)
		if code != http.StatusInternalServerError || b.ErrorClass != string(apperr.ClassInternal) || c.In(raw) {
			t.Errorf("%v: got %d %+v", err, code, b)
		}
	}
}
