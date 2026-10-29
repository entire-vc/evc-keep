package api

import (
	"errors"
	"net/http"
	"testing"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/identity"
)

// TestClassifyIdentityErr pins classifyIdentityErr's mapping: a route's own
// not-found sentinel renders 404/not_found, anything else (including one
// that merely wraps a different identity sentinel) is a genuine internal
// failure and must be labeled that way in both the HTTP response and the
// audit journal — not folded into not_found either way, the bug
// keep-leak-reviewer found in this route's first version.
func TestClassifyIdentityErr(t *testing.T) {
	dbErr := errors.New("connection reset by peer")

	cases := []struct {
		name        string
		err         error
		notFoundErr error
		wantStatus  int
		wantClass   apperr.Class
		wantAudit   audit.ErrorClass
		wantMessage string
	}{
		{
			name:        "matches the route's own not-found sentinel",
			err:         identity.ErrPrincipalNotFound,
			notFoundErr: identity.ErrPrincipalNotFound,
			wantStatus:  http.StatusNotFound,
			wantClass:   apperr.ClassNotFound,
			wantAudit:   audit.ErrClassNotFound,
			wantMessage: "principal not found",
		},
		{
			name:        "wraps the route's own not-found sentinel",
			err:         errors.Join(errors.New("issue: lookup failed"), identity.ErrPrincipalNotFound),
			notFoundErr: identity.ErrPrincipalNotFound,
			wantStatus:  http.StatusNotFound,
			wantClass:   apperr.ClassNotFound,
			wantAudit:   audit.ErrClassNotFound,
			wantMessage: "principal not found",
		},
		{
			name:        "a genuine internal failure is never folded into not_found",
			err:         dbErr,
			notFoundErr: identity.ErrPrincipalNotFound,
			wantStatus:  http.StatusInternalServerError,
			wantClass:   apperr.ClassInternal,
			wantAudit:   audit.ErrClassInternal,
			wantMessage: "internal error",
		},
		{
			name:        "the wrong route sentinel is also treated as internal, not not_found",
			err:         identity.ErrTokenUnknown,
			notFoundErr: identity.ErrPrincipalNotFound,
			wantStatus:  http.StatusInternalServerError,
			wantClass:   apperr.ClassInternal,
			wantAudit:   audit.ErrClassInternal,
			wantMessage: "internal error",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, class, auditClass, message := classifyIdentityErr(tc.err, tc.notFoundErr, "principal not found")
			if status != tc.wantStatus || class != tc.wantClass || auditClass != tc.wantAudit || message != tc.wantMessage {
				t.Errorf("classifyIdentityErr(%v, %v) = (%d, %q, %q, %q), want (%d, %q, %q, %q)",
					tc.err, tc.notFoundErr, status, class, auditClass, message,
					tc.wantStatus, tc.wantClass, tc.wantAudit, tc.wantMessage)
			}
		})
	}
}
