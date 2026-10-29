package api

import (
	"errors"
	"fmt"
	"testing"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/audit"
)

// TestClassifyErr pins classifyErr's mapping of a catalog error to the audit
// journal's closed error-class enum. A *apperr.Error wrapped by another
// error (fmt.Errorf("%w", ...), the shape a caller one layer up commonly
// produces) must classify exactly the same as the same error unwrapped —
// asAppErr previously used a plain type assertion, which only matches an
// *apperr.Error at the top of the chain, so a wrapped one silently fell
// through to ErrClassInternal in the journal even though writeAppError (which
// uses errors.As) rendered its real class to the caller — a keep-leak-reviewer
// finding: the response and the journal must never disagree about which kind
// of failure this was.
func TestClassifyErr(t *testing.T) {
	notFound := apperr.New(apperr.ClassNotFound, "secret not found")

	cases := []struct {
		name string
		err  error
		want audit.ErrorClass
	}{
		{"apperr at the top of the chain", notFound, audit.ErrClassNotFound},
		{"apperr wrapped one layer deep", fmt.Errorf("catalog: get secret: %w", notFound), audit.ErrClassNotFound},
		{"a genuine internal failure", errors.New("connection reset by peer"), audit.ErrClassInternal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyErr(tc.err); got != tc.want {
				t.Errorf("classifyErr(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}
