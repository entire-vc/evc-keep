// Package metatext validates single-line metadata before it is persisted.
package metatext

import (
	"fmt"
	"unicode"
	"unicode/utf8"

	"github.com/entire-vc/evc-keep/internal/apperr"
)

const (
	NameLimit        = 128
	DescriptionLimit = 1024
	LabelLimit       = 64
)

// Validate returns a closed error containing only the field and reason.
// Empty descriptions are permitted; required fields are checked by callers.
func Validate(field, value string, limit int) error {
	if !utf8.ValidString(value) {
		return invalid(field, "must be valid UTF-8")
	}
	if utf8.RuneCountInString(value) > limit {
		return invalid(field, "exceeds the rune limit")
	}
	for _, r := range value {
		if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Cs, unicode.Co, unicode.Zl, unicode.Zp) || (unicode.Is(unicode.Zs, r) && r != ' ') {
			return invalid(field, "contains a forbidden character")
		}
	}
	return nil
}

func invalid(field, reason string) error {
	return apperr.New(apperr.ClassInvalidArgument, fmt.Sprintf("%s %s", field, reason))
}
