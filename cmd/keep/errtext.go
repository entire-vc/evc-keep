package main

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/entire-vc/evc-keep/internal/apperr"
)

const (
	maxErrTextRunes = 512
	maxRequestIDLen = 64
	unexpectedValue = "(unexpected value)"
)

// sanitizeText makes server-supplied text safe to print on a terminal: every
// control (Cc: C0, DEL, C1 — ESC among them) and format (Cf: bidi overrides,
// zero-width) rune is dropped, line breaks become a space, invalid UTF-8 is
// dropped, and the result is cut to max runes with a trailing ellipsis.
func sanitizeText(s string, max int) string {
	var b strings.Builder
	n := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch {
		case r == utf8.RuneError && size <= 1:
			continue
		case isLineBreak(r):
			r = ' '
		case unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r):
			continue
		}
		if n == max {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// isLineBreak: LF, CR and the Unicode line/paragraph separators (U+2028/9).
func isLineBreak(r rune) bool {
	return r == '\n' || r == '\r' || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r)
}

// safeClass echoes a server-supplied error_class only when it is one of
// apperr's closed set; anything else is not printed.
func safeClass(c string) string {
	for _, k := range apperr.Classes() {
		if string(k) == c {
			return c
		}
	}
	return unexpectedValue
}

// safeRequestID passes a request id through only if it is short and made of
// token characters; otherwise it is not printed.
func safeRequestID(id string) string {
	if len(id) > maxRequestIDLen {
		return unexpectedValue
	}
	for _, r := range id {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' && r != '.' {
			return unexpectedValue
		}
	}
	return id
}
