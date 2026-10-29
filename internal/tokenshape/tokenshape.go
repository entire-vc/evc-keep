// Package tokenshape knows what the random part of a Keep identity token
// looks like — a run of at least BodyLen base32 characters — so that code far
// from internal/identity (the logger, the request-id parser) can refuse or
// blank it without importing the package that mints tokens.
//
// A token's random part is the entire credential; the "keep_<kind>_"
// prefix only helps a scanner recognize it. Matching on the prefix alone
// would therefore miss a leak of the part that matters, so this package
// matches the random part by itself. internal/identity's tests pin
// [BodyLen] and [Pattern] against what GenerateToken actually produces.
package tokenshape

import "regexp"

// BodyLen is the length of a token's random part: 32 bytes of randomness in
// unpadded base32.
const BodyLen = 52

// Pattern is the regular expression source for a token's random part, in
// either case: the alphabet is a-z and 2-7. It matches the whole run of
// that alphabet, not just 52 characters of it: a token written against
// other characters of its alphabet ("zz" + body) forms one longer run, and
// a match of exactly 52 would leave the token's last characters outside it.
const Pattern = `(?i)[a-z2-7]{52,}`

var re = regexp.MustCompile(Pattern)

// Contains reports whether s holds a run long enough to be a token's random
// part, wherever it sits and whatever surrounds it.
func Contains(s string) bool { return re.MatchString(s) }

// Redact returns b with every such run, in full, replaced by repl.
func Redact(b, repl []byte) []byte { return re.ReplaceAll(b, repl) }
