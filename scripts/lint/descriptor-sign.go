//go:build ruleguard

// This rule matches the selector before type normalization. Anonymous
// interfaces lose their receiver identity in forbidigo's type analysis.
package gorules

import "github.com/quasilyte/go-ruleguard/dsl"

func descriptorSign(m dsl.Matcher) {
	m.Match(`$receiver.Sign`).Report("descriptor-sign: signing is permitted only for job and intake descriptors")
}
