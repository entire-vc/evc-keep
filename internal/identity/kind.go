// Package identity is Keep's authentication and rights boundary: who a
// caller is (a human user, an agent acting for a sponsor, or a
// sponsor-less service), how that identity is proven (a bearer token),
// and what it may do (a sponsor's role in a scope, intersected with the
// agent's own grants). See ADR-001 §6 and the tenancy model §1 and §4.
//
// Every subsequent request in Keep gets its org_id from the Principal this
// package's middleware puts in context — never from a URL path or a
// request body again (this package's own acceptance requirement).
package identity

// Kind identifies what a Principal or a token belongs to, and is also the
// single-character infix in a token's own text — "keep_a_...",
// "keep_s_...", "keep_u_..." — so a reader (or a secret scanner) can tell
// a token's kind without looking anything up. See [GenerateToken].
type Kind string

const (
	// KindAgent is a non-human principal acting for a sponsor user; its
	// rights are bounded by the sponsor's — see [AgentPermissions].
	KindAgent Kind = "a"
	// KindService is a non-human principal with no sponsor, belonging to
	// a scope directly (tenancy model §1).
	KindService Kind = "s"
	// KindUser is a human principal. This package issues user tokens too
	// — OIDC and 2FA for humans are separate, later work; this package
	// does not implement them.
	KindUser Kind = "u"
)

// Valid reports whether k is one of the three defined kinds.
func (k Kind) Valid() bool {
	switch k {
	case KindAgent, KindService, KindUser:
		return true
	}
	return false
}

func (k Kind) String() string { return string(k) }
