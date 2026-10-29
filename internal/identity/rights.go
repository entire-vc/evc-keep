package identity

// Permission is one action Keep's authorization checks against. This
// package is the first to need a permission vocabulary at all — no earlier
// ADR/tenancy/threat-model doc defines one — so this is a deliberately
// small, first-draft set scoped to exactly what this package's own
// acceptance requirements exercise. A future catalog package is the
// natural place for this to grow into something richer once real
// per-secret authorization checks land there, and should reconcile with
// this file rather than invent a second vocabulary.
type Permission string

const (
	PermReadMetadata  Permission = "read_metadata"
	PermDeploy        Permission = "deploy"
	PermRotate        Permission = "rotate"
	PermCreateRef     Permission = "create_ref"
	PermManageRunners Permission = "manage_runners"
	// PermApprove decides deployment approvals. Only a human admin is ever
	// allowed to use it: the handler refuses any non-user principal itself,
	// whatever grants an agent holds.
	PermApprove Permission = "approve"
)

// Role is a user's membership role within one scope (the memberships
// table's role column). Same first-draft caveat as [Permission].
type Role string

const (
	RoleViewer Role = "viewer"
	RoleMember Role = "member"
	RoleAdmin  Role = "admin"
)

// rolePermissions is the closed mapping from a role to what it grants.
// Deliberately a package-level table, not a database one: a role's
// meaning is code, not tenant-configurable data, in this first draft.
var rolePermissions = map[Role]map[Permission]bool{
	RoleViewer: {PermReadMetadata: true},
	RoleMember: {PermReadMetadata: true, PermDeploy: true},
	RoleAdmin:  {PermReadMetadata: true, PermDeploy: true, PermRotate: true, PermCreateRef: true, PermManageRunners: true, PermApprove: true},
}

// PermissionsForRole returns the permissions r grants, as a fresh map the
// caller may not mutate the shared table through. An unknown or empty Role
// grants nothing — fail closed, never fail open on an unrecognized value.
func PermissionsForRole(r Role) map[Permission]bool {
	out := make(map[Permission]bool, len(rolePermissions[r]))
	for p := range rolePermissions[r] {
		out[p] = true
	}
	return out
}

// DefaultAgentGrants are the permissions every agent has the moment it is
// connected, before any row in agent_grants exists — this package's own
// design decision. rotate and create_ref require an explicit grant.
var DefaultAgentGrants = map[Permission]bool{
	PermReadMetadata: true,
	PermDeploy:       true,
}

// AgentPermissions computes what an agent may actually do in a scope: the
// intersection of its sponsor's role-derived permissions in that scope
// and the agent's own grant set (DefaultAgentGrants plus whatever
// explicitGrants holds) — ADR-001 §6, tenancy model §4, this package's own
// design decision: an agent's permissions are its sponsor's role-derived
// permissions in scope, intersected with the agent's own explicit grants.
// Always computed fresh from its two inputs, never cached: a sponsor who
// loses a role is reflected on the agent's very next call simply because
// the caller (see [Repo.EffectiveAgentPermissions]) looked the sponsor's
// role up again.
func AgentPermissions(sponsorRole Role, explicitGrants map[Permission]bool) map[Permission]bool {
	sponsorPerms := PermissionsForRole(sponsorRole)

	agentGrants := make(map[Permission]bool, len(DefaultAgentGrants)+len(explicitGrants))
	for p := range DefaultAgentGrants {
		agentGrants[p] = true
	}
	for p := range explicitGrants {
		agentGrants[p] = true
	}

	out := make(map[Permission]bool, len(agentGrants))
	for p := range agentGrants {
		if sponsorPerms[p] {
			out[p] = true
		}
	}
	return out
}
