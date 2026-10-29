package identity

import (
	"reflect"
	"testing"
)

// TestAgentPermissionsNeverExceedsSponsor is the table-driven rights test
// this package's own acceptance requirement calls for: an agent's effective permissions are
// always a subset of its sponsor's role-derived permissions, regardless
// of what the agent was explicitly granted.
func TestAgentPermissionsNeverExceedsSponsor(t *testing.T) {
	all := map[Permission]bool{
		PermReadMetadata: true, PermDeploy: true, PermRotate: true, PermCreateRef: true,
	}

	cases := []struct {
		name           string
		sponsorRole    Role
		explicitGrants map[Permission]bool
		want           map[Permission]bool
	}{
		{
			name:           "admin sponsor, no explicit grants — agent gets only its defaults",
			sponsorRole:    RoleAdmin,
			explicitGrants: nil,
			want:           map[Permission]bool{PermReadMetadata: true, PermDeploy: true},
		},
		{
			name:           "admin sponsor, full explicit grants — agent gets everything",
			sponsorRole:    RoleAdmin,
			explicitGrants: map[Permission]bool{PermRotate: true, PermCreateRef: true},
			want:           all,
		},
		{
			name:           "viewer sponsor, full explicit grants — capped at sponsor's read_metadata",
			sponsorRole:    RoleViewer,
			explicitGrants: map[Permission]bool{PermRotate: true, PermCreateRef: true},
			want:           map[Permission]bool{PermReadMetadata: true},
		},
		{
			name:           "member sponsor, full explicit grants — capped at sponsor's read+deploy",
			sponsorRole:    RoleMember,
			explicitGrants: map[Permission]bool{PermRotate: true, PermCreateRef: true},
			want:           map[Permission]bool{PermReadMetadata: true, PermDeploy: true},
		},
		{
			name:           "unknown/empty sponsor role — agent gets nothing, fail closed",
			sponsorRole:    Role("does-not-exist"),
			explicitGrants: map[Permission]bool{PermRotate: true, PermCreateRef: true},
			want:           map[Permission]bool{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := AgentPermissions(tc.sponsorRole, tc.explicitGrants)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("AgentPermissions(%q, %v) = %v, want %v", tc.sponsorRole, tc.explicitGrants, got, tc.want)
			}
			for p := range got {
				if !PermissionsForRole(tc.sponsorRole)[p] {
					t.Errorf("agent has permission %q that its sponsor's role %q does not grant — agent exceeded sponsor", p, tc.sponsorRole)
				}
			}
		})
	}
}

func TestPermissionsForRoleReturnsAFreshCopy(t *testing.T) {
	a := PermissionsForRole(RoleAdmin)
	a[Permission("zz-injected")] = true
	b := PermissionsForRole(RoleAdmin)
	if b[Permission("zz-injected")] {
		t.Fatal("mutating the map returned by PermissionsForRole leaked into the shared role table")
	}
}

func TestDefaultAgentGrantsNeverIncludeRotateOrCreateRef(t *testing.T) {
	if DefaultAgentGrants[PermRotate] {
		t.Error("DefaultAgentGrants must not include rotate — this package's own decision: rotate requires an explicit grant")
	}
	if DefaultAgentGrants[PermCreateRef] {
		t.Error("DefaultAgentGrants must not include create_ref — this package's own decision: create_ref requires an explicit grant")
	}
}
