package identity

import "testing"

func TestAdoptCarrierRequiresAdminOrExplicitGrantFromAdminSponsor(t *testing.T) {
	if DefaultAgentGrants[PermAdoptCarrier] || PermissionsForRole(RoleMember)[PermAdoptCarrier] || PermissionsForRole(RoleViewer)[PermAdoptCarrier] || !PermissionsForRole(RoleAdmin)[PermAdoptCarrier] {
		t.Fatal("adoption was made an ordinary deploy permission")
	}
	for _, role := range []Role{RoleViewer, RoleMember, RoleAdmin} {
		if AgentPermissions(role, nil)[PermAdoptCarrier] {
			t.Fatal("default agent may adopt a carrier")
		}
		got := AgentPermissions(role, map[Permission]bool{PermAdoptCarrier: true})[PermAdoptCarrier]
		if got != (role == RoleAdmin) {
			t.Fatal("explicit adoption grant exceeded its sponsor")
		}
	}
}
