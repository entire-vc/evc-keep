package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// MaxSealSeq is the largest seal_seq of the copied secret versions (0 if
// none); the target's next allocation must exceed it.
func (r *TransferRows) MaxSealSeq() int64 {
	var m int64
	for _, v := range r.SecretVersions {
		if v.SealSeq > m {
			m = v.SealSeq
		}
	}
	return m
}

// CopiedCounts returns the row count of every copied table by name. Tables of
// the registry that are not copied are absent, which means zero.
func (r *TransferRows) CopiedCounts() map[string]int64 {
	return map[string]int64{
		"organizations": int64(len(r.Organizations)), "users": int64(len(r.Users)),
		"agents": int64(len(r.Agents)), "services": int64(len(r.Services)),
		"memberships": int64(len(r.Memberships)), "agent_grants": int64(len(r.AgentGrants)),
		"workspaces": int64(len(r.Workspaces)), "projects": int64(len(r.Projects)),
		"stores": int64(len(r.Stores)), "store_bindings": int64(len(r.StoreBindings)),
		"override_locks": int64(len(r.OverrideLocks)), "secrets": int64(len(r.Secrets)),
		"secret_versions": int64(len(r.SecretVersions)), "keep_org_key_level": int64(len(r.OrgKeyLevels)),
		"keep_kek": int64(len(r.KEKs)), "keep_envelope": int64(len(r.Envelopes)),
		"org_ca": int64(len(r.OrgCAs)), "mesh_installations": int64(len(r.MeshInstallations)),
		"mesh_events": int64(len(r.MeshEvents)), "mesh_members": int64(len(r.MeshMembers)),
		"mesh_projects": int64(len(r.MeshProjects)), "mesh_agents": int64(len(r.MeshAgents)),
		"mesh_agent_keys": int64(len(r.MeshAgentKeys)), "mesh_sync_state": int64(len(r.MeshSyncStates)),
		"mesh_secret_nonces": int64(len(r.MeshSecretNonces)), "mesh_user_links": int64(len(r.MeshUserLinks)),
		"mesh_rotator_bindings": int64(len(r.MeshRotatorBindings)),
		"audit_chain_heads":     int64(len(r.AuditChainHeads)), "audit_records": int64(len(r.AuditRecords)),
	}
}

// ReadTransferRowsTx reads the copied rows of org inside the caller's
// transaction, so an importer can compare what it inserted with what the
// database now holds before it commits.
func ReadTransferRowsTx(ctx context.Context, tx pgx.Tx, org uuid.UUID) (*TransferRows, error) {
	return readTransferRows(ctx, tx, org)
}
