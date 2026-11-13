// Code generated from the reviewed transfer table registry; the column lists
// are verified against the live schema by TestTransferRowsMatchSchema.

package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// OrganizationRow is one row of organizations in the scoped-transfer snapshot.
type OrganizationRow struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	KeyLevel  string    `json:"key_level"`
}

func (r *OrganizationRow) scanDest() []any { return []any{&r.ID, &r.Name, &r.CreatedAt, &r.KeyLevel} }
func (r OrganizationRow) args() []any      { return []any{r.ID, r.Name, r.CreatedAt, r.KeyLevel} }

var organizationCols = []string{"id", "name", "created_at", "key_level"}

// UserRow is one row of users in the scoped-transfer snapshot.
type UserRow struct {
	ID          uuid.UUID  `json:"id"`
	OrgID       uuid.UUID  `json:"org_id"`
	Email       string     `json:"email"`
	CreatedAt   time.Time  `json:"created_at"`
	ExternalRef *string    `json:"external_ref"`
	Status      string     `json:"status"`
	RemovedAt   *time.Time `json:"removed_at"`
}

func (r *UserRow) scanDest() []any {
	return []any{&r.ID, &r.OrgID, &r.Email, &r.CreatedAt, &r.ExternalRef, &r.Status, &r.RemovedAt}
}
func (r UserRow) args() []any {
	return []any{r.ID, r.OrgID, r.Email, r.CreatedAt, r.ExternalRef, r.Status, r.RemovedAt}
}

var userCols = []string{"id", "org_id", "email", "created_at", "external_ref", "status", "removed_at"}

// AgentRow is one row of agents in the scoped-transfer snapshot.
type AgentRow struct {
	ID            uuid.UUID `json:"id"`
	OrgID         uuid.UUID `json:"org_id"`
	SponsorUserID uuid.UUID `json:"sponsor_user_id"`
	Name          string    `json:"name"`
	CreatedAt     time.Time `json:"created_at"`
	ExternalRef   *string   `json:"external_ref"`
	Status        string    `json:"status"`
}

func (r *AgentRow) scanDest() []any {
	return []any{&r.ID, &r.OrgID, &r.SponsorUserID, &r.Name, &r.CreatedAt, &r.ExternalRef, &r.Status}
}
func (r AgentRow) args() []any {
	return []any{r.ID, r.OrgID, r.SponsorUserID, r.Name, r.CreatedAt, r.ExternalRef, r.Status}
}

var agentCols = []string{"id", "org_id", "sponsor_user_id", "name", "created_at", "external_ref", "status"}

// ServiceRow is one row of services in the scoped-transfer snapshot.
type ServiceRow struct {
	ID         uuid.UUID `json:"id"`
	OrgID      uuid.UUID `json:"org_id"`
	OwnerScope string    `json:"owner_scope"`
	Name       string    `json:"name"`
	CreatedAt  time.Time `json:"created_at"`
}

func (r *ServiceRow) scanDest() []any {
	return []any{&r.ID, &r.OrgID, &r.OwnerScope, &r.Name, &r.CreatedAt}
}
func (r ServiceRow) args() []any { return []any{r.ID, r.OrgID, r.OwnerScope, r.Name, r.CreatedAt} }

var serviceCols = []string{"id", "org_id", "owner_scope", "name", "created_at"}

// MembershipRow is one row of memberships in the scoped-transfer snapshot.
type MembershipRow struct {
	ID        uuid.UUID `json:"id"`
	OrgID     uuid.UUID `json:"org_id"`
	UserID    uuid.UUID `json:"user_id"`
	Scope     string    `json:"scope"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

func (r *MembershipRow) scanDest() []any {
	return []any{&r.ID, &r.OrgID, &r.UserID, &r.Scope, &r.Role, &r.CreatedAt}
}
func (r MembershipRow) args() []any {
	return []any{r.ID, r.OrgID, r.UserID, r.Scope, r.Role, r.CreatedAt}
}

var membershipCols = []string{"id", "org_id", "user_id", "scope", "role", "created_at"}

// AgentGrantRow is one row of agent_grants in the scoped-transfer snapshot.
type AgentGrantRow struct {
	ID         uuid.UUID `json:"id"`
	OrgID      uuid.UUID `json:"org_id"`
	AgentID    uuid.UUID `json:"agent_id"`
	Permission string    `json:"permission"`
	CreatedAt  time.Time `json:"created_at"`
}

func (r *AgentGrantRow) scanDest() []any {
	return []any{&r.ID, &r.OrgID, &r.AgentID, &r.Permission, &r.CreatedAt}
}
func (r AgentGrantRow) args() []any {
	return []any{r.ID, r.OrgID, r.AgentID, r.Permission, r.CreatedAt}
}

var agentGrantCols = []string{"id", "org_id", "agent_id", "permission", "created_at"}

// WorkspaceRow is one row of workspaces in the scoped-transfer snapshot.
type WorkspaceRow struct {
	ID          uuid.UUID `json:"id"`
	OrgID       uuid.UUID `json:"org_id"`
	Name        string    `json:"name"`
	ExternalRef *string   `json:"external_ref"`
	CreatedAt   time.Time `json:"created_at"`
}

func (r *WorkspaceRow) scanDest() []any {
	return []any{&r.ID, &r.OrgID, &r.Name, &r.ExternalRef, &r.CreatedAt}
}
func (r WorkspaceRow) args() []any { return []any{r.ID, r.OrgID, r.Name, r.ExternalRef, r.CreatedAt} }

var workspaceCols = []string{"id", "org_id", "name", "external_ref", "created_at"}

// ProjectRow is one row of projects in the scoped-transfer snapshot.
type ProjectRow struct {
	ID          uuid.UUID `json:"id"`
	OrgID       uuid.UUID `json:"org_id"`
	WorkspaceID uuid.UUID `json:"workspace_id"`
	Name        string    `json:"name"`
	ExternalRef *string   `json:"external_ref"`
	CreatedAt   time.Time `json:"created_at"`
}

func (r *ProjectRow) scanDest() []any {
	return []any{&r.ID, &r.OrgID, &r.WorkspaceID, &r.Name, &r.ExternalRef, &r.CreatedAt}
}
func (r ProjectRow) args() []any {
	return []any{r.ID, r.OrgID, r.WorkspaceID, r.Name, r.ExternalRef, r.CreatedAt}
}

var projectCols = []string{"id", "org_id", "workspace_id", "name", "external_ref", "created_at"}

// StoreRow is one row of stores in the scoped-transfer snapshot.
type StoreRow struct {
	ID              uuid.UUID `json:"id"`
	OrgID           uuid.UUID `json:"org_id"`
	Provider        string    `json:"provider"`
	Name            string    `json:"name"`
	OwnerScopeLevel string    `json:"owner_scope_level"`
	OwnerScopeID    uuid.UUID `json:"owner_scope_id"`
	Status          string    `json:"status"`
	CreatedAt       time.Time `json:"created_at"`
}

func (r *StoreRow) scanDest() []any {
	return []any{&r.ID, &r.OrgID, &r.Provider, &r.Name, &r.OwnerScopeLevel, &r.OwnerScopeID, &r.Status, &r.CreatedAt}
}
func (r StoreRow) args() []any {
	return []any{r.ID, r.OrgID, r.Provider, r.Name, r.OwnerScopeLevel, r.OwnerScopeID, r.Status, r.CreatedAt}
}

var storeCols = []string{"id", "org_id", "provider", "name", "owner_scope_level", "owner_scope_id", "status", "created_at"}

// StoreBindingRow is one row of store_bindings in the scoped-transfer snapshot.
type StoreBindingRow struct {
	ID         uuid.UUID `json:"id"`
	OrgID      uuid.UUID `json:"org_id"`
	ScopeLevel string    `json:"scope_level"`
	ScopeID    uuid.UUID `json:"scope_id"`
	StoreID    uuid.UUID `json:"store_id"`
	CreatedAt  time.Time `json:"created_at"`
}

func (r *StoreBindingRow) scanDest() []any {
	return []any{&r.ID, &r.OrgID, &r.ScopeLevel, &r.ScopeID, &r.StoreID, &r.CreatedAt}
}
func (r StoreBindingRow) args() []any {
	return []any{r.ID, r.OrgID, r.ScopeLevel, r.ScopeID, r.StoreID, r.CreatedAt}
}

var storeBindingCols = []string{"id", "org_id", "scope_level", "scope_id", "store_id", "created_at"}

// OverrideLockRow is one row of override_locks in the scoped-transfer snapshot.
type OverrideLockRow struct {
	ID              uuid.UUID   `json:"id"`
	OrgID           uuid.UUID   `json:"org_id"`
	ScopeLevel      string      `json:"scope_level"`
	ScopeID         uuid.UUID   `json:"scope_id"`
	SelectorName    *string     `json:"selector_name"`
	SelectorClass   *string     `json:"selector_class"`
	Mode            string      `json:"mode"`
	AllowedStoreIds []uuid.UUID `json:"allowed_store_ids"`
	CreatedAt       time.Time   `json:"created_at"`
}

func (r *OverrideLockRow) scanDest() []any {
	return []any{&r.ID, &r.OrgID, &r.ScopeLevel, &r.ScopeID, &r.SelectorName, &r.SelectorClass, &r.Mode, &r.AllowedStoreIds, &r.CreatedAt}
}
func (r OverrideLockRow) args() []any {
	return []any{r.ID, r.OrgID, r.ScopeLevel, r.ScopeID, r.SelectorName, r.SelectorClass, r.Mode, r.AllowedStoreIds, r.CreatedAt}
}

var overrideLockCols = []string{"id", "org_id", "scope_level", "scope_id", "selector_name", "selector_class", "mode", "allowed_store_ids", "created_at"}

// SecretRow is one row of secrets in the scoped-transfer snapshot.
type SecretRow struct {
	ID              uuid.UUID `json:"id"`
	OrgID           uuid.UUID `json:"org_id"`
	ScopeLevel      string    `json:"scope_level"`
	ScopeID         uuid.UUID `json:"scope_id"`
	Name            string    `json:"name"`
	Class           string    `json:"class"`
	Type            string    `json:"type"`
	StoreID         uuid.UUID `json:"store_id"`
	ProviderRef     string    `json:"provider_ref"`
	Description     *string   `json:"description"`
	Status          string    `json:"status"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	DeployedVersion *string   `json:"deployed_version"`
}

func (r *SecretRow) scanDest() []any {
	return []any{&r.ID, &r.OrgID, &r.ScopeLevel, &r.ScopeID, &r.Name, &r.Class, &r.Type, &r.StoreID, &r.ProviderRef, &r.Description, &r.Status, &r.CreatedAt, &r.UpdatedAt, &r.DeployedVersion}
}
func (r SecretRow) args() []any {
	return []any{r.ID, r.OrgID, r.ScopeLevel, r.ScopeID, r.Name, r.Class, r.Type, r.StoreID, r.ProviderRef, r.Description, r.Status, r.CreatedAt, r.UpdatedAt, r.DeployedVersion}
}

var secretCols = []string{"id", "org_id", "scope_level", "scope_id", "name", "class", "type", "store_id", "provider_ref", "description", "status", "created_at", "updated_at", "deployed_version"}

// SecretVersionRow is one row of secret_versions in the scoped-transfer snapshot.
type SecretVersionRow struct {
	ID              uuid.UUID `json:"id"`
	OrgID           uuid.UUID `json:"org_id"`
	SecretID        uuid.UUID `json:"secret_id"`
	ProviderVersion string    `json:"provider_version"`
	Fingerprint     string    `json:"fingerprint"`
	Length          int32     `json:"length"`
	Disabled        bool      `json:"disabled"`
	CreatedAt       time.Time `json:"created_at"`
	SealSeq         int64     `json:"seal_seq"`
}

func (r *SecretVersionRow) scanDest() []any {
	return []any{&r.ID, &r.OrgID, &r.SecretID, &r.ProviderVersion, &r.Fingerprint, &r.Length, &r.Disabled, &r.CreatedAt, &r.SealSeq}
}
func (r SecretVersionRow) args() []any {
	return []any{r.ID, r.OrgID, r.SecretID, r.ProviderVersion, r.Fingerprint, r.Length, r.Disabled, r.CreatedAt, r.SealSeq}
}

var secretVersionCols = []string{"id", "org_id", "secret_id", "provider_version", "fingerprint", "length", "disabled", "created_at", "seal_seq"}

// OrgKeyLevelRow is one row of keep_org_key_level in the scoped-transfer snapshot.
type OrgKeyLevelRow struct {
	OrgID     string    `json:"org_id"`
	Level     string    `json:"level"`
	UpdatedBy string    `json:"updated_by"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (r *OrgKeyLevelRow) scanDest() []any {
	return []any{&r.OrgID, &r.Level, &r.UpdatedBy, &r.UpdatedAt}
}
func (r OrgKeyLevelRow) args() []any { return []any{r.OrgID, r.Level, r.UpdatedBy, r.UpdatedAt} }

var orgKeyLevelCols = []string{"org_id", "level", "updated_by", "updated_at"}

// KEKRow is one row of keep_kek in the scoped-transfer snapshot.
type KEKRow struct {
	ID              string    `json:"id"`
	OrgID           string    `json:"org_id"`
	DomainKey       string    `json:"domain_key"`
	DomainOrg       string    `json:"domain_org"`
	DomainWorkspace string    `json:"domain_workspace"`
	DomainProject   string    `json:"domain_project"`
	DomainUser      string    `json:"domain_user"`
	RootKeyID       string    `json:"root_key_id"`
	Wrapped         []byte    `json:"wrapped"`
	State           string    `json:"state"`
	CreatedAt       time.Time `json:"created_at"`
}

func (r *KEKRow) scanDest() []any {
	return []any{&r.ID, &r.OrgID, &r.DomainKey, &r.DomainOrg, &r.DomainWorkspace, &r.DomainProject, &r.DomainUser, &r.RootKeyID, &r.Wrapped, &r.State, &r.CreatedAt}
}
func (r KEKRow) args() []any {
	return []any{r.ID, r.OrgID, r.DomainKey, r.DomainOrg, r.DomainWorkspace, r.DomainProject, r.DomainUser, r.RootKeyID, r.Wrapped, r.State, r.CreatedAt}
}

var kEKCols = []string{"id", "org_id", "domain_key", "domain_org", "domain_workspace", "domain_project", "domain_user", "root_key_id", "wrapped", "state", "created_at"}

// EnvelopeRow is one row of keep_envelope in the scoped-transfer snapshot.
type EnvelopeRow struct {
	StoreOrg       string    `json:"store_org"`
	StoreWorkspace string    `json:"store_workspace"`
	StoreProject   string    `json:"store_project"`
	StoreUser      string    `json:"store_user"`
	SecretID       string    `json:"secret_id"`
	Name           string    `json:"name"`
	Version        int64     `json:"version"`
	KEKID          *string   `json:"kek_id"`
	WrappedDEK     []byte    `json:"wrapped_dek"`
	Ciphertext     []byte    `json:"ciphertext"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
}

func (r *EnvelopeRow) scanDest() []any {
	return []any{&r.StoreOrg, &r.StoreWorkspace, &r.StoreProject, &r.StoreUser, &r.SecretID, &r.Name, &r.Version, &r.KEKID, &r.WrappedDEK, &r.Ciphertext, &r.Status, &r.CreatedAt}
}
func (r EnvelopeRow) args() []any {
	return []any{r.StoreOrg, r.StoreWorkspace, r.StoreProject, r.StoreUser, r.SecretID, r.Name, r.Version, r.KEKID, r.WrappedDEK, r.Ciphertext, r.Status, r.CreatedAt}
}

var envelopeCols = []string{"store_org", "store_workspace", "store_project", "store_user", "secret_id", "name", "version", "kek_id", "wrapped_dek", "ciphertext", "status", "created_at"}

// OrgCARow is one row of org_ca in the scoped-transfer snapshot.
type OrgCARow struct {
	OrgID          uuid.UUID `json:"org_id"`
	CACertDER      []byte    `json:"ca_cert_der"`
	CAKEKID        string    `json:"ca_kek_id"`
	CAWrappedDEK   []byte    `json:"ca_wrapped_dek"`
	CACiphertext   []byte    `json:"ca_ciphertext"`
	SignKeyID      string    `json:"sign_key_id"`
	SignPubKey     []byte    `json:"sign_pub_key"`
	SignKEKID      string    `json:"sign_kek_id"`
	SignWrappedDEK []byte    `json:"sign_wrapped_dek"`
	SignCiphertext []byte    `json:"sign_ciphertext"`
	CreatedAt      time.Time `json:"created_at"`
}

func (r *OrgCARow) scanDest() []any {
	return []any{&r.OrgID, &r.CACertDER, &r.CAKEKID, &r.CAWrappedDEK, &r.CACiphertext, &r.SignKeyID, &r.SignPubKey, &r.SignKEKID, &r.SignWrappedDEK, &r.SignCiphertext, &r.CreatedAt}
}
func (r OrgCARow) args() []any {
	return []any{r.OrgID, r.CACertDER, r.CAKEKID, r.CAWrappedDEK, r.CACiphertext, r.SignKeyID, r.SignPubKey, r.SignKEKID, r.SignWrappedDEK, r.SignCiphertext, r.CreatedAt}
}

var orgCACols = []string{"org_id", "ca_cert_der", "ca_kek_id", "ca_wrapped_dek", "ca_ciphertext", "sign_key_id", "sign_pub_key", "sign_kek_id", "sign_wrapped_dek", "sign_ciphertext", "created_at"}

// MeshInstallationRow is one row of mesh_installations in the scoped-transfer snapshot.
type MeshInstallationRow struct {
	WorkspaceID   uuid.UUID `json:"workspace_id"`
	OrgID         uuid.UUID `json:"org_id"`
	MeshURL       string    `json:"mesh_url"`
	InstalledBy   uuid.UUID `json:"installed_by"`
	InstalledAt   time.Time `json:"installed_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	TokenSignedAt *int64    `json:"token_signed_at"`
	Mode          string    `json:"mode"`
}

func (r *MeshInstallationRow) scanDest() []any {
	return []any{&r.WorkspaceID, &r.OrgID, &r.MeshURL, &r.InstalledBy, &r.InstalledAt, &r.UpdatedAt, &r.TokenSignedAt, &r.Mode}
}
func (r MeshInstallationRow) args() []any {
	return []any{r.WorkspaceID, r.OrgID, r.MeshURL, r.InstalledBy, r.InstalledAt, r.UpdatedAt, r.TokenSignedAt, r.Mode}
}

var meshInstallationCols = []string{"workspace_id", "org_id", "mesh_url", "installed_by", "installed_at", "updated_at", "token_signed_at", "mode"}

// MeshEventRow is one row of mesh_events in the scoped-transfer snapshot.
type MeshEventRow struct {
	WorkspaceID uuid.UUID `json:"workspace_id"`
	EventID     string    `json:"event_id"`
	EventType   string    `json:"event_type"`
	ReceivedAt  time.Time `json:"received_at"`
}

func (r *MeshEventRow) scanDest() []any {
	return []any{&r.WorkspaceID, &r.EventID, &r.EventType, &r.ReceivedAt}
}
func (r MeshEventRow) args() []any { return []any{r.WorkspaceID, r.EventID, r.EventType, r.ReceivedAt} }

var meshEventCols = []string{"workspace_id", "event_id", "event_type", "received_at"}

// MeshMemberRow is one row of mesh_members in the scoped-transfer snapshot.
type MeshMemberRow struct {
	WorkspaceID uuid.UUID  `json:"workspace_id"`
	UserID      uuid.UUID  `json:"user_id"`
	Role        string     `json:"role"`
	RoleAt      time.Time  `json:"role_at"`
	Status      string     `json:"status"`
	StateAt     time.Time  `json:"state_at"`
	OrphanedAt  *time.Time `json:"orphaned_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

func (r *MeshMemberRow) scanDest() []any {
	return []any{&r.WorkspaceID, &r.UserID, &r.Role, &r.RoleAt, &r.Status, &r.StateAt, &r.OrphanedAt, &r.UpdatedAt}
}
func (r MeshMemberRow) args() []any {
	return []any{r.WorkspaceID, r.UserID, r.Role, r.RoleAt, r.Status, r.StateAt, r.OrphanedAt, r.UpdatedAt}
}

var meshMemberCols = []string{"workspace_id", "user_id", "role", "role_at", "status", "state_at", "orphaned_at", "updated_at"}

// MeshProjectRow is one row of mesh_projects in the scoped-transfer snapshot.
type MeshProjectRow struct {
	WorkspaceID uuid.UUID  `json:"workspace_id"`
	ProjectID   uuid.UUID  `json:"project_id"`
	Slug        string     `json:"slug"`
	Name        string     `json:"name"`
	IsArchived  bool       `json:"is_archived"`
	SlugAt      time.Time  `json:"slug_at"`
	NameAt      time.Time  `json:"name_at"`
	ArchivedAt  time.Time  `json:"archived_at"`
	Status      string     `json:"status"`
	StateAt     time.Time  `json:"state_at"`
	OrphanedAt  *time.Time `json:"orphaned_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

func (r *MeshProjectRow) scanDest() []any {
	return []any{&r.WorkspaceID, &r.ProjectID, &r.Slug, &r.Name, &r.IsArchived, &r.SlugAt, &r.NameAt, &r.ArchivedAt, &r.Status, &r.StateAt, &r.OrphanedAt, &r.UpdatedAt}
}
func (r MeshProjectRow) args() []any {
	return []any{r.WorkspaceID, r.ProjectID, r.Slug, r.Name, r.IsArchived, r.SlugAt, r.NameAt, r.ArchivedAt, r.Status, r.StateAt, r.OrphanedAt, r.UpdatedAt}
}

var meshProjectCols = []string{"workspace_id", "project_id", "slug", "name", "is_archived", "slug_at", "name_at", "archived_at", "status", "state_at", "orphaned_at", "updated_at"}

// MeshAgentRow is one row of mesh_agents in the scoped-transfer snapshot.
type MeshAgentRow struct {
	WorkspaceID   uuid.UUID  `json:"workspace_id"`
	AgentID       uuid.UUID  `json:"agent_id"`
	Slug          string     `json:"slug"`
	SlugAt        time.Time  `json:"slug_at"`
	SponsorUserID *uuid.UUID `json:"sponsor_user_id"`
	SponsorAt     time.Time  `json:"sponsor_at"`
	Status        string     `json:"status"`
	StateAt       time.Time  `json:"state_at"`
	OrphanedAt    *time.Time `json:"orphaned_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

func (r *MeshAgentRow) scanDest() []any {
	return []any{&r.WorkspaceID, &r.AgentID, &r.Slug, &r.SlugAt, &r.SponsorUserID, &r.SponsorAt, &r.Status, &r.StateAt, &r.OrphanedAt, &r.UpdatedAt}
}
func (r MeshAgentRow) args() []any {
	return []any{r.WorkspaceID, r.AgentID, r.Slug, r.SlugAt, r.SponsorUserID, r.SponsorAt, r.Status, r.StateAt, r.OrphanedAt, r.UpdatedAt}
}

var meshAgentCols = []string{"workspace_id", "agent_id", "slug", "slug_at", "sponsor_user_id", "sponsor_at", "status", "state_at", "orphaned_at", "updated_at"}

// MeshAgentKeyRow is one row of mesh_agent_keys in the scoped-transfer snapshot.
type MeshAgentKeyRow struct {
	WorkspaceID uuid.UUID  `json:"workspace_id"`
	AgentID     uuid.UUID  `json:"agent_id"`
	KeyID       string     `json:"key_id"`
	Label       string     `json:"label"`
	LabelAt     time.Time  `json:"label_at"`
	Status      string     `json:"status"`
	StateAt     time.Time  `json:"state_at"`
	OrphanedAt  *time.Time `json:"orphaned_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

func (r *MeshAgentKeyRow) scanDest() []any {
	return []any{&r.WorkspaceID, &r.AgentID, &r.KeyID, &r.Label, &r.LabelAt, &r.Status, &r.StateAt, &r.OrphanedAt, &r.UpdatedAt}
}
func (r MeshAgentKeyRow) args() []any {
	return []any{r.WorkspaceID, r.AgentID, r.KeyID, r.Label, r.LabelAt, r.Status, r.StateAt, r.OrphanedAt, r.UpdatedAt}
}

var meshAgentKeyCols = []string{"workspace_id", "agent_id", "key_id", "label", "label_at", "status", "state_at", "orphaned_at", "updated_at"}

// MeshSyncStateRow is one row of mesh_sync_state in the scoped-transfer snapshot.
type MeshSyncStateRow struct {
	WorkspaceID    uuid.UUID  `json:"workspace_id"`
	Cursor         string     `json:"cursor"`
	DirtySeq       int64      `json:"dirty_seq"`
	SyncedSeq      int64      `json:"synced_seq"`
	LastSyncAt     *time.Time `json:"last_sync_at"`
	LastResult     string     `json:"last_result"`
	LastErrorClass string     `json:"last_error_class"`
	OrphanedCount  int32      `json:"orphaned_count"`
	LastFullSyncAt *time.Time `json:"last_full_sync_at"`
}

func (r *MeshSyncStateRow) scanDest() []any {
	return []any{&r.WorkspaceID, &r.Cursor, &r.DirtySeq, &r.SyncedSeq, &r.LastSyncAt, &r.LastResult, &r.LastErrorClass, &r.OrphanedCount, &r.LastFullSyncAt}
}
func (r MeshSyncStateRow) args() []any {
	return []any{r.WorkspaceID, r.Cursor, r.DirtySeq, r.SyncedSeq, r.LastSyncAt, r.LastResult, r.LastErrorClass, r.OrphanedCount, r.LastFullSyncAt}
}

var meshSyncStateCols = []string{"workspace_id", "cursor", "dirty_seq", "synced_seq", "last_sync_at", "last_result", "last_error_class", "orphaned_count", "last_full_sync_at"}

// MeshSecretNonceRow is one row of mesh_secret_nonces in the scoped-transfer snapshot.
type MeshSecretNonceRow struct {
	WorkspaceID uuid.UUID `json:"workspace_id"`
	Nonce       string    `json:"nonce"`
	SeenAt      time.Time `json:"seen_at"`
}

func (r *MeshSecretNonceRow) scanDest() []any { return []any{&r.WorkspaceID, &r.Nonce, &r.SeenAt} }
func (r MeshSecretNonceRow) args() []any      { return []any{r.WorkspaceID, r.Nonce, r.SeenAt} }

var meshSecretNonceCols = []string{"workspace_id", "nonce", "seen_at"}

// MeshUserLinkRow is one row of mesh_user_links in the scoped-transfer snapshot.
type MeshUserLinkRow struct {
	WorkspaceID uuid.UUID `json:"workspace_id"`
	MeshUserID  uuid.UUID `json:"mesh_user_id"`
	OrgID       uuid.UUID `json:"org_id"`
	UserID      uuid.UUID `json:"user_id"`
	LinkedAt    time.Time `json:"linked_at"`
}

func (r *MeshUserLinkRow) scanDest() []any {
	return []any{&r.WorkspaceID, &r.MeshUserID, &r.OrgID, &r.UserID, &r.LinkedAt}
}
func (r MeshUserLinkRow) args() []any {
	return []any{r.WorkspaceID, r.MeshUserID, r.OrgID, r.UserID, r.LinkedAt}
}

var meshUserLinkCols = []string{"workspace_id", "mesh_user_id", "org_id", "user_id", "linked_at"}

// MeshRotatorBindingRow is one row of mesh_rotator_bindings in the scoped-transfer snapshot.
type MeshRotatorBindingRow struct {
	WorkspaceID uuid.UUID `json:"workspace_id"`
	OrgID       uuid.UUID `json:"org_id"`
	BoundBy     uuid.UUID `json:"bound_by"`
	BoundAt     time.Time `json:"bound_at"`
}

func (r *MeshRotatorBindingRow) scanDest() []any {
	return []any{&r.WorkspaceID, &r.OrgID, &r.BoundBy, &r.BoundAt}
}
func (r MeshRotatorBindingRow) args() []any {
	return []any{r.WorkspaceID, r.OrgID, r.BoundBy, r.BoundAt}
}

var meshRotatorBindingCols = []string{"workspace_id", "org_id", "bound_by", "bound_at"}

// AuditChainHeadRow is one row of audit_chain_heads in the scoped-transfer snapshot.
type AuditChainHeadRow struct {
	OrgID    string `json:"org_id"`
	Position int64  `json:"position"`
	Hash     string `json:"hash"`
}

func (r *AuditChainHeadRow) scanDest() []any { return []any{&r.OrgID, &r.Position, &r.Hash} }
func (r AuditChainHeadRow) args() []any      { return []any{r.OrgID, r.Position, r.Hash} }

var auditChainHeadCols = []string{"org_id", "position", "hash"}

// AuditRecordRow is one row of audit_records in the scoped-transfer snapshot.
type AuditRecordRow struct {
	ID                 string     `json:"id"`
	OrgID              string     `json:"org_id"`
	OrgSeq             int64      `json:"org_seq"`
	TS                 time.Time  `json:"ts"`
	RequestID          string     `json:"request_id"`
	Scope              string     `json:"scope"`
	ActorType          string     `json:"actor_type"`
	ActorID            string     `json:"actor_id"`
	ActorSponsorID     string     `json:"actor_sponsor_id"`
	ActorVia           string     `json:"actor_via"`
	IntentTaskRef      string     `json:"intent_task_ref"`
	IntentSessionRef   string     `json:"intent_session_ref"`
	IntentReason       string     `json:"intent_reason"`
	Action             string     `json:"action"`
	SecretID           string     `json:"secret_id"`
	SecretName         string     `json:"secret_name"`
	SecretVersion      string     `json:"secret_version"`
	TargetRunnerID     string     `json:"target_runner_id"`
	TargetHost         string     `json:"target_host"`
	TargetKind         string     `json:"target_kind"`
	TargetPath         string     `json:"target_path"`
	PolicyDecision     string     `json:"policy_decision"`
	PolicyRuleID       string     `json:"policy_rule_id"`
	ApprovalID         string     `json:"approval_id"`
	ApprovalApproverID string     `json:"approval_approver_id"`
	ApprovalDecidedAt  *time.Time `json:"approval_decided_at"`
	ResultStatus       string     `json:"result_status"`
	ResultFingerprint  string     `json:"result_fingerprint"`
	ResultLength       int32      `json:"result_length"`
	ResultHealth       string     `json:"result_health"`
	ResultErrorClass   string     `json:"result_error_class"`
	PrevHash           string     `json:"prev_hash"`
	Hash               string     `json:"hash"`
}

func (r *AuditRecordRow) scanDest() []any {
	return []any{&r.ID, &r.OrgID, &r.OrgSeq, &r.TS, &r.RequestID, &r.Scope, &r.ActorType, &r.ActorID, &r.ActorSponsorID, &r.ActorVia, &r.IntentTaskRef, &r.IntentSessionRef, &r.IntentReason, &r.Action, &r.SecretID, &r.SecretName, &r.SecretVersion, &r.TargetRunnerID, &r.TargetHost, &r.TargetKind, &r.TargetPath, &r.PolicyDecision, &r.PolicyRuleID, &r.ApprovalID, &r.ApprovalApproverID, &r.ApprovalDecidedAt, &r.ResultStatus, &r.ResultFingerprint, &r.ResultLength, &r.ResultHealth, &r.ResultErrorClass, &r.PrevHash, &r.Hash}
}
func (r AuditRecordRow) args() []any {
	return []any{r.ID, r.OrgID, r.OrgSeq, r.TS, r.RequestID, r.Scope, r.ActorType, r.ActorID, r.ActorSponsorID, r.ActorVia, r.IntentTaskRef, r.IntentSessionRef, r.IntentReason, r.Action, r.SecretID, r.SecretName, r.SecretVersion, r.TargetRunnerID, r.TargetHost, r.TargetKind, r.TargetPath, r.PolicyDecision, r.PolicyRuleID, r.ApprovalID, r.ApprovalApproverID, r.ApprovalDecidedAt, r.ResultStatus, r.ResultFingerprint, r.ResultLength, r.ResultHealth, r.ResultErrorClass, r.PrevHash, r.Hash}
}

var auditRecordCols = []string{"id", "org_id", "org_seq", "ts", "request_id", "scope", "actor_type", "actor_id", "actor_sponsor_id", "actor_via", "intent_task_ref", "intent_session_ref", "intent_reason", "action", "secret_id", "secret_name", "secret_version", "target_runner_id", "target_host", "target_kind", "target_path", "policy_decision", "policy_rule_id", "approval_id", "approval_approver_id", "approval_decided_at", "result_status", "result_fingerprint", "result_length", "result_health", "result_error_class", "prev_hash", "hash"}

// TransferRows is the typed, closed set of rows of one organization that an
// offline scoped transfer copies. Order of the fields is the foreign-key-safe
// insertion order.
type TransferRows struct {
	Organizations       []OrganizationRow       `json:"organizations"`
	Users               []UserRow               `json:"users"`
	Agents              []AgentRow              `json:"agents"`
	Services            []ServiceRow            `json:"services"`
	Memberships         []MembershipRow         `json:"memberships"`
	AgentGrants         []AgentGrantRow         `json:"agent_grants"`
	Workspaces          []WorkspaceRow          `json:"workspaces"`
	Projects            []ProjectRow            `json:"projects"`
	Stores              []StoreRow              `json:"stores"`
	StoreBindings       []StoreBindingRow       `json:"store_bindings"`
	OverrideLocks       []OverrideLockRow       `json:"override_locks"`
	Secrets             []SecretRow             `json:"secrets"`
	SecretVersions      []SecretVersionRow      `json:"secret_versions"`
	OrgKeyLevels        []OrgKeyLevelRow        `json:"keep_org_key_level"`
	KEKs                []KEKRow                `json:"keep_kek"`
	Envelopes           []EnvelopeRow           `json:"keep_envelope"`
	OrgCAs              []OrgCARow              `json:"org_ca"`
	MeshInstallations   []MeshInstallationRow   `json:"mesh_installations"`
	MeshEvents          []MeshEventRow          `json:"mesh_events"`
	MeshMembers         []MeshMemberRow         `json:"mesh_members"`
	MeshProjects        []MeshProjectRow        `json:"mesh_projects"`
	MeshAgents          []MeshAgentRow          `json:"mesh_agents"`
	MeshAgentKeys       []MeshAgentKeyRow       `json:"mesh_agent_keys"`
	MeshSyncStates      []MeshSyncStateRow      `json:"mesh_sync_state"`
	MeshSecretNonces    []MeshSecretNonceRow    `json:"mesh_secret_nonces"`
	MeshUserLinks       []MeshUserLinkRow       `json:"mesh_user_links"`
	MeshRotatorBindings []MeshRotatorBindingRow `json:"mesh_rotator_bindings"`
	AuditChainHeads     []AuditChainHeadRow     `json:"audit_chain_heads"`
	AuditRecords        []AuditRecordRow        `json:"audit_records"`
}

// transferTables lists every copied table with the columns and the row order
// the reader uses; the columns are checked against the live schema by a test.
var transferTables = []struct {
	name  string
	cols  []string
	order string
}{
	{"organizations", organizationCols, "id"},
	{"users", userCols, "id"},
	{"agents", agentCols, "id"},
	{"services", serviceCols, "id"},
	{"memberships", membershipCols, "id"},
	{"agent_grants", agentGrantCols, "id"},
	{"workspaces", workspaceCols, "id"},
	{"projects", projectCols, "id"},
	{"stores", storeCols, "id"},
	{"store_bindings", storeBindingCols, "id"},
	{"override_locks", overrideLockCols, "id"},
	{"secrets", secretCols, "id"},
	{"secret_versions", secretVersionCols, "seal_seq"},
	{"keep_org_key_level", orgKeyLevelCols, "org_id"},
	{"keep_kek", kEKCols, "id"},
	{"keep_envelope", envelopeCols, "store_org, store_workspace, store_project, store_user, secret_id, version"},
	{"org_ca", orgCACols, "org_id"},
	{"mesh_installations", meshInstallationCols, "workspace_id"},
	{"mesh_events", meshEventCols, "workspace_id, event_id"},
	{"mesh_members", meshMemberCols, "workspace_id, user_id"},
	{"mesh_projects", meshProjectCols, "workspace_id, project_id"},
	{"mesh_agents", meshAgentCols, "workspace_id, agent_id"},
	{"mesh_agent_keys", meshAgentKeyCols, "workspace_id, agent_id, key_id"},
	{"mesh_sync_state", meshSyncStateCols, "workspace_id"},
	{"mesh_secret_nonces", meshSecretNonceCols, "workspace_id, nonce"},
	{"mesh_user_links", meshUserLinkCols, "workspace_id, mesh_user_id"},
	{"mesh_rotator_bindings", meshRotatorBindingCols, "workspace_id"},
	{"audit_chain_heads", auditChainHeadCols, "org_id"},
	{"audit_records", auditRecordCols, "org_seq"},
}

// readTransferRows reads every copied table inside the caller's snapshot transaction.
func readTransferRows(ctx context.Context, tx pgx.Tx, org uuid.UUID) (*TransferRows, error) {
	r := &TransferRows{}
	var err error
	if r.Organizations, err = readTable[OrganizationRow](ctx, tx, "organizations", organizationCols, "id", org); err != nil {
		return nil, err
	}
	if r.Users, err = readTable[UserRow](ctx, tx, "users", userCols, "id", org); err != nil {
		return nil, err
	}
	if r.Agents, err = readTable[AgentRow](ctx, tx, "agents", agentCols, "id", org); err != nil {
		return nil, err
	}
	if r.Services, err = readTable[ServiceRow](ctx, tx, "services", serviceCols, "id", org); err != nil {
		return nil, err
	}
	if r.Memberships, err = readTable[MembershipRow](ctx, tx, "memberships", membershipCols, "id", org); err != nil {
		return nil, err
	}
	if r.AgentGrants, err = readTable[AgentGrantRow](ctx, tx, "agent_grants", agentGrantCols, "id", org); err != nil {
		return nil, err
	}
	if r.Workspaces, err = readTable[WorkspaceRow](ctx, tx, "workspaces", workspaceCols, "id", org); err != nil {
		return nil, err
	}
	if r.Projects, err = readTable[ProjectRow](ctx, tx, "projects", projectCols, "id", org); err != nil {
		return nil, err
	}
	if r.Stores, err = readTable[StoreRow](ctx, tx, "stores", storeCols, "id", org); err != nil {
		return nil, err
	}
	if r.StoreBindings, err = readTable[StoreBindingRow](ctx, tx, "store_bindings", storeBindingCols, "id", org); err != nil {
		return nil, err
	}
	if r.OverrideLocks, err = readTable[OverrideLockRow](ctx, tx, "override_locks", overrideLockCols, "id", org); err != nil {
		return nil, err
	}
	if r.Secrets, err = readTable[SecretRow](ctx, tx, "secrets", secretCols, "id", org); err != nil {
		return nil, err
	}
	if r.SecretVersions, err = readTable[SecretVersionRow](ctx, tx, "secret_versions", secretVersionCols, "seal_seq", org); err != nil {
		return nil, err
	}
	if r.OrgKeyLevels, err = readTable[OrgKeyLevelRow](ctx, tx, "keep_org_key_level", orgKeyLevelCols, "org_id", org); err != nil {
		return nil, err
	}
	if r.KEKs, err = readTable[KEKRow](ctx, tx, "keep_kek", kEKCols, "id", org); err != nil {
		return nil, err
	}
	if r.Envelopes, err = readTable[EnvelopeRow](ctx, tx, "keep_envelope", envelopeCols, "store_org, store_workspace, store_project, store_user, secret_id, version", org); err != nil {
		return nil, err
	}
	if r.OrgCAs, err = readTable[OrgCARow](ctx, tx, "org_ca", orgCACols, "org_id", org); err != nil {
		return nil, err
	}
	if r.MeshInstallations, err = readTable[MeshInstallationRow](ctx, tx, "mesh_installations", meshInstallationCols, "workspace_id", org); err != nil {
		return nil, err
	}
	if r.MeshEvents, err = readTable[MeshEventRow](ctx, tx, "mesh_events", meshEventCols, "workspace_id, event_id", org); err != nil {
		return nil, err
	}
	if r.MeshMembers, err = readTable[MeshMemberRow](ctx, tx, "mesh_members", meshMemberCols, "workspace_id, user_id", org); err != nil {
		return nil, err
	}
	if r.MeshProjects, err = readTable[MeshProjectRow](ctx, tx, "mesh_projects", meshProjectCols, "workspace_id, project_id", org); err != nil {
		return nil, err
	}
	if r.MeshAgents, err = readTable[MeshAgentRow](ctx, tx, "mesh_agents", meshAgentCols, "workspace_id, agent_id", org); err != nil {
		return nil, err
	}
	if r.MeshAgentKeys, err = readTable[MeshAgentKeyRow](ctx, tx, "mesh_agent_keys", meshAgentKeyCols, "workspace_id, agent_id, key_id", org); err != nil {
		return nil, err
	}
	if r.MeshSyncStates, err = readTable[MeshSyncStateRow](ctx, tx, "mesh_sync_state", meshSyncStateCols, "workspace_id", org); err != nil {
		return nil, err
	}
	if r.MeshSecretNonces, err = readTable[MeshSecretNonceRow](ctx, tx, "mesh_secret_nonces", meshSecretNonceCols, "workspace_id, nonce", org); err != nil {
		return nil, err
	}
	if r.MeshUserLinks, err = readTable[MeshUserLinkRow](ctx, tx, "mesh_user_links", meshUserLinkCols, "workspace_id, mesh_user_id", org); err != nil {
		return nil, err
	}
	if r.MeshRotatorBindings, err = readTable[MeshRotatorBindingRow](ctx, tx, "mesh_rotator_bindings", meshRotatorBindingCols, "workspace_id", org); err != nil {
		return nil, err
	}
	if r.AuditChainHeads, err = readTable[AuditChainHeadRow](ctx, tx, "audit_chain_heads", auditChainHeadCols, "org_id", org); err != nil {
		return nil, err
	}
	if r.AuditRecords, err = readTable[AuditRecordRow](ctx, tx, "audit_records", auditRecordCols, "org_seq", org); err != nil {
		return nil, err
	}
	return r, nil
}

// insertTransferRows inserts every table in foreign-key-safe order with explicit
// column lists, never upserting.
func insertTransferRows(ctx context.Context, tx pgx.Tx, r *TransferRows) error {
	if err := insertTable(ctx, tx, "organizations", organizationCols, r.Organizations); err != nil {
		return err
	}
	if err := insertTable(ctx, tx, "users", userCols, r.Users); err != nil {
		return err
	}
	if err := insertTable(ctx, tx, "agents", agentCols, r.Agents); err != nil {
		return err
	}
	if err := insertTable(ctx, tx, "services", serviceCols, r.Services); err != nil {
		return err
	}
	if err := insertTable(ctx, tx, "memberships", membershipCols, r.Memberships); err != nil {
		return err
	}
	if err := insertTable(ctx, tx, "agent_grants", agentGrantCols, r.AgentGrants); err != nil {
		return err
	}
	if err := insertTable(ctx, tx, "workspaces", workspaceCols, r.Workspaces); err != nil {
		return err
	}
	if err := insertTable(ctx, tx, "projects", projectCols, r.Projects); err != nil {
		return err
	}
	if err := insertTable(ctx, tx, "stores", storeCols, r.Stores); err != nil {
		return err
	}
	if err := insertTable(ctx, tx, "store_bindings", storeBindingCols, r.StoreBindings); err != nil {
		return err
	}
	if err := insertTable(ctx, tx, "override_locks", overrideLockCols, r.OverrideLocks); err != nil {
		return err
	}
	if err := insertTable(ctx, tx, "secrets", secretCols, r.Secrets); err != nil {
		return err
	}
	if err := insertTable(ctx, tx, "secret_versions", secretVersionCols, r.SecretVersions); err != nil {
		return err
	}
	if err := insertTable(ctx, tx, "keep_org_key_level", orgKeyLevelCols, r.OrgKeyLevels); err != nil {
		return err
	}
	if err := insertTable(ctx, tx, "keep_kek", kEKCols, r.KEKs); err != nil {
		return err
	}
	if err := insertTable(ctx, tx, "keep_envelope", envelopeCols, r.Envelopes); err != nil {
		return err
	}
	if err := insertTable(ctx, tx, "org_ca", orgCACols, r.OrgCAs); err != nil {
		return err
	}
	if err := insertTable(ctx, tx, "mesh_installations", meshInstallationCols, r.MeshInstallations); err != nil {
		return err
	}
	if err := insertTable(ctx, tx, "mesh_events", meshEventCols, r.MeshEvents); err != nil {
		return err
	}
	if err := insertTable(ctx, tx, "mesh_members", meshMemberCols, r.MeshMembers); err != nil {
		return err
	}
	if err := insertTable(ctx, tx, "mesh_projects", meshProjectCols, r.MeshProjects); err != nil {
		return err
	}
	if err := insertTable(ctx, tx, "mesh_agents", meshAgentCols, r.MeshAgents); err != nil {
		return err
	}
	if err := insertTable(ctx, tx, "mesh_agent_keys", meshAgentKeyCols, r.MeshAgentKeys); err != nil {
		return err
	}
	if err := insertTable(ctx, tx, "mesh_sync_state", meshSyncStateCols, r.MeshSyncStates); err != nil {
		return err
	}
	if err := insertTable(ctx, tx, "mesh_secret_nonces", meshSecretNonceCols, r.MeshSecretNonces); err != nil {
		return err
	}
	if err := insertTable(ctx, tx, "mesh_user_links", meshUserLinkCols, r.MeshUserLinks); err != nil {
		return err
	}
	if err := insertTable(ctx, tx, "mesh_rotator_bindings", meshRotatorBindingCols, r.MeshRotatorBindings); err != nil {
		return err
	}
	if err := insertTable(ctx, tx, "audit_chain_heads", auditChainHeadCols, r.AuditChainHeads); err != nil {
		return err
	}
	if err := insertTable(ctx, tx, "audit_records", auditRecordCols, r.AuditRecords); err != nil {
		return err
	}
	return nil
}
