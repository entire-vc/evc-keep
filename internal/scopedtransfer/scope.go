package scopedtransfer

// ScopeKind says how a table's rows are tied to the selected organization.
type ScopeKind uint8

const (
	// ScopeColumn: a column of the table equals the selected organization.
	ScopeColumn ScopeKind = iota + 1
	// ScopeSelf: the table's own id column is the selected organization.
	ScopeSelf
	// ScopeParent: rows have no organization column; they are reachable only
	// through a foreign key to a parent table that is itself scoped.
	ScopeParent
)

// Scope is one reviewed, closed scope rule. It is metadata for the reader,
// not SQL: a reader must use exactly this column or parent and nothing else.
type Scope struct {
	Kind   ScopeKind
	Column string // org column (ScopeColumn), id column (ScopeSelf), FK column (ScopeParent)
	Parent string // parent table (ScopeParent only)
	// ParentKey is the parent column the foreign key references (ScopeParent only).
	ParentKey string
}

var scopes = map[string]Scope{
	"organizations":                 {ScopeSelf, "id", "", ""},
	"users":                         {ScopeColumn, "org_id", "", ""},
	"agents":                        {ScopeColumn, "org_id", "", ""},
	"services":                      {ScopeColumn, "org_id", "", ""},
	"memberships":                   {ScopeColumn, "org_id", "", ""},
	"agent_grants":                  {ScopeColumn, "org_id", "", ""},
	"tokens":                        {ScopeColumn, "org_id", "", ""},
	"workspaces":                    {ScopeColumn, "org_id", "", ""},
	"projects":                      {ScopeColumn, "org_id", "", ""},
	"stores":                        {ScopeColumn, "org_id", "", ""},
	"store_bindings":                {ScopeColumn, "org_id", "", ""},
	"override_locks":                {ScopeColumn, "org_id", "", ""},
	"secrets":                       {ScopeColumn, "org_id", "", ""},
	"secret_versions":               {ScopeColumn, "org_id", "", ""},
	"audit_chain_heads":             {ScopeColumn, "org_id", "", ""},
	"audit_records":                 {ScopeColumn, "org_id", "", ""},
	"keep_kek":                      {ScopeColumn, "org_id", "", ""},
	"keep_envelope":                 {ScopeColumn, "store_org", "", ""},
	"keep_org_key_level":            {ScopeColumn, "org_id", "", ""},
	"org_ca":                        {ScopeColumn, "org_id", "", ""},
	"scoped_transfer_ledger":        {ScopeColumn, "org_id", "", ""},
	"enroll_tokens":                 {ScopeColumn, "org_id", "", ""},
	"runners":                       {ScopeColumn, "org_id", "", ""},
	"intake_links":                  {ScopeColumn, "org_id", "", ""},
	"carriers":                      {ScopeColumn, "org_id", "", ""},
	"deployment_policies":           {ScopeColumn, "org_id", "", ""},
	"deployment_requests":           {ScopeColumn, "org_id", "", ""},
	"approval_requests":             {ScopeColumn, "org_id", "", ""},
	"deployment_jobs":               {ScopeColumn, "org_id", "", ""},
	"console_sessions":              {ScopeColumn, "org_id", "", ""},
	"exec_templates":                {ScopeColumn, "org_id", "", ""},
	"rotation_runs":                 {ScopeColumn, "org_id", "", ""},
	"rotation_steps":                {ScopeParent, "run_id", "rotation_runs", "id"},
	"rotation_secret_epochs":        {ScopeColumn, "org_id", "", ""},
	"carrier_verifications":         {ScopeColumn, "org_id", "", ""},
	"carrier_verification_items":    {ScopeColumn, "org_id", "", ""},
	"rotation_keys":                 {ScopeColumn, "org_id", "", ""},
	"rotation_intents":              {ScopeColumn, "org_id", "", ""},
	"intake_rotation_links":         {ScopeColumn, "org_id", "", ""},
	"mesh_installations":            {ScopeColumn, "org_id", "", ""},
	"mesh_events":                   {ScopeParent, "workspace_id", "mesh_installations", "workspace_id"},
	"mesh_user_links":               {ScopeColumn, "org_id", "", ""},
	"mesh_gate_requests":            {ScopeColumn, "org_id", "", ""},
	"mesh_members":                  {ScopeParent, "workspace_id", "mesh_installations", "workspace_id"},
	"mesh_projects":                 {ScopeParent, "workspace_id", "mesh_installations", "workspace_id"},
	"mesh_agents":                   {ScopeParent, "workspace_id", "mesh_installations", "workspace_id"},
	"mesh_agent_keys":               {ScopeParent, "workspace_id", "mesh_installations", "workspace_id"},
	"mesh_sync_state":               {ScopeParent, "workspace_id", "mesh_installations", "workspace_id"},
	"mesh_secret_nonces":            {ScopeParent, "workspace_id", "mesh_installations", "workspace_id"},
	"mesh_pending_installs":         {ScopeColumn, "org_id", "", ""},
	"mesh_rotator_pending_installs": {ScopeColumn, "org_id", "", ""},
	"mesh_rotator_bindings":         {ScopeColumn, "org_id", "", ""},
	"restart_requests":              {ScopeColumn, "org_id", "", ""},
}

// TableScope returns the scope rule of a registry table.
func TableScope(table string) (Scope, bool) {
	s, ok := scopes[table]
	return s, ok
}
