package mcp

import "time"

// The answer types below are the only shapes a tool ever returns. Each one
// is a row of threat model §4.3's closed list; closed_test.go walks them by
// reflection. Replies from the REST API are decoded into them with unknown
// fields refused, so a field outside the list cannot pass through.

// StoreRef is Secret.store{id,name,provider}.
type StoreRef struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Provider string `json:"provider"`
}

// Secret is the §4.3 Secret row.
type Secret struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	Scope          string     `json:"scope"`
	Class          string     `json:"class"`
	Type           string     `json:"type"`
	Description    string     `json:"description,omitempty"`
	Store          StoreRef   `json:"store"`
	ProviderRef    string     `json:"provider_ref"`
	CurrentVersion string     `json:"current_version,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	Owner          string     `json:"owner,omitempty"`
}

// SecretVersion is the §4.3 Version row.
type SecretVersion struct {
	Version     string    `json:"version"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by,omitempty"`
	Fingerprint string    `json:"fingerprint"`
	Length      int       `json:"length"`
	Status      string    `json:"status"`
}

// SecretList is the answer of list_secrets.
type SecretList struct {
	Secrets []Secret `json:"secrets"`
}

// SecretMeta is the answer of get_secret_meta: the Secret row and its versions.
type SecretMeta struct {
	Secret   Secret          `json:"secret"`
	Versions []SecretVersion `json:"versions"`
}

// InputLink is the §4.3 input link row.
type InputLink struct {
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
	RequestID string    `json:"request_id"`
}

// DeployHealth is DeployResult.healthcheck.
type DeployHealth struct {
	Status    string    `json:"status"`
	CheckedAt time.Time `json:"checked_at"`
}

// DeployApproval is DeployResult.approval.
type DeployApproval struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	URL    string `json:"url"`
}

// DeployResult is the §4.3 deploy/rotate/verify result row. ok=false with
// neither error_class nor approval means the runner has not answered yet.
type DeployResult struct {
	OK          bool            `json:"ok"`
	RequestID   string          `json:"request_id"`
	Fingerprint string          `json:"fingerprint,omitempty"`
	Version     string          `json:"version,omitempty"`
	Healthcheck *DeployHealth   `json:"healthcheck,omitempty"`
	ErrorClass  string          `json:"error_class,omitempty"`
	Approval    *DeployApproval `json:"approval,omitempty"`
}

// CarrierTarget is Carrier.target{kind,path}.
type CarrierTarget struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
}

// Carrier is the §4.3 Carrier row: where a secret is laid, never what it is.
type Carrier struct {
	ID               string        `json:"id"`
	SecretID         string        `json:"secret_id"`
	Host             string        `json:"host"`
	RunnerID         string        `json:"runner_id,omitempty"`
	Target           CarrierTarget `json:"target"`
	Consumer         string        `json:"consumer,omitempty"`
	Healthcheck      string        `json:"healthcheck,omitempty"`
	Status           string        `json:"status"`
	LastVerifiedAt   *time.Time    `json:"last_verified_at,omitempty"`
	FingerprintMatch bool          `json:"fingerprint_match"`
}

// RotateCarrier is one carrier's row of a rotation status.
type RotateCarrier struct {
	CarrierID string `json:"carrier_id"`
	Phase     string `json:"phase"`
	State     string `json:"state"`
}

// RotateResult is the §4.3 rotate result row with the per-carrier progress of
// the two-phase run. ok=false with neither error_class nor a version means
// the run has not finished; a failed run carries its class and no version.
type RotateResult struct {
	OK          bool            `json:"ok"`
	RequestID   string          `json:"request_id"`
	Fingerprint string          `json:"fingerprint,omitempty"`
	Version     string          `json:"version,omitempty"`
	ErrorClass  string          `json:"error_class,omitempty"`
	Carriers    []RotateCarrier `json:"carriers,omitempty"`
	Approval    *DeployApproval `json:"approval,omitempty"`
}

// ErrorAnswer is the §4.3 Error row.
type ErrorAnswer struct {
	ErrorClass string `json:"error_class"`
	Message    string `json:"message"`
	RequestID  string `json:"request_id,omitempty"`
}

// CarrierRow is one §4.3 Carrier row of a verification: where the carrier is
// and whether it holds the current version. status is pending, match,
// mismatch, unreachable or failed.
type CarrierRow struct {
	ID               string        `json:"id"`
	Host             string        `json:"host"`
	RunnerID         string        `json:"runner_id,omitempty"`
	Target           CarrierTarget `json:"target"`
	Status           string        `json:"status"`
	LastVerifiedAt   *time.Time    `json:"last_verified_at,omitempty"`
	FingerprintMatch *bool         `json:"fingerprint_match,omitempty"`
	ErrorClass       string        `json:"error_class,omitempty"`
}

// CarrierVerifyResult is the answer of verify_carriers: the verify result row
// with one Carrier row per carrier. ok=false with a pending row means a runner
// has not answered yet.
type CarrierVerifyResult struct {
	OK          bool         `json:"ok"`
	RequestID   string       `json:"request_id"`
	Fingerprint string       `json:"fingerprint,omitempty"`
	Version     string       `json:"version,omitempty"`
	Carriers    []CarrierRow `json:"carriers"`
}
