package api

import (
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/tenancy"
)

// StoreRef is the "store" sub-object of a Secret response — threat model
// §4.3's Secret row, "store{id,name,provider}".
type StoreRef struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Provider string `json:"provider"`
}

// Secret is the wire shape of one catalog entry — a subset of the threat
// model's §4.3 closed field list for Secret (id, name, scope, class, type,
// description, store{id,name,provider}, provider_ref, current_version,
// created_at, updated_at, expires_at, owner). Fields the catalog schema does
// not yet carry (current_version as its own column, expires_at, owner) are
// simply omitted — a strict subset of the closed list is always allowed; it
// is a superset that closedFieldsRegistry's guard test exists to catch.
type Secret struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Scope       string    `json:"scope"`
	Class       string    `json:"class"`
	Type        string    `json:"type"`
	Description string    `json:"description,omitempty"`
	Store       StoreRef  `json:"store"`
	ProviderRef string    `json:"provider_ref"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// newSecret builds a Secret response from a catalog row and the store it
// resolved to. store is looked up separately (Catalog.Store) because
// tenancy.SecretRef only carries the store's id.
func newSecret(s tenancy.SecretRef, store catalog.Store) Secret {
	var desc string
	if s.Description != nil {
		desc = *s.Description
	}
	return Secret{
		ID:          s.ID.String(),
		Name:        s.Name,
		Scope:       s.Scope.String(),
		Class:       s.Class,
		Type:        s.Type,
		Description: desc,
		Store:       StoreRef{ID: store.ID.String(), Name: store.Name, Provider: store.Provider},
		ProviderRef: s.ProviderRef,
		CreatedAt:   s.CreatedAt,
		UpdatedAt:   s.UpdatedAt,
	}
}

// SecretVersion is the wire shape of one secret_versions row — the threat
// model's §4.3 Version row (version, created_at, created_by, fingerprint,
// length, status). created_by is omitted: the schema does not record it
// today.
type SecretVersion struct {
	Version     string    `json:"version"`
	CreatedAt   time.Time `json:"created_at"`
	Fingerprint string    `json:"fingerprint"`
	Length      int       `json:"length"`
	Status      string    `json:"status"`
}

const (
	versionStatusCurrent  = "current"
	versionStatusPrevious = "previous"
	versionStatusDisabled = "disabled"
)

// newSecretVersions converts catalog rows (ordered newest first, see
// [catalog.Catalog.ListVersions]) into their wire shape, computing each
// one's status: the newest non-disabled version is "current", any
// non-disabled version behind it is "previous", and a disabled version is
// always "disabled" regardless of its position.
func newSecretVersions(rows []catalog.SecretVersion) []SecretVersion {
	out := make([]SecretVersion, 0, len(rows))
	seenCurrent := false
	for _, v := range rows {
		status := versionStatusDisabled
		if !v.Disabled {
			if !seenCurrent {
				status = versionStatusCurrent
				seenCurrent = true
			} else {
				status = versionStatusPrevious
			}
		}
		out = append(out, SecretVersion{
			Version:     v.ProviderVersion,
			CreatedAt:   v.CreatedAt,
			Fingerprint: v.Fingerprint,
			Length:      v.Length,
			Status:      status,
		})
	}
	return out
}

// createSecretRequest is the request body for POST /orgs/{org_id}/secrets.
type createSecretRequest struct {
	ScopeLevel  string `json:"scope_level"`
	ScopeID     string `json:"scope_id"`
	Name        string `json:"name"`
	Class       string `json:"class"`
	Type        string `json:"type"`
	ProviderRef string `json:"provider_ref"`
	Description string `json:"description"`
}

// issueTokenRequest is the request body for POST /orgs/{org_id}/tokens. Kind
// is restricted to agent/service by [handleIssueToken] — a request that
// mints a user token is not this route's job.
type issueTokenRequest struct {
	Kind        string     `json:"kind"`
	PrincipalID string     `json:"principal_id"`
	Scope       string     `json:"scope"`
	ExpiresAt   *time.Time `json:"expires_at"`
}

// okResult is the threat model's §4.3 generic action-result row, narrowed to
// what token revocation needs (ok, request_id).
type okResult struct {
	OK        bool   `json:"ok"`
	RequestID string `json:"request_id"`
}

// AuditVerifyResult is the wire shape of GET /orgs/{org_id}/audit/verify —
// the threat model's §4.8/§4.3 audit-verify-result row: a direct
// projection of [audit.VerifyResult], no renaming and nothing added.
// BrokenID, BrokenPosition and BreakKind are omitted from the wire on a
// clean chain (Go's zero values for all three), matching §4.8's own
// worked example.
//
// BrokenID is carried through exactly as [audit.Verify] returns it —
// already sanitized to a ULID or the fixed "(malformed id)" placeholder by
// audit's own safeRecordID (see audit/verify.go's doc) — and must never be
// sanitized again here: a second, different sanitizer would be a second
// place to keep in sync with audit's closed shape, not an added safety
// margin.
type AuditVerifyResult struct {
	OK             bool   `json:"ok"`
	RequestID      string `json:"request_id"`
	Checked        int64  `json:"checked"`
	BrokenID       string `json:"broken_id,omitempty"`
	BrokenPosition int64  `json:"broken_position,omitempty"`
	BreakKind      string `json:"break_kind,omitempty"`
}

// newAuditVerifyResult builds the wire response from res — see
// AuditVerifyResult's own doc for why every field is copied verbatim, with
// no added sanitization.
func newAuditVerifyResult(res audit.VerifyResult, requestID string) AuditVerifyResult {
	return AuditVerifyResult{
		OK:             res.OK,
		RequestID:      requestID,
		Checked:        res.Checked,
		BrokenID:       res.BrokenID,
		BrokenPosition: res.BrokenPosition,
		BreakKind:      string(res.BreakKind),
	}
}
