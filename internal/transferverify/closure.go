// Package transferverify checks, before any effect, that a snapshot read by
// internal/store is exactly one organization's closed state. It sits beside the
// store because it needs the audit chain verifier, and the audit package's
// tests import the store.
package transferverify

import (
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/google/uuid"
)

// ClosureClass names why a snapshot is not a closed copy of one organization.
// It is a closed set; nothing taken from a row ever appears in it.
type ClosureClass string

const (
	// ClosureScope: a row belongs to another organization or the selected
	// organization/workspace/installation singletons do not hold.
	ClosureScope ClosureClass = "scope"
	// ClosureReference: a row refers to a row that is not in the snapshot.
	ClosureReference ClosureClass = "reference"
	// ClosureChain: the audit chain or its head does not verify.
	ClosureChain ClosureClass = "audit_chain"
	// ClosureShape: a value is outside what the target schema can hold.
	ClosureShape ClosureClass = "shape"
)

// ClosureError is the only error [Closure] returns.
type ClosureError struct{ Class ClosureClass }

func (e ClosureError) Error() string {
	return "store: transfer snapshot is not closed: " + string(e.Class)
}

// Closure checks, before any effect, that the rows are exactly one
// organization's closed state: every row is the organization's, every
// reference is satisfied inside the snapshot, and the audit chain and head
// verify. The database enforces most references again at insert; this check
// exists so a bad snapshot is refused before a target transaction opens.
func Closure(r *store.TransferRows, org uuid.UUID) error {
	scope := func() error { return ClosureError{ClosureScope} }
	ref := func() error { return ClosureError{ClosureReference} }
	o := org.String()

	// Profile 1 has exactly one tenancy workspace; profile 2 (native Mesh
	// store mode) has none and no project, which needs one. Anything else is
	// not a closed organization of either profile.
	if len(r.Organizations) != 1 || r.Organizations[0].ID != org || len(r.Workspaces) > 1 ||
		(len(r.Workspaces) == 0 && len(r.Projects) != 0) ||
		len(r.MeshInstallations) != 1 || len(r.OrgCAs) > 1 || len(r.OrgKeyLevels) > 1 ||
		len(r.AuditChainHeads) > 1 {
		return scope()
	}
	mws := r.MeshInstallations[0].WorkspaceID
	if r.MeshInstallations[0].OrgID != org {
		return scope()
	}

	users := map[uuid.UUID]bool{}
	for _, v := range r.Users {
		if v.OrgID != org {
			return scope()
		}
		users[v.ID] = true
	}
	agents := map[uuid.UUID]bool{}
	for _, v := range r.Agents {
		if v.OrgID != org {
			return scope()
		}
		if !users[v.SponsorUserID] {
			return ref()
		}
		agents[v.ID] = true
	}
	for _, v := range r.Services {
		if v.OrgID != org {
			return scope()
		}
	}
	for _, v := range r.Memberships {
		if v.OrgID != org {
			return scope()
		}
		if !users[v.UserID] {
			return ref()
		}
	}
	for _, v := range r.AgentGrants {
		if v.OrgID != org {
			return scope()
		}
		if !agents[v.AgentID] {
			return ref()
		}
	}
	workspaces := map[uuid.UUID]bool{}
	for _, v := range r.Workspaces {
		if v.OrgID != org {
			return scope()
		}
		workspaces[v.ID] = true
	}
	for _, v := range r.Projects {
		if v.OrgID != org {
			return scope()
		}
		if !workspaces[v.WorkspaceID] {
			return ref()
		}
	}
	stores := map[uuid.UUID]bool{}
	for _, v := range r.Stores {
		if v.OrgID != org {
			return scope()
		}
		stores[v.ID] = true
	}
	for _, v := range r.StoreBindings {
		if v.OrgID != org {
			return scope()
		}
		if !stores[v.StoreID] {
			return ref()
		}
	}
	for _, v := range r.OverrideLocks {
		if v.OrgID != org {
			return scope()
		}
		for _, id := range v.AllowedStoreIds {
			if !stores[id] {
				return ref()
			}
		}
	}
	secrets := map[uuid.UUID]bool{}
	for _, v := range r.Secrets {
		if v.OrgID != org {
			return scope()
		}
		if !stores[v.StoreID] {
			return ref()
		}
		secrets[v.ID] = true
	}
	seals := map[int64]bool{}
	for _, v := range r.SecretVersions {
		if v.OrgID != org {
			return scope()
		}
		if !secrets[v.SecretID] {
			return ref()
		}
		if v.SealSeq <= 0 || seals[v.SealSeq] {
			return ClosureError{ClosureShape}
		}
		seals[v.SealSeq] = true
	}
	for _, v := range r.OrgKeyLevels {
		if v.OrgID != o {
			return scope()
		}
	}
	keks := map[string]bool{}
	// Without a tenancy workspace no workspace or project key domain or
	// envelope scope can name one that is in the snapshot: such a scope would
	// be a dangling AAD reference, so it is refused instead of guessed at.
	noWorkspace := len(r.Workspaces) == 0
	for _, v := range r.KEKs {
		if v.OrgID != o || v.DomainOrg != o {
			return scope()
		}
		if noWorkspace && (v.DomainWorkspace != "" || v.DomainProject != "") {
			return scope()
		}
		keks[v.ID] = true
	}
	for _, v := range r.Envelopes {
		if v.StoreOrg != o {
			return scope()
		}
		if noWorkspace && (v.StoreWorkspace != "" || v.StoreProject != "") {
			return scope()
		}
		if v.KEKID != nil && !keks[*v.KEKID] {
			return ref()
		}
	}
	for _, v := range r.OrgCAs {
		if v.OrgID != org {
			return scope()
		}
		if !keks[v.CAKEKID] || !keks[v.SignKEKID] {
			return ref()
		}
	}
	for _, v := range r.MeshEvents {
		if v.WorkspaceID != mws {
			return scope()
		}
	}
	for _, v := range r.MeshMembers {
		if v.WorkspaceID != mws {
			return scope()
		}
	}
	for _, v := range r.MeshProjects {
		if v.WorkspaceID != mws {
			return scope()
		}
	}
	for _, v := range r.MeshAgents {
		if v.WorkspaceID != mws {
			return scope()
		}
	}
	for _, v := range r.MeshAgentKeys {
		if v.WorkspaceID != mws {
			return scope()
		}
	}
	for _, v := range r.MeshSyncStates {
		if v.WorkspaceID != mws {
			return scope()
		}
	}
	for _, v := range r.MeshSecretNonces {
		if v.WorkspaceID != mws {
			return scope()
		}
	}
	for _, v := range r.MeshUserLinks {
		if v.WorkspaceID != mws || v.OrgID != org {
			return scope()
		}
		if !users[v.UserID] {
			return ref()
		}
	}
	for _, v := range r.MeshRotatorBindings {
		if v.WorkspaceID != mws || v.OrgID != org {
			return scope()
		}
	}
	return verifyAuditChain(r, o)
}

// verifyAuditChain walks the copied audit chain with the journal's own
// recomputation, in memory, before it is written anywhere.
func verifyAuditChain(r *store.TransferRows, org string) error {
	recs := make([]audit.StoredRecord, 0, len(r.AuditRecords))
	for _, a := range r.AuditRecords {
		rec := audit.Record{
			ID: a.ID, TS: a.TS.UTC(), RequestID: a.RequestID, OrgID: a.OrgID, Scope: a.Scope,
			Actor:    audit.Actor{Type: audit.ActorType(a.ActorType), ID: a.ActorID, SponsorID: a.ActorSponsorID, Via: audit.ActorVia(a.ActorVia)},
			Intent:   audit.Intent{TaskRef: a.IntentTaskRef, SessionRef: a.IntentSessionRef, Reason: a.IntentReason},
			Action:   audit.Action(a.Action),
			Secret:   audit.SecretRef{ID: a.SecretID, Name: a.SecretName, Version: a.SecretVersion},
			Target:   audit.Target{RunnerID: a.TargetRunnerID, Host: a.TargetHost, Kind: a.TargetKind, Path: a.TargetPath},
			Policy:   audit.Policy{Decision: audit.PolicyDecision(a.PolicyDecision), RuleID: a.PolicyRuleID},
			Approval: audit.Approval{ID: a.ApprovalID, ApproverID: a.ApprovalApproverID},
			Result: audit.Result{Status: audit.ResultStatus(a.ResultStatus), Fingerprint: a.ResultFingerprint, Length: int(a.ResultLength),
				Health: audit.HealthStatus(a.ResultHealth), ErrorClass: audit.ErrorClass(a.ResultErrorClass)},
			PrevHash: a.PrevHash,
		}
		if a.ApprovalDecidedAt != nil {
			rec.Approval.DecidedAt = a.ApprovalDecidedAt.UTC()
		}
		recs = append(recs, audit.StoredRecord{Record: rec, Seq: a.OrgSeq, Hash: a.Hash})
	}
	var head audit.StoredHead
	if len(r.AuditChainHeads) == 1 {
		h := r.AuditChainHeads[0]
		if h.OrgID != org {
			return ClosureError{ClosureScope}
		}
		head = audit.StoredHead{Present: true, Position: h.Position, Hash: h.Hash}
	}
	res, err := audit.VerifyRows(org, recs, head)
	if err != nil || !res.OK {
		return ClosureError{ClosureChain}
	}
	return nil
}
