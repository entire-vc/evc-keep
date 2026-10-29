// Package audit is the R-AUD-1 journal: an append-only, hash-chained record
// of every security-relevant action Keep takes, keyed per organization. See
// the threat model's §4.2 for the normative schema this package implements
// field for field, and doc.go for the canonical-JSON and hash-chain format.
//
// Record is a closed Go struct, not a map or a JSON blob: every field the
// journal will ever store is named here, with its own concrete type. No
// field anywhere in this package's exported types is `any`, a
// `map[string]any` (or any other map with an interface{} element type), or
// `json.RawMessage` — see record_test.go's TestRecordSchemaIsClosed, which
// walks the type tree by reflection and fails if one appears. That is
// deliberate: a schema enforced only by a runtime check after the fact can
// be bypassed by whatever wrote the escape-hatch field; a schema closed at
// the type level cannot be, because there is no field to put an unlisted
// value into in the first place.
package audit

import (
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
)

// ActorType is the closed set of principal kinds the threat model's §4.2
// actor.type may take.
type ActorType string

const (
	ActorAgent   ActorType = "agent"
	ActorUser    ActorType = "user"
	ActorService ActorType = "service"
	ActorRunner  ActorType = "runner"
	ActorSystem  ActorType = "system"
)

// ActorVia is the closed set of entry points a request can arrive through
// (threat model §4.2 actor.via).
type ActorVia string

const (
	ViaAPI        ActorVia = "api"
	ViaCLI        ActorVia = "cli"
	ViaMCP        ActorVia = "mcp"
	ViaMeshPlugin ActorVia = "mesh-plugin"
	ViaConsole    ActorVia = "console"
)

// PolicyDecision is the closed set of outcomes a policy check can reach
// (threat model §4.2 policy.decision).
type PolicyDecision string

const (
	DecisionAllow            PolicyDecision = "allow"
	DecisionDeny             PolicyDecision = "deny"
	DecisionApprovalRequired PolicyDecision = "approval_required"
)

// ResultStatus is the closed set of outcomes an audited action can reach
// (threat model §4.2 result.status).
type ResultStatus string

const (
	StatusOK      ResultStatus = "ok"
	StatusFailed  ResultStatus = "failed"
	StatusPending ResultStatus = "pending"
)

// HealthStatus is the closed set of carrier-healthcheck outcomes (threat
// model §4.2 result.health).
type HealthStatus string

const (
	HealthOK      HealthStatus = "ok"
	HealthFailed  HealthStatus = "failed"
	HealthSkipped HealthStatus = "skipped"
	// HealthUnset means "not applicable to this action" (most actions never
	// run a carrier healthcheck at all) — distinct from HealthSkipped, which
	// means a healthcheck was scheduled and explicitly not run.
	HealthUnset HealthStatus = ""
)

// ErrorClass is the closed taxonomy result.error_class draws from — see the
// threat model's §4.2: a value drawn from a closed enumeration, never
// arbitrary text. It is deliberately small and provider/OS-agnostic; a provider's
// own error text never reaches this field (threat model §4.4) — only which
// of these buckets it falls into.
type ErrorClass string

const (
	// ErrClassNone is the zero value: the action did not fail.
	ErrClassNone             ErrorClass = ""
	ErrClassInvalidArgument  ErrorClass = "invalid_argument"
	ErrClassNotFound         ErrorClass = "not_found"
	ErrClassPermissionDenied ErrorClass = "permission_denied"
	ErrClassPolicyDenied     ErrorClass = "policy_denied"
	ErrClassProviderError    ErrorClass = "provider_error"
	ErrClassTargetError      ErrorClass = "target_error"
	ErrClassInternal         ErrorClass = "internal"
)

// Action is the audited action's own name (threat model §4.2 action). It is
// a closed set: the constants below are the registry, and Record.validate and
// the migration's audit_records_action_closed CHECK both refuse any other
// value. That matters beyond tidiness — Action is the one record field the
// service log line carries (see WithLogger), so a free-form name would be a
// free-form string in the log; a shape check is not enough, a 64-character
// lower-case hex string is a well-formed name and the encoding of a 28-byte
// value.
//
// A new action is added in one change with its constant, its entry in
// registeredActions, and a migration that replaces the CHECK list;
// TestActionRegistryMatchesMigrationCheck fails if the two lists differ. The
// threat model's §4.2 also names families (secret.rotate.*, carrier.*,
// policy.*, approval.*): a family is not itself an action, and its members
// are registered by the change that introduces the component emitting them.
type Action string

const ActionDeployResult Action = "deploy.result"

// ActionSecretRotate records a two-phase rotation: the request (pending, or
// approval_required while a human decides) and its outcome. Names, version,
// fingerprint, length and a closed error class only.
const ActionSecretRotate Action = "secret.rotate"

// ActionCarrierVerify records a carrier verification: the request that fans
// out into per-carrier jobs, and each runner's report. Metadata only.
const ActionCarrierVerify Action = "carrier.verify"

// The approval.* actions record a human confirmation of a deployment request:
// the request is raised, then decided.
const (
	ActionApprovalRequested Action = "approval.requested"
	ActionApprovalDecided   Action = "approval.decided"
)

const (
	ActionSecretCreateRef      Action = "secret.create_ref"
	ActionSecretInput          Action = "secret.input"
	ActionSecretDeploy         Action = "secret.deploy"
	ActionDeployRequested      Action = "deploy.requested"
	ActionDeployPolicyDecision Action = "deploy.policy_decision"
	ActionSecretDisable        Action = "secret.disable"
	ActionRunnerEnroll         Action = "runner.enroll"
	ActionRunnerRevoke         Action = "runner.revoke"
	ActionRunnerRenew          Action = "runner.renew"
	// ActionRunnerEnrollTokenIssue is the admin-side half of runner
	// registration: an enrollment token issued (internal/enrolltoken), as
	// distinct from ActionRunnerEnroll, its later redemption by a runner.
	ActionRunnerEnrollTokenIssue Action = "runner.enroll_token_issue"
	ActionExecRun                Action = "exec.run"
	// The org.key_level.* actions are the outcomes of a key-level change
	// (internal/builtin/sealer): applied, refused because it would weaken
	// the level without confirmation, and failed part-way through.
	ActionOrgKeyLevelRequested    Action = "org.key_level.requested"
	ActionOrgKeyLevelChanged      Action = "org.key_level.changed"
	ActionOrgKeyLevelChangeDenied Action = "org.key_level.change_denied"
	ActionOrgKeyLevelChangeFailed Action = "org.key_level.change_failed"
	ActionKEKPurge                Action = "kek.purge"
	// ActionTokenIssue and ActionTokenRevoke cover internal/api's token
	// issuance/revocation routes — minting or revoking a credential is
	// exactly the kind of security-relevant action R-AUD-1 exists to record.
	ActionIntakeIssued    Action = "intake.link_issued"
	ActionIntakeCompleted Action = "intake.completed"
	ActionIntakeExpired   Action = "intake.expired"
	ActionTokenIssue      Action = "identity.token_issue"
	ActionTokenRevoke     Action = "identity.token_revoke"
	// ActionMeshInstall is the admin connecting a Mesh workspace to Keep
	// (POST /mesh/install).
	ActionMeshInstall Action = "mesh.install"
	// ActionMeshInstallPending is the admin opening the window in which Mesh's
	// own install handshake may bind a workspace (POST
	// /orgs/{org}/mesh/pending-installs).
	ActionMeshInstallPending Action = "mesh.install.pending"
	// ActionMeshSecretPut and ActionMeshSecretResolve are a Mesh workspace
	// writing and reading a value of its own namespace (PUT and POST
	// .../resolve under /orgs/{org}/mesh/secrets/{ref}).
	ActionMeshSecretPut     Action = "mesh.secret.put"
	ActionMeshSecretResolve Action = "mesh.secret.resolve" // #nosec G101 -- action name, not a value
	// ActionMeshToken is Mesh delivering the extension actor token of a
	// connected workspace (POST /mesh/token).
	ActionMeshToken Action = "mesh.token"
	// ActionOrgBootstrap is keep-server bootstrap-org: an organization, its
	// CA and its first admin created by the operator on the host.
	ActionOrgBootstrap Action = "org.bootstrap"
	// ActionStoreBindDefault is keep-server bind-default-store: the builtin
	// store "default" bound at the organization scope of an existing
	// organization.
	ActionStoreBindDefault Action = "store.bind_default"
	// ActionDeployPolicySet is keep-server set-deploy-policy: an
	// organization's deployment policy replaced by the operator on the host.
	// The reason carries revisions, limits and rule keys, never a value.
	ActionDeployPolicySet Action = "deploy.policy_set"
)

// registeredActions lists every constant above; Known reads it.
var registeredActions = []Action{
	ActionDeployResult, ActionCarrierVerify, ActionSecretRotate,
	ActionApprovalRequested, ActionApprovalDecided,
	ActionIntakeIssued, ActionIntakeCompleted, ActionIntakeExpired,
	ActionSecretCreateRef,
	ActionSecretInput,
	ActionSecretDeploy,
	ActionDeployRequested,
	ActionDeployPolicyDecision,
	ActionSecretDisable,
	ActionRunnerEnroll,
	ActionRunnerRevoke,
	ActionRunnerRenew,
	ActionRunnerEnrollTokenIssue,
	ActionExecRun,
	ActionOrgKeyLevelRequested,
	ActionOrgKeyLevelChanged,
	ActionOrgKeyLevelChangeDenied,
	ActionOrgKeyLevelChangeFailed,
	ActionKEKPurge,
	ActionTokenIssue,
	ActionTokenRevoke,
	ActionMeshInstall,
	ActionMeshInstallPending,
	ActionMeshSecretPut,
	ActionMeshSecretResolve,
	ActionMeshToken,
	ActionOrgBootstrap,
	ActionStoreBindDefault,
	ActionDeployPolicySet,
}

// Known reports whether a is in the registry.
func (a Action) Known() bool {
	for _, k := range registeredActions {
		if a == k {
			return true
		}
	}
	return false
}

// Actor identifies who (or what) performed the audited action, and how
// they reached Keep. SponsorID is set only when Type is ActorAgent — it is
// the sponsoring user's id (threat model §4: an agent acts on its
// sponsor's behalf) and is empty for every other actor type.
type Actor struct {
	Type      ActorType `json:"type"`
	ID        string    `json:"id"`
	SponsorID string    `json:"sponsor_id"`
	Via       ActorVia  `json:"via"`
}

// Intent carries the caller-supplied context for why an action happened.
// Reason is free text but bounded — see NewReason.
type Intent struct {
	TaskRef    string `json:"task_ref"`
	SessionRef string `json:"session_ref"`
	Reason     string `json:"reason"`
}

// maxReasonRunes is the threat model's §4.2 bound on intent.reason: at
// most 200 runes.
const maxReasonRunes = 200

// NewReason truncates s to at most maxReasonRunes runes, so a caller can
// pass arbitrary free text without hand-rolling the truncation the schema
// requires. Truncation is by rune, not by byte, so it never splits a
// multi-byte UTF-8 character.
func NewReason(s string) string {
	r := []rune(s)
	if len(r) <= maxReasonRunes {
		return s
	}
	return string(r[:maxReasonRunes])
}

// SecretRef identifies the secret an action concerns, by reference only —
// never a value. Zero value (all fields empty) means the action was not
// about any particular secret (e.g. "runner.enroll").
type SecretRef struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Target identifies where a secret was deployed or a command ran (threat
// model §4.2 target). Zero value means the action had no target.
type Target struct {
	RunnerID string `json:"runner_id"`
	Host     string `json:"host"`
	Kind     string `json:"kind"`
	Path     string `json:"path"`
}

// Policy carries the policy decision an action was evaluated against (threat
// model §4.2 policy). Zero value means no policy check applied.
type Policy struct {
	Decision PolicyDecision `json:"decision"`
	RuleID   string         `json:"rule_id"`
}

// Approval carries the human approval an action required, if any (threat
// model §4.2 approval). Zero value (including a zero DecidedAt) means no
// approval was involved.
type Approval struct {
	ID         string    `json:"id"`
	ApproverID string    `json:"approver_id"`
	DecidedAt  time.Time `json:"decided_at"`
}

// Result carries the outcome of the audited action (threat model §4.2
// result). Fingerprint is a fingerprint string (pkg/fingerprint's "kfp1:…"
// form) — never a value or a key — and Length is the value's byte length,
// both already-safe-to-log metadata per the threat model's §4.1.
type Result struct {
	Status      ResultStatus `json:"status"`
	Fingerprint string       `json:"fingerprint"`
	Length      int          `json:"length"`
	Health      HealthStatus `json:"health"`
	ErrorClass  ErrorClass   `json:"error_class"`
}

// Record is one R-AUD-1 journal entry — the threat model's §4.2 schema,
// field for field. See the package doc for why every field here is a named,
// concrete type and never `any`, a `map[string]any`, or `json.RawMessage`.
//
// A caller building a Record for [Journaler.Append] leaves ID, TS, and
// PrevHash at their zero values: Append fills all three itself (a fresh
// ULID, the current time, and the organization's current chain head) and
// ignores whatever a caller supplies for them — see journal.go. They are
// still fields of Record, rather than a separate output-only type, because
// they are part of the stored and returned record the threat model
// specifies; only their *origin* (server-computed, not caller-supplied) is
// restricted.
type Record struct {
	ID        string    `json:"id"`
	TS        time.Time `json:"ts"`
	RequestID string    `json:"request_id"`
	OrgID     string    `json:"org_id"`
	Scope     string    `json:"scope"`
	Actor     Actor     `json:"actor"`
	Intent    Intent    `json:"intent"`
	Action    Action    `json:"action"`
	Secret    SecretRef `json:"secret"`
	Target    Target    `json:"target"`
	Policy    Policy    `json:"policy"`
	Approval  Approval  `json:"approval"`
	Result    Result    `json:"result"`
	PrevHash  string    `json:"prev_hash"`
}

// errInvalidRecord is what validate wraps. The messages name the offending
// FIELD, never its value: a value that failed validation is by definition
// not one of the known-safe shapes, so it must not travel into an error.
var errInvalidRecord = errors.New("audit: invalid record")

func invalidField(field string) error {
	return fmt.Errorf("%w: field %s is not in its closed set or shape", errInvalidRecord, field)
}

// validate enforces at runtime what the Go types alone cannot: the named
// string types of the closed enumerations accept any text (a caller can
// convert an arbitrary string to ErrorClass), so every closed field is
// checked against its set here, before anything is hashed or stored. The
// migration's CHECK constraints repeat these rules as a second barrier.
func (r Record) validate() error {
	switch r.Actor.Type {
	case ActorAgent, ActorUser, ActorService, ActorRunner, ActorSystem:
	default:
		return invalidField("actor.type")
	}
	switch r.Actor.Via {
	case ViaAPI, ViaCLI, ViaMCP, ViaMeshPlugin, ViaConsole, "":
	default:
		return invalidField("actor.via")
	}
	switch r.Policy.Decision {
	case DecisionAllow, DecisionDeny, DecisionApprovalRequired, "":
	default:
		return invalidField("policy.decision")
	}
	switch r.Result.Status {
	case StatusOK, StatusFailed, StatusPending:
	default:
		return invalidField("result.status")
	}
	switch r.Result.Health {
	case HealthOK, HealthFailed, HealthSkipped, HealthUnset:
	default:
		return invalidField("result.health")
	}
	switch r.Result.ErrorClass {
	case ErrClassNone, ErrClassInvalidArgument, ErrClassNotFound, ErrClassPermissionDenied,
		ErrClassPolicyDenied, ErrClassProviderError, ErrClassTargetError, ErrClassInternal:
	default:
		return invalidField("result.error_class")
	}
	if r.Result.Fingerprint != "" && !fingerprint.Valid(r.Result.Fingerprint) {
		return invalidField("result.fingerprint")
	}
	if r.Result.Length < 0 {
		return invalidField("result.length")
	}
	if r.RequestID != "" && !reqid.Valid(r.RequestID) {
		return invalidField("request_id")
	}
	if utf8.RuneCountInString(r.Intent.Reason) > maxReasonRunes {
		return invalidField("intent.reason")
	}
	if !r.Action.Known() {
		return invalidField("action")
	}
	// Free text must be valid UTF-8: Postgres refuses anything else, and its
	// own error message echoes the offending byte. The error names the field
	// only, and never the text.
	for _, f := range []struct{ name, val string }{
		{"org_id", r.OrgID},
		{"scope", r.Scope},
		{"actor.id", r.Actor.ID},
		{"actor.sponsor_id", r.Actor.SponsorID},
		{"intent.task_ref", r.Intent.TaskRef},
		{"intent.session_ref", r.Intent.SessionRef},
		{"intent.reason", r.Intent.Reason},
		{"secret.id", r.Secret.ID},
		{"secret.name", r.Secret.Name},
		{"secret.version", r.Secret.Version},
		{"target.runner_id", r.Target.RunnerID},
		{"target.host", r.Target.Host},
		{"target.kind", r.Target.Kind},
		{"target.path", r.Target.Path},
		{"policy.rule_id", r.Policy.RuleID},
		{"approval.id", r.Approval.ID},
		{"approval.approver_id", r.Approval.ApproverID},
	} {
		if !utf8.ValidString(f.val) {
			return invalidField(f.name)
		}
	}
	return nil
}
