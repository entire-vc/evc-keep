// Package deployment owns server-side deployment policy and durable requests.
// It handles authenticated references and metadata, never secret values.
package deployment

import (
	"errors"
	"regexp"
	"strings"

	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

// Decision is a closed policy outcome. Approval never creates a runnable job.
type Decision string

const (
	Allow            Decision = "allow"
	ApprovalRequired Decision = "approval_required"
)

var (
	ErrInvalidArgument = errors.New("deployment: invalid argument")
	ErrPolicyDenied    = errors.New("deployment: policy denied")
)

// Rule admits one secret to a target kind below a directory on selected hosts.
// RunnerID and Labels, when both supplied, must both match.
// An absent SecretID never acts as an organization-wide wildcard.
type Rule struct {
	SecretID   uuid.UUID              `json:"secret_id"`
	RunnerID   string                 `json:"runner_id,omitempty"`
	Labels     map[string]string      `json:"labels,omitempty"`
	Kind       runnerproto.TargetKind `json:"kind"`
	PathPrefix string                 `json:"path_prefix"`
}
type Policy struct {
	Rules []Rule `json:"rules"`
	// ExecRules admit one exec template with one secret on selected hosts
	// without a human, when the template declares network none. Without a
	// matching rule an exec request waits for approval, like a deployment.
	ExecRules []ExecRule `json:"exec_rules,omitempty"`
	// AdoptionRules allow an exact read-only destination, independently of
	// every deployment rule. Production still needs a bound human approval.
	AdoptionRules []AdoptionRule `json:"adoption_rules,omitempty"`
}

// AdoptionRule admits one secret on one enrolled runner and one exact YAML
// field. It never grants a directory, another field, or a write operation.
type AdoptionRule struct {
	SecretID uuid.UUID              `json:"secret_id"`
	RunnerID uuid.UUID              `json:"runner_id"`
	Kind     runnerproto.TargetKind `json:"kind"`
	Path     string                 `json:"path"`
	Field    string                 `json:"field"`
}

// EvaluateAdoption keeps the production host restrictions of deployment.
// Without an exact adoption rule a human must approve this frozen request.
// A human approval is the authorization for that one destination and version;
// an older approval or an ordinary deployment rule cannot authorize it.
func EvaluateAdoption(p Policy, host Host, secretID uuid.UUID, class string, target runnerproto.Target) (Decision, error) {
	if secretID == uuid.Nil || !validPolicy(p) || !validAdoptionTarget(target) {
		return "", ErrInvalidArgument
	}
	if class == "prod" {
		if !host.AttributesKnown || host.UIDShared {
			return "", ErrPolicyDenied
		}
		return ApprovalRequired, nil
	}
	for _, rule := range p.AdoptionRules {
		if rule.SecretID == secretID && rule.RunnerID.String() == host.ID && rule.Kind == target.Kind && rule.Path == target.Path && rule.Field == target.Field {
			return Allow, nil
		}
	}
	return ApprovalRequired, nil
}

func validAdoptionTarget(target runnerproto.Target) bool {
	return target.Kind.SupportsAction(runnerproto.ActionAdopt) && target.Validate() == nil &&
		!networkTarget(target) && target.Consumer == "" && target.Unit == "" &&
		target.Mode == 0o600 && target.UID == 0 && target.GID == 0
}

// ExecRule has the same host selectors as Rule. A network template is never
// admitted by a rule: only a human approves destinations.
type ExecRule struct {
	SecretID   uuid.UUID         `json:"secret_id"`
	TemplateID string            `json:"template_id"`
	RunnerID   string            `json:"runner_id,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// ExecAllowed reports whether an exec rule admits this secret, template and
// host. Labels need known host attributes, as in Evaluate.
func ExecAllowed(p Policy, host Host, secretID uuid.UUID, templateID string) bool {
	if secretID == uuid.Nil || !validPolicy(p) {
		return false
	}
	for _, rule := range p.ExecRules {
		if rule.SecretID != secretID || rule.TemplateID != templateID {
			continue
		}
		if rule.RunnerID != "" && rule.RunnerID != host.ID {
			continue
		}
		if len(rule.Labels) > 0 && !host.AttributesKnown {
			continue
		}
		matched := true
		for k, v := range rule.Labels {
			if host.Labels[k] != v {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

// Host comes from the enrolled runner registry, never from a deployment body.
// Unknown legacy attributes do not authorize label matches or production use.
type Host struct {
	ID              string
	AttributesKnown bool
	UIDShared       bool
	Labels          map[string]string
}

// Evaluate uses the secret ID and class from the org-validated catalog entry.
// registered reports whether this exact production target was approved;
// it is also trusted server state, not a caller-controlled flag.
func Evaluate(p Policy, host Host, secretID uuid.UUID, class string, target runnerproto.Target, registered bool) (Decision, error) {
	if secretID == uuid.Nil || !validPolicy(p) || target.Validate() != nil || networkTarget(target) {
		return "", ErrInvalidArgument
	}
	if class == "prod" && (!host.AttributesKnown || host.UIDShared) {
		return "", ErrPolicyDenied
	}
	if class == "prod" && !registered {
		return ApprovalRequired, nil
	}
	for _, rule := range p.Rules {
		if rule.SecretID != secretID {
			continue
		}
		if rule.Kind != target.Kind || !strings.HasPrefix(target.Path, rule.PathPrefix+"/") {
			continue
		}
		if rule.RunnerID != "" && rule.RunnerID != host.ID {
			continue
		}
		if len(rule.Labels) > 0 && !host.AttributesKnown {
			continue
		}
		matched := true
		for k, v := range rule.Labels {
			if host.Labels[k] != v {
				matched = false
				break
			}
		}
		if matched {
			return Allow, nil
		}
	}
	return ApprovalRequired, nil
}

func networkTarget(target runnerproto.Target) bool {
	// Colons cover schemes, host:port and literal IPv6 addresses, including
	// addresses embedded in otherwise absolute filesystem paths.
	for _, s := range []string{target.Path, target.Field, target.Unit, string(target.Kind)} {
		if strings.Contains(s, ":") {
			return true
		}
	}
	return false
}

func validLabels(labels map[string]string) bool {
	for key, value := range labels {
		switch key {
		case "environment":
			if value != "development" && value != "staging" && value != "production" {
				return false
			}
		case "platform":
			if value != "linux" && value != "darwin" {
				return false
			}
		default:
			return false
		}
	}

	return true
}

func validPolicy(p Policy) bool {
	if len(p.Rules) > 128 {
		return false
	}
	for _, rule := range p.Rules {
		if rule.RunnerID == "" && len(rule.Labels) == 0 {
			return false
		}
		if len(rule.RunnerID) > 64 || runnerproto.ValidatePath(rule.PathPrefix) != nil || strings.Contains(rule.PathPrefix, ":") {
			return false
		}
		known := false
		for _, kind := range runnerproto.TargetKinds {
			if rule.Kind == kind {
				known = true
			}
		}
		if !known {
			return false
		}
		if !validLabels(rule.Labels) {
			return false
		}
	}
	if len(p.ExecRules) > 128 {
		return false
	}
	idRe := regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	for _, rule := range p.ExecRules {
		if rule.SecretID == uuid.Nil || !idRe.MatchString(rule.TemplateID) || len(rule.RunnerID) > 64 ||
			(rule.RunnerID == "" && len(rule.Labels) == 0) || !validLabels(rule.Labels) {
			return false
		}
	}
	if len(p.AdoptionRules) > 128 {
		return false
	}
	seen := make(map[AdoptionRule]bool, len(p.AdoptionRules))
	for _, rule := range p.AdoptionRules {
		target := runnerproto.Target{Kind: rule.Kind, Path: rule.Path, Field: rule.Field, Mode: 0o600}
		if rule.SecretID == uuid.Nil || rule.RunnerID == uuid.Nil || !validAdoptionTarget(target) || seen[rule] {
			return false
		}
		seen[rule] = true
	}
	return true
}
