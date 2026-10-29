package deployment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrRevisionMismatch is a policy replacement whose expected revision is not
// the stored one; nothing is written.
var ErrRevisionMismatch = errors.New("deployment: policy revision changed")

// PolicyError names the first rule a replacement refuses. Its message holds
// field paths and fixed text only, never caller input.
type PolicyError struct{ msg string }

func (e *PolicyError) Error() string        { return e.msg }
func (e *PolicyError) Is(target error) bool { return target == ErrInvalidArgument }

func policyErr(format string, a ...any) error { return &PolicyError{msg: fmt.Sprintf(format, a...)} }

// PolicyChange replaces an organization's deployment policy as a whole.
// MaxPerHour 0 keeps the stored limit (10 for an organization without a
// policy row). ExpectRevision -1 skips the revision check; 0 expects no row.
type PolicyChange struct {
	OrgID          uuid.UUID
	Policy         Policy
	MaxPerHour     int
	ExpectRevision int64
	DryRun         bool
	Actor          audit.Actor
}

// PolicyChangeResult describes the stored (or, on a dry run, the would-be)
// policy and the change against the previous one, by rule key only.
type PolicyChangeResult struct {
	Revision, PrevRevision     int64
	MaxPerHour, PrevMaxPerHour int
	Rules, ExecRules           int
	Added, Removed             []string
}

// DecodePolicy reads one policy object and nothing else: a value that is not
// an object (null would decode to an empty policy), an unknown field or any
// data after the object is refused.
func DecodePolicy(data []byte) (Policy, error) {
	if trimmed := bytes.TrimLeft(data, " \t\r\n"); len(trimmed) == 0 || trimmed[0] != '{' {
		return Policy{}, policyErr("the policy file is not one policy object with known fields only")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return Policy{}, policyErr("the policy file is not one policy object with known fields only")
	}
	var rest json.RawMessage
	if err := dec.Decode(&rest); !errors.Is(err, io.EOF) {
		return Policy{}, policyErr("the policy file has data after the policy object")
	}
	return p, nil
}

// SetPolicy replaces an organization's deployment policy in one transaction
// with its audit record. The organization row is locked first, as Submit
// does, so a policy edit and a deployment decision never interleave.
func (r *Repo) SetPolicy(ctx context.Context, c PolicyChange) (PolicyChangeResult, error) {
	if r == nil || r.pool == nil || r.journal == nil {
		return PolicyChangeResult{}, ErrUnavailable
	}
	if c.OrgID == uuid.Nil || c.Actor.ID == "" || c.MaxPerHour < 0 || c.MaxPerHour > 1000 || c.ExpectRevision < -1 {
		return PolicyChangeResult{}, ErrInvalidArgument
	}
	if c.Policy.Rules == nil {
		c.Policy.Rules = []Rule{}
	}
	if !validPolicy(c.Policy) {
		return PolicyChangeResult{}, policyErr("the policy fails validation (selectors, kinds, path prefixes, labels, template ids or rule count)")
	}
	for i, rule := range c.Policy.Rules {
		if rule.SecretID == uuid.Nil {
			return PolicyChangeResult{}, policyErr("rules[%d].secret_id is missing", i)
		}
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return PolicyChangeResult{}, ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var org uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, c.OrgID).Scan(&org); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return PolicyChangeResult{}, ErrNotFound
		}
		return PolicyChangeResult{}, ErrUnavailable
	}
	if err = checkPolicyRefs(ctx, tx, c.OrgID, c.Policy); err != nil {
		return PolicyChangeResult{}, err
	}
	prev := Policy{Rules: []Rule{}}
	var prevRaw []byte
	res := PolicyChangeResult{PrevMaxPerHour: 10}
	err = tx.QueryRow(ctx, `SELECT rules,max_deploys_per_hour,revision FROM deployment_policies WHERE org_id=$1 FOR UPDATE`, c.OrgID).
		Scan(&prevRaw, &res.PrevMaxPerHour, &res.PrevRevision)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return PolicyChangeResult{}, ErrUnavailable
	case json.Unmarshal(prevRaw, &prev) != nil:
		// A stored policy that no longer parses is replaced; its rules are
		// shown as removed under no key.
		prev = Policy{Rules: []Rule{}}
	}
	if c.ExpectRevision >= 0 && c.ExpectRevision != res.PrevRevision {
		return PolicyChangeResult{}, ErrRevisionMismatch
	}
	res.MaxPerHour = res.PrevMaxPerHour
	if c.MaxPerHour > 0 {
		res.MaxPerHour = c.MaxPerHour
	}
	res.Revision = res.PrevRevision + 1
	res.Rules, res.ExecRules = len(c.Policy.Rules), len(c.Policy.ExecRules)
	res.Added, res.Removed = diffKeys(policyKeys(prev), policyKeys(c.Policy))
	if c.DryRun {
		return res, nil
	}
	raw, err := json.Marshal(c.Policy)
	if err != nil {
		return PolicyChangeResult{}, ErrInvalidArgument
	}
	if _, err = tx.Exec(ctx, `INSERT INTO deployment_policies(org_id,rules,max_deploys_per_hour,revision) VALUES($1,$2,$3,1)
		ON CONFLICT (org_id) DO UPDATE SET rules=EXCLUDED.rules,max_deploys_per_hour=EXCLUDED.max_deploys_per_hour,revision=deployment_policies.revision+1`,
		c.OrgID, raw, res.MaxPerHour); err != nil {
		return PolicyChangeResult{}, ErrUnavailable
	}
	rec, err := r.journal.AppendTx(ctx, tx, audit.Record{
		OrgID:  c.OrgID.String(),
		Scope:  tenancy.Org(c.OrgID).String(),
		Actor:  c.Actor,
		Intent: audit.Intent{Reason: PolicyChangeReason(res)},
		Action: audit.ActionDeployPolicySet,
		Result: audit.Result{Status: audit.StatusOK},
	})
	if err != nil {
		return PolicyChangeResult{}, ErrUnavailable
	}
	if err = tx.Commit(ctx); err != nil {
		return PolicyChangeResult{}, ErrUnavailable
	}
	r.journal.LogCommitted(ctx, rec)
	return res, nil
}

// checkPolicyRefs requires every secret named by a rule to be a catalog
// secret of this organization and every runner named by id to be enrolled in
// it, so a rule cannot point at another tenant's objects.
func checkPolicyRefs(ctx context.Context, tx pgx.Tx, org uuid.UUID, p Policy) error {
	check := func(field string, secretID uuid.UUID, runnerID string) error {
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM secrets WHERE org_id=$1 AND id=$2)`, org, secretID).Scan(&ok); err != nil {
			return ErrUnavailable
		}
		if !ok {
			return policyErr("%s.secret_id is not a secret of this organization", field)
		}
		if runnerID == "" {
			return nil
		}
		id, err := uuid.Parse(runnerID)
		if err != nil {
			return policyErr("%s.runner_id is not a uuid", field)
		}
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM runners WHERE org_id=$1 AND id=$2)`, org, id).Scan(&ok); err != nil {
			return ErrUnavailable
		}
		if !ok {
			return policyErr("%s.runner_id is not a runner of this organization", field)
		}
		return nil
	}
	for i, rule := range p.Rules {
		if err := check(fmt.Sprintf("rules[%d]", i), rule.SecretID, rule.RunnerID); err != nil {
			return err
		}
	}
	for i, rule := range p.ExecRules {
		if err := check(fmt.Sprintf("exec_rules[%d]", i), rule.SecretID, rule.RunnerID); err != nil {
			return err
		}
	}
	return nil
}

// policyKeys names each rule as secret_id/runner_id|labels/kind/path_prefix
// (exec rules: exec:secret_id/runner_id|labels/template_id).
func policyKeys(p Policy) []string {
	keys := make([]string, 0, len(p.Rules)+len(p.ExecRules))
	for _, rule := range p.Rules {
		keys = append(keys, rule.SecretID.String()+"/"+hostKey(rule.RunnerID, rule.Labels)+"/"+string(rule.Kind)+"/"+rule.PathPrefix)
	}
	for _, rule := range p.ExecRules {
		keys = append(keys, "exec:"+rule.SecretID.String()+"/"+hostKey(rule.RunnerID, rule.Labels)+"/"+rule.TemplateID)
	}
	return keys
}

func hostKey(runnerID string, labels map[string]string) string {
	parts := make([]string, 0, len(labels)+1)
	if runnerID != "" {
		parts = append(parts, runnerID)
	}
	names := make([]string, 0, len(labels))
	for k := range labels {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		parts = append(parts, k+"="+labels[k])
	}
	return strings.Join(parts, "|")
}

func diffKeys(prev, next []string) (added, removed []string) {
	in := func(set []string, k string) bool {
		for _, s := range set {
			if s == k {
				return true
			}
		}
		return false
	}
	for _, k := range next {
		if !in(prev, k) && !in(added, k) {
			added = append(added, k)
		}
	}
	for _, k := range prev {
		if !in(next, k) && !in(removed, k) {
			removed = append(removed, k)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// PolicyChangeReason is the journal reason of a policy replacement: revision,
// limit and the rule keys added (+) and removed (-), cut to the reason bound
// with a count of the keys left out.
func PolicyChangeReason(res PolicyChangeResult) string {
	const limit = 200
	head := "revision=" + strconv.FormatInt(res.PrevRevision, 10) + "->" + strconv.FormatInt(res.Revision, 10) +
		" max_per_hour=" + strconv.Itoa(res.PrevMaxPerHour) + "->" + strconv.Itoa(res.MaxPerHour)
	items := make([]string, 0, len(res.Added)+len(res.Removed))
	for _, k := range res.Added {
		items = append(items, " +"+k)
	}
	for _, k := range res.Removed {
		items = append(items, " -"+k)
	}
	out := head
	for i, item := range items {
		more := ""
		if rest := len(items) - i - 1; rest > 0 {
			more = " (+" + strconv.Itoa(rest) + " more)"
		}
		if utf8.RuneCountInString(out+item+more) > limit {
			return out + " (+" + strconv.Itoa(len(items)-i) + " more)"
		}
		out += item
	}
	return out
}
