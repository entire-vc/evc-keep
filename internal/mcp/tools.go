package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

const (
	defaultWait = 30
	maxWait     = 120
)

// pollEvery is how often deploy asks for the runner's result.
var pollEvery = time.Second

var (
	fingerprintShape = regexp.MustCompile(`^kfp1:[a-z0-9]{1,16}:[a-z2-7]{16}$`)
	scopeLevel       = map[string]bool{"user": true, "proj": true, "ws": true, "org": true}
)

type toolbox struct{ b *backend }

func newToolbox(b *backend) *toolbox { return &toolbox{b: b} }

type tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations map[string]any `json:"annotations,omitempty"`
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }

func schema(required []string, props map[string]any) map[string]any {
	s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func (t *toolbox) list() []tool {
	readOnly := map[string]any{"readOnlyHint": true}
	return []tool{
		{Name: "list_secrets", Description: "List the secrets defined at one scope: names, versions' owners and locators, never values.",
			InputSchema: schema([]string{"scope_level", "scope_id"}, map[string]any{
				"scope_level": map[string]any{"type": "string", "enum": []string{"user", "proj", "ws", "org"}},
				"scope_id":    str("scope id")}), Annotations: readOnly},
		{Name: "get_secret_meta", Description: "Metadata of one secret and its versions: version, fingerprint, length, status. Never the value.",
			InputSchema: schema([]string{"secret_id"}, map[string]any{"secret_id": str("secret id")}), Annotations: readOnly},
		{Name: "request_secret_input", Description: "Issue a one-time link for a human to enter the value in a browser. The value never passes through this tool or the agent.",
			InputSchema: schema([]string{"secret"}, map[string]any{
				"secret": str("secret name"), "ttl": str("link lifetime, e.g. 30m, at most 24h"),
				"workspace_id": str("workspace context"), "project_id": str("project context")})},
		{Name: "deploy", Description: "Ask a runner to lay the secret into a target on its host. Returns the result, a pending state, or an approval link for a human.",
			InputSchema: schema([]string{"secret", "runner_id", "target"}, map[string]any{
				"secret": str("secret name"), "runner_id": str("runner id"),
				"target": schema([]string{"path", "uid", "gid"}, map[string]any{
					"kind": str("target kind, default env-file"), "path": str("path on the runner host"), "field": str("variable or key inside the target"),
					"unit": str("launchd label or systemd unit"), "consumer": str("service to restart: launchd:<label> or systemd:<unit>"),
					"mode": str("file permission bits, octal, default 0600"),
					"uid":  map[string]any{"type": "integer", "minimum": 0}, "gid": map[string]any{"type": "integer", "minimum": 0}}),
				"workspace_id": str("workspace context"), "project_id": str("project context"),
				"request_id":   str("idempotency key; repeat the same value to retry"),
				"wait_seconds": map[string]any{"type": "integer", "minimum": 0, "maximum": maxWait, "description": "how long to wait for the runner, default 30"}})},
		{Name: "register_carrier", Description: "Record where a deployed secret now lives: host, target and consumer. The server accepts it only for a destination it approved and a version it deployed there; no value or fingerprint is passed.",
			InputSchema: schema([]string{"secret_id", "version", "host", "target_kind", "target_path"}, map[string]any{
				"secret_id": str("secret id"), "version": str("version that was deployed"), "host": str("host name of an enrolled runner"),
				"target_kind": str("target kind, e.g. env-file"), "target_path": str("path on that host"), "target_field": str("variable or key inside the target"),
				"consumer": str("service that reads it: launchd:<label> or systemd:<unit>")})},
		{Name: "rotate", Description: "Rotate a secret in two phases: a new version is created on the Keep side, laid out on every registered carrier and activated only when all of them confirm its fingerprint. The agent passes no value. mode generate returns the per-carrier progress; mode human_input returns a one-time link for a human to enter the new value.",
			InputSchema: schema([]string{"secret_id", "mode"}, map[string]any{
				"secret_id":    str("secret id"),
				"mode":         map[string]any{"type": "string", "enum": []string{"generate", "human_input"}},
				"wait_seconds": map[string]any{"type": "integer", "minimum": 0, "maximum": maxWait, "description": "how long to wait for the run, default 30"}})},
		{Name: "verify_carriers", Description: "Ask each runner whether the carriers of a secret still hold its current version. Returns per-carrier status and a fingerprint match, never a value.",
			InputSchema: schema([]string{"secret"}, map[string]any{
				"secret": str("secret name"), "workspace_id": str("workspace context"), "project_id": str("project context"),
				"request_id":   str("idempotency key; repeat the same value to retry"),
				"wait_seconds": map[string]any{"type": "integer", "minimum": 0, "maximum": maxWait, "description": "how long to wait for the runners, default 30"}}), Annotations: readOnly},
	}
}

// call runs one tool. known is false for a name that is not a tool.
func (t *toolbox) call(ctx context.Context, name string, raw json.RawMessage) (res any, known bool) {
	var (
		out any
		err error
	)
	switch name {
	case "list_secrets":
		out, err = t.listSecrets(ctx, raw)
	case "get_secret_meta":
		out, err = t.secretMeta(ctx, raw)
	case "request_secret_input":
		out, err = t.requestInput(ctx, raw)
	case "deploy":
		out, err = t.deploy(ctx, raw)
	case "register_carrier":
		out, err = t.registerCarrier(ctx, raw)
	case "rotate":
		out, err = t.rotate(ctx, raw)
	case "verify_carriers":
		out, err = t.verifyCarriers(ctx, raw)
	default:
		return nil, false
	}
	if err != nil {
		return answer(errorAnswer(err), true), true
	}
	return answer(out, false), true
}

func answer(v any, isError bool) map[string]any {
	b, _ := json.Marshal(v)
	return map[string]any{"content": []map[string]any{{"type": "text", "text": string(b)}}, "isError": isError}
}

// argError is a refused argument. Its text is a fixed template: the offending
// input is never quoted back.
type argError struct{ msg string }

func (e *argError) Error() string { return e.msg }

var errBadArgs = &argError{"arguments are invalid"}

func decodeArgs(raw json.RawMessage, into any) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = json.RawMessage("{}")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(into) != nil || d.More() {
		return errBadArgs
	}
	return nil
}

func validUUID(s string) bool { _, err := uuid.Parse(s); return err == nil }

// canonicalUUID reports whether s is a non-nil UUID in the one form the REST
// layer writes (lowercase, hyphenated): uuid.Parse alone also takes urn:,
// braces and bare hex, which would pass an arbitrary 128 bits through.
func canonicalUUID(s string) bool {
	u, err := uuid.Parse(s)
	return err == nil && u != uuid.Nil && u.String() == s
}

// plain reports whether s is a non-empty text of at most max runes with no
// control characters.
func plain(s string, max int) bool {
	if s == "" || utf8.RuneCountInString(s) > max || !utf8.ValidString(s) {
		return false
	}
	return !strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) })
}

func optional(s string, max int) bool { return s == "" || plain(s, max) }

// decodeStrict reads a REST reply into v and refuses any field v lacks.
func decodeStrict(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return errUnexpectedShape
	}
	// Nothing may follow the one value, not even a stray closing bracket.
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return errUnexpectedShape
	}
	return nil
}

var errUnexpectedShape = errors.New("server answered with an unexpected shape")

// asciiGraphic reports whether s is at most max bytes of printable ASCII
// without blanks: a locator has no room for anything else.
func asciiGraphic(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

var versionStatus = map[string]bool{"current": true, "previous": true, "disabled": true, "erased": true}

// closedSecret reports whether every text in a Secret row has the shape of
// what its field may hold. A reply that fails is refused whole: a value can
// only reach an answer through a string field, so none goes unchecked except
// the description, which is free text by design and only bounded.
func closedSecret(s Secret) bool {
	return provider.ValidRef(s.ProviderRef) && asciiGraphic(s.ProviderRef, 1024) &&
		plain(s.ID, 64) && plain(s.Name, 253) && plain(s.Scope, 128) && plain(s.Class, 64) && plain(s.Type, 64) &&
		plain(s.Store.ID, 64) && plain(s.Store.Name, 253) && plain(s.Store.Provider, 64) &&
		optional(s.CurrentVersion, 128) && optional(s.Owner, 128) && utf8.RuneCountInString(s.Description) <= 4096
}

// closedVersion is the same for a Version row; the fingerprint must be a
// kfp1 digest, the only digest of a value there is.
func closedVersion(v SecretVersion) bool {
	return plain(v.Version, 128) && optional(v.CreatedBy, 128) && fingerprintShape.MatchString(v.Fingerprint) && versionStatus[v.Status] && v.Length >= 0
}

func (t *toolbox) listSecrets(ctx context.Context, raw json.RawMessage) (any, error) {
	var a struct {
		ScopeLevel string `json:"scope_level"`
		ScopeID    string `json:"scope_id"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	if !scopeLevel[a.ScopeLevel] || !validUUID(a.ScopeID) {
		return nil, errBadArgs
	}
	q := url.Values{"scope_level": {a.ScopeLevel}, "scope_id": {a.ScopeID}}
	_, body, err := t.b.do(ctx, http.MethodGet, t.b.orgPath("/secrets?"+q.Encode()), nil)
	if err != nil {
		return nil, err
	}
	out := SecretList{Secrets: []Secret{}}
	if err := decodeStrict(body, &out.Secrets); err != nil {
		return nil, err
	}
	for _, s := range out.Secrets {
		if !closedSecret(s) {
			return nil, errUnexpectedShape
		}
	}
	return out, nil
}

func (t *toolbox) secretMeta(ctx context.Context, raw json.RawMessage) (any, error) {
	var a struct {
		SecretID string `json:"secret_id"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	if !validUUID(a.SecretID) {
		return nil, errBadArgs
	}
	var out SecretMeta
	_, body, err := t.b.do(ctx, http.MethodGet, t.b.orgPath("/secrets/"+a.SecretID), nil)
	if err != nil {
		return nil, err
	}
	if err := decodeStrict(body, &out.Secret); err != nil || !closedSecret(out.Secret) {
		return nil, errUnexpectedShape
	}
	_, body, err = t.b.do(ctx, http.MethodGet, t.b.orgPath("/secrets/"+a.SecretID+"/versions"), nil)
	if err != nil {
		return nil, err
	}
	out.Versions = []SecretVersion{}
	if err := decodeStrict(body, &out.Versions); err != nil {
		return nil, err
	}
	for _, v := range out.Versions {
		if !closedVersion(v) {
			return nil, errUnexpectedShape
		}
	}
	return out, nil
}

func (t *toolbox) requestInput(ctx context.Context, raw json.RawMessage) (any, error) {
	var a struct {
		Secret      string `json:"secret"`
		TTL         string `json:"ttl"`
		WorkspaceID string `json:"workspace_id"`
		ProjectID   string `json:"project_id"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	if !plain(a.Secret, 253) || !optional(a.TTL, 16) || !optional(a.WorkspaceID, 64) || !optional(a.ProjectID, 64) {
		return nil, errBadArgs
	}
	if a.TTL != "" {
		if d, err := time.ParseDuration(a.TTL); err != nil || d <= 0 || d > 24*time.Hour {
			return nil, errBadArgs
		}
	}
	status, body, err := t.b.do(ctx, http.MethodPost, "/v1/input-links",
		map[string]string{"secret": a.Secret, "ttl": a.TTL, "workspace_id": a.WorkspaceID, "project_id": a.ProjectID})
	if err != nil {
		return nil, err
	}
	var out InputLink
	if status != http.StatusCreated || decodeStrict(body, &out) != nil || out.URL == "" || out.RequestID == "" || out.ExpiresAt.IsZero() {
		return nil, errUnexpectedShape
	}
	return out, nil
}

func (t *toolbox) registerCarrier(ctx context.Context, raw json.RawMessage) (any, error) {
	var a struct {
		SecretID    string `json:"secret_id"`
		Version     string `json:"version"`
		Host        string `json:"host"`
		TargetKind  string `json:"target_kind"`
		TargetPath  string `json:"target_path"`
		TargetField string `json:"target_field"`
		Consumer    string `json:"consumer"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	if !validUUID(a.SecretID) || !plain(a.Version, 64) || !plain(a.Host, 253) || !plain(a.TargetKind, 32) || !plain(a.TargetPath, 4096) ||
		!optional(a.TargetField, 256) || !optional(a.Consumer, 256) {
		return nil, errBadArgs
	}
	status, body, err := t.b.do(ctx, http.MethodPost, t.b.orgPath("/secrets/"+a.SecretID+"/carriers"), map[string]string{
		"version": a.Version, "host": a.Host, "target_kind": a.TargetKind, "target_path": a.TargetPath,
		"target_field": a.TargetField, "consumer": a.Consumer})
	if err != nil {
		return nil, err
	}
	var out Carrier
	if status != http.StatusCreated || decodeStrict(body, &out) != nil || out.ID == "" || out.SecretID != a.SecretID || out.Status == "" ||
		(out.RunnerID != "" && !canonicalUUID(out.RunnerID)) {
		return nil, errUnexpectedShape
	}
	return out, nil
}

type deployTarget struct {
	Kind     string `json:"kind"`
	Path     string `json:"path"`
	Field    string `json:"field"`
	Unit     string `json:"unit"`
	Consumer string `json:"consumer"`
	Mode     string `json:"mode"`
	UID      *int64 `json:"uid"`
	GID      *int64 `json:"gid"`
}

func (t *toolbox) deploy(ctx context.Context, raw json.RawMessage) (any, error) {
	var a struct {
		Secret      string       `json:"secret"`
		RunnerID    string       `json:"runner_id"`
		Target      deployTarget `json:"target"`
		WorkspaceID string       `json:"workspace_id"`
		ProjectID   string       `json:"project_id"`
		RequestID   string       `json:"request_id"`
		WaitSeconds *int         `json:"wait_seconds"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	tg := a.Target
	wait := defaultWait
	if a.WaitSeconds != nil {
		wait = *a.WaitSeconds
	}
	if !plain(a.Secret, 253) || !validUUID(a.RunnerID) || !plain(tg.Path, 4096) || tg.UID == nil || tg.GID == nil || *tg.UID < 0 || *tg.GID < 0 ||
		!optional(tg.Kind, 32) || !optional(tg.Field, 256) || !optional(tg.Unit, 256) || !optional(tg.Consumer, 256) || !optional(tg.Mode, 8) ||
		!optional(a.WorkspaceID, 64) || !optional(a.ProjectID, 64) || (a.RequestID != "" && !reqid.Valid(a.RequestID)) || wait < 0 || wait > maxWait {
		return nil, errBadArgs
	}
	if tg.Kind == "" {
		tg.Kind = "env-file"
	}
	if tg.Mode == "" {
		tg.Mode = "0600"
	}
	status, body, err := t.b.do(ctx, http.MethodPost, "/v1/deployments", map[string]any{
		"secret": a.Secret, "runner_id": a.RunnerID, "workspace_id": a.WorkspaceID, "project_id": a.ProjectID,
		"request_id": a.RequestID, "target": tg})
	if err != nil {
		return nil, err
	}
	res, err := decodeDeploy(body)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	for status == http.StatusAccepted && res.Approval == nil && time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pollEvery):
		}
		status, body, err = t.b.do(ctx, http.MethodGet, "/v1/deployments/"+url.PathEscape(res.RequestID), nil)
		if err != nil {
			return nil, err
		}
		if res, err = decodeDeploy(body); err != nil {
			return nil, err
		}
	}
	return res, nil
}

var carrierStatus = map[string]bool{"pending": true, "match": true, "mismatch": true, "unreachable": true, "failed": true}

// maxCarrierRows bounds one verification, as the server does.
const maxCarrierRows = 100

// verifyCarriers is a thin wrapper over POST/GET /v1/carriers/verify: it adds
// no decision of its own, only the argument checks and a bounded wait.
func (t *toolbox) verifyCarriers(ctx context.Context, raw json.RawMessage) (any, error) {
	var a struct {
		Secret      string `json:"secret"`
		WorkspaceID string `json:"workspace_id"`
		ProjectID   string `json:"project_id"`
		RequestID   string `json:"request_id"`
		WaitSeconds *int   `json:"wait_seconds"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	wait := defaultWait
	if a.WaitSeconds != nil {
		wait = *a.WaitSeconds
	}
	if !plain(a.Secret, 253) || !optional(a.WorkspaceID, 64) || !optional(a.ProjectID, 64) ||
		(a.RequestID != "" && !reqid.Valid(a.RequestID)) || wait < 0 || wait > maxWait {
		return nil, errBadArgs
	}
	status, body, err := t.b.do(ctx, http.MethodPost, "/v1/carriers/verify", map[string]string{
		"secret": a.Secret, "workspace_id": a.WorkspaceID, "project_id": a.ProjectID, "request_id": a.RequestID})
	if err != nil {
		return nil, err
	}
	res, err := decodeCarrierVerify(body)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	for status == http.StatusAccepted && time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pollEvery):
		}
		status, body, err = t.b.do(ctx, http.MethodGet, "/v1/carriers/verify/"+url.PathEscape(res.RequestID), nil)
		if err != nil {
			return nil, err
		}
		if res, err = decodeCarrierVerify(body); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// decodeCarrierVerify reads a verification into its closed object. A reply
// with a field outside the list, a status outside the closed set or a text of
// the wrong shape is refused whole.
func decodeCarrierVerify(body []byte) (CarrierVerifyResult, error) {
	var r CarrierVerifyResult
	if decodeStrict(body, &r) != nil || !reqid.Valid(r.RequestID) || r.Carriers == nil || len(r.Carriers) > maxCarrierRows {
		return CarrierVerifyResult{}, errUnexpectedShape
	}
	if (r.Fingerprint != "" && !fingerprintShape.MatchString(r.Fingerprint)) || !optional(r.Version, 128) {
		return CarrierVerifyResult{}, errUnexpectedShape
	}
	for _, c := range r.Carriers {
		if !validUUID(c.ID) || (c.RunnerID != "" && !validUUID(c.RunnerID)) || !plain(c.Host, 253) ||
			!plain(c.Target.Kind, 32) || !plain(c.Target.Path, 4096) || !carrierStatus[c.Status] ||
			(c.ErrorClass != "" && !runnerproto.ErrorClass(c.ErrorClass).Valid()) {
			return CarrierVerifyResult{}, errUnexpectedShape
		}
	}
	return r, nil
}

var (
	rotatePhase = map[string]bool{"deploy": true, "verify": true}
	rotateState = map[string]bool{"pending": true, "ok": true, "failed": true, "stale": true}
	versionRe   = regexp.MustCompile(`^[1-9][0-9]{0,8}$`)
)

// rotateClasses is the closed list of failure classes a rotation reports.
var rotateClasses = map[string]bool{"no_carriers": true, "deploy_failed": true, "fingerprint_mismatch": true, "unhealthy": true,
	"verify_failed": true, "revoke_failed": true, "prepare_failed": true, "internal_error": true, string(apperr.ClassInternal): true, string(apperr.ClassPermissionDenied): true}

var approvalStatus = map[string]bool{"requested": true, "approved": true, "rejected": true, "expired": true}

func (t *toolbox) rotate(ctx context.Context, raw json.RawMessage) (any, error) {
	var a struct {
		SecretID    string `json:"secret_id"`
		Mode        string `json:"mode"`
		WaitSeconds *int   `json:"wait_seconds"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	wait := defaultWait
	if a.WaitSeconds != nil {
		wait = *a.WaitSeconds
	}
	if !validUUID(a.SecretID) || (a.Mode != "generate" && a.Mode != "human_input") || wait < 0 || wait > maxWait {
		return nil, errBadArgs
	}
	base := t.b.orgPath("/secrets/" + a.SecretID + "/rotate")
	status, body, err := t.b.do(ctx, http.MethodPost, base, map[string]string{"mode": a.Mode})
	if err != nil {
		return nil, err
	}
	if a.Mode == "human_input" {
		var out InputLink
		if status != http.StatusAccepted || decodeStrict(body, &out) != nil || out.URL == "" || out.RequestID == "" || out.ExpiresAt.IsZero() {
			return nil, errUnexpectedShape
		}
		return out, nil
	}
	// The contract: 202 starts a run, the status is 200 or 202. Any other 2xx is
	// not this endpoint's answer.
	if status != http.StatusAccepted {
		return nil, errUnexpectedShape
	}
	res, err := decodeRotate(status, body)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	// A rotation waiting for a human is answered with the approval link at once:
	// polling would only wait for the person.
	for status == http.StatusAccepted && time.Now().Before(deadline) && !waitsForHuman(res) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pollEvery):
		}
		status, body, err = t.b.do(ctx, http.MethodGet, base+"/"+url.PathEscape(res.RequestID), nil)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK && status != http.StatusAccepted {
			return nil, errUnexpectedShape
		}
		if res, err = decodeRotate(status, body); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// decodeRotate reads a rotation answer and refuses it whole unless every text
// has the shape of what its field may hold.
func decodeRotate(status int, body []byte) (RotateResult, error) {
	var r RotateResult
	if decodeStrict(body, &r) != nil || !validUUID(r.RequestID) || len(r.Carriers) > 256 {
		return RotateResult{}, errUnexpectedShape
	}
	if (r.ErrorClass != "" && !rotateClasses[r.ErrorClass]) || (r.Fingerprint != "" && !fingerprintShape.MatchString(r.Fingerprint)) ||
		(r.Version != "" && !versionRe.MatchString(r.Version)) {
		return RotateResult{}, errUnexpectedShape
	}
	// A version is the active one only once the run is done; a class names a failure.
	if (!r.OK && (r.Version != "" || r.Fingerprint != "")) || (r.OK && r.ErrorClass != "") {
		return RotateResult{}, errUnexpectedShape
	}
	// 202 is a run in progress and nothing else; 200 with ok=true is a finished
	// run and names the active version and its fingerprint.
	if (status == http.StatusAccepted && (r.OK || r.ErrorClass != "")) || (status == http.StatusOK && r.OK && (r.Version == "" || r.Fingerprint == "")) {
		return RotateResult{}, errUnexpectedShape
	}
	if a := r.Approval; a != nil && (!validUUID(a.ID) || !approvalStatus[a.Status] || a.URL == "" || len(a.URL) > 512 || strings.ContainsAny(a.URL, " \t\r\n")) {
		return RotateResult{}, errUnexpectedShape
	}
	for _, c := range r.Carriers {
		if !validUUID(c.CarrierID) || !rotatePhase[c.Phase] || !rotateState[c.State] {
			return RotateResult{}, errUnexpectedShape
		}
	}
	return r, nil
}

func waitsForHuman(r RotateResult) bool { return r.Approval != nil && r.Approval.Status == "requested" }

func decodeDeploy(body []byte) (DeployResult, error) {
	var r DeployResult
	if decodeStrict(body, &r) != nil || !reqid.Valid(r.RequestID) {
		return DeployResult{}, errUnexpectedShape
	}
	if r.ErrorClass != "" && knownClass(r.ErrorClass) != r.ErrorClass {
		return DeployResult{}, errUnexpectedShape
	}
	if r.Fingerprint != "" && !fingerprintShape.MatchString(r.Fingerprint) {
		return DeployResult{}, errUnexpectedShape
	}
	return r, nil
}

// errorAnswer turns any failure into the §4.3 Error row. A class the server
// sent is kept only if it has the shape of one; its message is a template
// from our own server, stripped of control characters and cut short.
func errorAnswer(err error) ErrorAnswer {
	var (
		ae *apiError
		ar *argError
		te *transportError
	)
	switch {
	case errors.As(err, &ae):
		class := knownClass(ae.ErrorClass)
		rid := ae.RequestID
		if !reqid.Valid(rid) {
			rid = ""
		}
		return ErrorAnswer{ErrorClass: class, Message: "the server refused the request: " + class, RequestID: rid}
	case errors.As(err, &ar):
		return ErrorAnswer{ErrorClass: string(apperr.ClassInvalidArgument), Message: ar.msg}
	case errors.As(err, &te):
		return ErrorAnswer{ErrorClass: string(apperr.ClassNotReady), Message: te.kind}
	case errors.Is(err, errUnexpectedShape):
		return ErrorAnswer{ErrorClass: string(apperr.ClassInternal), Message: errUnexpectedShape.Error()}
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded), errors.Is(err, io.ErrClosedPipe):
		return ErrorAnswer{ErrorClass: string(apperr.ClassNotReady), Message: "request cancelled"}
	}
	return ErrorAnswer{ErrorClass: string(apperr.ClassInternal), Message: "internal error"}
}

// knownClass keeps a class the server sent only if our own closed list has
// it; any other string is a stranger's text and becomes "internal".
func knownClass(c string) string {
	for _, k := range apperr.Classes() {
		if string(k) == c {
			return c
		}
	}
	return string(apperr.ClassInternal)
}
