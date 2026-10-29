package api

import (
	"reflect"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/intake"
)

// This is a closed-field guard: every response type this package puts on
// the wire must carry only json field names from the threat model's §4.3
// closed list — reflection over the Go type, not a hand-maintained
// checklist, so a field added to a struct without also being added to
// §4.3 fails this test rather than shipping silently.
//
// closedFieldsRegistry is the list every exported response type must be
// registered in, in the same change that introduces the type — see the
// keep-api-surface skill. Each entry names the type, the exact set of json
// field names §4.3 allows for that kind of object, and — for a field that
// itself nests another closed object (Secret.Store) — which other entry's
// allowed set governs it.
type closedFieldsEntry struct {
	name    string
	typ     reflect.Type
	allowed map[string]bool
	// nested maps a field's json name to the allowed set that field's own
	// type must be checked against, for a field whose value is itself a
	// closed sub-object (e.g. Secret's "store").
	nested map[string]map[string]bool
}

func fieldSet(names ...string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[n] = true
	}
	return out
}

// storeRefFields is §4.3's Secret row's own store{id,name,provider} shape.
var storeRefFields = fieldSet("id", "name", "provider")

// errorFields is §4.3's Error row.
var errorFields = fieldSet("error_class", "message", "request_id")

// resultFields is §4.3's "deploy/rotate/verify result" row. okResult only
// ever populates ok and request_id — a subset of this row is always allowed,
// see [closedFieldsEntry]'s own doc.
var resultFields = fieldSet("ok", "request_id", "fingerprint", "version", "healthcheck", "error_class", "approval")

// auditVerifyFields is §4.8/§4.3's audit-verify-result row.
var auditVerifyFields = fieldSet("ok", "request_id", "checked", "broken_id", "broken_position", "break_kind")

// tokenIssueFields is identity.IssueResponse's own shape: the one place
// anywhere in Keep a token's plaintext legitimately reaches the wire (see
// that type's doc). "token" is the single, explicitly documented exception
// this guard allows outside §4.3's table — this route's own acceptance
// criterion. The rest of the fields (token_id, last4, kind, scope,
// expires_at, created_at) are ordinary identifiers and metadata, the same
// category of value §4.3 already allows elsewhere (ids, timestamps, a
// closed-enum kind) — flagged in this MR for the threat model doc to fold
// this into its own row, since no existing §4.3 row names a token issuance
// response.
//
// This entry reflects over IssueResponse, not the literal type WireJSON
// puts on the wire (identity's own unexported issueWire) — that type can't
// be named from outside internal/identity, so this walk can't see it
// directly, so a field added only to issueWire would reach the wire
// unchecked here. internal/identity's own
// TestIssueWireFieldsMatchIssueResponse closes that gap at the one place
// that can see both types, pinning issueWire's json fields to
// IssueResponse's — so this entry stays a faithful proxy for the real wire
// shape as long as that test passes.
var tokenIssueFields = fieldSet("token_id", "token", "last4", "kind", "scope", "expires_at", "created_at")

// deployHealthFields and deployApprovalFields are the nested objects of §4.3's
// deploy result row: the consumer state after the job and the approval request
// reference (id, status, where a human decides it).
var (
	deployHealthFields   = fieldSet("status", "checked_at")
	deployApprovalFields = fieldSet("id", "status", "url")
)

// §4.3.2 admits exactly two exceptions for the verify-result row, both bound
// to that schema: a "carriers" list of Carrier rows, and an error_class inside
// a row of that list. A standalone read of Carriers has neither, and no other
// object may take either. verifyResultExceptions names the fields and the one
// registry entry allowed to carry them; TestVerifyResultExceptionsAreBound
// holds every other entry to it.
var (
	carrierFields       = fieldSet("id", "host", "runner_id", "target", "status", "last_verified_at", "fingerprint_match")
	carrierVerifyRow    = fieldSet("id", "host", "runner_id", "target", "status", "last_verified_at", "fingerprint_match", "error_class")
	carrierVerifyFields = fieldSet("ok", "request_id", "fingerprint", "version", "carriers")
	carrierTargetFields = fieldSet("kind", "path")

	verifyResultSchema     = "CarrierVerifyResult"
	verifyRowSchema        = "CarrierVerifyItem"
	rotateResultSchema     = "RotateResult" // §4.3.3: carriers[] of {carrier_id, phase, state}
	verifyResultExceptions = fieldSet("carriers", "error_class")
)

// carrierRowFields is §4.3's Carrier row of the register and list routes.
var carrierRowFields = fieldSet("id", "secret_id", "host", "runner_id", "target", "consumer", "healthcheck", "status", "last_verified_at", "fingerprint_match")

// rotateCarrierFields is one carrier's row of a rotation status.
var rotateCarrierFields = fieldSet("carrier_id", "phase", "state")

var closedFieldsRegistry = []closedFieldsEntry{
	{name: "Carrier", typ: reflect.TypeOf(Carrier{}), allowed: carrierRowFields, nested: map[string]map[string]bool{"target": carrierTargetFields}},
	{
		name:    verifyResultSchema,
		typ:     reflect.TypeOf(CarrierVerifyResult{}),
		allowed: carrierVerifyFields,
		nested:  map[string]map[string]bool{"carriers": carrierVerifyRow},
	},
	{
		name:    verifyRowSchema,
		typ:     reflect.TypeOf(CarrierVerifyItem{}),
		allowed: carrierVerifyRow,
		nested:  map[string]map[string]bool{"target": carrierTargetFields},
	},
	{name: "CarrierTarget", typ: reflect.TypeOf(CarrierTarget{}), allowed: carrierTargetFields},
	{
		name:    "DeployResult",
		typ:     reflect.TypeOf(DeployResult{}),
		allowed: resultFields,
		nested:  map[string]map[string]bool{"healthcheck": deployHealthFields, "approval": deployApprovalFields},
	},
	{
		name:    "RotateResult",
		typ:     reflect.TypeOf(RotateResult{}),
		allowed: fieldSet("ok", "request_id", "fingerprint", "version", "error_class", "carriers", "approval"),
		nested:  map[string]map[string]bool{"carriers": rotateCarrierFields, "approval": deployApprovalFields},
	},
	{name: "RotateApproval", typ: reflect.TypeOf(RotateApproval{}), allowed: deployApprovalFields},
	{name: "RotateCarrier", typ: reflect.TypeOf(RotateCarrier{}), allowed: rotateCarrierFields},
	{name: "DeployHealth", typ: reflect.TypeOf(DeployHealth{}), allowed: deployHealthFields},
	{name: "DeployApproval", typ: reflect.TypeOf(DeployApproval{}), allowed: deployApprovalFields},
	{name: "intake.Issued", typ: reflect.TypeOf(intake.Issued{}), allowed: fieldSet("url", "expires_at", "request_id")},
	{name: "intake.Result", typ: reflect.TypeOf(intake.Result{}), allowed: fieldSet("version", "fingerprint")},
	{
		name:    "Secret",
		typ:     reflect.TypeOf(Secret{}),
		allowed: fieldSet("id", "name", "scope", "class", "type", "description", "store", "provider_ref", "current_version", "created_at", "updated_at", "expires_at", "owner"),
		nested:  map[string]map[string]bool{"store": storeRefFields},
	},
	{name: "StoreRef", typ: reflect.TypeOf(StoreRef{}), allowed: storeRefFields},
	{
		name:    "SecretVersion",
		typ:     reflect.TypeOf(SecretVersion{}),
		allowed: fieldSet("version", "created_at", "created_by", "fingerprint", "length", "status"),
	},
	{name: "apperr.Body", typ: reflect.TypeOf(apperr.Body{}), allowed: errorFields},
	{name: "RestartRequest", typ: reflect.TypeOf(RestartRequest{}), allowed: fieldSet("request_id", "lane", "key_version", "fingerprint", "claim_token")},
	{name: "okResult", typ: reflect.TypeOf(okResult{}), allowed: resultFields},
	{name: "identity.IssueResponse", typ: reflect.TypeOf(identity.IssueResponse{}), allowed: tokenIssueFields},
	// keep_secret is the one-time disclosure of Keep's own secret for the
	// workspace at install, like identity.IssueResponse's token.
	{name: "MeshInstallResult", typ: reflect.TypeOf(MeshInstallResult{}), allowed: fieldSet("ok", "request_id", "keep_secret")},
	// ref is the name the workspace gave its own setting; the value is never
	// part of the answer (it is returned only by resolve, which has no struct).
	{name: "MeshSecretPutResult", typ: reflect.TypeOf(MeshSecretPutResult{}), allowed: fieldSet("ref", "version", "fingerprint")},
	{name: "MeshSessionResult", typ: reflect.TypeOf(MeshSessionResult{}), allowed: fieldSet("ok", "request_id")},
	// commit and build_time identify the build, the same for every caller.
	{name: "VersionResult", typ: reflect.TypeOf(VersionResult{}), allowed: fieldSet("commit", "build_time")},
	{name: "AuditVerifyResult", typ: reflect.TypeOf(AuditVerifyResult{}), allowed: auditVerifyFields},
}

// jsonName returns f's wire name, or "" for a field json.Marshal would never
// emit (an explicit "-" tag, or an unexported field — Go's own encoding/json
// never serializes those, so this guard has nothing to check there).
func jsonName(f reflect.StructField) string {
	if f.PkgPath != "" { // unexported
		return ""
	}
	tag := f.Tag.Get("json")
	if tag == "-" {
		return ""
	}
	name, _, _ := strings.Cut(tag, ",")
	if name == "" {
		name = f.Name
	}
	return name
}

// closedFieldsViolations walks e's type and returns one message per json
// field that is not in e's allowed set, recursing into a nested closed
// sub-object where e.nested says to. Returning a plain slice (rather than
// writing straight to a *testing.T) is what lets
// [TestResponseFieldsAreClosed_RedRun] below assert the walk itself is
// capable of failing, without fabricating a fake *testing.T to observe.
func closedFieldsViolations(e closedFieldsEntry) []string {
	var out []string
	typ := e.typ
	for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice {
		typ = typ.Elem()
	}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		name := jsonName(f)
		if name == "" {
			continue
		}
		if !e.allowed[name] {
			out = append(out, e.name+": field "+f.Name+" (json "+name+") is not in the threat model's §4.3 closed list for this object")
			continue
		}
		if nestedAllowed, ok := e.nested[name]; ok {
			out = append(out, closedFieldsViolations(closedFieldsEntry{name: e.name + "." + name, typ: f.Type, allowed: nestedAllowed})...)
		}
	}
	return out
}

// TestResponseFieldsAreClosed is guard (a): every registered response type's
// json field names must be a subset of its §4.3 object's allowed set.
func TestResponseFieldsAreClosed(t *testing.T) {
	for _, e := range closedFieldsRegistry {
		t.Run(e.name, func(t *testing.T) {
			for _, msg := range closedFieldsViolations(e) {
				t.Error(msg)
			}
		})
	}
}

// TestResponseFieldsAreClosed_RedRun is this guard's own red run: before
// trusting a check as passing, show it can fail. A response type carrying a
// field outside the closed list — the shape a careless "add a debug field"
// change would take — must fail the walk above, not silently pass it.
func TestResponseFieldsAreClosed_RedRun(t *testing.T) {
	type leaky struct {
		ID    string `json:"id"`
		Value string `json:"value"`
	}
	e := closedFieldsEntry{name: "leaky", typ: reflect.TypeOf(leaky{}), allowed: fieldSet("id")}

	violations := closedFieldsViolations(e)
	if len(violations) == 0 {
		t.Fatal("closedFieldsViolations found nothing wrong with a type carrying an unregistered \"value\" field — the guard cannot fail, so it proves nothing")
	}
}

// TestResponseFieldsAreClosed_NestedPointerRedRun shows the walk follows a
// pointer to a nested object: a field added only inside the nested type must
// fail, not be skipped because the parent field is a pointer.
func TestResponseFieldsAreClosed_NestedPointerRedRun(t *testing.T) {
	type inner struct {
		ID    string `json:"id"`
		Value string `json:"value"`
	}
	type outer struct {
		Approval *inner `json:"approval"`
	}
	e := closedFieldsEntry{name: "outer", typ: reflect.TypeOf(outer{}), allowed: fieldSet("approval"),
		nested: map[string]map[string]bool{"approval": fieldSet("id")}}
	if len(closedFieldsViolations(e)) == 0 {
		t.Fatal("a \"value\" field inside a pointer-nested object passed the closed-field walk")
	}
}

// isCarrierRow reports whether a field set is Carrier-shaped: it shares at
// least three fields with the standalone Carrier object, so dropping "host"
// or renaming the entry does not hide a row.
func isCarrierRow(set map[string]bool) bool {
	n := 0
	for f := range carrierFields {
		if set[f] {
			n++
		}
	}
	return n >= 3
}

// exceptionViolations returns one message per place that takes a §4.3.2
// exception outside its schema. Both a registry entry's own set and every
// nested set are checked: a "carriers" field anywhere but the verify result,
// and "error_class" in a Carrier-shaped row anywhere but the verify result's
// carriers[] element. The two schema names are tied to their Go types, so
// reusing a name for another type fails. Error and result objects carry
// error_class by §4.3 itself and are not Carrier rows.
func exceptionViolations(reg []closedFieldsEntry) []string {
	var out []string
	pinned := map[string]reflect.Type{
		verifyResultSchema: reflect.TypeOf(CarrierVerifyResult{}),
		verifyRowSchema:    reflect.TypeOf(CarrierVerifyItem{}),
		rotateResultSchema: reflect.TypeOf(RotateResult{}),
	}
	for _, e := range reg {
		if want, ok := pinned[e.name]; ok && e.typ != want {
			out = append(out, e.name+": the name is bound to its own Go type")
		}
		if e.allowed["carriers"] && e.name != verifyResultSchema && e.name != rotateResultSchema {
			out = append(out, e.name+": \"carriers\" is allowed only in "+verifyResultSchema+" and "+rotateResultSchema)
		}
		if isCarrierRow(e.allowed) && e.allowed["error_class"] && e.name != verifyRowSchema {
			out = append(out, e.name+": \"error_class\" in a Carrier row is allowed only in "+verifyRowSchema)
		}
		for field, set := range e.nested {
			if set["carriers"] {
				out = append(out, e.name+"."+field+": \"carriers\" nested outside the verify result")
			}
			if isCarrierRow(set) && set["error_class"] && (e.name != verifyResultSchema || field != "carriers") {
				out = append(out, e.name+"."+field+": \"error_class\" in a nested Carrier row is allowed only as "+verifyResultSchema+".carriers")
			}
		}
	}
	return out
}

// TestVerifyResultExceptionsAreBound pins §4.3.2: the two exceptions live in
// the verify-result schema alone, and the standalone Carrier shape has neither.
func TestVerifyResultExceptionsAreBound(t *testing.T) {
	for _, msg := range exceptionViolations(closedFieldsRegistry) {
		t.Error(msg)
	}
	if carrierFields["error_class"] || carrierFields["carriers"] {
		t.Fatal("the standalone Carrier field set must not carry a §4.3.2 exception")
	}
	for name := range verifyResultExceptions {
		found := false
		for _, e := range closedFieldsRegistry {
			found = found || e.allowed[name]
		}
		if !found {
			t.Fatalf("exception %q is registered nowhere; drop it from the table", name)
		}
	}
}

// TestVerifyResultExceptions_RedRun shows each binding can fail: error_class
// in a standalone Carrier row (with and without "host"), in a row nested into
// another object, "carriers" on another object or nested elsewhere, and a
// schema name reused for another type all fail; the real shapes pass.
func TestVerifyResultExceptions_RedRun(t *testing.T) {
	row := fieldSet("id", "host", "status", "error_class")
	rowNoHost := fieldSet("id", "runner_id", "target", "status", "error_class")
	bad := map[string]closedFieldsEntry{
		"standalone row":         {name: "CarrierRead", allowed: row},
		"standalone row no host": {name: "CarrierRead", allowed: rowNoHost},
		"nested row elsewhere":   {name: "DeployResult", allowed: fieldSet("ok", "approval"), nested: map[string]map[string]bool{"approval": row}},
		"carriers elsewhere":     {name: "DeployResult", allowed: fieldSet("ok", "carriers")},
		"carriers renamed in verify result": {name: verifyResultSchema, typ: reflect.TypeOf(CarrierVerifyResult{}), allowed: fieldSet("ok", "targets"),
			nested: map[string]map[string]bool{"targets": row}},
		"carriers in a reused rotate name": {name: rotateResultSchema, typ: reflect.TypeOf(struct{}{}), allowed: fieldSet("ok", "carriers")},
		"row schema name reused":           {name: verifyRowSchema, typ: reflect.TypeOf(struct{}{}), allowed: row},
	}
	for name, e := range bad {
		if len(exceptionViolations([]closedFieldsEntry{e})) == 0 {
			t.Errorf("%s passed the binding", name)
		}
	}
	if got := exceptionViolations(closedFieldsRegistry); len(got) != 0 {
		t.Fatalf("positive control failed: %v", got)
	}
}

// TestVerifyRowExtraFieldFails: an extra field inside an element of carriers[]
// is caught through the verify result's nested walk, not only on the row type.
func TestVerifyRowExtraFieldFails(t *testing.T) {
	type row struct {
		ID         string `json:"id"`
		ErrorClass string `json:"error_class"`
		Message    string `json:"message"`
	}
	type result struct {
		OK       bool  `json:"ok"`
		Carriers []row `json:"carriers"`
	}
	e := closedFieldsEntry{name: verifyResultSchema, typ: reflect.TypeOf(result{}), allowed: carrierVerifyFields,
		nested: map[string]map[string]bool{"carriers": carrierVerifyRow}}
	if len(closedFieldsViolations(e)) == 0 {
		t.Fatal("an extra field in a carriers[] element passed the closed walk")
	}
}

// TestResponseFieldsAreClosed_NestedSliceRedRun shows the walk follows a slice
// of nested objects: a field added only to the element type must fail.
func TestResponseFieldsAreClosed_NestedSliceRedRun(t *testing.T) {
	type inner struct {
		ID    string `json:"id"`
		Value string `json:"value"`
	}
	type outer struct {
		Items []inner `json:"items"`
	}
	e := closedFieldsEntry{name: "outer", typ: reflect.TypeOf(outer{}), allowed: fieldSet("items"),
		nested: map[string]map[string]bool{"items": fieldSet("id")}}
	if len(closedFieldsViolations(e)) == 0 {
		t.Fatal("a \"value\" field inside a slice-nested object passed the closed-field walk")
	}
}
