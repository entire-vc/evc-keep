package mcp

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// Every answer type listed in closedAnswers must carry only json field names
// from threat model §4.3. The walk is by reflection, but the list of types is
// kept by hand: a new answer type has to be added to it in the same change.
// internal/api's closed_fields_test.go states the same rule for the REST types.

func names(n ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range n {
		m[x] = true
	}
	return m
}

var closedAnswers = []struct {
	typ     reflect.Type
	allowed map[string]bool
}{
	{reflect.TypeOf(Secret{}), names("id", "name", "scope", "class", "type", "description", "store", "provider_ref", "current_version", "created_at", "updated_at", "expires_at", "owner")},
	{reflect.TypeOf(StoreRef{}), names("id", "name", "provider")},
	{reflect.TypeOf(SecretVersion{}), names("version", "created_at", "created_by", "fingerprint", "length", "status")},
	{reflect.TypeOf(InputLink{}), names("url", "expires_at", "request_id")},
	{reflect.TypeOf(DeployResult{}), names("ok", "request_id", "fingerprint", "version", "healthcheck", "error_class", "approval")},
	{reflect.TypeOf(DeployHealth{}), names("status", "checked_at")},
	{reflect.TypeOf(DeployApproval{}), names("id", "status", "url")},
	{reflect.TypeOf(Carrier{}), names("id", "secret_id", "host", "runner_id", "target", "consumer", "healthcheck", "status", "last_verified_at", "fingerprint_match")},
	{reflect.TypeOf(CarrierVerifyResult{}), names("ok", "request_id", "fingerprint", "version", "carriers")},
	{reflect.TypeOf(CarrierRow{}), names("id", "host", "runner_id", "target", "status", "last_verified_at", "fingerprint_match", "error_class")},
	{reflect.TypeOf(CarrierTarget{}), names("kind", "path")},
	{reflect.TypeOf(RotateResult{}), names("ok", "request_id", "fingerprint", "version", "error_class", "carriers", "approval")},
	{reflect.TypeOf(RotateCarrier{}), names("carrier_id", "phase", "state")},
	{reflect.TypeOf(ErrorAnswer{}), names("error_class", "message", "request_id")},
	// Tool envelopes: lists of closed objects, nothing else.
	{reflect.TypeOf(SecretList{}), names("secrets")},
	{reflect.TypeOf(SecretMeta{}), names("secret", "versions")},
}

func TestAnswerTypesStayInTheClosedList(t *testing.T) {
	registered := map[reflect.Type]bool{}
	for _, e := range closedAnswers {
		registered[e.typ] = true
	}
	for _, e := range closedAnswers {
		for i := 0; i < e.typ.NumField(); i++ {
			f := e.typ.Field(i)
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name == "" || name == "-" || !e.allowed[name] {
				t.Errorf("%s.%s: json field %q is outside the closed list", e.typ.Name(), f.Name, name)
			}
			// A field's type must be plain, or itself a registered closed type:
			// no map, interface or raw message can smuggle an open shape.
			ft := f.Type
			for ft.Kind() == reflect.Pointer || ft.Kind() == reflect.Slice {
				ft = ft.Elem()
			}
			switch {
			case ft == reflect.TypeOf(time.Time{}):
			case ft.Kind() == reflect.Struct:
				if !registered[ft] {
					t.Errorf("%s.%s: nested type %s is not registered", e.typ.Name(), f.Name, ft.Name())
				}
			case ft.Kind() == reflect.String, ft.Kind() == reflect.Bool, ft.Kind() == reflect.Int:
			default:
				t.Errorf("%s.%s: open type %s", e.typ.Name(), f.Name, ft)
			}
		}
	}
}

// The guard must be able to fail: a type with a value field is caught.
func TestClosedGuardSeesAForbiddenField(t *testing.T) {
	type leaky struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	allowed := names("name")
	var bad []string
	typ := reflect.TypeOf(leaky{})
	for i := 0; i < typ.NumField(); i++ {
		name, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
		if !allowed[name] {
			bad = append(bad, name)
		}
	}
	if len(bad) != 1 || bad[0] != "value" {
		t.Fatalf("the guard's own check is blind: %v", bad)
	}
}
