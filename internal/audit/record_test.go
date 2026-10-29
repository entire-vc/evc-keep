package audit

import (
	"encoding/json"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

// forbiddenFieldTypes walks t (and every struct field nested inside it,
// recursively) and returns a description of the first field whose type is
// `any`/interface{}, a map with an interface{} element type, or
// json.RawMessage — the three shapes that would let a value bypass the
// closed §4.2 schema by riding inside a field that isn't itself part of it.
// A plain `map[string]string` (or any map with a concrete, non-interface
// element type) is NOT flagged: it cannot hold an arbitrary nested value
// the way map[string]any can, so it isn't the hazard this check exists for
// — nothing in Record uses one today, but the check is precise about what
// it forbids rather than banning every map.
func forbiddenFieldTypes(t reflect.Type, path string) string {
	rawMessageType := reflect.TypeOf(json.RawMessage(nil))

	switch t.Kind() {
	case reflect.Interface:
		return path + " is an interface type (any/interface{})"
	case reflect.Map:
		if t.Elem().Kind() == reflect.Interface {
			return path + " is a map with an interface{} element (map[...]any)"
		}
		return ""
	case reflect.Struct:
		if t == rawMessageType {
			return path + " is json.RawMessage"
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if got := forbiddenFieldTypes(f.Type, path+"."+f.Name); got != "" {
				return got
			}
		}
		return ""
	case reflect.Pointer, reflect.Slice, reflect.Array:
		return forbiddenFieldTypes(t.Elem(), path+"[]")
	default:
		return ""
	}
}

// TestRecordSchemaIsClosed is the reflection-based guard record.go's own
// doc promises: no field anywhere under Record is `any`, a map with an
// interface{} element, or json.RawMessage. See forbiddenFieldTypes'
// doc for exactly what it looks for and why those three shapes specifically.
//
// Red-run proof this test can fail: add a field of type
// `map[string]any` to Record (or any nested type here) and re-run — this
// test must go red. Verified by hand in a scratch copy of the tree: adding
// `Extra map[string]any` to Record makes TestRecordSchemaIsClosed fail with
// "Record.Extra is a map with an interface{} element (map[...]any)".
func TestRecordSchemaIsClosed(t *testing.T) {
	// Positive control: prove the walker itself can find something, on a
	// throwaway type never used by Record — an empty result from the real
	// check below would otherwise be indistinguishable from "nothing to
	// find" and "the walker never looked".
	type probe struct{ X map[string]any }
	if got := forbiddenFieldTypes(reflect.TypeOf(probe{}), "probe"); got == "" {
		t.Fatal("forbiddenFieldTypes did not flag a map[string]any on a throwaway probe type — the walker is broken, not the code clean")
	}

	if got := forbiddenFieldTypes(reflect.TypeOf(Record{}), "Record"); got != "" {
		t.Errorf("closed-schema violation: %s", got)
	}
}

// TestRecordJSONKeysMatchThreatModel pins Record's on-wire shape against
// the exact key set the threat model's §4.2 lists — a field renamed via its
// json tag, or a field added without updating that doc, changes this list
// and must be a deliberate, reviewed edit, not a silent drift.
func TestRecordJSONKeysMatchThreatModel(t *testing.T) {
	want := []string{
		"id", "ts", "request_id", "org_id", "scope",
		"actor", "intent", "action", "secret", "target", "policy", "approval", "result",
		"prev_hash",
	}

	raw, err := json.Marshal(Record{})
	if err != nil {
		t.Fatalf("marshal zero Record: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, k := range want {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %q in Record's JSON output", k)
		}
	}
	if len(m) != len(want) {
		var got []string
		for k := range m {
			got = append(got, k)
		}
		t.Errorf("Record's JSON has %d keys, threat model §4.2 lists %d — got %v", len(m), len(want), got)
	}
}

func TestNewReason_TruncatesByRune(t *testing.T) {
	// A multi-byte rune (é = 2 bytes in UTF-8) at the truncation boundary
	// must not be split into invalid UTF-8 — that's the whole reason this
	// truncates by []rune, not by byte slicing.
	base := strings.Repeat("é", 199) // 199 runes, well within bound
	over := base + "éé"              // 201 runes — 1 over

	if got := NewReason(base); got != base {
		t.Errorf("NewReason should not touch a string already within bound")
	}

	got := NewReason(over)
	gotRunes := []rune(got)
	if len(gotRunes) != maxReasonRunes {
		t.Fatalf("NewReason(len 201 runes) = %d runes, want %d", len(gotRunes), maxReasonRunes)
	}
	if !strings.HasPrefix(over, got) {
		t.Errorf("NewReason truncated output is not a prefix of the input: got %q", got)
	}
	if !json.Valid([]byte(`"` + strings.ReplaceAll(got, `"`, `\"`) + `"`)) {
		t.Errorf("NewReason produced invalid UTF-8 at the truncation boundary: %q", got)
	}
}

// TestClosedSchemaFieldDoesNotCompile is an extra requirement checked
// before the feature code: trying to put a canary value into a field the
// schema doesn't have must not compile — proven with a real `go build`,
// not just the reflection check above (which proves Record has no
// interface-shaped escape hatch; this proves a caller can't sidestep that
// by inventing a field name that was never there). testdata/closed_schema
// deliberately fails to build; go build/vet/test's "./..." walk already
// skips any directory named testdata (see that package's doc), so this is
// the ONLY thing that ever builds it, on purpose, expecting failure.
func TestClosedSchemaFieldDoesNotCompile(t *testing.T) {
	cmd := exec.Command("go", "build", "./testdata/closed_schema/") //nolint:gosec // G204: fixed literal args, not external input
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected ./testdata/closed_schema to fail to build (it assigns a nonexistent Record field), but it built cleanly")
	}
	if !strings.Contains(string(out), "unknown field") {
		t.Errorf("build failed, but not for the expected reason (want an \"unknown field\" error): %s", out)
	}
}

func TestNewReason_ExactlyAtBoundIsUnchanged(t *testing.T) {
	s := strings.Repeat("x", maxReasonRunes)
	if got := NewReason(s); got != s {
		t.Errorf("NewReason(exactly %d runes) changed the string", maxReasonRunes)
	}
}
