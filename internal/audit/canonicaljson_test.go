package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sampleRecord() Record {
	return Record{
		ID:        "01J000000000000000000000",
		TS:        time.Date(2026, 9, 23, 13, 0, 0, 0, time.UTC),
		RequestID: "req-1",
		OrgID:     "org-1",
		Scope:     "proj:demo",
		Actor:     Actor{Type: ActorAgent, ID: "agent-1", SponsorID: "user-1", Via: ViaAPI},
		Intent:    Intent{TaskRef: "task-1", SessionRef: "sess-1", Reason: "test"},
		Action:    "secret.create_ref",
		Secret:    SecretRef{ID: "sec-1", Name: "demo", Version: "v1"},
		Target:    Target{RunnerID: "runner-1", Host: "host-1", Kind: "env-file", Path: "/etc/env"},
		Policy:    Policy{Decision: DecisionAllow, RuleID: "rule-1"},
		Approval:  Approval{},
		Result:    Result{Status: StatusOK, Fingerprint: "kfp1:abc", Length: 40, Health: HealthUnset, ErrorClass: ErrClassNone},
		PrevHash:  GenesisHash,
	}
}

func TestCanonicalJSON_NoInsignificantWhitespace(t *testing.T) {
	b, err := canonicalJSON(sampleRecord())
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	s := string(b)
	for _, forbidden := range []string{": ", ", ", "  ", "\n", "\t"} {
		if containsSubstring(s, forbidden) {
			t.Errorf("canonical JSON contains insignificant whitespace %q: %s", forbidden, s)
		}
	}
	if !json.Valid(b) {
		t.Errorf("canonical JSON is not valid JSON: %s", s)
	}
}

func TestCanonicalJSON_KeysAreSortedAtEveryLevel(t *testing.T) {
	b, err := canonicalJSON(sampleRecord())
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}

	var generic map[string]json.RawMessage
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatalf("unmarshal canonical output: %v", err)
	}

	// Top-level keys, read back out in the ORDER THEY APPEAR IN THE RAW
	// BYTES (not map iteration order, which Go randomizes) — extracted via
	// json.Decoder.Token, which walks the byte stream, not a map.
	got := topLevelKeyOrder(t, b)
	want := append([]string{}, got...)
	sortStrings(want)
	if !equalStrings(got, want) {
		t.Errorf("top-level keys are not sorted: got %v, want %v", got, want)
	}

	// Spot-check one nested object too.
	nestedOrder := topLevelKeyOrder(t, []byte(generic["actor"]))
	nestedWant := append([]string{}, nestedOrder...)
	sortStrings(nestedWant)
	if !equalStrings(nestedOrder, nestedWant) {
		t.Errorf("nested 'actor' keys are not sorted: got %v, want %v", nestedOrder, nestedWant)
	}
}

func TestCanonicalJSON_Deterministic(t *testing.T) {
	r := sampleRecord()
	a, err := canonicalJSON(r)
	if err != nil {
		t.Fatalf("canonicalJSON (1st): %v", err)
	}
	b, err := canonicalJSON(r)
	if err != nil {
		t.Fatalf("canonicalJSON (2nd): %v", err)
	}
	if string(a) != string(b) {
		t.Errorf("canonicalJSON is not deterministic across calls with the same input:\n%s\nvs\n%s", a, b)
	}
}

func TestCanonicalJSON_DifferentRecordsProduceDifferentOutput(t *testing.T) {
	a := sampleRecord()
	b := sampleRecord()
	b.Intent.Reason = "different"

	ja, err := canonicalJSON(a)
	if err != nil {
		t.Fatalf("canonicalJSON(a): %v", err)
	}
	jb, err := canonicalJSON(b)
	if err != nil {
		t.Fatalf("canonicalJSON(b): %v", err)
	}
	if string(ja) == string(jb) {
		t.Errorf("two records differing in Intent.Reason canonicalized to the same bytes")
	}
}

// TestCanonicalJSON_EveryFieldChangesOutput is the mutation-script's own
// target (scripts/check-audit-mutations.sh, job "audit-mutations"): a
// review found that only actor_id had a test proving
// it actually participates in computeHash's input — a field that quietly
// fell out of canonicalJSON (a rebase of verify.go/record.go, a migration
// that stops populating a column) would let a superuser-bypass tamper of
// that column go undetected by Verify, and nothing in this package would
// notice. This test changes exactly one field at a time off a fixed
// baseline and requires canonicalJSON's output to change every time — one
// case per JSON key the Record family actually has, at every nesting level.
//
// The table's completeness is itself checked below, the same way
// record_test.go's TestRecordJSONKeysMatchThreatModel pins Record's own
// top-level keys: a field added to Record or one of its nested types
// without a matching case here fails loudly instead of shipping unproven.
func TestCanonicalJSON_EveryFieldChangesOutput(t *testing.T) {
	base := sampleRecord()
	baseJSON, err := canonicalJSON(base)
	if err != nil {
		t.Fatalf("canonicalJSON(base): %v", err)
	}

	cases := []struct {
		key    string
		mutate func(*Record)
	}{
		{"id", func(r *Record) { r.ID += "-x" }},
		{"ts", func(r *Record) { r.TS = r.TS.Add(time.Second) }},
		{"request_id", func(r *Record) { r.RequestID += "-x" }},
		{"org_id", func(r *Record) { r.OrgID += "-x" }},
		{"scope", func(r *Record) { r.Scope += "-x" }},
		{"actor.type", func(r *Record) { r.Actor.Type = ActorUser }},
		{"actor.id", func(r *Record) { r.Actor.ID += "-x" }},
		{"actor.sponsor_id", func(r *Record) { r.Actor.SponsorID += "-x" }},
		{"actor.via", func(r *Record) { r.Actor.Via = ViaCLI }},
		{"intent.task_ref", func(r *Record) { r.Intent.TaskRef += "-x" }},
		{"intent.session_ref", func(r *Record) { r.Intent.SessionRef += "-x" }},
		{"intent.reason", func(r *Record) { r.Intent.Reason += "-x" }},
		{"action", func(r *Record) { r.Action += "-x" }},
		{"secret.id", func(r *Record) { r.Secret.ID += "-x" }},
		{"secret.name", func(r *Record) { r.Secret.Name += "-x" }},
		{"secret.version", func(r *Record) { r.Secret.Version += "-x" }},
		{"target.runner_id", func(r *Record) { r.Target.RunnerID += "-x" }},
		{"target.host", func(r *Record) { r.Target.Host += "-x" }},
		{"target.kind", func(r *Record) { r.Target.Kind += "-x" }},
		{"target.path", func(r *Record) { r.Target.Path += "-x" }},
		{"policy.decision", func(r *Record) { r.Policy.Decision = DecisionDeny }},
		{"policy.rule_id", func(r *Record) { r.Policy.RuleID += "-x" }},
		{"approval.id", func(r *Record) { r.Approval.ID += "-x" }},
		{"approval.approver_id", func(r *Record) { r.Approval.ApproverID += "-x" }},
		{"approval.decided_at", func(r *Record) { r.Approval.DecidedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }},
		{"result.status", func(r *Record) { r.Result.Status = StatusFailed }},
		{"result.fingerprint", func(r *Record) { r.Result.Fingerprint += "-x" }},
		{"result.length", func(r *Record) { r.Result.Length++ }},
		{"result.health", func(r *Record) { r.Result.Health = HealthOK }},
		{"result.error_class", func(r *Record) { r.Result.ErrorClass = ErrClassInternal }},
		{"prev_hash", func(r *Record) { r.PrevHash = strings.Repeat("1", len(GenesisHash)) }},
	}

	seen := map[string]bool{}
	for _, tc := range cases {
		tc := tc
		seen[tc.key] = true
		t.Run(tc.key, func(t *testing.T) {
			mutated := base
			tc.mutate(&mutated)
			mutatedJSON, err := canonicalJSON(mutated)
			if err != nil {
				t.Fatalf("canonicalJSON(mutated): %v", err)
			}
			if string(mutatedJSON) == string(baseJSON) {
				t.Errorf("changing %s did not change canonicalJSON's output — this field does not participate in computeHash's input, so a superuser-bypass tamper of the matching DB column would NOT be caught by Verify", tc.key)
			}
		})
	}

	// Completeness positive control: every JSON key Record and its nested
	// types actually emit must have a case above, at both nesting levels
	// this table uses. An empty allWant here (a walker that found nothing)
	// would make the "missing case" loop below vacuously pass — checked
	// first so a broken walker fails loudly instead of certifying nothing.
	allWant := recordJSONKeysAtEveryLevel(t)
	if len(allWant) < 25 {
		t.Fatalf("only found %d JSON keys across Record's nesting levels — the walker is broken, not the schema small", len(allWant))
	}
	for _, key := range allWant {
		if !seen[key] {
			t.Errorf("Record (or a nested field) has JSON key %q with no case in this test's table — add one", key)
		}
	}
}

// recordJSONKeysAtEveryLevel returns "key" for each top-level Record field
// and "parent.key" for each field of Record's seven nested struct types —
// exactly the dotted shape TestCanonicalJSON_EveryFieldChangesOutput's table
// uses. Marshaling each zero-valued type directly (rather than reflecting
// on Go field names) is deliberate: it is what actually ends up in
// canonicalJSON's input, tag renames and all, the same reasoning
// TestRecordJSONKeysMatchThreatModel already applies to Record's own
// top-level keys.
func recordJSONKeysAtEveryLevel(t *testing.T) []string {
	t.Helper()
	nested := map[string]interface{}{
		"actor":    Actor{},
		"intent":   Intent{},
		"secret":   SecretRef{},
		"target":   Target{},
		"policy":   Policy{},
		"approval": Approval{},
		"result":   Result{},
	}
	var keys []string
	for _, k := range jsonKeysOf(t, Record{}) {
		// A key with its own entry in nested is a struct field represented
		// below at the dotted "parent.child" level instead — not a leaf
		// this test's table has (or needs) a bare-name case for.
		if _, isContainer := nested[k]; isContainer {
			continue
		}
		keys = append(keys, k)
	}
	for parent, v := range nested {
		for _, k := range jsonKeysOf(t, v) {
			keys = append(keys, parent+"."+k)
		}
	}
	return keys
}

// jsonKeysOf returns v's top-level JSON object keys via json.Marshal — see
// recordJSONKeysAtEveryLevel's doc for why marshaling beats reflecting on
// field names directly.
func jsonKeysOf(t *testing.T, v interface{}) []string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %T: %v", v, err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal %T: %v", v, err)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// --- small local helpers, kept dependency-free on purpose (no testify) ---

func containsSubstring(s, sub string) bool {
	return len(sub) == 0 || indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// topLevelKeyOrder returns the top-level object keys of b in the order they
// appear in the byte stream, using json.Decoder.Token so it reflects the
// actual serialized order rather than a re-parsed map's (randomized) order.
// skipValue does the recursive-descent part: dec.More() is scoped to the
// innermost still-open array/object, so this correctly walks past a nested
// object or array's whole contents without needing to track depth by hand.
func topLevelKeyOrder(t *testing.T, b []byte) []string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(b))

	open, err := dec.Token()
	if err != nil {
		t.Fatalf("read opening token: %v", err)
	}
	if d, ok := open.(json.Delim); !ok || d != '{' {
		t.Fatalf("expected object, got %v", open)
	}

	var keys []string
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			t.Fatalf("read key token: %v", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			t.Fatalf("expected string key, got %v", keyTok)
		}
		keys = append(keys, key)
		skipValue(t, dec)
	}
	if _, err := dec.Token(); err != nil { // closing '}'
		t.Fatalf("read closing token: %v", err)
	}
	return keys
}

// skipValue consumes exactly one JSON value from dec — a scalar, or an
// entire nested object/array — without inspecting its contents.
func skipValue(t *testing.T, dec *json.Decoder) {
	t.Helper()
	tok, err := dec.Token()
	if err != nil {
		t.Fatalf("read value token: %v", err)
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim == '}' || delim == ']' {
		return // scalar value already fully consumed
	}
	for dec.More() {
		if delim == '{' {
			if _, err := dec.Token(); err != nil { // nested key
				t.Fatalf("read nested key token: %v", err)
			}
		}
		skipValue(t, dec)
	}
	if _, err := dec.Token(); err != nil { // closing delim
		t.Fatalf("read nested closing token: %v", err)
	}
}
