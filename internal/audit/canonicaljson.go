package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// canonicalJSON renders r as the doc.go canonical form: object keys sorted
// lexically at every nesting level, no insignificant whitespace anywhere.
// This is what [computeHash] feeds to SHA-256 — see doc.go for why a
// canonical form is needed at all (Go's own json.Marshal already emits a
// deterministic byte sequence for a fixed struct, but it orders keys by
// struct-field declaration order, not lexically, and the chain must not
// silently change shape if this package's field order is ever edited).
//
// The two-step marshal-then-canonicalize below (rather than walking the
// struct directly) is deliberate: it reuses encoding/json's struct-tag
// handling — including time.Time's RFC3339Nano formatting — instead of
// reimplementing it, and it works unchanged if Record ever grows a field,
// with no second place to keep in sync.
func canonicalJSON(r Record) ([]byte, error) {
	tagged, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("marshal record: %w", err)
	}

	dec := json.NewDecoder(bytes.NewReader(tagged))
	dec.UseNumber()
	var generic interface{}
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("decode record for canonicalization: %w", err)
	}

	var buf bytes.Buffer
	if err := writeCanonical(&buf, generic); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// writeCanonical writes v to buf as canonical JSON: object keys sorted
// lexically, no whitespace. v is always something json.Decoder.Decode
// produced with UseNumber (map[string]interface{}, []interface{},
// json.Number, string, bool, or nil), never a Go struct — canonicalJSON
// converts through encoding/json first specifically so this function never
// has to know about Record's shape.
func writeCanonical(buf *bytes.Buffer, v interface{}) error {
	switch val := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return fmt.Errorf("marshal object key %q: %w", k, err)
			}
			buf.Write(kb)
			buf.WriteByte(':')
			if err := writeCanonical(buf, val[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	case []interface{}:
		buf.WriteByte('[')
		for i, e := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	default:
		// json.Number, string, bool, nil — encoding/json already renders
		// each of these with no insignificant whitespace.
		b, err := json.Marshal(val)
		if err != nil {
			return fmt.Errorf("marshal scalar of type %T: %w", val, err)
		}
		buf.Write(b)
		return nil
	}
}
