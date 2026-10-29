package api

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

// validSurrogateEscapes inspects the original, syntactically valid JSON.
// encoding/json otherwise silently replaces unpaired surrogates with U+FFFD.
// Escaped backslashes are skipped, preserving literal Unicode escape text.
func validSurrogateEscapes(raw []byte) bool {
	inString := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if len(raw)-i < 5 {
			return false
		}
		n, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if n >= 0xd800 && n <= 0xdbff {
			if len(raw)-i < 7 || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		} else if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
	}
	return !inString
}

// metadataWireField returns a closed metadata field name for an invalid wire
// value. Token iteration preserves duplicate fields and resolves escaped keys;
// RawMessage keeps invalid UTF-8 and surrogate escapes intact for validation.
func metadataWireField(raw []byte, valid func([]byte) bool) string {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return "request body"
	}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return "request body"
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return "request body"
		}
		field, ok := key.(string)
		if !ok {
			return "request body"
		}
		if valid(value) {
			continue
		}
		for _, allowed := range []string{"name", "description", "class", "type"} {
			if strings.EqualFold(field, allowed) {
				return allowed
			}
		}
	}
	return "request body"
}
