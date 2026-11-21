//go:build unix

package targets

import (
	"bytes"
	"io"
	"strings"

	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"go.yaml.in/yaml/v3"
)

const (
	maxYAMLBytes = 1 << 20
	maxYAMLDepth = 32
	maxYAMLNodes = 16384
)

// YAMLObservation contains only policy-supplied metadata and a keyed digest.
type YAMLObservation struct {
	Field       string
	Fingerprint string
	Length      int
}

// FingerprintYAML reads exact, policy-supplied fields using the same bounded
// reader as target observation. It never returns file-supplied names or values.
// A malformed document or an unsupported selected value fails the whole read.
func FingerprintYAML(content []byte, fields []string, key fingerprint.Key) ([]YAMLObservation, error) {
	if len(fields) == 0 || len(fields) > 256 {
		return nil, writeFailed("unsupported YAML fields")
	}
	seen := map[string]bool{}
	for _, field := range fields {
		if !yamlField(field) || seen[field] {
			return nil, writeFailed("unsupported YAML field")
		}
		seen[field] = true
	}
	doc, err := parseYAML(content)
	if err != nil {
		return nil, err
	}
	out := []YAMLObservation{}
	for _, field := range fields {
		v, found, err := yamlScalar(doc, field)
		if err != nil {
			return nil, err
		}
		if !found {
			continue
		}
		length := v.Len()
		fp, err := computeFingerprint(key, v)
		v.Wipe()
		if err != nil {
			return nil, writeFailed("YAML fingerprint failed")
		}
		out = append(out, YAMLObservation{Field: field, Fingerprint: fp, Length: length})
	}
	return out, nil
}

func readYAMLScalar(content []byte, field string) (secret.Value, bool, error) {
	if !yamlField(field) {
		return secret.Value{}, false, writeFailed("unsupported YAML field")
	}
	doc, err := parseYAML(content)
	if err != nil {
		return secret.Value{}, false, err
	}
	return yamlScalar(doc, field)
}

func parseYAML(content []byte) (*yaml.Node, error) {
	if len(content) > maxYAMLBytes {
		return nil, writeFailed("unsupported YAML size")
	}
	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(content))
	if dec.Decode(&doc) != nil {
		// Never wrap parser diagnostics: they can contain values, keys,
		// alias names or excerpts from a neighbouring secret.
		return nil, writeFailed("invalid YAML document")
	}
	var extra yaml.Node
	if dec.Decode(&extra) != io.EOF || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode || !safeYAML(&doc) {
		return nil, writeFailed("unsupported or ambiguous YAML document")
	}
	return &doc, nil
}

func yamlScalar(doc *yaml.Node, field string) (secret.Value, bool, error) {
	n := doc.Content[0]
	for _, key := range strings.Split(field, ".") {
		if n.Kind != yaml.MappingNode {
			return secret.Value{}, false, writeFailed("YAML field path is not a mapping")
		}
		var hit *yaml.Node
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == key {
				hit = n.Content[i+1]
			}
		}
		if hit == nil {
			return secret.Value{}, false, nil
		}
		n = hit
	}
	if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
		return secret.Value{}, false, writeFailed("YAML field is not a string scalar")
	}
	// YAML 1.1 consumers may resolve these plain strings as booleans. Require
	// quotes rather than attest a value whose interpretation is ambiguous.
	if n.Style == 0 {
		switch strings.ToLower(n.Value) {
		case "y", "n", "yes", "no", "on", "off":
			return secret.Value{}, false, writeFailed("ambiguous YAML string scalar")
		}
	}
	// Like encoding/json, the YAML decoder owns immutable string copies.
	// They stay inside this zone and become collectible with the node tree;
	// only our owned byte copy and secret.Value can be explicitly wiped.
	raw := []byte(n.Value)
	defer wipe(raw)
	return secret.New(raw), true, nil
}

func yamlField(field string) bool {
	if field == "" || len(field) > 256 {
		return false
	}
	parts := strings.Split(field, ".")
	if len(parts) > 16 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, c := range []byte(p) {
			switch {
			case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_', c == '-':
			default:
				return false
			}
		}
	}
	return true
}

// safeYAML checks the entire document, not just the selected branch. A
// duplicate or an alias elsewhere can change how a consumer interprets it.
// No decode into interface{} and no alias/merge resolution is performed.
func safeYAML(doc *yaml.Node) bool {
	type item struct {
		n     *yaml.Node
		depth int
	}
	stack := []item{{doc, 0}}
	count := 0
	for len(stack) != 0 {
		i := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		n := i.n
		count++
		if count > maxYAMLNodes || i.depth > maxYAMLDepth || n.Anchor != "" || n.Alias != nil || n.Style&yaml.TaggedStyle != 0 {
			return false
		}
		switch n.Kind {
		case yaml.DocumentNode:
			if n != doc || len(n.Content) != 1 {
				return false
			}
		case yaml.MappingNode:
			if n.Tag != "!!map" || len(n.Content)%2 != 0 {
				return false
			}
			seen := map[string]bool{}
			for j := 0; j < len(n.Content); j += 2 {
				k := n.Content[j]
				if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || k.Value == "<<" || seen[k.Value] {
					return false
				}
				seen[k.Value] = true
			}
		case yaml.SequenceNode:
			if n.Tag != "!!seq" {
				return false
			}
		case yaml.ScalarNode:
			switch n.Tag {
			case "!!str", "!!null", "!!bool", "!!int", "!!float", "!!timestamp":
			default:
				return false
			}
		default:
			return false
		}
		if count+len(stack)+len(n.Content) > maxYAMLNodes {
			return false
		}
		for _, child := range n.Content {
			stack = append(stack, item{child, i.depth + 1})
		}
	}
	return true
}
