package discover

import (
	"bytes"
	"encoding/xml"
	"io"

	"github.com/entire-vc/evc-keep/pkg/fingerprint"
)

type entry struct{ name, value []byte }

func parseCarrier(data []byte, rule Rule, path string, key fingerprint.Key) ([]Finding, error) {
	var entries []entry
	var err error
	switch rule.Kind {
	case EnvFile:
		entries, err = envEntries(data)
	case SystemdUnit:
		entries, err = unitEntries(data)
	case LaunchdPlist:
		entries, err = plistEntries(data)
	case MCPConfig:
		entries, err = mcpEntries(data)
	case Credential:
		entries = []entry{{name: []byte(rule.Names[0]), value: bytes.Clone(data)}}
	default:
		return nil, ErrPolicy
	}
	defer func() {
		for _, e := range entries {
			wipe(e.name)
			wipe(e.value)
		}
	}()
	if err != nil {
		return nil, ErrParse
	}
	seen := map[string]bool{}
	out := []Finding{}
	for _, e := range entries {
		// Select the policy string; never copy a file-supplied name into output.
		for _, name := range rule.Names {
			if bytes.Equal(e.name, []byte(name)) {
				if seen[name] {
					return nil, ErrParse
				}
				seen[name] = true
				f, err := finding(path, name, e.value, key)
				if err != nil {
					return nil, err
				}
				out = append(out, f)
			}
		}
	}
	return out, nil
}

func envEntries(data []byte) ([]entry, error) {
	out := []entry{}
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(out) >= 4096 {
			return out, ErrParse
		}
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		if bytes.HasPrefix(line, []byte("export ")) {
			line = bytes.TrimSpace(line[7:])
		}
		eq := bytes.IndexByte(line, '=')
		if eq <= 0 || !validName(string(line[:eq])) {
			return out, ErrParse
		}
		// Blanks after '=' are shell word separators, not value bytes.
		// Only an empty assignment followed by a comment is unambiguous.
		if eq+1 < len(line) && (line[eq+1] == ' ' || line[eq+1] == '\t') {
			rest := bytes.TrimSpace(line[eq+1:])
			if len(rest) > 0 && rest[0] != '#' {
				return out, ErrParse
			}
			out = append(out, entry{name: bytes.Clone(line[:eq]), value: []byte{}})
			continue
		}
		value, end, err := word(line, eq+1, true)
		if err != nil {
			wipe(value)
			return out, ErrParse
		}
		rest := bytes.TrimSpace(line[end:])
		if len(rest) > 0 && rest[0] != '#' {
			wipe(value)
			return out, ErrParse
		}
		out = append(out, entry{name: bytes.Clone(line[:eq]), value: value})
	}
	return out, nil
}

// word decodes literal single/double quoted or unquoted words. This is a
// conservative literal subset, never a shell invocation or an expander.
// Shell expansions, multiline values and unsupported escapes fail closed.
func word(data []byte, start int, shell bool) ([]byte, int, error) {
	i := start
	for i < len(data) && (data[i] == ' ' || data[i] == '\t') {
		i++
	}
	out := []byte{}
	quote := byte(0)
	for ; i < len(data); i++ {
		c := data[i]
		if c == 0 || c == '\r' || c == '\n' {
			return out, i, ErrParse
		}
		if quote == 0 && (c == ' ' || c == '\t') {
			break
		}
		if c == '\'' || c == '"' {
			if quote == 0 {
				quote = c
				continue
			}
			if quote == c {
				quote = 0
				continue
			}
		}
		if shell && quote != '\'' && (c == '$' || c == '`' || quote == 0 && bytes.ContainsRune([]byte(";&|()<>~"), rune(c))) {
			return out, i, ErrParse
		}
		if !shell && c == '%' {
			return out, i, ErrParse
		} // unit specifiers are not literal observations
		if c == '\\' && (quote != '\'' || !shell) {
			i++
			if i >= len(data) {
				return out, i, ErrParse
			}
			c = data[i]
			doubleEscape := c == '\\' || c == '"' || c == '$' || c == '`'
			if shell && quote == '"' && !doubleEscape {
				return out, i, ErrParse
			}
			if !shell {
				switch c {
				case 'n':
					c = '\n'
				case 'r':
					c = '\r'
				case 't':
					c = '\t'
				case 's':
					c = ' '
				case '\\', '\'', '"':
				default:
					return out, i, ErrParse
				}
			} else if c != '\\' && c != '\'' && c != '"' && c != ' ' && c != '\t' && c != '$' && c != '`' {
				return out, i, ErrParse
			}
		}
		out = appendWiped(out, []byte{c})
	}
	if quote != 0 {
		return out, i, ErrParse
	}
	return out, i, nil
}

func unitEntries(data []byte) ([]entry, error) {
	out := []entry{}
	service := false
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(out) >= 4096 {
			return out, ErrParse
		}
		if len(line) == 0 || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			if line[len(line)-1] != ']' {
				return out, ErrParse
			}
			service = bytes.Equal(line, []byte("[Service]"))
			continue
		}
		if !service {
			continue
		}
		eq := bytes.IndexByte(line, '=')
		if eq < 0 {
			return out, ErrParse
		}
		name := bytes.TrimSpace(line[:eq])
		// EnvironmentFile and LoadCredential paths are NOT followed here.
		// The local policy must independently grant reads of their files.
		if !bytes.Equal(name, []byte("Environment")) {
			continue
		}
		content := bytes.TrimSpace(line[eq+1:])
		if len(content) == 0 {
			for _, e := range out {
				wipe(e.name)
				wipe(e.value)
			}
			out = nil
			continue
		}
		for pos := 0; pos < len(content); {
			value, end, err := word(content, pos, false)
			if err != nil {
				wipe(value)
				return out, ErrParse
			}
			eq := bytes.IndexByte(value, '=')
			if eq <= 0 || !validName(string(value[:eq])) {
				wipe(value)
				return out, ErrParse
			}
			out = append(out, entry{name: bytes.Clone(value[:eq]), value: bytes.Clone(value[eq+1:])})
			wipe(value)
			pos = end
			for pos < len(content) && (content[pos] == ' ' || content[pos] == '\t') {
				pos++
			}
		}
	}
	return out, nil
}

type xmlNode struct {
	tag      string
	text     []byte
	children []*xmlNode
}

func (n *xmlNode) destroy() {
	if n == nil {
		return
	}
	wipe(n.text)
	for _, child := range n.children {
		child.destroy()
	}
}

func plistEntries(data []byte) ([]entry, error) {
	if bytes.HasPrefix(data, []byte("bplist")) {
		return binaryPlistEntries(data)
	}
	root := &xmlNode{}
	defer root.destroy()
	stack := []*xmlNode{root}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	nodes := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, ErrParse
		}
		switch token := token.(type) {
		case xml.StartElement:
			nodes++
			if len(stack) > 64 || nodes > 4096 || token.Name.Space != "" {
				return nil, ErrParse
			}
			n := &xmlNode{tag: token.Name.Local}
			parent := stack[len(stack)-1]
			parent.children = append(parent.children, n)
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) <= 1 {
				return nil, ErrParse
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			parent := stack[len(stack)-1]
			parent.text = appendWiped(parent.text, token)
		}
	}
	if len(stack) != 1 || len(root.children) != 1 || root.children[0].tag != "plist" {
		return nil, ErrParse
	}
	plist := root.children[0]
	if len(plist.children) != 1 || plist.children[0].tag != "dict" || len(bytes.TrimSpace(root.text)) > 0 || len(bytes.TrimSpace(plist.text)) > 0 {
		return nil, ErrParse
	}
	dict := plist.children[0]
	if len(dict.children)%2 != 0 || len(bytes.TrimSpace(dict.text)) > 0 {
		return nil, ErrParse
	}
	var environment *xmlNode
	for i := 0; i < len(dict.children); i += 2 {
		if dict.children[i].tag != "key" {
			return nil, ErrParse
		}
		if bytes.Equal(dict.children[i].text, []byte("EnvironmentVariables")) {
			if environment != nil {
				return nil, ErrParse
			}
			environment = dict.children[i+1]
		}
	}
	if environment == nil {
		return []entry{}, nil
	}
	if environment.tag != "dict" || len(environment.children)%2 != 0 || len(bytes.TrimSpace(environment.text)) > 0 {
		return nil, ErrParse
	}
	out := []entry{}
	for i := 0; i < len(environment.children); i += 2 {
		k, v := environment.children[i], environment.children[i+1]
		if k.tag != "key" || v.tag != "string" || len(k.children) > 0 || len(v.children) > 0 || !validName(string(k.text)) {
			return out, ErrParse
		}
		out = append(out, entry{name: bytes.Clone(k.text), value: bytes.Clone(v.text)})
	}
	return out, nil
}
