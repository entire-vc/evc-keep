package discover

import (
	"bytes"
	"encoding/json"
	"unicode/utf16"
	"unicode/utf8"
)

// JSON strings are decoded into mutable byte slices, rather than immutable
// Go strings containing values. The whole temporary tree is wiped on return.
type jsonNode struct {
	kind     byte
	text     []byte
	keys     [][]byte
	children []*jsonNode
}

func (n *jsonNode) destroy() {
	if n == nil {
		return
	}
	wipe(n.text)
	for _, k := range n.keys {
		wipe(k)
	}
	for _, c := range n.children {
		c.destroy()
	}
}
func (n *jsonNode) get(key string) *jsonNode {
	if n.kind != '{' {
		return nil
	}
	for i, k := range n.keys {
		if bytes.Equal(k, []byte(key)) {
			return n.children[i]
		}
	}
	return nil
}

type jsonParser struct {
	data       []byte
	pos, nodes int
}

func (p *jsonParser) space() {
	for p.pos < len(p.data) && bytes.ContainsRune([]byte(" \r\n\t"), rune(p.data[p.pos])) {
		p.pos++
	}
}

func mcpEntries(data []byte) ([]entry, error) {
	if !json.Valid(data) || !utf8.Valid(data) {
		return nil, ErrParse
	}
	p := jsonParser{data: data}
	root, err := p.node(0)
	defer root.destroy()
	if err != nil {
		return nil, ErrParse
	}
	servers := root.get("mcpServers")
	if servers == nil || servers.kind != '{' {
		return nil, ErrParse
	}
	out := []entry{}
	for _, server := range servers.children {
		if server.kind != '{' {
			return out, ErrParse
		}
		env := server.get("env")
		if env == nil {
			continue
		}
		if env.kind != '{' {
			return out, ErrParse
		}
		for i, v := range env.children {
			if v.kind != '"' || !validName(string(env.keys[i])) {
				return out, ErrParse
			}
			out = append(out, entry{name: bytes.Clone(env.keys[i]), value: bytes.Clone(v.text)})
		}
	}
	return out, nil
}

func (p *jsonParser) node(depth int) (*jsonNode, error) {
	p.space()
	p.nodes++
	n := &jsonNode{}
	if depth > 64 || p.nodes > 4096 || p.pos >= len(p.data) {
		return n, ErrParse
	}
	n.kind = p.data[p.pos]
	switch n.kind {
	case '"':
		b, err := p.str()
		n.text = b
		return n, err
	case '{', '[':
		p.pos++
		p.space()
		end := byte('}')
		if n.kind == '[' {
			end = ']'
		}
		if p.data[p.pos] == end {
			p.pos++
			return n, nil
		}
		for {
			if n.kind == '{' {
				if len(n.keys) >= 256 {
					return n, ErrParse
				}
				k, err := p.str()
				if err != nil || len(k) > 256 {
					wipe(k)
					return n, ErrParse
				}
				for _, old := range n.keys {
					if bytes.Equal(old, k) {
						wipe(k)
						return n, ErrParse
					}
				}
				n.keys = append(n.keys, k)
				p.space()
				p.pos++ // colon, already validated by json.Valid
			}
			child, err := p.node(depth + 1)
			n.children = append(n.children, child)
			if err != nil {
				return n, err
			}
			p.space()
			if p.data[p.pos] == end {
				p.pos++
				return n, nil
			}
			p.pos++
			p.space()
		}
	default:
		// Numbers, booleans and null are never secret env string values.
		for p.pos < len(p.data) && !bytes.ContainsRune([]byte(",]} \r\n\t"), rune(p.data[p.pos])) {
			p.pos++
		}
		return n, nil
	}
}

func (p *jsonParser) str() ([]byte, error) {
	p.space()
	if p.pos >= len(p.data) || p.data[p.pos] != '"' {
		return nil, ErrParse
	}
	p.pos++
	out := []byte{}
	for p.pos < len(p.data) {
		c := p.data[p.pos]
		p.pos++
		if c == '"' {
			return out, nil
		}
		if c != '\\' {
			out = appendWiped(out, []byte{c})
			continue
		}
		c = p.data[p.pos]
		p.pos++
		switch c {
		case '"', '\\', '/':
			out = appendWiped(out, []byte{c})
		case 'b':
			out = appendWiped(out, []byte{'\b'})
		case 'f':
			out = appendWiped(out, []byte{'\f'})
		case 'n':
			out = appendWiped(out, []byte{'\n'})
		case 'r':
			out = appendWiped(out, []byte{'\r'})
		case 't':
			out = appendWiped(out, []byte{'\t'})
		case 'u':
			r := p.hexRune()
			if utf16.IsSurrogate(r) {
				if r < 0xd800 || r > 0xdbff || p.pos+6 > len(p.data) || p.data[p.pos] != '\\' || p.data[p.pos+1] != 'u' {
					return out, ErrParse
				}
				p.pos += 2
				low := p.hexRune()
				if low < 0xdc00 || low > 0xdfff {
					return out, ErrParse
				}
				r = utf16.DecodeRune(r, low)
			}
			var encoded [utf8.UTFMax]byte
			count := utf8.EncodeRune(encoded[:], r)
			out = appendWiped(out, encoded[:count])
			wipe(encoded[:])
		default:
			return out, ErrParse
		}
	}
	return out, ErrParse
}

func (p *jsonParser) hexRune() rune {
	var r rune
	for i := 0; i < 4; i++ {
		c := p.data[p.pos]
		p.pos++
		r <<= 4
		switch {
		case c >= '0' && c <= '9':
			r += rune(c - '0')
		case c >= 'a' && c <= 'f':
			r += rune(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			r += rune(c - 'A' + 10)
		}
	}
	return r
}
