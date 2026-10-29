//go:build unix

package targets

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"

	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// launchdEnvHandler sets one key in the existing plist's top-level
// EnvironmentVariables dict, leaving every other byte of the plist
// untouched. It edits the XML text surgically rather than parsing and
// re-serializing the whole plist, the same reason env-file is line-surgical:
// a full round-trip through a generic XML/plist encoder is not obliged to
// reproduce the original's formatting, comments or key order. It stays in
// []byte throughout, so the neighbouring variables of the dict — other
// services' secrets — can be wiped, never left in an immutable string.
//
// Because it edits text, it must be sure of where it is editing. A byte
// search for "<key>EnvironmentVariables</key>" is not that: a comment, a
// CDATA section or a <string> can carry a copy of it ahead of the real key,
// and the value would land in argv or in a comment. The document is
// therefore tokenized (encoding/xml, the same grammar launchd's own parser
// reads) and the dict is located by its position in the token stream: the
// value of the key "EnvironmentVariables" among the children of the root
// <plist>'s own <dict>. The dict must hold plain key/scalar entries only;
// anything else is refused.
type launchdEnvHandler struct{}

const envVarsKey = "EnvironmentVariables"

var (
	strOpen  = []byte("<string>")
	strClose = []byte("</string>")
)

func isXMLSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }

// envLoc is where the EnvironmentVariables dict and, inside it, the
// wanted field's entry sit, as absolute byte offsets into the plist:
// [start, end) is the dict's content (just after its "<dict>", just before its
// "</dict>"), entry the field's value element.
type envLoc struct {
	start, end int
	entry      stringEntry
}

// stringEntry: found=false means the key is not in the dict. tokStart/tokEnd
// span the whole value element (`<string>…</string>` or `<string/>`),
// textStart/textEnd its text (equal for an empty `<string/>`).
type stringEntry struct {
	found              bool
	tokStart, tokEnd   int
	textStart, textEnd int
}

var envScalarElements = map[string]bool{"string": true, "integer": true, "real": true, "true": true, "false": true, "data": true, "date": true}

func plistMalformed() error { return writeFailed("plist is not well-formed XML") }

func isBlank(b []byte) bool {
	for _, c := range b {
		if !isXMLSpace(c) {
			return false
		}
	}
	return true
}

// locateEnvDict walks plist's tokens once. Every error is a class and a
// reason of this package's own wording: the decoder's message can quote the
// text it choked on, and the text is a file full of other services' secrets.
func locateEnvDict(plist []byte, field string) (envLoc, error) {
	dec := xml.NewDecoder(bytes.NewReader(plist))
	var (
		loc         envLoc
		stack       []string
		keyBuf      []byte
		topKey      string
		topKeyReady bool
		inEnv, done bool
		envKey      string
		envKeyReady bool
		entryOpen   bool
	)
	for {
		before := int(dec.InputOffset())
		tok, err := dec.RawToken()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return envLoc{}, plistMalformed()
		}
		after := int(dec.InputOffset())
		switch t := tok.(type) {
		case xml.StartElement:
			name := t.Name.Local
			selfClosing := bytes.HasSuffix(plist[before:after], []byte("/>"))
			stack = append(stack, name)
			n := len(stack)
			switch {
			case inEnv:
				if len(t.Attr) > 0 {
					return envLoc{}, writeFailed("EnvironmentVariables dict holds an element with attributes; not supported")
				}
				switch {
				case n > 4:
					return envLoc{}, writeFailed("EnvironmentVariables dict holds nested elements; not supported")
				case name == "dict" || name == "array":
					return envLoc{}, writeFailed("EnvironmentVariables dict holds comments or nested containers; not supported")
				case name == "key":
					if envKeyReady {
						return envLoc{}, plistMalformed()
					}
					keyBuf = keyBuf[:0]
				case envScalarElements[name]:
					if !envKeyReady {
						return envLoc{}, plistMalformed()
					}
					envKeyReady = false
					if envKey == field {
						if loc.entry.found {
							return envLoc{}, writeFailed("EnvironmentVariables has more than one entry for %q; refusing to guess which is current", field)
						}
						if name != "string" {
							return envLoc{}, writeFailed("existing entry for %q is not a string", field)
						}
						loc.entry = stringEntry{found: true, tokStart: before, textStart: after, textEnd: after, tokEnd: after}
						entryOpen = true
					}
				default:
					return envLoc{}, writeFailed("EnvironmentVariables dict holds an unknown element; not supported")
				}
			case n == 3 && stack[0] == "plist" && stack[1] == "dict":
				if name == "key" {
					keyBuf = keyBuf[:0]
					topKeyReady = false
					break
				}
				if topKeyReady && topKey == envVarsKey {
					if name != "dict" {
						return envLoc{}, writeFailed("EnvironmentVariables key is not followed by <dict>")
					}
					if selfClosing {
						return envLoc{}, writeFailed("EnvironmentVariables is an empty <dict/>; not supported yet")
					}
					if done {
						return envLoc{}, writeFailed("plist has more than one %s key", envVarsKey)
					}
					inEnv = true
					loc.start = after
				}
				topKeyReady = false
			}
		case xml.CharData:
			switch {
			case inEnv && len(stack) == 3 && !isBlank(t):
				return envLoc{}, plistMalformed()
			case inEnv && len(stack) == 4 && stack[3] == "key", !inEnv && len(stack) == 3 && stack[2] == "key":
				keyBuf = append(keyBuf, t...)
			}
		case xml.Comment, xml.Directive, xml.ProcInst:
			// A comment, directive or processing instruction inside the dict is
			// refused: the entry is edited as text, and a comment that holds a
			// copy of an entry is something nobody should have to reason about.
			if inEnv {
				return envLoc{}, writeFailed("EnvironmentVariables dict holds comments or nested containers; not supported")
			}
		case xml.EndElement:
			n := len(stack)
			if n == 0 || stack[n-1] != t.Name.Local {
				return envLoc{}, plistMalformed()
			}
			name := stack[n-1]
			switch {
			case inEnv && n == 4 && name == "key":
				envKey, envKeyReady = string(keyBuf), true
			case inEnv && n == 4 && entryOpen && name != "key":
				loc.entry.textEnd, loc.entry.tokEnd = before, after
				entryOpen = false
			case inEnv && n == 3:
				if envKeyReady {
					return envLoc{}, plistMalformed()
				}
				loc.end = before
				inEnv, done = false, true
			case !inEnv && n == 3 && name == "key":
				topKey, topKeyReady = string(keyBuf), true
			}
			stack = stack[:n-1]
		}
	}
	if len(stack) != 0 {
		return envLoc{}, writeFailed("plist has an unclosed element")
	}
	if !done {
		return envLoc{}, writeFailed("plist has no <key>%s</key> dict", envVarsKey)
	}
	return loc, nil
}

func (launchdEnvHandler) foldsExisting() bool { return true }

func (launchdEnvHandler) build(existing []byte, exists bool, t runnerproto.Target, v secret.Value) ([]byte, error) {
	if !exists {
		return nil, writeFailed("launchd-env target does not exist yet; it only edits an existing plist")
	}
	val := bytesOf(v)
	defer wipe(val)
	var esc bytes.Buffer
	if err := xml.EscapeText(&esc, val); err != nil {
		return nil, writeFailed("escape value for plist: %v", err)
	}
	defer func() { wipe(esc.Bytes()) }()
	// xml.EscapeText swaps a character XML cannot hold (a control character)
	// for U+FFFD instead of failing; the fingerprint would then attest to the
	// altered value. Refuse anything that does not survive the round trip.
	rt, err := xmlUnescape(esc.Bytes())
	defer wipe(rt)
	if err != nil || !bytes.Equal(rt, val) {
		return nil, denied("value cannot be represented in a plist string")
	}

	loc, err := locateEnvDict(existing, t.Field)
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	out.Grow(len(existing) + esc.Len() + len(t.Field) + 32)
	if e := loc.entry; e.found {
		out.Write(existing[:e.tokStart])
		out.Write(strOpen)
		out.Write(esc.Bytes())
		out.Write(strClose)
		out.Write(existing[e.tokEnd:])
	} else {
		out.Write(existing[:loc.end])
		out.WriteString("<key>" + t.Field + "</key>")
		out.Write(strOpen)
		out.Write(esc.Bytes())
		out.Write(strClose)
		out.Write(existing[loc.end:])
	}
	return out.Bytes(), nil
}

func (launchdEnvHandler) readBack(content []byte, t runnerproto.Target) (secret.Value, error) {
	loc, err := locateEnvDict(content, t.Field)
	if err != nil {
		return secret.Value{}, err
	}
	if !loc.entry.found {
		return secret.Value{}, writeFailed("field %q not found in the EnvironmentVariables dict of the written plist", t.Field)
	}
	unescaped, err := xmlUnescape(content[loc.entry.textStart:loc.entry.textEnd])
	if err != nil {
		// The decoder's own message can quote the text it choked on — a
		// fragment of the value — so none of it is passed on.
		return secret.Value{}, writeFailed("unescape plist value: malformed XML text")
	}
	return secret.New(unescaped), nil
}

// xmlUnescape decodes the character data of a plist <string> without ever
// building a Go string from it, so the result can be wiped.
func xmlUnescape(raw []byte) ([]byte, error) {
	doc := make([]byte, 0, len(raw)+7)
	doc = append(doc, "<r>"...)
	doc = append(doc, raw...)
	doc = append(doc, "</r>"...)
	defer wipe(doc)

	dec := xml.NewDecoder(bytes.NewReader(doc))
	var out []byte
	for {
		tok, err := dec.RawToken()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			wipe(out)
			return nil, errors.New("malformed")
		}
		if cd, ok := tok.(xml.CharData); ok {
			out = append(out, cd...)
		}
	}
}
