//go:build unix

package targets

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// jsonPathHandler sets one string value at a dotted key path inside a JSON
// object — mcp-config's `mcpServers.<name>.env.<VAR>`. Unlike env-file and
// launchd-env this does a full decode/re-encode round trip: JSON has no
// comment or key-order convention worth preserving byte for byte the way a
// shell-sourced env file or a hand-edited plist does.
//
// encoding/json only decodes onto Go strings, so the existing document —
// neighbouring values included, potentially other services' secrets in the
// same file — comes back from decodeObject as Go strings that cannot be
// wiped; that half is an accepted, documented limitation (see decodeObject),
// not something this package's own code controls. The value being written
// is a different matter: json.Marshal also only accepts a Go string, but
// jsonQuoteBytes below builds the equivalent JSON string literal straight
// from the secret's own []byte, via a json.RawMessage, so build wipes its own
// quoted copy once Marshal has read it, instead of holding a Go string of it
// for the rest of the call.
//
// That wipe does not reach every copy: encoding/json's own encoder keeps a
// pool of internal scratch buffers (encode.go's encodeState, sync.Pool'd)
// that it compacts the whole output through, including this value's quoted
// bytes, before returning out — those buffers are process-lifetime, reused
// by unrelated encodes, and outside this package's reach. That is why build
// does not call json.MarshalIndent: MarshalIndent calls Marshal into a
// buffer of its own, then re-indents that into a second buffer, and hands
// back only the second one — the first is a copy of this value this package
// never gets a handle to, so it can never wipe it. build calls Marshal and
// Indent itself instead, into two buffers it owns and wipes in turn.
//
// Owning the buffer is not the same as it never growing: json.Indent can
// still reallocate its destination mid-call if what build reserved for it
// turns out too small, and whatever backing array it abandons along the way
// — a full copy of the document, this value included — is gone before build
// ever gets a handle on it, the same way MarshalIndent's hidden first buffer
// was. build avoids that by measuring the exact number of bytes Indent will
// add before it ever runs on the real value (see the comment above that
// step) and reserving at least that many (see the reserve comment below for
// why "at least", not "exactly"). json.Marshal's own compact pass has the
// same kind of hidden growth (its encodeState scratch buffer can itself
// reallocate, both from the pool copy above and from the HTML-escaping
// pass over this value's own bytes) and is a limitation of encoding/json
// itself, open regardless of which of its entry points build calls.
type jsonPathHandler struct{}

func splitField(field string) ([]string, error) {
	if field == "" {
		return nil, denied("field is required for a JSON-path target")
	}
	segs := strings.Split(field, ".")
	for _, s := range segs {
		if s == "" {
			return nil, denied("field %q has an empty path segment", field)
		}
	}
	return segs, nil
}

// decodeObject decodes content as exactly one JSON object. The error it
// returns carries a class and, for a syntax error, a byte offset — never the
// decoder's own message: encoding/json quotes a character of the input in it
// ("invalid character 'k' looking for beginning of value"), and the input is
// a file that holds other servers' secrets next to the one being written.
//
// This is also the one unavoidable boundary where a secret already on disk
// becomes an un-wipeable Go string: encoding/json's decoder only ever
// produces string, not []byte, for a JSON string value, and that is a
// private implementation detail of the standard library, not something a
// caller can pass a buffer into. Reading the boundary out from under
// encoding/json — a hand-written decoder — is not done here; it is why the
// value going the other way, into the document (resolveJSONPath, jsonQuoteBytes),
// is built without ever needing this decoder to touch it.
func decodeObject(content []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(content))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, writeFailed("%s", jsonErrClass(err))
	}
	// Decoder stops after the first value: a second document (or garbage)
	// after it would be silently dropped by the re-encode.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, writeFailed("JSON has data after the top-level object")
		}
		return nil, writeFailed("%s", jsonErrClass(err))
	}
	if doc == nil {
		return nil, writeFailed("JSON top level is not an object")
	}
	return doc, nil
}

func jsonErrClass(err error) string {
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syn):
		return fmt.Sprintf("target is not valid JSON (syntax error at byte %d)", syn.Offset)
	case errors.As(err, &typ):
		return "JSON top level is not an object"
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		return "target is not valid JSON (unexpected end of input)"
	default:
		return "target is not valid JSON"
	}
}

func (jsonPathHandler) foldsExisting() bool { return true }

// reserveJSONIndentBuf is the byte count build.Grow's for its json.Indent
// destination, behind a test seam — same convention as wipe/
// computeFingerprint. Natural input never exercises the buf.Cap() check
// below (the measurement above already makes an undersized reservation
// unreachable); a test overrides this var to force one anyway and prove the
// fail-closed branch actually refuses instead of silently returning content
// from a run that already reallocated and abandoned an unwiped copy.
var reserveJSONIndentBuf = func(n int) int { return n }

func (jsonPathHandler) build(existing []byte, exists bool, t runnerproto.Target, v secret.Value) ([]byte, error) {
	segs, err := splitField(t.Field)
	if err != nil {
		return nil, err
	}
	doc := map[string]any{}
	if exists && len(bytes.TrimSpace(existing)) > 0 {
		var err error
		if doc, err = decodeObject(existing); err != nil {
			return nil, err
		}
		if doc == nil {
			// decodeObject already refuses a top-level JSON null; this is
			// defense in depth for that check specifically, right where doc
			// is next written to. If decodeObject's own check ever regressed,
			// silently substituting {} here would turn a refusal into a
			// write — the same refusal, not a fallback, is the only safe
			// response.
			return nil, writeFailed("JSON top level is not an object")
		}
	}

	val := bytesOf(v)
	defer wipe(val)
	// json.Marshal swaps invalid UTF-8 for U+FFFD instead of failing.
	if !utf8.Valid(val) {
		return nil, denied("value is not valid UTF-8; a JSON string cannot hold it byte for byte")
	}
	quoted := jsonQuoteBytes(val)
	// Wiped once Marshal below has copied out of it, not before: doc holds
	// this same slice (via the json.RawMessage assigned below), and wiping
	// it here is what erases that copy — doc itself is otherwise just
	// dropped unwiped along with everything else this function allocated.
	defer wipe(quoted)

	m, leaf, err := resolveJSONPath(doc, segs)
	if err != nil {
		return nil, err
	}

	// Indent only ever adds whitespace at structural boundaries (braces,
	// brackets, commas, colons) and copies whatever is inside a string
	// through unchanged, so exactly how many bytes it adds over its compact
	// input depends on the document's shape alone — never on this field's
	// value, its length, or its content. Measuring that overhead now, with
	// an empty string standing in at this same path, gets the exact number
	// to reserve for the real pass below without the real value ever going
	// near a buffer json.Indent might still need to grow.
	m[leaf] = json.RawMessage(`""`)
	measureCompact, err := json.Marshal(doc)
	if err != nil {
		return nil, writeFailed("encode JSON failed")
	}
	// Neither of these ever holds the real value (the placeholder above is
	// the literal `""`), only whatever neighbouring, already-un-wipeable
	// content decodeObject read in — wiped anyway, for symmetry with every
	// other buffer build touches, not because it closes a gap here.
	defer wipe(measureCompact)
	var measureBuf bytes.Buffer
	if err := json.Indent(&measureBuf, measureCompact, "", "  "); err != nil {
		return nil, writeFailed("encode JSON failed")
	}
	overhead := measureBuf.Len() - len(measureCompact)
	defer wipe(measureBuf.Bytes())

	// json.RawMessage carries quoted's bytes straight into the re-encode
	// (MarshalJSON just returns them as-is): the map never holds a Go string
	// copy of the secret on the way out, only on the way back in through
	// decodeObject's read of the file we ourselves just wrote — see its
	// comment.
	m[leaf] = json.RawMessage(quoted)

	compact, err := json.Marshal(doc)
	if err != nil {
		// Not %v: the only thing that can make this fail is the value's own
		// json.RawMessage (everything else in doc came back from
		// decodeObject, which only ever produces re-encodable values), and
		// encoding/json's error on a malformed RawMessage quotes a byte of
		// it — exactly the failure jsonErrClass exists to avoid on the way
		// in, mirrored here on the way back out.
		return nil, writeFailed("encode JSON failed")
	}
	defer wipe(compact)

	// json.Indent's own implementation unconditionally calls
	// dst.Grow(2*len(src)) before it writes anything — so reserving only
	// the exact measured size here still lets Indent itself override a
	// tighter reservation with its own, larger floor for the common case
	// where 2x would have been enough anyway (harmless on its own, since
	// nothing has been written yet at that point, but it makes a smaller
	// reservation here pointless: Indent would just grow past it right
	// away). Reserving whichever of the two is bigger means Indent's own
	// Grow call always finds enough already there and never touches the
	// buffer again itself, whether the document is ordinary or, like the
	// array case above, one where indentation truly exceeds double.
	reserve := len(compact) + overhead
	if naive := 2*len(compact) + 1; naive > reserve {
		reserve = naive
	}
	var buf bytes.Buffer
	buf.Grow(reserveJSONIndentBuf(reserve))
	reservedCap := buf.Cap()
	// Captured before Indent runs, not after: a slice header is its own
	// (pointer, len, cap) tuple, so orig keeps referring to this exact
	// backing array even if Indent later points buf itself at a new one.
	// This is honestly only partial cover, not a full one: encoding/json's
	// appendIndent writes into (a growing series of copies of) this same
	// array via Go's append, so if the reservation really is too small —
	// the case the measurement above exists to make unreachable — the
	// specific copy holding the document in full, this value included, is
	// one of append's own intermediate arrays, not this one; only this
	// slot's own filled prefix is ever wiped here. That gap is why the exact
	// measurement, not this wipe, is the real guarantee; this wipe is
	// best-effort on top of it, for whatever this reservation itself did
	// hold before Indent moved on.
	orig := buf.AvailableBuffer()
	if err := json.Indent(&buf, compact, "", "  "); err != nil {
		wipe(orig[:cap(orig)])
		wipe(buf.Bytes())
		return nil, writeFailed("encode JSON failed")
	}
	if buf.Cap() != reservedCap {
		// The measurement above exists to make this unreachable: Indent
		// reallocated its destination anyway, which means the document was
		// copied at least once, this value included, into memory this
		// function never gets to wipe (see orig's comment above). Fail
		// closed rather than hand back content that came from a run that
		// already leaked a copy — no amount of wiping here fixes that, only
		// never reaching this branch does.
		wipe(orig[:cap(orig)])
		wipe(buf.Bytes())
		return nil, writeFailed("encode JSON failed")
	}
	indented := buf.Bytes()
	defer wipe(indented)

	out := make([]byte, len(indented)+1)
	n := copy(out, indented)
	out[n] = '\n'
	return out, nil
}

// resolveJSONPath walks doc to the map that directly holds the field's last
// path segment, creating any missing intermediate object along the way, and
// validates the leaf itself is a secret-shaped slot: absent, null, or an
// existing string. An object or array at the field is somebody's
// configuration; replacing it with the secret string would destroy it, and
// the fingerprint would still match.
//
// It returns the map and key rather than doing the assignment itself: build
// needs to write this same slot twice, once with a placeholder to measure
// json.Indent's overhead and once with the real value, and the second write
// must not re-run this validation against the placeholder it just wrote.
func resolveJSONPath(doc map[string]any, segs []string) (map[string]any, string, error) {
	m := doc
	for _, s := range segs[:len(segs)-1] {
		next, ok := m[s]
		if !ok {
			nm := map[string]any{}
			m[s] = nm
			m = nm
			continue
		}
		nm, ok := next.(map[string]any)
		if !ok {
			return nil, "", writeFailed("path segment %q is not a JSON object", s)
		}
		m = nm
	}
	leaf := segs[len(segs)-1]
	switch m[leaf].(type) {
	case nil, string:
	default:
		return nil, "", writeFailed("existing value at the field is not a string; refusing to replace it")
	}
	return m, leaf, nil
}

const hexDigits = "0123456789abcdef"

// jsonQuoteBytes returns val as a JSON string literal, quotes included,
// without ever copying it into a Go string. It escapes exactly what JSON
// syntax requires — '"', '\', and the C0 control characters — and passes
// every other byte through unchanged, including multi-byte UTF-8 sequences
// (val is validated UTF-8 by the caller) and '<', '>', '&', which encoding/
// json escapes for HTML/script safety by its own default: build's Marshal
// call here never turns that off, so the compact pass it runs over a
// json.RawMessage's bytes applies that escaping to this value exactly as it
// would to any other string in the document, and this function does not need
// to duplicate it.
// A var, not a plain func, only so TestJSONEncodeErrorLeaksNoByteOfValue can
// substitute a deliberately broken quoter and prove the encode-failure path
// above stays silent about the value even when this function has a bug.
var jsonQuoteBytes = func(val []byte) []byte {
	out := make([]byte, 0, len(val)+2)
	out = append(out, '"')
	for _, c := range val {
		switch {
		case c == '"' || c == '\\':
			out = append(out, '\\', c)
		case c == '\n':
			out = append(out, '\\', 'n')
		case c == '\r':
			out = append(out, '\\', 'r')
		case c == '\t':
			out = append(out, '\\', 't')
		case c < 0x20:
			out = append(out, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xF])
		default:
			out = append(out, c)
		}
	}
	out = append(out, '"')
	return out
}

func getJSONPath(doc map[string]any, segs []string) (string, error) {
	m := doc
	for _, s := range segs[:len(segs)-1] {
		next, ok := m[s]
		if !ok {
			return "", writeFailed("path segment %q not found in written JSON", s)
		}
		nm, ok := next.(map[string]any)
		if !ok {
			return "", writeFailed("path segment %q is not a JSON object", s)
		}
		m = nm
	}
	leaf, ok := m[segs[len(segs)-1]]
	if !ok {
		return "", writeFailed("field not found in written JSON")
	}
	s, ok := leaf.(string)
	if !ok {
		return "", writeFailed("field in written JSON is not a string")
	}
	return s, nil
}

func (jsonPathHandler) readBack(content []byte, t runnerproto.Target) (secret.Value, error) {
	segs, err := splitField(t.Field)
	if err != nil {
		return secret.Value{}, err
	}
	doc, err := decodeObject(content)
	if err != nil {
		return secret.Value{}, err
	}
	s, err := getJSONPath(doc, segs)
	if err != nil {
		return secret.Value{}, err
	}
	return secret.New([]byte(s)), nil
}
