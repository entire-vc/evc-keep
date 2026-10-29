//go:build unix

package targets

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

func TestMCPConfigSetsDottedPathCreatesMissingObjects(t *testing.T) {
	dir := realDir(t)
	path := filepath.Join(dir, "mcp.json")
	mustWriteFile(t, path, []byte(`{"mcpServers":{"other":{"command":"x"}}}`), 0o600)

	uids, gids := noAgents()
	if _, err := Write(target(runnerproto.TargetMCPConfig, path, "mcpServers.myserver.env.API_KEY"), newValue("v1"), uids, gids, testFPKey(t)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(mustReadFile(t, path), &doc); err != nil {
		t.Fatalf("written file is not valid JSON: %v", err)
	}
	servers := doc["mcpServers"].(map[string]any)
	if _, ok := servers["other"]; !ok {
		t.Fatal("pre-existing sibling server was dropped")
	}
	my := servers["myserver"].(map[string]any)
	env := my["env"].(map[string]any)
	if env["API_KEY"] != "v1" {
		t.Fatalf("API_KEY = %v, want v1", env["API_KEY"])
	}
}

func TestMCPConfigCreatesWhenMissing(t *testing.T) {
	dir := realDir(t)
	path := filepath.Join(dir, "mcp.json")
	uids, gids := noAgents()
	fp, err := Write(target(runnerproto.TargetMCPConfig, path, "mcpServers.s.env.KEY"), newValue("v"), uids, gids, testFPKey(t))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if fp == "" {
		t.Fatal("empty fingerprint")
	}
}

func TestJSONPathNonObjectSegmentRefused(t *testing.T) {
	dir := realDir(t)
	path := filepath.Join(dir, "mcp.json")
	mustWriteFile(t, path, []byte(`{"mcpServers":"not-an-object"}`), 0o600)
	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetMCPConfig, path, "mcpServers.s.env.KEY"), newValue("v"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrWrite, "path segment that is not a JSON object")
}

func TestJSONPathMalformedExistingRefused(t *testing.T) {
	dir := realDir(t)
	path := filepath.Join(dir, "mcp.json")
	mustWriteFile(t, path, []byte(`{not json`), 0o600)
	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetMCPConfig, path, "mcpServers.s.env.KEY"), newValue("v"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrWrite, "malformed existing JSON target")
}

// A malformed existing config may hold the *neighbouring* secrets of other
// servers. encoding/json's syntax errors quote a character of the input
// ("invalid character 'k' looking for beginning of value"), so passing the
// decoder's error through puts a fragment of that content into the text.
// Only the class and the byte offset may leave.
func TestJSONPathMalformedExistingErrorLeaksNothing(t *testing.T) {
	c := canary.New()
	for name, existing := range map[string]string{
		"unquoted-value":   `{"other":{"env":{"TOKEN":` + c.Value(0) + `}}}`,
		"unquoted-key":     `{` + c.Value(0) + `: 1}`,
		"array-at-top":     `["` + c.Value(0) + `"]`,
		"truncated-inside": `{"other":{"env":{"TOKEN":"` + c.Value(0),
	} {
		t.Run(name, func(t *testing.T) {
			dir := realDir(t)
			path := filepath.Join(dir, "mcp.json")
			mustWriteFile(t, path, []byte(existing), 0o600)
			uids, gids := noAgents()
			_, err := Write(target(runnerproto.TargetMCPConfig, path, "mcpServers.s.env.KEY"), newValue("v"), uids, gids, testFPKey(t))
			wantErr(t, err, ErrWrite, "malformed existing JSON target")
			msg := err.Error()
			first := "'" + c.Value(0)[:1] + "'"
			if c.In(msg) || strings.Contains(msg, first) || strings.Contains(msg, "invalid character") {
				t.Fatalf("error text carries a fragment of the file's content: %v", err)
			}
		})
	}
}

// TestJSONPathTrailingDataRefused: encoding/json's Decoder stops after the
// first value, so a second document in the file would be silently dropped by
// the re-encode.
func TestJSONPathTrailingDataRefused(t *testing.T) {
	dir := realDir(t)
	path := filepath.Join(dir, "mcp.json")
	existing := `{"a":"b"}{"c":"d"}`
	mustWriteFile(t, path, []byte(existing), 0o600)
	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetMCPConfig, path, "mcpServers.s.env.KEY"), newValue("v"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrWrite, "trailing data after the JSON object")
	if got := string(mustReadFile(t, path)); got != existing {
		t.Fatalf("file changed despite the refusal: %q", show([]byte(got)))
	}
}

// Garbage after the top-level object goes through the same sanitised error
// path, and a bare `null` (which encoding/json decodes into a nil map
// without an error) must be refused, not panic on assignment.
func TestJSONPathTrailingGarbageErrorLeaksNothing(t *testing.T) {
	c := canary.New()
	path := filepath.Join(realDir(t), "mcp.json")
	mustWriteFile(t, path, []byte(`{"a":"b"} `+c.Value(0)), 0o600)
	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetMCPConfig, path, "mcpServers.s.env.KEY"), newValue("v"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrWrite, "garbage after the JSON object")
	msg := err.Error()
	if strings.Contains(msg, "'"+c.Value(0)[:1]+"'") || strings.Contains(msg, "invalid character") {
		t.Fatalf("error text carries a fragment of the file's content: %v", err)
	}
}

func TestJSONPathNullDocumentRefused(t *testing.T) {
	path := filepath.Join(realDir(t), "mcp.json")
	mustWriteFile(t, path, []byte(`null`), 0o600)
	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetMCPConfig, path, "mcpServers.s.env.KEY"), newValue("v"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrWrite, "top-level null")
}

// TestJSONQuoteBytesMatchesStandardLibraryStringEncoding: jsonQuoteBytes
// builds the JSON string literal for the secret value straight from its
// []byte, without ever holding it as a Go string (see jsonPathHandler's doc
// comment on why). This proves that avoiding the copy does not change the
// bytes produced: for every case that could plausibly diverge — quotes,
// backslashes, the short C0 escapes, other control characters, NUL, HTML
// metacharacters, the U+2028/U+2029 line separators, and multi-byte UTF-8
// including a character outside the BMP — embedding jsonQuoteBytes's output
// as a json.RawMessage inside the same document and marshalling it produces
// byte-for-byte what json.MarshalIndent would have produced from the
// equivalent Go string.
func TestJSONQuoteBytesMatchesStandardLibraryStringEncoding(t *testing.T) {
	cases := []struct {
		name string
		s    string
	}{
		{"empty", ""},
		{"plain", "plain"},
		{"quotes and backslash", `with "quotes" and \backslash\`},
		{"tab", "tab\ttab"},
		{"newline", "newline\nnewline"},
		{"carriage return", "cr\rcr"},
		{"other control chars", "control\x01\x02\x1f-chars"},
		{"nul byte", "nul\x00byte"},
		{"html metacharacters", "<script>alert(1)</script>&amp;"},
		{"line separators", "line separator pair"},
		{"multi-byte utf8 and astral", "emoji-🔑-and-中文"},
		{"del", "del\x7fchar"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := map[string]any{"k": json.RawMessage(jsonQuoteBytes([]byte(c.s)))}
			got, err := json.MarshalIndent(doc, "", "  ")
			if err != nil {
				t.Fatalf("marshal with jsonQuoteBytes output: %v", err)
			}
			want, err := json.MarshalIndent(map[string]any{"k": c.s}, "", "  ")
			if err != nil {
				t.Fatalf("reference marshal: %v", err)
			}
			if string(got) != string(want) {
				t.Fatalf("jsonQuoteBytes(%q):\n got  %s\n want %s", c.s, got, want)
			}
		})
	}
}

// TestMCPConfigFingerprintRoundTripsThroughByteQuoting is jsonpath's twin of
// TestLaunchdEnvFingerprintRoundTripsThroughXMLEscaping: a value carrying
// exactly the characters jsonQuoteBytes must escape, written through the
// full Write path and read back, must fingerprint as the same value that
// went in.
func TestMCPConfigFingerprintRoundTripsThroughByteQuoting(t *testing.T) {
	dir := realDir(t)
	path := filepath.Join(dir, "mcp.json")
	uids, gids := noAgents()
	key := testFPKey(t)
	val := canary.New().Value(0) + "&<>\"'\n\t\x01 tail"
	fp, err := Write(target(runnerproto.TargetMCPConfig, path, "mcpServers.s.env.KEY"), newValue(val), uids, gids, key)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	want, err := fingerprint.Compute(key, newValue(val))
	if err != nil {
		t.Fatal(err)
	}
	if fp != want {
		t.Fatalf("fingerprint of what was read back %q != fingerprint of the value %q", fp, want)
	}
}

// TestJSONEncodeErrorLeaksNoByteOfValue: build's encode-error path used to
// format json.MarshalIndent's own error text into the returned error
// (writeFailed("encode JSON: %v", err)). encoding/json's error on a
// malformed json.RawMessage quotes the offending byte straight out of the
// value that failed to encode — a real leak surface if jsonQuoteBytes ever
// stops producing valid JSON for some input. jsonQuoteBytes cannot actually
// do that today (see the differential test above and the mutation script's
// no-json-quote-* entries), so this substitutes a deliberately broken
// quoter — one that skips escaping '"' the way a regression in
// jsonQuoteBytes itself might — to reach the encode-error path for real, and
// checks build's message never carries a byte of the value regardless of
// what broke.
func TestJSONEncodeErrorLeaksNoByteOfValue(t *testing.T) {
	orig := jsonQuoteBytes
	defer func() { jsonQuoteBytes = orig }()
	jsonQuoteBytes = func(val []byte) []byte {
		out := make([]byte, 0, len(val)+2)
		out = append(out, '"')
		out = append(out, val...) // no escaping at all
		out = append(out, '"')
		return out
	}

	c := canary.New()
	dir := realDir(t)
	path := filepath.Join(dir, "mcp.json")
	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetMCPConfig, path, "mcpServers.s.env.KEY"), newValue(`"`+c.Value(0)), uids, gids, testFPKey(t))
	wantErr(t, err, ErrWrite, "encode JSON")
	msg := err.Error()
	first := "'" + c.Value(0)[:1] + "'"
	// Not just c.In(msg): encoding/json's error on a malformed RawMessage
	// quotes only the single offending byte, well short of the canary's
	// full match length — the same distinction its read-side sibling,
	// TestJSONPathMalformedExistingErrorLeaksNothing, already checks for.
	if c.In(msg) || strings.Contains(msg, first) || strings.Contains(msg, "invalid character") {
		t.Fatalf("encode-error message carries a fragment of the value: %v", err)
	}
}

// TestBuildWipesIntermediateJSONBuffers guards the fix that replaced build's
// single json.MarshalIndent call with separate json.Marshal and json.Indent
// calls into buffers build owns: MarshalIndent hands back only its second,
// re-indented buffer, so the first — a full copy of the encoded document,
// value included — was never reachable to wipe. build now owns both
// buffers (compact, indented) and wipes each in turn.
//
// testing.AllocsPerRun can't observe this — it counts allocations, not
// whether a specific one got zeroed. This goes through the wipe seam
// instead: wraps the package's wipe var to record a copy of every slice's
// content right before it's zeroed, then calls build directly (not through
// Write, which has read-back and secure-write copies of its own — noise
// this test isn't about) and checks what build itself actually wiped.
func TestBuildWipesIntermediateJSONBuffers(t *testing.T) {
	c := canary.New()
	val := c.Value(0)
	quotedForm := `"` + val + `"`

	type snapshot struct {
		before []byte // copy of the content, taken before wipe zeroed it
		live   []byte // the real slice, to check its post-call state
	}
	var snaps []snapshot
	orig := wipe
	defer func() { wipe = orig }()
	wipe = func(b []byte) {
		if len(b) > 0 {
			before := make([]byte, len(b))
			copy(before, b)
			snaps = append(snaps, snapshot{before: before, live: b})
		}
		orig(b)
	}

	h := jsonPathHandler{}
	tgt := target(runnerproto.TargetMCPConfig, "/unused", "mcpServers.s.env.KEY")
	out, err := h.build(nil, false, tgt, newValue(val))
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	// out is a separate allocation build makes after every wipe above has
	// already run (they're deferred, so they fire before build returns to
	// us): if out shared backing memory with any wiped buffer, this would
	// find zero bytes where the value belongs instead of the value itself —
	// the aliasing check, made by way of an ordinary content check rather
	// than comparing addresses directly.
	if !strings.Contains(string(out), quotedForm) {
		t.Fatalf("result missing the value intact (len %d)", len(out))
	}

	if len(snaps) == 0 {
		t.Fatal("wipe was never called")
	}
	for i, s := range snaps {
		for j, b := range s.live {
			if b != 0 {
				t.Fatalf("wiped slice %d not zero at byte %d after the call that was supposed to wipe it", i, j)
			}
		}
	}

	// build wipes four buffers of its own: val (bytesOf's copy, unquoted),
	// quoted (jsonQuoteBytes' output), compact (json.Marshal) and indented
	// (json.Indent). Only the last three carry the value in its JSON-quoted
	// form — this counts those specifically, so dropping either of the two
	// this fix introduced (compact, indented) fails it.
	quotedCopies := 0
	for _, s := range snaps {
		if strings.Contains(string(s.before), quotedForm) {
			quotedCopies++
		}
	}
	const wantQuotedCopies = 3 // quoted, compact, indented
	if quotedCopies < wantQuotedCopies {
		t.Fatalf("only %d wiped buffers held the value's JSON-quoted form, want at least %d (quoted, compact, indented)", quotedCopies, wantQuotedCopies)
	}
}

// TestBuildIndentReservationHoldsForArrayHeavyDocument guards the fix that
// replaced build's `buf.Grow(2*len(compact)+1)` guess with an exact,
// measured reservation: an empty document (the only shape
// TestBuildWipesIntermediateJSONBuffers exercises) never grows enough to
// tell the two apart, since indentation overhead scales with the number of
// structural tokens (braces, brackets, commas), not with the document's raw
// length. A realistic MCP config full of short array elements and several
// sibling env vars — an ordinary shape, not a contrived one — routinely
// makes indentation more than double the compact form, past what the old
// guess reserved.
//
// build now fails closed (see its comment on the buf.Cap() check) instead
// of silently succeeding from a run that already reallocated and abandoned
// an unwiped copy of the document, so the guard here is simply that build
// still succeeds and returns the value intact for a document sized to
// overflow the old guess — under the guess, this would instead return an
// error.
func TestBuildIndentReservationHoldsForArrayHeavyDocument(t *testing.T) {
	// Many short array elements maximize the ratio of indentation overhead
	// (roughly constant per element: a newline plus depth's worth of indent
	// spaces) to compact length (one byte of content per element here) —
	// confirmed by measurement to make the indented form nearly triple the
	// compact one, well past a naive 2x guess, while staying an entirely
	// ordinary shape for a real config (a server's argv, a long allowlist).
	elems := make([]string, 60)
	for i := range elems {
		elems[i] = `"x"`
	}
	existing := []byte(`{"mcpServers":{"other":{"args":[` + strings.Join(elems, ",") + `]}}}`)

	c := canary.New()
	val := c.Value(0)
	h := jsonPathHandler{}
	tgt := target(runnerproto.TargetMCPConfig, "/unused", "mcpServers.s.env.KEY")
	out, err := h.build(existing, true, tgt, newValue(val))
	if err != nil {
		t.Fatalf("build: %v (an insufficient reservation now fails closed instead of leaking a copy — see build's buf.Cap() check)", err)
	}
	if !strings.Contains(string(out), `"`+val+`"`) {
		t.Fatalf("result missing the value intact (len %d)", len(out))
	}
	if !strings.Contains(string(out), `"other"`) {
		t.Fatal("result dropped the pre-existing sibling server")
	}

	// A wrong reservation this test could reach either errors out above (an
	// undersized one trips build's own buf.Cap() check) or succeeds with
	// spare capacity that never shows up in the output (an oversized one is
	// harmless) — this isn't a check on the reservation itself, only on the
	// content build actually produced: that it matches, byte for byte, an
	// independently computed json.Indent pass over the same document with
	// the value set the ordinary way (a plain Go string, not build's
	// json.RawMessage route), not merely that it contains the value
	// somewhere.
	var want map[string]any
	if err := json.Unmarshal(existing, &want); err != nil {
		t.Fatalf("test fixture is not valid JSON: %v", err)
	}
	want["mcpServers"].(map[string]any)["s"] = map[string]any{"env": map[string]any{"KEY": val}}
	wantCompact, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var wantIndented bytes.Buffer
	if err := json.Indent(&wantIndented, wantCompact, "", "  "); err != nil {
		t.Fatalf("json.Indent: %v", err)
	}
	if got := out[:len(out)-1]; !bytes.Equal(got, wantIndented.Bytes()) {
		t.Fatalf("output length %d, want %d; content diverges from an independent json.Indent pass over the same document", len(got), wantIndented.Len())
	}
	if out[len(out)-1] != '\n' {
		t.Fatalf("output missing trailing newline")
	}
}

// TestBuildFailsClosedWhenIndentReservationTooSmall guards the buf.Cap()
// check itself (jsonpath.go, right after the json.Indent call), not just the
// measurement that is meant to make it unreachable: on real input the
// measurement above always sizes the reservation correctly, so nothing short
// of a bug in the measurement itself would ever exercise the fail-closed
// branch. This forces it anyway, through the reserveJSONIndentBuf seam, and
// checks build actually refuses instead of returning content from a run
// that already reallocated its destination and abandoned an unwiped copy of
// the document — value included.
func TestBuildFailsClosedWhenIndentReservationTooSmall(t *testing.T) {
	origReserve := reserveJSONIndentBuf
	defer func() { reserveJSONIndentBuf = origReserve }()
	reserveJSONIndentBuf = func(int) int { return 1 }

	c := canary.New()
	val := c.Value(0)
	h := jsonPathHandler{}
	tgt := target(runnerproto.TargetMCPConfig, "/unused", "mcpServers.s.env.KEY")
	out, err := h.build(nil, false, tgt, newValue(val))
	if err == nil {
		t.Fatalf("build succeeded despite a forced-undersized reservation; want a refusal wrapping ErrWrite")
	}
	if !errors.Is(err, ErrWrite) {
		t.Fatalf("err = %v, want it to wrap ErrWrite", err)
	}
	if out != nil {
		t.Fatalf("build returned %d bytes of content alongside an error", len(out))
	}
	if c.In(err.Error()) {
		t.Fatalf("error text carries the value: %q", err.Error())
	}
}
