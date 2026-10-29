package obs

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"log/slog"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestAllowListIsPinned makes widening the closed key set a deliberate,
// reviewed edit of this file: a key added to allowed without being added
// here (and so without a reviewer reading why) fails.
func TestAllowListIsPinned(t *testing.T) {
	want := []string{"action", "auth_reason", "body_len", "count", "duration_ms", "error_class", "kind", "method", "request_id", "route", "stack", "status"}
	var got []string
	for k := range allowed {
		got = append(got, k)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("allow-list changed:\n got %v\nwant %v\nupdate this test together with the threat-model note that justifies the new key", got, want)
	}
}

func TestDisallowedKeysAreDroppedWithNamedWarning(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf)
	logger.Info("m", "token", "value-that-must-not-appear", "password", "another", "route", "/x", "secret_id", "abc")
	out := buf.String()
	if out == "" {
		t.Fatal("nothing was logged, the probe proves nothing")
	}
	for _, bad := range []string{"value-that-must-not-appear", "another"} {
		if strings.Contains(out, bad) {
			t.Errorf("value of a disallowed key reached the log: %s", out)
		}
	}
	for _, name := range []string{`"key":"token"`, `"key":"password"`} {
		if !strings.Contains(out, name) {
			t.Errorf("no warning naming the dropped key %s in: %s", name, out)
		}
	}
	if !strings.Contains(out, `"route":"/x"`) || !strings.Contains(out, `"secret_id":"abc"`) {
		t.Errorf("allowed keys were lost: %s", out)
	}
}

func fakeBody(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
}

type wrapped struct{ Data struct{ Token string } }

// TestTokenShapedValuesNeverReachTheLog: obs filters keys, and the "*_id"
// suffix rule lets a value through under a key such as "principal_id". A
// value shaped like a Keep token must not survive to the output whatever
// key, nesting or message carries it.
func TestTokenShapedValuesNeverReachTheLog(t *testing.T) {
	body := fakeBody(t)
	tok := "keep_a_" + body
	var w wrapped
	w.Data.Token = tok

	cases := map[string]func(l *slog.Logger){
		"allowed *_id key, full token":  func(l *slog.Logger) { l.Info("m", "principal_id", tok) },
		"allowed *_id key, body only":   func(l *slog.Logger) { l.Info("m", "principal_id", body) },
		"request_id":                    func(l *slog.Logger) { l.Info("m", "request_id", body) },
		"name key":                      func(l *slog.Logger) { l.Info("m", "name", tok) },
		"message text":                  func(l *slog.Logger) { l.Info("failed for " + tok) },
		"nested struct under _id key":   func(l *slog.Logger) { l.Info("m", "token_id", w) },
		"map under _id key":             func(l *slog.Logger) { l.Info("m", "token_id", map[string]string{"t": tok}) },
		"group":                         func(l *slog.Logger) { l.Info("m", slog.Group("g", slog.String("token_id", tok))) },
		"WithAttrs":                     func(l *slog.Logger) { l.With("principal_id", tok).Info("m") },
		"stack value":                   func(l *slog.Logger) { l.Info("m", "stack", "pkg.f("+tok+")\n\t/x.go:1 +0x1") },
		"error value under error_class": func(l *slog.Logger) { l.Info("m", "error_class", "bad "+tok) },
	}
	for name, do := range cases {
		var buf bytes.Buffer
		do(New(&buf))
		if buf.Len() == 0 {
			t.Errorf("%s: nothing was logged, the probe proves nothing", name)
			continue
		}
		if strings.Contains(buf.String(), body) {
			t.Errorf("%s: token material reached the log: %s", name, buf.String())
		}
	}
}

// TestTokenPressedAgainstItsAlphabetLeavesNoTail: text of the token's own
// alphabet written right before or after its random part makes one longer
// run. A scrub that blanks only 52 characters of it leaves the rest of the
// token behind — with 51 characters in front, 51 of the token's 52.
func TestTokenPressedAgainstItsAlphabetLeavesNoTail(t *testing.T) {
	body := fakeBody(t)
	for _, k := range []int{1, 2, 3, 26, 51} {
		pad := strings.Repeat("z", k)
		var buf bytes.Buffer
		New(&buf).Info("principal "+pad+body, "request_id", pad+body, "principal_id", body+pad)
		var line map[string]any
		if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
			t.Fatalf("%d: log line is not JSON: %v: %s", k, err, buf.String())
		}
		for key, want := range map[string]string{
			"msg": "principal [REDACTED]", "request_id": "[REDACTED]", "principal_id": "[REDACTED]",
		} {
			if line[key] != want {
				t.Errorf("%d adjacent characters: %s = %q, want %q", k, key, line[key], want)
			}
		}
	}
}

// TestTokenInALongRecordIsScrubbed: a record is one Write however long it
// is, and the scrub must not depend on its size. Records of several KB are
// ordinary (a panic's stack, a long message), so a token after 4 KB of
// other text is placed where a size-limited scrub would stop looking.
func TestTokenInALongRecordIsScrubbed(t *testing.T) {
	body := fakeBody(t)
	filler := strings.Repeat("- ", 2048)
	cases := map[string]func(l *slog.Logger){
		"message": func(l *slog.Logger) { l.Info(filler + body) },
		"value":   func(l *slog.Logger) { l.Info("m", "principal_id", filler+body) },
		"stack":   func(l *slog.Logger) { l.Info("m", "stack", filler, "principal_id", body) },
	}
	for name, do := range cases {
		var buf bytes.Buffer
		do(New(&buf))
		if buf.Len() < 4096 {
			t.Fatalf("%s: record is %d bytes, the probe needs one of at least 4 KB", name, buf.Len())
		}
		if strings.Contains(buf.String(), body) || !strings.Contains(buf.String(), "[REDACTED]") {
			t.Errorf("%s: token in a %d-byte record was not scrubbed", name, buf.Len())
		}
	}
}

// TestScrubLeavesOrdinaryLinesAlone is the negative control for the test
// above: scrubbing that rewrites everything would pass it too.
func TestScrubLeavesOrdinaryLinesAlone(t *testing.T) {
	reqID, secretID := uuid.NewString(), uuid.NewString()
	var buf bytes.Buffer
	New(&buf).Info("request served", "method", "GET", "route", "/orgs/{org_id}/secrets", "status", 200,
		"request_id", reqID, "secret_id", secretID, "duration_ms", 12)
	out := buf.String()
	for _, keep := range []string{"request served", "GET", "/orgs/{org_id}/secrets", reqID, secretID} {
		if !strings.Contains(out, keep) {
			t.Errorf("ordinary content %q was altered: %s", keep, out)
		}
	}
}

// TestTokenAsKeyNameIsScrubbedFromTheDropWarning: a dropped attribute is
// reported by naming its key, and a key is caller-supplied text too.
func TestTokenAsKeyNameIsScrubbedFromTheDropWarning(t *testing.T) {
	body := fakeBody(t)
	var buf bytes.Buffer
	New(&buf).Info("m", "keep_a_"+body, 1)
	if buf.Len() == 0 {
		t.Fatal("nothing was logged, the probe proves nothing")
	}
	if strings.Contains(buf.String(), body) {
		t.Errorf("a token used as a key name reached the log: %s", buf.String())
	}
}

// TestWithAttrsAppliesTheAllowList: attributes bound with With go through
// WithAttrs, a path of its own.
func TestWithAttrsAppliesTheAllowList(t *testing.T) {
	var buf bytes.Buffer
	New(&buf).With("password", "hunter2-not-real", "route", "/x").Info("m")
	out := buf.String()
	if out == "" {
		t.Fatal("nothing was logged, the probe proves nothing")
	}
	if strings.Contains(out, "hunter2-not-real") {
		t.Errorf("a disallowed key bound with With reached the log: %s", out)
	}
	if !strings.Contains(out, `"route":"/x"`) {
		t.Errorf("an allowed key bound with With was lost: %s", out)
	}
}

// TestKeyRulesArePinned pins the shape rules beside the fixed set: which
// key names pass, and which do not. Widening a rule changes this table in
// the same review.
func TestKeyRulesArePinned(t *testing.T) {
	for k, want := range map[string]bool{
		"method": true, "auth_reason": true, "action": true, "stack": true,
		"id": true, "name": true, "secret_id": true, "owner_name": true, "token_id": true,
		"token": false, "value": false, "secret": false, "password": false, "session": false,
		"authorization": false, "secret_value": false, "token_value": false, "x_ids": false,
		"idx": false, "ID": false, "": false,
	} {
		if got := isAllowed(k); got != want {
			t.Errorf("isAllowed(%q) = %v, want %v", k, got, want)
		}
	}
}

// flipValuer answers an integer the first time it is resolved and a string
// after that: a check that resolves once and forwards the original passes it.
type flipValuer struct {
	n    *int
	text string
}

func (f flipValuer) LogValue() slog.Value {
	*f.n++
	if *f.n == 1 {
		return slog.IntValue(1)
	}
	return slog.StringValue(f.text)
}

// TestNumericKeysCarryOnlyIntegers: "count" and "body_len" are allowed for
// numbers; a string under either must not reach the log, bound directly or
// with With, while an integer still passes (the positive control).
func TestNumericKeysCarryOnlyIntegers(t *testing.T) {
	const probe = "kcprobe0numeric0key"
	for _, key := range []string{"count", "body_len"} {
		var buf bytes.Buffer
		l := New(&buf)
		l.Info("direct", key, 7)
		if !strings.Contains(buf.String(), `"`+key+`":7`) {
			t.Fatalf("an integer under %q was lost, the probe proves nothing: %s", key, buf.String())
		}
		buf.Reset()
		l.Info("direct", key, probe)
		l.With(key, probe).Info("bound")
		if strings.Contains(buf.String(), probe) {
			t.Errorf("a string under %q reached the log: %s", key, buf.String())
		}
	}
	for _, key := range []string{"count", "body_len"} {
		var buf bytes.Buffer
		n := 0
		v := flipValuer{n: &n, text: probe}
		New(&buf).Info("flip", key, v)
		New(&buf).With(key, v).Info("flip")
		if strings.Contains(buf.String(), probe) {
			t.Errorf("a value that changes kind between resolves reached the log under %q: %s", key, buf.String())
		}
	}
}
