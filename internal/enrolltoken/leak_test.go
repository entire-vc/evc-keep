package enrolltoken

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// tokenBody is a token's random part, without the "keep_renr_" prefix.
func tokenBody(t *testing.T, tok string) string {
	t.Helper()
	if !strings.HasPrefix(tok, tokenPrefix) {
		t.Fatalf("not an enrollment token: %q", tok)
	}
	return strings.TrimPrefix(tok, tokenPrefix)
}

// leaksIn reports whether needle appears in haystack under any encoding
// internal/testutil/canary's own detector covers, including the raw body
// alone (see [TestLeaksInSeesTokenBodyWithoutPrefix]).
func leaksIn(haystack, needle string) bool {
	if needle == "" {
		return false
	}
	if canary.Of(needle).In(haystack) {
		return true
	}
	if strings.HasPrefix(needle, tokenPrefix) {
		return canary.Of(strings.TrimPrefix(needle, tokenPrefix)).In(haystack)
	}
	return false
}

// TestLeaksInSeesTokenBodyWithoutPrefix is the positive control for every
// leak test in this file — mirrors internal/identity's own.
func TestLeaksInSeesTokenBodyWithoutPrefix(t *testing.T) {
	tok, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	text := tok.Reveal()
	body := tokenBody(t, text)
	if !leaksIn("x "+body+" y", text) {
		t.Fatal("leaksIn is blind to the token body without its prefix; every leak test built on it proves less than it says")
	}
	if leaksIn("keep_renr_ and some unrelated log line", text) {
		t.Fatal("leaksIn reports a leak in text that holds no token material")
	}
}

var loggerKinds = map[string]func(io.Writer) *slog.Logger{
	"obs": func(w io.Writer) *slog.Logger { return slog.New(obs.NewHandler(w, slog.LevelDebug)) },
	"raw": func(w io.Writer) *slog.Logger {
		return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
	},
}

// TestTokenValueNeverRendersAsItself covers the token as a value of its own
// type: every fmt verb, text and JSON encodings, slog, and one level of
// nesting under an unexported field (where fmt does not call any method).
// Mirrors internal/identity's TestTokenValueNeverRendersAsItself.
func TestTokenValueNeverRendersAsItself(t *testing.T) {
	tok, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	text := tok.Reveal()

	type hidden struct{ tok any }
	logs := map[string]string{}
	for hname, newLogger := range loggerKinds {
		var buf bytes.Buffer
		logger := newLogger(&buf)
		logger.Info("m", "token_id", tok)
		logger.Info("m", "token_id", hidden{tok})
		logs[hname+" log line"] = buf.String()
	}

	jb, _ := json.Marshal(tok)
	jm, _ := json.Marshal(map[string]any{"t": tok})
	renders := map[string]string{
		"nested %+v":  fmt.Sprintf("%+v", hidden{tok}),
		"nested %#v":  fmt.Sprintf("%#v", hidden{tok}),
		"json":        string(jb),
		"json in map": string(jm),
	}
	for name, line := range logs {
		renders[name] = line
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		renders[verb] = fmt.Sprintf(verb, tok)
	}
	for name, s := range renders {
		if s == "" {
			t.Errorf("%s: rendered nothing, the probe is broken", name)
		}
		if leaksIn(s, text) {
			t.Errorf("token rendered as itself through %s: %s", name, s)
		}
	}
}

func TestTokenCannotBeDecoded(t *testing.T) {
	var tok Token
	if err := json.Unmarshal([]byte(`"keep_renr_x"`), &tok); err == nil {
		t.Error("json.Unmarshal decoded text into a Token")
	}
	if err := tok.UnmarshalText([]byte("keep_renr_x")); err == nil {
		t.Error("UnmarshalText decoded text into a Token")
	}
	if !tok.IsZero() {
		t.Error("a failed decode left text in the Token")
	}
}

// TestTokenAsMapKeyIsRedacted: encoding/json writes a map key through
// MarshalText, a path separate from MarshalJSON.
func TestTokenAsMapKeyIsRedacted(t *testing.T) {
	tok, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(map[Token]int{tok: 1})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if leaksIn(string(b), tok.Reveal()) {
		t.Errorf("a Token used as a map key was written out: %s", b)
	}
}

// TestTokenNeverLeaksThroughNestedForms is the same shape of attack as
// internal/identity's TestTokenNeverLeaksThroughNestedForms, aimed at
// IssueResult/IssueResponse: redaction that lives only on the top-level
// value must survive being placed inside another value, an error, or a log
// line under an obs allow-listed key.
func TestTokenNeverLeaksThroughNestedForms(t *testing.T) {
	repo, db := newRepo(t)
	ctx := context.Background()
	org := seedOrg(t, db)
	admin := seedUser(t, db, org)
	res, err := repo.Issue(ctx, IssueParams{OrgID: org, Host: "h", PolicySHA256: testPolicySHA256, CreatedBy: admin})
	if err != nil {
		t.Fatal(err)
	}
	resp := res.Response()
	tok := res.Token.Reveal()

	type hidden struct{ res IssueResult }
	type hiddenResp struct{ resp IssueResponse }
	type Exported struct{ Data IssueResponse }
	type ExportedPtr struct{ Data *IssueResponse }
	type ExportedResult struct{ Data IssueResult }

	rendered := fmt.Sprintf("issue failed: %+v", hidden{res})
	renders := map[string]string{
		"%+v unexported IssueResult field":  fmt.Sprintf("%+v", hidden{res}),
		"%v unexported IssueResult field":   fmt.Sprintf("%v", hidden{res}),
		"%#v unexported IssueResult field":  fmt.Sprintf("%#v", hidden{res}),
		"%+v unexported IssueResponse":      fmt.Sprintf("%+v", hiddenResp{resp}),
		"%#v unexported IssueResponse":      fmt.Sprintf("%#v", hiddenResp{resp}),
		"errors.New of a %+v rendering":     errors.New(rendered).Error(),
		"Errorf %v of nested":               fmt.Errorf("issue failed: %v", hidden{res}).Error(),
		"%+v exported field":                fmt.Sprintf("%+v", Exported{resp}),
		"%+v pointer field":                 fmt.Sprintf("%+v", ExportedPtr{&resp}),
		"%+v slice of results":              fmt.Sprintf("%+v", []IssueResult{res}),
		"%+v map of responses":              fmt.Sprintf("%+v", map[string]IssueResponse{"k": resp}),
		"%+v any holding nested":            fmt.Sprintf("%+v", []any{hidden{res}}),
		"%+v exported IssueResult in field": fmt.Sprintf("%+v", ExportedResult{res}),
	}
	for name, s := range renders {
		if s == "" {
			t.Errorf("%s: rendered nothing, the probe is broken", name)
		}
		if leaksIn(s, tok) {
			t.Errorf("%s leaked the token: %s", name, s)
		}
	}

	for name, v := range map[string]any{
		"json envelope value":   Exported{resp},
		"json envelope pointer": ExportedPtr{&resp},
		"json map":              map[string]any{"data": resp},
		"json slice":            []IssueResponse{resp},
	} {
		b, _ := json.Marshal(v)
		if leaksIn(string(b), tok) {
			t.Errorf("%s leaked the token: %s", name, b)
		}
	}

	for name, v := range map[string]any{
		"envelope value":   Exported{resp},
		"envelope pointer": ExportedPtr{&resp},
		"unexported":       hidden{res},
		"slice":            []IssueResponse{resp},
		"the token itself": res.Token,
	} {
		for hname, newLogger := range loggerKinds {
			var buf bytes.Buffer
			newLogger(&buf).Info("issued", "token_id", v)
			if buf.Len() == 0 {
				t.Fatalf("%s via %s: nothing was logged, the probe proves nothing", name, hname)
			}
			if leaksIn(buf.String(), tok) {
				t.Errorf("logging %s via %s leaked the token: %s", name, hname, buf.String())
			}
		}
	}
}

// TestErrorsNeverEchoTokenOrRejectReason is the card's red-run test #4's
// enrollment-token half: a canary planted as the token itself must never
// surface in ErrTokenRejected (constant, but checked anyway since a future
// change could wrap it with details) nor in any other error this package
// returns, across every rejection reason Redeem collapses into
// ErrTokenRejected — reuse, expiry, wrong host, wrong policy, unknown token.
func TestErrorsNeverEchoTokenOrRejectReason(t *testing.T) {
	repo, db := newRepo(t)
	ctx := context.Background()
	org := seedOrg(t, db)
	admin := seedUser(t, db, org)
	res, err := repo.Issue(ctx, IssueParams{OrgID: org, Host: "h", PolicySHA256: testPolicySHA256, CreatedBy: admin})
	if err != nil {
		t.Fatal(err)
	}
	tok := res.Token.Reveal()

	// Burn it once, legitimately.
	if _, err := repo.Redeem(ctx, res.Token, RedeemParams{Host: "h", PolicySHA256: testPolicySHA256}); err != nil {
		t.Fatal(err)
	}

	attempts := []struct {
		name  string
		token Token
		p     RedeemParams
	}{
		{"reuse", res.Token, RedeemParams{Host: "h", PolicySHA256: testPolicySHA256}},
		{"wrong host", res.Token, RedeemParams{Host: "other", PolicySHA256: testPolicySHA256}},
		{"wrong policy", res.Token, RedeemParams{Host: "h", PolicySHA256: "ff" + testPolicySHA256[2:]}},
		{"unknown", NewToken(tokenPrefix + strings.Repeat("a", tokenLen)), RedeemParams{Host: "h", PolicySHA256: testPolicySHA256}},
	}
	for _, a := range attempts {
		_, err := repo.Redeem(ctx, a.token, a.p)
		if err == nil {
			t.Fatalf("%s: Redeem unexpectedly succeeded", a.name)
		}
		if err != ErrTokenRejected {
			t.Errorf("%s: err = %v, want the single ErrTokenRejected sentinel (no distinguishing reason)", a.name, err)
		}
		if leaksIn(err.Error(), tok) {
			t.Errorf("%s: error echoed the token: %v", a.name, err)
		}
		if leaksIn(err.Error(), a.token.Reveal()) {
			t.Errorf("%s: error echoed the presented token: %v", a.name, err)
		}
	}
}

// gitleaksRuleRegex reads the keep-runner-enroll-token rule's regex out of
// the repo's own .gitleaks.toml rather than keeping a second copy of it
// here — mirrors internal/identity's gitleaksRuleRegex.
func gitleaksRuleRegex(t *testing.T) *regexp.Regexp {
	t.Helper()
	raw, err := os.ReadFile("../../.gitleaks.toml")
	if err != nil {
		t.Fatalf("read .gitleaks.toml: %v", err)
	}
	m := regexp.MustCompile(`(?s)id\s*=\s*"keep-runner-enroll-token".*?regex\s*=\s*'''(.*?)'''`).FindSubmatch(raw)
	if m == nil {
		t.Fatal(".gitleaks.toml has no keep-runner-enroll-token rule with a '''-quoted regex")
	}
	return regexp.MustCompile(string(m[1]))
}

func TestGitleaksRuleMatchesGeneratedToken(t *testing.T) {
	re := gitleaksRuleRegex(t)
	tok, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if !re.MatchString("token = \"" + tok.Reveal() + "\"") {
		t.Errorf(".gitleaks.toml keep-runner-enroll-token does not match a generated token")
	}
}
