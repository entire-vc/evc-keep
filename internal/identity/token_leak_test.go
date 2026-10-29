package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/google/uuid"
)

// tokenBody is a token's random part, without the "keep_<kind>_" prefix.
func tokenBody(t *testing.T, tok string) string {
	t.Helper()
	m := tokenRe.FindStringSubmatch(tok)
	if m == nil {
		t.Fatalf("not a token (length %d, does not match tokenRe)", len(tok))
	}
	return m[2]
}

// TestLeaksInSeesTokenBodyWithoutPrefix is the positive control for every
// leak test in this package: a leak of the token's body alone (no
// "keep_a_") must be reported, because the body is the entire secret and a
// scanner keyed on the prefix will not flag it.
func TestLeaksInSeesTokenBodyWithoutPrefix(t *testing.T) {
	tok, err := GenerateToken(KindAgent)
	if err != nil {
		t.Fatal(err)
	}
	text := Reveal(tok)
	body := tokenBody(t, text)
	if !leaksIn("x "+body+" y", text) {
		t.Fatal("leaksIn is blind to the token body without its prefix; every leak test built on it proves less than it says")
	}
	if leaksIn("keep_a_ and some unrelated log line", text) {
		t.Fatal("leaksIn reports a leak in text that holds no token material")
	}
}

// TestTokenNeverLeaksThroughNestedForms is the reproduction of the review
// findings: redaction that lives only on the top-level value does not
// survive being placed inside another value.
func TestTokenNeverLeaksThroughNestedForms(t *testing.T) {
	db := testDB(t)
	repo := NewRepo(db)
	ctx := context.Background()

	org := seedOrg(t, db)
	sponsor := seedUser(t, db, org)
	agent := seedAgent(t, db, org, sponsor)
	res, err := repo.Issue(ctx, IssueParams{OrgID: org, Kind: KindAgent, PrincipalID: agent, Scope: "org:" + org.String()})
	if err != nil {
		t.Fatal(err)
	}
	resp := res.Response()
	tok := Reveal(res.Token)

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

	// json.Marshal of an envelope that merely contains the response — the
	// shape a log call or a generic error path produces.
	for name, v := range map[string]any{
		"json envelope value":   Exported{resp},
		"json envelope pointer": ExportedPtr{&resp},
		"json IssueResponse":    resp,
		"json map":              map[string]any{"data": resp},
		"json slice":            []IssueResponse{resp},
	} {
		b, _ := json.Marshal(v)
		if leaksIn(string(b), tok) {
			t.Errorf("%s leaked the token: %s", name, b)
		}
	}

	// Logging, under a key obs's allow-list passes ("token_id" ends in
	// "_id"; slog only resolves LogValue on the top-level value). Once
	// through obs, whose output scrub is a layer of its own, and once
	// through a bare slog JSON handler, so the types' own redaction is
	// exercised without that layer's help.
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

// loggerKinds builds the two loggers a leak test runs against: Keep's own
// (allow-list plus output scrub) and a bare slog JSON handler.
var loggerKinds = map[string]func(io.Writer) *slog.Logger{
	"obs": func(w io.Writer) *slog.Logger { return slog.New(obs.NewHandler(w, slog.LevelDebug)) },
	"raw": func(w io.Writer) *slog.Logger {
		return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
	},
}

// TestTokenValueNeverRendersAsItself covers the token as a value of its own
// type: every fmt verb, text and JSON encodings, slog, and one level of
// nesting under an unexported field (where fmt does not call any method).
func TestTokenValueNeverRendersAsItself(t *testing.T) {
	for _, k := range []Kind{KindAgent, KindService, KindUser} {
		tok, err := GenerateToken(k)
		if err != nil {
			t.Fatal(err)
		}
		text := Reveal(tok)

		type hidden struct{ tok any }
		logs := map[string]string{}
		for hname, newLogger := range loggerKinds {
			var buf bytes.Buffer
			logger := newLogger(&buf)
			logger.Info("m", "principal_id", tok)
			logger.Info("m", "principal_id", hidden{tok})
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
		// Verbs go through a variable so vet does not reject %d on a string
		// before the token has a type of its own.
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
			renders[verb] = fmt.Sprintf(verb, tok)
		}
		for name, s := range renders {
			if s == "" {
				t.Errorf("kind %s %s: rendered nothing, the probe is broken", k, name)
			}
			if leaksIn(s, text) {
				t.Errorf("kind %s: token rendered as itself through %s: %s", k, name, s)
			}
		}
	}
}

// TestRequestIDNeverEchoesTokenBody: a token's random part is 52 chars of
// [a-z2-7], which reqid used to accept as a request id — echoed in the
// X-Request-Id response header and logged under request_id, where the
// gitleaks rule (which wants the "keep_x_" prefix) does not see it. Forms
// that split or truncate the part are probed too: a check that only looks
// for one unbroken run is walked around by a hyphen.
func TestRequestIDNeverEchoesTokenBody(t *testing.T) {
	for _, k := range []Kind{KindAgent, KindService, KindUser} {
		tok, err := GenerateToken(k)
		if err != nil {
			t.Fatal(err)
		}
		body := tokenBody(t, Reveal(tok))
		for name, in := range map[string]string{
			"bare body":          body,
			"body with a lead":   "req-" + body,
			"body with a tail":   body + "-1",
			"body split by dash": body[:26] + "-" + body[26:],
			"body split by 0":    body[:26] + "0" + body[26:],
			"body, 51 chars":     body[:51],
		} {
			got := reqid.FromHeader(in)
			if leaksIn(got, Reveal(tok)) {
				t.Errorf("kind %s, %s: FromHeader echoed token material: %q", k, name, got)
			}
		}
	}
	// Positive controls: ordinary ids are still reused verbatim, so the
	// refusal above is not "refuse everything".
	for _, ok := range []string{"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "req-1234", strings.Repeat("a", 32)} {
		if got := reqid.FromHeader(ok); got != ok {
			t.Errorf("FromHeader(%q) = %q, want the id reused", ok, got)
		}
	}
}

// gitleaksRuleRegex reads the keep-identity-token rule's regex out of the
// repo's own .gitleaks.toml rather than keeping a second copy of it here.
func gitleaksRuleRegex(t *testing.T) *regexp.Regexp {
	t.Helper()
	raw, err := os.ReadFile("../../.gitleaks.toml")
	if err != nil {
		t.Fatalf("read .gitleaks.toml: %v", err)
	}
	m := regexp.MustCompile(`(?s)id\s*=\s*"keep-identity-token".*?regex\s*=\s*'''(.*?)'''`).FindSubmatch(raw)
	if m == nil {
		t.Fatal(".gitleaks.toml has no keep-identity-token rule with a '''-quoted regex")
	}
	return regexp.MustCompile(string(m[1]))
}

// TestGitleaksRuleCoversEveryTokenKind: a narrowing of the scanner rule to
// one kind (`keep_a_`) must turn this red.
func TestGitleaksRuleCoversEveryTokenKind(t *testing.T) {
	re := gitleaksRuleRegex(t)
	for _, k := range []Kind{KindAgent, KindService, KindUser} {
		tok, err := GenerateToken(k)
		if err != nil {
			t.Fatal(err)
		}
		text := Reveal(tok)
		if !re.MatchString("token = \"" + text + "\"") {
			t.Errorf(".gitleaks.toml keep-identity-token does not match a generated kind %q token", k)
		}
	}
}

func TestBearerTokenRoundTripsIntoAuthenticate(t *testing.T) {
	// The Authorization header is the one place a token legitimately
	// arrives as text; it must still parse after the token got its own type.
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	tok, err := GenerateToken(KindUser)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+Reveal(tok))
	got, ok := bearerToken(req)
	if !ok || Reveal(got) != Reveal(tok) {
		t.Fatalf("bearerToken did not return the presented token (ok=%v)", ok)
	}
}

// TestTokenAsMapKeyIsRedacted: encoding/json writes a map key through
// MarshalText, a path separate from MarshalJSON.
func TestTokenAsMapKeyIsRedacted(t *testing.T) {
	tok := mustToken(t, KindAgent)
	b, err := json.Marshal(map[Token]int{tok: 1})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if leaksIn(string(b), Reveal(tok)) {
		t.Errorf("a Token used as a map key was written out: %s", b)
	}
}

func TestTokenCannotBeDecoded(t *testing.T) {
	var tok Token
	if err := json.Unmarshal([]byte(`"keep_a_x"`), &tok); err == nil {
		t.Error("json.Unmarshal decoded text into a Token")
	}
	if err := tok.UnmarshalText([]byte("keep_a_x")); err == nil {
		t.Error("UnmarshalText decoded text into a Token")
	}
	if !tok.IsZero() {
		t.Error("a failed decode left text in the Token")
	}
}

// TestWireJSONCarriesEveryField checks values, not only key names: an
// issuance response that loses the kind or scope is as broken as one that
// loses the token.
func TestWireJSONCarriesEveryField(t *testing.T) {
	tok := mustToken(t, KindService)
	exp := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	resp := IssueResponse{
		TokenID: uuid.New(), Token: tok, Last4: Last4(tok), Kind: KindService,
		Scope: "org:abc", ExpiresAt: &exp, CreatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	b, err := resp.WireJSON()
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	for field, want := range map[string]any{
		"token_id": resp.TokenID.String(), "token": Reveal(tok), "last4": resp.Last4,
		"kind": "s", "scope": "org:abc", "expires_at": "2030-01-02T03:04:05Z",
		"created_at": "2026-01-02T03:04:05Z",
	} {
		if got[field] != want {
			t.Errorf("WireJSON %s = %v, want %v", field, got[field], want)
		}
	}
}

// TestAuthenticateNeverEchoesANearRealToken: a presented token that is the
// real one plus a character is malformed, and its rejection must not carry
// the text back — the probe with an unrelated string would not notice.
func TestAuthenticateNeverEchoesANearRealToken(t *testing.T) {
	db := testDB(t)
	repo := NewRepo(db)
	org := seedOrg(t, db)
	user := seedUser(t, db, org)
	res, err := repo.Issue(context.Background(), IssueParams{OrgID: org, Kind: KindUser, PrincipalID: user, Scope: "org:" + org.String()})
	if err != nil {
		t.Fatal(err)
	}
	near := NewToken(Reveal(res.Token) + "x")
	_, err = repo.Authenticate(context.Background(), near)
	if err == nil {
		t.Fatal("a near-real token authenticated")
	}
	if leaksIn(err.Error(), Reveal(res.Token)) {
		t.Errorf("Authenticate echoed the presented token: %v", err)
	}
	rec := serve(RequireAuth(repo, nil)(neverCalledHandler(t)), newAuthRequest(Reveal(near)))
	if leaksIn(rec.Body.String(), Reveal(res.Token)) {
		t.Error("response body echoed the presented token (body suppressed)")
	}
}
