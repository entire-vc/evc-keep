package api

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/jackc/pgx/v5"
)

// issuedTokenFields is the closed field list of the one-time response to
// POST /orgs/{org_id}/tokens: the threat model's limited exception to the
// §4.3 closed lists. `token` is the only field that carries a credential.
var issuedTokenFields = []string{"created_at", "expires_at", "kind", "last4", "scope", "token", "token_id"}

func sortedKeys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// objectKeys returns the keys of a JSON object in document order, duplicates
// included: a map would collapse a repeated key and hide a second copy.
func objectKeys(t *testing.T, body []byte) []string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(body))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		t.Fatalf("issue response is not a JSON object")
	}
	var keys []string
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			t.Fatalf("issue response: %v", err)
		}
		keys = append(keys, k.(string))
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			t.Fatalf("issue response: %v", err)
		}
	}
	return keys
}

// tokenForms returns the token as it could leave through an encoder:
// as is, hex, base64 (std and raw-url), query-escaped and reversed.
func tokenForms(token string) []string {
	rev := []byte(token)
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return []string{
		token,
		hex.EncodeToString([]byte(token)),
		base64.StdEncoding.EncodeToString([]byte(token)),
		base64.RawURLEncoding.EncodeToString([]byte(token)),
		url.QueryEscape(token),
		string(rev),
	}
}

// leaksToken reports whether text carries the token in any of its forms.
func leaksToken(text string, forms []string) (string, bool) {
	lower := strings.ToLower(text)
	for i, form := range forms {
		if strings.Contains(text, form) || strings.Contains(lower, strings.ToLower(form)) {
			return []string{"raw", "hex", "base64", "base64-rawurl", "query-escaped", "reversed"}[i], true
		}
	}
	return "", false
}

// anywhereInDatabase reports whether needle occurs in the text form of any
// row of any public table.
func anywhereInDatabase(t *testing.T, f *routeFixture, needle string) bool {
	t.Helper()
	rows, err := f.pool.Query(f.ctx, `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan table name: %v", err)
		}
		tables = append(tables, n)
	}
	rows.Close()
	for _, n := range tables {
		var found bool
		q := `SELECT EXISTS (SELECT 1 FROM ` + pgx.Identifier{n}.Sanitize() + ` x WHERE x::text LIKE '%' || $1 || '%')`
		if err := f.pool.QueryRow(f.ctx, q, needle).Scan(&found); err != nil {
			t.Fatalf("scan table %s: %v", n, err)
		}
		if found {
			return true
		}
	}
	return false
}

// TestTokenIssue_ResponseIsExactlyTheOneTimeContract: the 201 body has
// exactly the contract fields (an extra field is red, a missing one too), the
// response is not cacheable, and the token text appears nowhere else: not in
// the revoke response, not in any header.
func TestTokenIssue_ResponseIsExactlyTheOneTimeContract(t *testing.T) {
	f := newRouteFixture(t)
	admin := f.mustAdmin("admin")
	adminBearer := f.mustToken(identity.KindUser, admin.ID, "org:"+f.org.ID.String())
	agent := f.mustAgent(admin, "ci-agent")
	path := "/orgs/" + f.org.ID.String() + "/tokens"
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)

	issue := f.do(http.MethodPost, path, adminBearer, map[string]any{
		"kind": "a", "principal_id": agent.ID.String(), "scope": "org:" + f.org.ID.String(), "expires_at": expires,
	})
	if issue.Code != http.StatusCreated {
		t.Fatalf("issue token: status = %d, want 201", issue.Code)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(issue.Body.Bytes(), &fields); err != nil {
		t.Fatalf("issue response is not a JSON object: %v", err)
	}
	keys := objectKeys(t, issue.Body.Bytes())
	sort.Strings(keys)
	if got, want := strings.Join(keys, ","), strings.Join(issuedTokenFields, ","); got != want {
		t.Fatalf("issue response fields = %s, want exactly %s (each once)", got, want)
	}
	res := issue.Result()
	defer func() { _ = res.Body.Close() }()
	if got := res.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("issue response Cache-Control = %q, want no-store", got)
	}
	var token string
	if err := json.Unmarshal(fields["token"], &token); err != nil || token == "" {
		t.Fatalf("token field is not a non-empty string")
	}
	if n := strings.Count(issue.Body.String(), token); n != 1 {
		t.Fatalf("the token occurs %d times in the issue response, want exactly once", n)
	}
	var last4 string
	_ = json.Unmarshal(fields["last4"], &last4)
	if len(last4) != 4 || last4 != token[len(token)-4:] {
		t.Fatalf("last4 is not exactly the last four characters of the token")
	}
	for name, raw := range fields {
		if name == "token" {
			continue
		}
		var v string
		_ = json.Unmarshal(raw, &v)
		for i := 0; i+8 <= len(token); i++ {
			if strings.Contains(v, token[i:i+8]) {
				t.Fatalf("field %s carries a piece of the token", name)
			}
		}
	}
	forms := tokenForms(token)
	// Positive controls: the detector sees every form planted in text, sees
	// the raw token in the real issue response, and sees an encoded form
	// planted into that very response.
	for i, form := range forms {
		if _, ok := leaksToken("x"+form+"y", forms); !ok {
			t.Fatalf("token detector is blind to form %d; the checks below prove nothing", i)
		}
	}
	if _, ok := leaksToken(issue.Body.String(), forms[:1]); !ok {
		t.Fatalf("token detector does not see the token in the real issue response")
	}
	// A form equal to the raw token (a URL-safe token escapes to itself) is
	// not another form.
	var encoded []string
	for _, form := range forms[1:] {
		if form != token {
			encoded = append(encoded, form)
		}
	}
	if len(encoded) == 0 {
		t.Fatalf("no encoded form of the token to scan for")
	}
	for i, form := range encoded {
		if _, ok := leaksToken(issue.Body.String()+" "+form, encoded); !ok {
			t.Fatalf("encoded-form scan of the issue response is blind to form %d", i)
		}
	}
	// The issue response carries the token once, as is, and in no other form.
	if _, bad := leaksToken(issue.Body.String(), encoded); bad {
		t.Fatalf("the token is repeated in the issue response in an encoded form")
	}
	for name, vals := range res.Header {
		for _, v := range vals {
			if form, bad := leaksToken(v, forms); bad {
				t.Fatalf("the token (%s form) is repeated in response header %s", form, name)
			}
		}
	}

	if !strings.Contains(f.logbuf.String(), "request_id") {
		t.Fatalf("the log buffer is empty: the log search below would prove nothing")
	}
	if form, bad := leaksToken(f.logbuf.String(), forms); bad {
		t.Fatalf("the token (%s form) is in the log output", form)
	}
	if !anywhereInDatabase(t, f, f.org.ID.String()) {
		t.Fatalf("database search control failed: a known value was not found")
	}
	for i, form := range forms {
		if anywhereInDatabase(t, f, form) {
			t.Fatalf("the token (form %d) is stored in the database", i)
		}
	}

	var tokenID string
	_ = json.Unmarshal(fields["token_id"], &tokenID)
	revoke := f.do(http.MethodPost, path+"/"+tokenID+"/revoke", adminBearer, nil)
	if revoke.Code != http.StatusOK {
		t.Fatalf("revoke: status = %d, want 200", revoke.Code)
	}
	if form, bad := leaksToken(revoke.Body.String(), forms); bad {
		t.Fatalf("the token (%s form) is repeated in the revoke response", form)
	}
	rres := revoke.Result()
	defer func() { _ = rres.Body.Close() }()
	_, _ = io.Copy(io.Discard, rres.Body)
	for name, vals := range rres.Header {
		for _, v := range vals {
			if form, bad := leaksToken(v, forms); bad {
				t.Fatalf("the token (%s form) is repeated in revoke response header %s", form, name)
			}
		}
	}

	// No later read repeats it either: every GET route, with real ids.
	org := f.org.ID.String()
	for _, p := range []string{
		"/orgs/" + org + "/secrets",
		"/orgs/" + org + "/audit/verify",
		"/v1/input-links/" + tokenID,
		"/v1/deployments/" + tokenID,
		"/healthz",
		"/readyz",
	} {
		get := f.do(http.MethodGet, p, adminBearer, nil)
		if get.Code == http.StatusMethodNotAllowed || get.Code == 0 {
			t.Fatalf("GET %s is not a served route (status %d): the check proves nothing", p, get.Code)
		}
		if form, bad := leaksToken(get.Body.String(), forms); bad {
			t.Fatalf("the token (%s form) is repeated in GET %s", form, p)
		}
		for name, vals := range get.Result().Header {
			for _, v := range vals {
				if form, bad := leaksToken(v, forms); bad {
					t.Fatalf("the token (%s form) is in GET %s header %s", form, p, name)
				}
			}
		}
	}
	if form, bad := leaksToken(f.logbuf.String(), forms); bad {
		t.Fatalf("the token (%s form) reached the log after revoke and reads", form)
	}
}

// TestTokenIssue_WithoutExpiryOmitsOnlyExpiresAt: the field set never grows
// when no expiry is requested; only expires_at is absent.
func TestTokenIssue_WithoutExpiryOmitsOnlyExpiresAt(t *testing.T) {
	f := newRouteFixture(t)
	admin := f.mustAdmin("admin")
	adminBearer := f.mustToken(identity.KindUser, admin.ID, "org:"+f.org.ID.String())
	agent := f.mustAgent(admin, "ci-agent")

	issue := f.do(http.MethodPost, "/orgs/"+f.org.ID.String()+"/tokens", adminBearer, map[string]any{
		"kind": "a", "principal_id": agent.ID.String(), "scope": "org:" + f.org.ID.String(),
	})
	if issue.Code != http.StatusCreated {
		t.Fatalf("issue token: status = %d, want 201", issue.Code)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(issue.Body.Bytes(), &fields); err != nil {
		t.Fatalf("issue response is not a JSON object: %v", err)
	}
	want := make([]string, 0, len(issuedTokenFields))
	for _, k := range issuedTokenFields {
		if k != "expires_at" {
			want = append(want, k)
		}
	}
	if got := strings.Join(sortedKeys(fields), ","); got != strings.Join(want, ",") {
		t.Fatalf("issue response fields = %s, want %s", got, strings.Join(want, ","))
	}
	res := issue.Result()
	defer func() { _ = res.Body.Close() }()
	if got := res.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("issue response Cache-Control = %q, want no-store", got)
	}
}
