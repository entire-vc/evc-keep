package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

func secretRow(ref string) map[string]any {
	return map[string]any{"id": testSecretID, "name": "db-password", "scope": "org:" + testOrg, "class": "prod", "type": "password",
		"store": map[string]any{"id": "s1", "name": "builtin", "provider": "builtin"}, "provider_ref": ref,
		"created_at": time.Unix(1, 0).UTC(), "updated_at": time.Unix(2, 0).UTC()}
}

// provider_ref is a locator, not any string: a server that puts something
// else there (a value, say) is refused whole by both metadata tools.
func TestProviderRefMustBeALocator(t *testing.T) {
	c := canary.New()
	value := c.Value(1)
	requireDetectorSees(t, c, "x "+value)
	bad := []string{value, "plain-" + value, "http://" + value, "builtin://", "builtin:// " + value, "builtin://a\n" + value, "", "builtin://a\v" + value, "builtin://a\u00a0" + value, "builtin://a\u2028" + value, "builtin://\x1b[31m", "builtin://" + strings.Repeat("a", 1100)}
	for _, ref := range bad {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/versions") {
				_ = json.NewEncoder(w).Encode([]any{})
				return
			}
			if strings.HasSuffix(r.URL.Path, "/secrets") {
				_ = json.NewEncoder(w).Encode([]any{secretRow(ref)})
				return
			}
			_ = json.NewEncoder(w).Encode(secretRow(ref))
		}))
		out := session(t, newTestServer(t, srv.URL, "tok"),
			call(1, "list_secrets", map[string]any{"scope_level": "org", "scope_id": testOrg}),
			call(2, "get_secret_meta", map[string]any{"secret_id": testSecretID}))
		srv.Close()
		if strings.Count(out, `"isError":true`) != 2 {
			t.Fatalf("provider_ref %q was passed on: %s", ref, out)
		}
		if c.In(out) {
			t.Fatalf("canary reached an answer: %s", out)
		}
	}
	for _, ref := range []string{"builtin://default/db-password", "op://vault/item/field", "sops://f.yaml#k", "vault://kv/data/x"} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/versions") {
				_ = json.NewEncoder(w).Encode([]any{})
				return
			}
			if strings.HasSuffix(r.URL.Path, "/secrets") {
				_ = json.NewEncoder(w).Encode([]any{secretRow(ref)})
				return
			}
			_ = json.NewEncoder(w).Encode(secretRow(ref))
		}))
		out := session(t, newTestServer(t, srv.URL, "tok"),
			call(1, "list_secrets", map[string]any{"scope_level": "org", "scope_id": testOrg}),
			call(2, "get_secret_meta", map[string]any{"secret_id": testSecretID}))
		srv.Close()
		if strings.Contains(out, `"isError":true`) || !strings.Contains(out, strings.ReplaceAll(ref, "#", `#`)) {
			t.Fatalf("positive control: locator %q refused: %s", ref, out)
		}
	}
}

// An error reply is the closed row too: an extra field, a second document or
// a field of different spelling makes the whole reply unusable, and the
// answer names only a class.
func TestErrorReplyWithUnknownFieldIsRefused(t *testing.T) {
	c := canary.New()
	value := c.Value(1)
	good := map[string]any{"error_class": "not_found", "message": "m", "request_id": testRequest}
	for name, body := range map[string]string{
		"extra field":   `{"error_class":"internal","message":"m","request_id":"` + testRequest + `","debug":"` + value + `"}`,
		"status field":  `{"error_class":"internal","message":"m","request_id":"` + testRequest + `","Status":500}`,
		"second doc":    `{"error_class":"internal","message":"m"} {"debug":"` + value + `"}`,
		"trailing text": `{"error_class":"internal","message":"m"} ` + value,
		"nested extra":  `{"error_class":"internal","message":{"x":"` + value + `"}}`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(body))
		}))
		out := session(t, newTestServer(t, srv.URL, "tok"), everyCall()...)
		srv.Close()
		if !strings.Contains(out, "unreadable error") || strings.Contains(out, "the server refused the request") {
			t.Fatalf("%s: reply with an unknown field was accepted as an error row: %s", name, out)
		}
		if c.In(out) {
			t.Fatalf("%s: canary reached an answer", name)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_ = json.NewEncoder(w).Encode(good)
	}))
	defer srv.Close()
	if out := session(t, newTestServer(t, srv.URL, "tok"), everyCall()...); !strings.Contains(out, "the server refused the request: not_found") {
		t.Fatalf("positive control: closed error row not used: %s", out)
	}
}

// Every free string of a metadata answer has the shape of what it may hold:
// a digest that is not kfp1, a status outside the list, or control text in a
// name makes the reply unusable, and nothing of it reaches the answer.
func TestMetadataStringsKeepTheirShape(t *testing.T) {
	c := canary.New()
	value := c.Value(1)
	requireDetectorSees(t, c, "x "+value)
	for name, tweak := range map[string]func(secret map[string]any, version map[string]any){
		"fingerprint is not kfp1": func(_, v map[string]any) { v["fingerprint"] = value },
		"fingerprint is a hash":   func(_, v map[string]any) { v["fingerprint"] = "sha256:" + value },
		"status outside list":     func(_, v map[string]any) { v["status"] = value },
		"version has control":     func(_, v map[string]any) { v["version"] = "v\n" + value },
		"created_by has control":  func(_, v map[string]any) { v["created_by"] = "u\x1b" + value },
		"name has control":        func(s, _ map[string]any) { s["name"] = "n\n" + value },
		"class has control":       func(s, _ map[string]any) { s["class"] = "c\n" + value },
		"owner is long":           func(s, _ map[string]any) { s["owner"] = strings.Repeat("o", 200) + value },
		"store name is long":      func(s, _ map[string]any) { s["store"].(map[string]any)["name"] = strings.Repeat("s", 300) + value },
		"description is huge":     func(s, _ map[string]any) { s["description"] = strings.Repeat("d", 5000) + value },
	} {
		secret := secretRow("builtin://default/db-password")
		version := map[string]any{"version": "v1", "created_at": time.Unix(1, 0).UTC(), "fingerprint": "kfp1:k:abcdefghijklmnop", "length": 12, "status": "current"}
		tweak(secret, version)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, "/versions"):
				_ = json.NewEncoder(w).Encode([]any{version})
			case strings.HasSuffix(r.URL.Path, "/secrets"):
				_ = json.NewEncoder(w).Encode([]any{secret})
			default:
				_ = json.NewEncoder(w).Encode(secret)
			}
		}))
		out := session(t, newTestServer(t, srv.URL, "tok"),
			call(1, "list_secrets", map[string]any{"scope_level": "org", "scope_id": testOrg}),
			call(2, "get_secret_meta", map[string]any{"secret_id": testSecretID}))
		srv.Close()
		if !strings.Contains(out, `"isError":true`) || c.In(out) {
			t.Fatalf("%s: reply was passed on or echoed: %s", name, out)
		}
	}
	// Positive control: untouched rows go through.
	secret := secretRow("builtin://default/db-password")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/versions") {
			_ = json.NewEncoder(w).Encode([]any{map[string]any{"version": "v1", "created_at": time.Unix(1, 0).UTC(), "fingerprint": "kfp1:k:abcdefghijklmnop", "length": 12, "status": "current"}})
			return
		}
		_ = json.NewEncoder(w).Encode(secret)
	}))
	defer srv.Close()
	if out := session(t, newTestServer(t, srv.URL, "tok"), call(1, "get_secret_meta", map[string]any{"secret_id": testSecretID})); strings.Contains(out, `"isError":true`) {
		t.Fatalf("positive control refused: %s", out)
	}
}
