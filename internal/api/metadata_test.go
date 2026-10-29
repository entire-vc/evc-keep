package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

func TestCreateRefMetadataInvalidUTF8(t *testing.T) {
	f := newRouteFixture(t)
	u := f.mustAdmin("admin")
	bearer := f.mustToken(identity.KindUser, u.ID, "org:"+f.org.ID.String())
	f.mustStore("safe", tenancy.Org(f.org.ID))
	c := canary.New()
	// encoding/json ordinarily replaces invalid UTF-8 with U+FFFD before
	// the catalog can see it. Keep the original wire bytes in this probe.
	body := `{"scope_level":"org","scope_id":"` + f.org.ID.String() + `","name":"` + c.Value(0) + "\xff" + `","class":"credential","type":"generic","provider_ref":"builtin://default/test"}`
	r := httptest.NewRequest(http.MethodPost, "/orgs/"+f.org.ID.String()+"/secrets", bytes.NewBufferString(body))
	r.Header.Set("Authorization", "Bearer "+bearer)
	res := httptest.NewRecorder()
	f.router.ServeHTTP(res, r)
	var got apperr.Body
	if res.Code != http.StatusBadRequest || json.Unmarshal(res.Body.Bytes(), &got) != nil || got.ErrorClass != "invalid_argument" {
		t.Fatal("API accepted invalid UTF-8 metadata")
	}
	if !c.In(body) || c.In(res.Body.String()) || c.In(f.logbuf.String()) {
		t.Fatal("UTF-8 canary output control failed")
	}
}

func TestCreateRefMetadataSurrogateEscapes(t *testing.T) {
	f := newRouteFixture(t)
	u := f.mustAdmin("admin")
	bearer := f.mustToken(identity.KindUser, u.ID, "org:"+f.org.ID.String())
	f.mustStore("safe", tenancy.Org(f.org.ID))
	c := canary.New()
	path := "/orgs/" + f.org.ID.String() + "/secrets"
	for _, suffix := range []string{`\ud800`, `\udc00`, `\ud800\u0061`, `\ud800\ud800`} {
		body := `{"scope_level":"org","scope_id":"` + f.org.ID.String() + `","name":"` + c.Value(0) + suffix + `","class":"credential","type":"generic","provider_ref":"builtin://default/test"}`
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+bearer)
		res := httptest.NewRecorder()
		f.router.ServeHTTP(res, r)
		var got apperr.Body
		if res.Code != http.StatusBadRequest || json.Unmarshal(res.Body.Bytes(), &got) != nil || got.ErrorClass != "invalid_argument" {
			t.Fatal("API accepted unpaired surrogate metadata")
		}
		if !c.In(body) || c.In(res.Body.String()) || c.In(f.logbuf.String()) {
			t.Fatal("surrogate canary output control failed")
		}
	}
	for _, pair := range []struct{ wire, decoded string }{{`\ud83d\ude80`, "\U0001f680"}, {`\\ud800`, `\ud800`}} {
		body := `{"scope_level":"org","scope_id":"` + f.org.ID.String() + `","name":"safe` + pair.wire + `","class":"credential","type":"generic","provider_ref":"builtin://default/test"}`
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+bearer)
		res := httptest.NewRecorder()
		f.router.ServeHTTP(res, r)
		var got Secret
		if res.Code != http.StatusCreated || json.Unmarshal(res.Body.Bytes(), &got) != nil || got.Name != "safe"+pair.decoded {
			t.Fatal("API changed valid surrogate or literal escape metadata")
		}
	}
}

func TestCreateRefMetadataAPIClosedErrors(t *testing.T) {
	f := newRouteFixture(t)
	u := f.mustAdmin("admin")
	bearer := f.mustToken(identity.KindUser, u.ID, "org:"+f.org.ID.String())
	f.mustStore("safe", tenancy.Org(f.org.ID))
	c := canary.New()
	if !c.In("error " + c.Value(0)) {
		t.Fatal("canary positive control failed")
	}
	path := "/orgs/" + f.org.ID.String() + "/secrets"
	for _, field := range []string{"name", "description", "class", "type"} {
		for shape, bad := range map[string]string{"esc": "\x1b[2J", "csi": "\u009b2J", "osc": "\x1b]0;x\x07", "rlo": "\u202e", "line": "\u2028"} {
			t.Run(field+"/"+shape, func(t *testing.T) {
				body := map[string]string{"scope_level": "org", "scope_id": f.org.ID.String(), "name": "safe", "class": "credential", "type": "generic", "provider_ref": "builtin://default/test"}
				body[field] = c.Value(0) + bad
				res := f.do(http.MethodPost, path, bearer, body)
				var got apperr.Body
				if res.Code != http.StatusBadRequest || json.Unmarshal(res.Body.Bytes(), &got) != nil || got.ErrorClass != "invalid_argument" || !strings.Contains(got.Message, field) {
					t.Fatal("API accepted hostile metadata or returned an unclassified error")
				}
				if c.In(res.Body.String()) || c.In(f.logbuf.String()) {
					t.Fatal("rejected metadata escaped to response or log")
				}
			})
		}
	}
	// Positive server control and a content assertion on the read side.
	good := f.do(http.MethodPost, path, bearer, map[string]string{"scope_level": "org", "scope_id": f.org.ID.String(), "name": "safe", "class": "credential", "type": "generic", "description": "plain single line", "provider_ref": "builtin://default/test"})
	if good.Code != http.StatusCreated {
		t.Fatal("valid metadata refused")
	}
	list := f.do(http.MethodGet, path+"?scope_level=org&scope_id="+f.org.ID.String(), bearer, nil)
	var rows []Secret
	if list.Code != http.StatusOK || json.Unmarshal(list.Body.Bytes(), &rows) != nil || len(rows) != 1 || rows[0].Name != "safe" {
		t.Fatal("rejected metadata persisted in list")
	}
}

func TestCreateRefMetadataWireFieldErrors(t *testing.T) {
	f := newRouteFixture(t)
	u := f.mustAdmin("admin")
	bearer := f.mustToken(identity.KindUser, u.ID, "org:"+f.org.ID.String())
	f.mustStore("safe", tenancy.Org(f.org.ID))
	c := canary.New()
	path := "/orgs/" + f.org.ID.String() + "/secrets"
	good := map[string]string{"scope_level": "org", "scope_id": f.org.ID.String(), "name": "wire-safe", "description": "plain", "class": "credential", "type": "generic", "provider_ref": "builtin://default/test"}
	prefix, err := json.Marshal(good)
	if err != nil {
		t.Fatal("wire positive control could not encode")
	}
	wireNames := map[string]string{"name": `na\u006de`, "description": `descrip\u0074ion`, "class": `cl\u0061ss`, "type": `ty\u0070e`}
	for field, escaped := range wireNames {
		for _, wireName := range []string{escaped, strings.ToUpper(field)} {
			for shape, suffix := range map[string]string{"utf8": "\xff", "surrogate": `\ud800`} {
				for _, lastGood := range []bool{false, true} {
					t.Run(field+"/"+wireName+"/"+shape, func(t *testing.T) {
						// Decode RawMessage values, including escaped and duplicate field names,
						// without normalizing the invalid metadata bytes before classification.
						body := string(prefix[:len(prefix)-1]) + `,"` + wireName + `":"` + c.Value(0) + suffix + `"`
						if lastGood {
							body += `,"` + field + `":"safe"`
						}
						body += `}`
						r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
						r.Header.Set("Authorization", "Bearer "+bearer)
						res := httptest.NewRecorder()
						f.router.ServeHTTP(res, r)
						var got apperr.Body
						reason := "UTF-8"
						if shape == "surrogate" {
							reason = "surrogate"
						}
						if res.Code != http.StatusBadRequest || json.Unmarshal(res.Body.Bytes(), &got) != nil || got.ErrorClass != "invalid_argument" || !strings.Contains(got.Message, field) || !strings.Contains(got.Message, reason) {
							t.Fatal("wire metadata error omitted the closed field or reason")
						}
						if !c.In(body) || c.In(res.Body.String()) || c.In(f.logbuf.String()) {
							t.Fatal("wire field canary control failed")
						}
					})
				}
			}
		}
	}
	res := f.do(http.MethodPost, path, bearer, good)
	if res.Code != http.StatusCreated {
		t.Fatal("valid wire metadata refused")
	}
	list := f.do(http.MethodGet, path+"?scope_level=org&scope_id="+f.org.ID.String(), bearer, nil)
	var rows []Secret
	if list.Code != http.StatusOK || json.Unmarshal(list.Body.Bytes(), &rows) != nil || len(rows) != 1 || rows[0].Name != "wire-safe" {
		t.Fatal("invalid wire metadata persisted")
	}
}
