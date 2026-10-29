package security

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These checks examine actual wire JSON, not the server's response structs.
var catalogWireFields = map[string]string{ //nolint:gosec // G101: response field names, no credential literals
	"secret":  "id name scope class type description store provider_ref current_version created_at updated_at expires_at owner",
	"store":   "id name provider",
	"version": "version created_at created_by fingerprint length status",
	"error":   "error_class message request_id",
	"result":  "ok request_id",
	// One-time credential issuance has a separate identity contract. Its
	// absence from the response allowlist is reported separately by the audit.
	"issue": "token token_id last4 kind scope expires_at created_at",
}

func catalogWireCheck(raw []byte, kind string, nonempty bool) error {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return fmt.Errorf("response is not JSON")
	}
	var walk func(any, string) error
	walk = func(v any, shape string) error {
		if rows, ok := v.([]any); ok {
			if nonempty && len(rows) == 0 {
				return fmt.Errorf("positive control returned an empty list")
			}
			for _, row := range rows {
				if err := walk(row, shape); err != nil {
					return err
				}
			}
			return nil
		}
		obj, ok := v.(map[string]any)
		if !ok || len(obj) == 0 {
			return fmt.Errorf("expected nonempty object")
		}
		allowed := " " + catalogWireFields[shape] + " "
		for key, value := range obj {
			// Never include an untrusted key or value in an error.
			if !strings.Contains(allowed, " "+key+" ") {
				return fmt.Errorf("unlisted response field")
			}
			if key == "store" {
				if err := walk(value, "store"); err != nil {
					return err
				}
			} else if _, nested := value.(map[string]any); nested {
				return fmt.Errorf("unexpected nested object")
			} else if _, nested := value.([]any); nested {
				return fmt.Errorf("unexpected nested list")
			}
		}
		return nil
	}
	return walk(v, kind)
}

type catalogOutput struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *catalogOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}
func (b *catalogOutput) snapshot() string { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }

type catalogReply struct {
	status  int
	body    []byte
	headers http.Header
}
type catalogAudit struct {
	t                                                                                  *testing.T
	pool                                                                               *pgxpool.Pool
	url, cli, token, otherToken, org, otherOrg, secret, otherSecret, agent, otherAgent string
	meta, otherMeta                                                                    canary.Canary
	tokenOrgs                                                                          map[string]string
	probes                                                                             []canary.Canary
	stdout, stderr                                                                     catalogOutput
	client                                                                             *http.Client
}

func catalogSafe(t *testing.T, err error, operation string) {
	t.Helper()
	if err != nil {
		t.Fatal(operation + " failed (details suppressed)")
	}
}

// This is an audit, so known contract failures remain visible observations in
// the ordinary suite. A strict run reproduces each finding as a failing test;
// it is not an acceptance pass merely because the observation suite is green.
func catalogRequirement(t *testing.T, check string, satisfied bool) {
	t.Helper()
	if satisfied {
		return
	}
	t.Log("FINDING contract requirement failed: " + check)
	if catalogStrict(check, os.Getenv("KEEP_CATALOG_AUDIT_STRICT")) {
		t.Error("strict contract requirement failed: " + check)
	}
}

func catalogStrict(check, mode string) bool { return mode == check || mode == "all" }

func catalogBuild(t *testing.T, name string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), name)
	c := osexec.Command("go", "build", "-o", bin, "../../cmd/"+name) //nolint:gosec // fixed commands in this repository
	c.Env = catalogEnv()
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("build %s failed (output length %d)", name, len(out))
	}
	return bin
}

func catalogAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	catalogSafe(t, err, "reserve port")
	a := l.Addr().String()
	catalogSafe(t, l.Close(), "release port")
	return a
}

// Child processes receive only these platform paths and explicitly supplied
// disposable settings. Unrelated credentials must not cross this boundary.
// HOME is retained so child go builds can find the module/build caches and
// toolchain. This filters environment variables, not filesystem access: children
// can still read files under that home. CLI calls use explicit disposable config
// paths below; this harness assumes a trusted checkout and local toolchain.
func catalogEnv(extra ...string) []string {
	var result []string
	for _, key := range []string{"PATH", "HOME", "TMPDIR"} {
		if value, ok := os.LookupEnv(key); ok {
			result = append(result, key+"="+value)
		}
	}
	return append(result, extra...)
}

func newCatalogAudit(t *testing.T, serverEnv ...string) *catalogAudit {
	t.Helper()
	dsn := pgscratch.New(t, map[string]string{
		"log_error_verbosity": "terse", "log_min_error_statement": "panic", "log_statement": "'none'",
		"log_min_duration_statement": "-1", "log_min_duration_sample": "-1", "log_transaction_sample_rate": "0", "log_min_messages": "fatal",
	})
	server := catalogBuild(t, "keep-server")
	w := &catalogAudit{t: t, cli: catalogBuild(t, "keep"), meta: canary.New(), otherMeta: canary.New(), tokenOrgs: make(map[string]string)}
	migrate := osexec.Command(server, "migrate", "up") //nolint:gosec // this test's binary
	migrate.Env = catalogEnv("KEEP_DATABASE_URL=" + dsn)
	_, err := migrate.CombinedOutput()
	catalogSafe(t, err, "migrate scratch database")
	w.pool, err = pgxpool.New(pgscratch.Context(t), dsn)
	catalogSafe(t, err, "open scratch database")
	t.Cleanup(w.pool.Close)
	ctx := pgscratch.Context(t)
	tr, cat := tenancy.New(w.pool), catalog.New(w.pool)
	seed := func(label string, meta canary.Canary) (string, string, string, string) {
		org, err := tr.CreateOrganization(ctx, "audit-"+label+uuid.NewString(), "")
		catalogSafe(t, err, "create organization")
		user := uuid.New()
		_, err = w.pool.Exec(ctx, `INSERT INTO users(id,org_id,email) VALUES($1,$2,$3)`, user, org.ID, label+"@example.test")
		catalogSafe(t, err, "create user")
		_, err = w.pool.Exec(ctx, `INSERT INTO memberships(id,org_id,user_id,scope,role) VALUES($1,$2,$3,$4,'admin')`, uuid.New(), org.ID, user, tenancy.Org(org.ID).String())
		catalogSafe(t, err, "create membership")
		agent, err := tr.CreateAgent(ctx, org.ID, user, "audit")
		catalogSafe(t, err, "create agent")
		issued, err := identity.NewRepo(w.pool).Issue(ctx, identity.IssueParams{OrgID: org.ID, Kind: identity.KindUser, PrincipalID: user, Scope: tenancy.Org(org.ID).String()})
		catalogSafe(t, err, "issue synthetic credential")
		wire, err := issued.Response().WireJSON()
		catalogSafe(t, err, "encode synthetic credential")
		var cred struct {
			Token string `json:"token"`
		}
		catalogSafe(t, json.Unmarshal(wire, &cred), "decode synthetic credential")
		w.trackToken(cred.Token, org.ID.String())
		store, err := cat.CreateStore(ctx, org.ID, "builtin", "audit-store", tenancy.Org(org.ID))
		catalogSafe(t, err, "create store")
		_, err = cat.CreateStoreBinding(ctx, org.ID, tenancy.Org(org.ID), store.ID)
		catalogSafe(t, err, "bind store")
		ref, err := cat.CreateRef(ctx, catalog.CreateRefInput{Org: org.ID, Scope: tenancy.Org(org.ID), Name: meta.Value(1), Description: meta.Value(2), Class: "dev", Type: "generic", ProviderRef: "builtin://audit/" + label})
		catalogSafe(t, err, "create reference")
		_, err = cat.AddVersion(ctx, org.ID, ref.ID, "v1", "kfp1:audit:AAAAAAAAAA", 32)
		catalogSafe(t, err, "seed version metadata")
		return org.ID.String(), ref.ID.String(), cred.Token, agent.ID.String()
	}
	w.org, w.secret, w.token, w.agent = seed("a", w.meta)
	w.otherOrg, w.otherSecret, w.otherToken, w.otherAgent = seed("b", w.otherMeta)
	roleDSN := pgscratch.NewRole(t, dsn, "keep_app")
	dir := t.TempDir()
	root := make([]byte, 32)
	_, err = rand.Read(root)
	catalogSafe(t, err, "generate synthetic root")
	rootPath := filepath.Join(dir, "root")
	catalogSafe(t, os.WriteFile(rootPath, root, 0o600), "write synthetic root")
	clear(root)
	// Use the standard library's disposable certificate, without adding any
	// trust to the host. Only this client's isolated transport trusts it.
	tlsFixture := httptest.NewTLSServer(http.NotFoundHandler())
	cert := tlsFixture.TLS.Certificates[0]
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	catalogSafe(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600), "write test certificate")
	keyBytes, err := marshalCatalogKey(cert.PrivateKey)
	catalogSafe(t, err, "marshal test listener key")
	catalogSafe(t, os.WriteFile(keyPath, keyBytes, 0o600), "write test listener key")
	w.client = tlsFixture.Client()
	tlsFixture.Close()
	t.Cleanup(w.client.CloseIdleConnections)
	addr := catalogAddr(t)
	w.url = "https://" + addr
	procCtx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	cmd := osexec.CommandContext(procCtx, server) //nolint:gosec // this test's binary
	cmd.Env = catalogEnv("KEEP_DATABASE_URL="+roleDSN, "KEEP_ROOT_KEY_FILE="+rootPath, "KEEP_HTTP_ADDR="+catalogAddr(t), "KEEP_RUNNER_ADDR="+addr, "KEEP_PUBLIC_URL="+w.url, "KEEP_SERVER_TLS_CERT_FILE="+certPath, "KEEP_SERVER_TLS_KEY_FILE="+keyPath)
	cmd.Env = append(cmd.Env, serverEnv...)
	cmd.Stdout, cmd.Stderr = &w.stdout, &w.stderr
	catalogSafe(t, cmd.Start(), "start server")
	t.Cleanup(func() { cancel(); _ = cmd.Wait() })
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		r, err := w.client.Get(w.url + "/healthz")
		if err == nil {
			_ = r.Body.Close()
			if r.StatusCode == 200 {
				return w
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("server readiness failed (process output suppressed)")
	return nil
}

func (w *catalogAudit) trackToken(token, org string) {
	if token == "" {
		w.t.Fatal("empty credential cannot be tracked")
	}
	w.tokenOrgs[token] = org
	w.probes = append(w.probes, canary.Of(token))
	if pos := strings.LastIndex(token, "_"); pos >= 0 && pos+1 < len(token) {
		w.probes = append(w.probes, canary.Of(token[pos+1:]))
	}
}

func catalogContains(probes []canary.Canary, raw string) bool {
	for _, c := range probes {
		if c.In(raw) {
			return true
		}
	}
	// Check embedded Basic/JSON base64 at every alignment as well.
	for _, word := range strings.FieldsFunc(raw, func(r rune) bool {
		return (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') && !strings.ContainsRune("+/=_-", r)
	}) {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			decoded, err := enc.DecodeString(word)
			if err != nil {
				continue
			}
			for _, c := range probes {
				if c.In(string(decoded)) {
					return true
				}
			}
		}
	}
	return false
}

func (w *catalogAudit) noLeak(t *testing.T, raw string) {
	t.Helper()
	if catalogContains(w.probes, raw) {
		t.Fatal("credential canary detected (value suppressed)")
	}
}

func (w *catalogAudit) request(t *testing.T, method, path, token, body string, headers map[string]string) catalogReply {
	t.Helper()
	r, err := http.NewRequestWithContext(t.Context(), method, w.url+path, strings.NewReader(body))
	catalogSafe(t, err, "construct request")
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	resp, err := w.client.Do(r)
	catalogSafe(t, err, "send request")
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	catalogSafe(t, err, "read response")
	w.noLeak(t, fmt.Sprint(resp.Header))
	reply := catalogReply{resp.StatusCode, out, resp.Header}
	// The authenticated credential determines which metadata is foreign,
	// including bodies reached through injected query/header/body org IDs.
	if org := w.tokenOrgs[token]; org != "" {
		foreign, ids := w.otherMeta, []string{w.otherOrg, w.otherSecret}
		if org == w.otherOrg {
			foreign, ids = w.meta, []string{w.org, w.secret}
		}
		wire := string(out) + fmt.Sprint(resp.Header)
		// Errors may echo an ID supplied in the request. Only successful data
		// responses are prohibited from containing foreign object IDs.
		if reply.status < 200 || reply.status >= 300 {
			ids = nil
		}
		catalogSafe(t, catalogForeignCheck(wire, foreign, ids...), "foreign metadata/object guard")
	}
	return reply
}

func catalogExpect(t *testing.T, r catalogReply, status int, shape string, nonempty bool) {
	t.Helper()
	if err := catalogStatusCheck(r.status, status); err != nil {
		t.Fatal(err)
	}
	catalogSafe(t, catalogWireCheck(r.body, shape, nonempty), "closed wire schema")
}

func catalogStatusCheck(actual, want int) error {
	if actual != want {
		return fmt.Errorf("HTTP status=%d want=%d (body suppressed)", actual, want)
	}
	return nil
}

func catalogForeignCheck(raw string, foreign canary.Canary, ids ...string) error {
	if foreign.In(raw) {
		return fmt.Errorf("foreign metadata detected")
	}
	for _, id := range ids {
		if id != "" && strings.Contains(raw, id) {
			return fmt.Errorf("foreign object detected")
		}
	}
	return nil
}

func catalogSameError(foreign, missing catalogReply) error {
	if foreign.status != missing.status || catalogError(foreign.body) == "invalid-json" || catalogError(foreign.body) != catalogError(missing.body) {
		return fmt.Errorf("foreign/missing error oracle")
	}
	return nil
}

type catalogIssued struct {
	Token   string `json:"token"`
	TokenID string `json:"token_id"`
}

func catalogDecodeIssued(raw []byte) (catalogIssued, error) {
	var issued catalogIssued
	if json.Unmarshal(raw, &issued) != nil || issued.Token == "" || issued.TokenID == "" {
		return catalogIssued{}, fmt.Errorf("invalid or empty issuance response")
	}
	return issued, nil
}

func catalogError(raw []byte) string {
	var obj map[string]any
	if json.Unmarshal(raw, &obj) != nil {
		return "invalid-json"
	}
	delete(obj, "request_id")
	b, _ := json.Marshal(obj)
	return string(b)
}

// catalogErrorClass is the error_class of an error body, empty when absent.
func catalogErrorClass(raw []byte) string {
	var obj struct {
		Class string `json:"error_class"`
	}
	if json.Unmarshal(raw, &obj) != nil {
		return ""
	}
	return obj.Class
}

// TestCatalogRequirementProbe runs only when explicitly selected by strict_all.
// A separate test process lets the parent observe a genuine testing.T failure.
func TestCatalogRequirementProbe(t *testing.T) {
	check := os.Getenv("KEEP_CATALOG_REQUIREMENT_PROBE")
	if check == "" {
		return
	}
	catalogRequirement(t, check, os.Getenv("KEEP_CATALOG_REQUIREMENT_SATISFIED") == "true")
}

// TestCatalogProcessAudit exercises the catalog and credential routes on a
// real keep-server with a clean migrated PostgreSQL database (contracts
// 4.3/4.4 and cross-organization isolation). No response/error is printed.
func TestCatalogProcessAudit(t *testing.T) {
	// The audit below sends far more requests per principal than the
	// default catalog limit allows; the limit has its own test further down.
	w := newCatalogAudit(t, "KEEP_CATALOG_RATE_PER_MINUTE=60000", "KEEP_CATALOG_BURST=10000")
	base := "/orgs/" + w.org
	query := "?scope_level=org&scope_id=" + w.org
	for _, tc := range []struct{ name, path, shape string }{
		{"list", base + "/secrets" + query, "secret"},
		{"metadata", base + "/secrets/" + w.secret, "secret"},
		{"versions", base + "/secrets/" + w.secret + "/versions", "version"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := w.request(t, "GET", tc.path, w.token, "", nil)
			catalogExpect(t, r, 200, tc.shape, true)
			w.noLeak(t, string(r.body))
			if tc.shape == "secret" && (!w.meta.In(string(r.body)) || !bytes.Contains(r.body, []byte(w.meta.Value(2)))) {
				t.Fatal("metadata positive control absent")
			}
			t.Log("PASS wire fields, credential leak, metadata positive control")
		})
	}
	t.Run("create", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"scope_level": "org", "scope_id": w.org, "name": "created-audit", "class": "dev", "type": "generic", "provider_ref": "builtin://audit/created", "description": w.meta.Value(2)})
		r := w.request(t, "POST", base+"/secrets", w.token, string(body), nil)
		catalogExpect(t, r, 201, "secret", true)
		w.noLeak(t, string(r.body))
		t.Log("PASS wire fields, credential leak, create")
	})
	t.Run("foreign_id_matches_missing", func(t *testing.T) {
		// Both organizations' own tokens can read their fixture.
		own := w.request(t, "GET", "/orgs/"+w.otherOrg+"/secrets/"+w.otherSecret, w.otherToken, "", nil)
		catalogExpect(t, own, 200, "secret", true)
		w.noLeak(t, string(own.body))
		if !bytes.Contains(own.body, []byte(w.otherMeta.Value(1))) || !bytes.Contains(own.body, []byte(w.otherMeta.Value(2))) || !bytes.Contains(own.body, []byte(w.otherSecret)) {
			t.Fatal("organization B metadata/object positive control absent")
		}
		for _, suffix := range []string{"", "/versions"} {
			missingID := uuid.NewString()
			missing := w.request(t, "GET", base+"/secrets/"+missingID+suffix, w.token, "", nil)
			foreign := w.request(t, "GET", base+"/secrets/"+w.otherSecret+suffix, w.token, "", nil)
			catalogExpect(t, missing, 404, "error", true)
			catalogExpect(t, foreign, 404, "error", true)
			w.noLeak(t, string(foreign.body)+string(missing.body))
			if strings.ReplaceAll(catalogError(missing.body), missingID, "<requested-id>") != strings.ReplaceAll(catalogError(foreign.body), w.otherSecret, "<requested-id>") || !bytes.Contains(missing.body, []byte(`"secret_not_found"`)) {
				t.Fatal("missing/foreign error oracle")
			}
		}
		t.Log("PASS identical secret_not_found for absent/foreign IDs")
	})
	t.Run("organization_path", func(t *testing.T) {
		for _, route := range []struct{ method, suffix string }{
			{"GET", "/secrets" + query}, {"POST", "/secrets"},
			{"GET", "/secrets/" + w.otherSecret}, {"GET", "/secrets/" + w.otherSecret + "/versions"},
			{"POST", "/tokens"}, {"POST", "/tokens/" + uuid.NewString() + "/revoke"},
		} {
			r := w.request(t, route.method, "/orgs/"+w.otherOrg+route.suffix, w.token, `{}`, nil)
			catalogExpect(t, r, 404, "error", true)
			w.noLeak(t, string(r.body))
			missing := w.request(t, route.method, "/orgs/"+uuid.NewString()+route.suffix, w.token, `{}`, nil)
			catalogExpect(t, missing, 404, "error", true)
			w.noLeak(t, string(missing.body))
			if catalogError(r.body) != catalogError(missing.body) {
				t.Fatal("foreign/missing organization oracle")
			}
			if bytes.Contains(r.body, []byte(w.otherSecret)) || w.otherMeta.In(string(r.body)) {
				t.Fatal("foreign metadata exposed")
			}
			// A foreign or absent organization is not_found; secret_not_found
			// is only for a secret ID inside the caller's own organization.
			catalogRequirement(t, "organization_error", catalogErrorClass(r.body) == "not_found")
		}
	})
	t.Run("organization_list_query", func(t *testing.T) {
		// A real, nonempty B list proves the foreign scope exists.
		other := w.request(t, "GET", "/orgs/"+w.otherOrg+"/secrets?scope_level=org&scope_id="+w.otherOrg, w.otherToken, "", nil)
		catalogExpect(t, other, 200, "secret", true)
		w.noLeak(t, string(other.body))
		if !bytes.Contains(other.body, []byte(w.otherSecret)) || !w.otherMeta.In(string(other.body)) {
			t.Fatal("foreign scope list positive control absent")
		}
		foreign := w.request(t, "GET", base+"/secrets?scope_level=org&scope_id="+w.otherOrg, w.token, "", nil)
		missing := w.request(t, "GET", base+"/secrets?scope_level=org&scope_id="+uuid.NewString(), w.token, "", nil)
		catalogExpect(t, foreign, 200, "secret", false)
		catalogExpect(t, missing, 200, "secret", false)
		w.noLeak(t, string(foreign.body)+string(missing.body))
		catalogSafe(t, catalogForeignCheck(string(foreign.body)+string(missing.body), w.otherMeta, w.otherSecret), "foreign scope list metadata/object guard")
		// Lists deliberately return an empty array for inaccessible scopes.
		if !bytes.Equal(bytes.TrimSpace(foreign.body), []byte("[]")) || !bytes.Equal(bytes.TrimSpace(foreign.body), bytes.TrimSpace(missing.body)) {
			t.Fatal("foreign/missing list scope_id oracle or nonempty list")
		}
		t.Log("PASS foreign/missing list scope_id have identical empty lists")
	})
	t.Run("organization_body_header", func(t *testing.T) {
		headers := map[string]string{"X-Org-ID": w.otherOrg, "Org-ID": w.otherOrg}
		r := w.request(t, "GET", base+"/secrets/"+w.secret+"?org_id="+w.otherOrg, w.token, "", headers)
		catalogExpect(t, r, 200, "secret", true)
		if !bytes.Contains(r.body, []byte(w.secret)) {
			t.Fatal("header/query changed identity")
		}
		body, _ := json.Marshal(map[string]string{"scope_level": "org", "scope_id": w.otherOrg, "name": "foreign-create", "class": "dev", "type": "generic", "provider_ref": "builtin://audit/foreign"})
		r = w.request(t, "POST", base+"/secrets", w.token, string(body), headers)
		catalogExpect(t, r, 404, "error", true)
		w.noLeak(t, string(r.body))
		catalogRequirement(t, "organization_error", catalogErrorClass(r.body) == "not_found")
		missingOrg := uuid.NewString()
		missingBody, _ := json.Marshal(map[string]string{"scope_level": "org", "scope_id": missingOrg, "name": "foreign-create", "class": "dev", "type": "generic", "provider_ref": "builtin://audit/foreign"})
		missing := w.request(t, "POST", base+"/secrets", w.token, string(missingBody), headers)
		catalogExpect(t, missing, 404, "error", true)
		w.noLeak(t, string(missing.body))
		catalogSafe(t, catalogSameError(r, missing), "foreign/missing scope_id")
		body, _ = json.Marshal(map[string]string{"kind": "a", "principal_id": w.agent, "scope": "org:" + w.otherOrg})
		r = w.request(t, "POST", base+"/tokens", w.token, string(body), headers)
		catalogExpect(t, r, 400, "error", true)
		w.noLeak(t, string(r.body))
		// A foreign organization scope in a token request is invalid_argument,
		// allowed only while it is the same answer as for an absent one (below).
		catalogRequirement(t, "organization_error", catalogErrorClass(r.body) == "invalid_argument")
		missingBody, _ = json.Marshal(map[string]string{"kind": "a", "principal_id": w.agent, "scope": "org:" + missingOrg})
		missing = w.request(t, "POST", base+"/tokens", w.token, string(missingBody), headers)
		catalogExpect(t, missing, 400, "error", true)
		w.noLeak(t, string(missing.body))
		catalogSafe(t, catalogSameError(r, missing), "foreign/missing token scope")
		// An organization id smuggled into the body is an undeclared field:
		// refused outright (strict decoding), never read as an identity.
		for _, route := range []struct {
			path string
			body map[string]string
		}{
			{"/secrets", map[string]string{"scope_level": "org", "scope_id": w.otherOrg, "org_id": w.otherOrg, "name": "foreign-create", "class": "dev", "type": "generic", "provider_ref": "builtin://audit/foreign"}},
			{"/tokens", map[string]string{"kind": "a", "principal_id": w.agent, "scope": "org:" + w.otherOrg, "org_id": w.otherOrg}},
			// Own organization scope: valid but for the undeclared field, so
			// only strict decoding (not scope validation) can refuse it.
			{"/tokens", map[string]string{"kind": "a", "principal_id": w.agent, "scope": "org:" + w.org, "org_id": w.org}},
		} {
			raw, _ := json.Marshal(route.body)
			r := w.request(t, "POST", base+route.path, w.token, string(raw), headers)
			catalogExpect(t, r, 400, "error", true)
			w.noLeak(t, string(r.body))
			catalogRequirement(t, "organization_error", catalogErrorClass(r.body) == "invalid_argument")
		}
		var n int
		catalogSafe(t, w.pool.QueryRow(pgscratch.Context(t), `SELECT count(*) FROM secrets WHERE name='foreign-create'`).Scan(&n), "check denied write")
		if n != 0 {
			t.Fatal("foreign write was persisted")
		}
		t.Log("PASS (findings above) authenticated organization cannot be overridden")
	})
	t.Run("credentials", func(t *testing.T) { w.auditCredentials(t, base) })
	t.Run("foreign_revoke", func(t *testing.T) { w.auditForeignRevoke(t, base) })
	t.Run("malformed_and_size", func(t *testing.T) { w.auditMalformed(t, base) })
	t.Run("cli", func(t *testing.T) { w.auditCLI(t) })
	t.Run("journal_and_process_output", func(t *testing.T) {
		rows, err := w.pool.Query(pgscratch.Context(t), `SELECT row_to_json(r)::text FROM audit_records r`)
		catalogSafe(t, err, "read journal")
		defer rows.Close()
		count := 0
		for rows.Next() {
			var row string
			catalogSafe(t, rows.Scan(&row), "read journal row")
			w.noLeak(t, row)
			count++
		}
		catalogSafe(t, rows.Err(), "iterate journal")
		if count == 0 {
			t.Fatal("journal positive control empty")
		}
		out := w.stdout.snapshot() + w.stderr.snapshot()
		if !strings.Contains(out, "listening") {
			t.Fatal("process output positive control empty")
		}
		w.noLeak(t, out)
		t.Logf("PASS journal rows=%d; stdout/stderr captured; no credential canary", count)
	})
}

func marshalCatalogKey(key any) ([]byte, error) {
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), nil
}

func (w *catalogAudit) auditCredentials(t *testing.T, base string) {
	body, _ := json.Marshal(map[string]string{"kind": "a", "principal_id": w.agent, "scope": "org:" + w.org})
	r := w.request(t, "POST", base+"/tokens", w.token, string(body), nil)
	catalogExpect(t, r, 201, "issue", true)
	catalogRequirement(t, "issuance_allowlist", catalogWireCheck(r.body, "result", true) == nil)
	// The newly issued credential is permitted ONLY in this issuance body.
	w.noLeak(t, string(r.body)) // existing bearer must never be echoed here
	issued, err := catalogDecodeIssued(r.body)
	catalogSafe(t, err, "decode issuance credential")
	w.trackToken(issued.Token, w.org)
	w.noLeak(t, fmt.Sprint(r.headers))
	catalogExpect(t, w.request(t, "GET", base+"/secrets?scope_level=org&scope_id="+w.org, issued.Token, "", nil), 200, "secret", true)
	r = w.request(t, "POST", base+"/tokens/"+issued.TokenID+"/revoke", w.token, `{}`, nil)
	catalogExpect(t, r, 200, "result", true)
	w.noLeak(t, string(r.body))
	r = w.request(t, "GET", base+"/secrets?scope_level=org&scope_id="+w.org, issued.Token, "", nil)
	catalogExpect(t, r, 401, "error", true)
	w.noLeak(t, string(r.body))
	invalid := canary.New()
	w.probes = append(w.probes, invalid)
	r = w.request(t, "GET", base+"/secrets", invalid.Value(1), "", nil)
	catalogExpect(t, r, 401, "error", true)
	w.noLeak(t, string(r.body))
	t.Log("PASS (findings above) issue/use/revoke; invalid/revoked tokens absent from responses and headers")
}

func (w *catalogAudit) auditForeignRevoke(t *testing.T, base string) {
	otherBase := "/orgs/" + w.otherOrg
	body, _ := json.Marshal(map[string]string{"kind": "a", "principal_id": w.otherAgent, "scope": "org:" + w.otherOrg})
	reply := w.request(t, "POST", otherBase+"/tokens", w.otherToken, string(body), nil)
	catalogExpect(t, reply, 201, "issue", true)
	w.noLeak(t, string(reply.body))
	issued, err := catalogDecodeIssued(reply.body)
	catalogSafe(t, err, "decode organization B credential")
	w.trackToken(issued.Token, w.otherOrg)
	w.noLeak(t, fmt.Sprint(reply.headers))
	use := func(status int, shape string) {
		t.Helper()
		r := w.request(t, "GET", otherBase+"/secrets?scope_level=org&scope_id="+w.otherOrg, issued.Token, "", nil)
		catalogExpect(t, r, status, shape, true)
		w.noLeak(t, string(r.body))
		if status == 200 && !bytes.Contains(r.body, []byte(w.otherMeta.Value(1))) {
			t.Fatal("organization B credential positive control absent")
		}
	}
	use(200, "secret")
	for _, path := range []string{base, otherBase} {
		denied := w.request(t, "POST", path+"/tokens/"+issued.TokenID+"/revoke", w.token, `{}`, nil)
		catalogExpect(t, denied, 404, "error", true)
		w.noLeak(t, string(denied.body))
		missing := w.request(t, "POST", path+"/tokens/"+uuid.NewString()+"/revoke", w.token, `{}`, nil)
		catalogExpect(t, missing, 404, "error", true)
		w.noLeak(t, string(missing.body))
		catalogSafe(t, catalogSameError(denied, missing), "foreign/missing token revoke")
		use(200, "secret") // denial must leave the real B credential usable
	}
	own := w.request(t, "POST", otherBase+"/tokens/"+issued.TokenID+"/revoke", w.otherToken, `{}`, nil)
	catalogExpect(t, own, 200, "result", true)
	w.noLeak(t, string(own.body))
	use(401, "error") // positive control: the same credential can be revoked
	t.Log("PASS real B token: A revoke through paths A/B denied; still usable after each; own revoke invalidates")
}

func (w *catalogAudit) auditMalformed(t *testing.T, base string) {
	c := canary.New()
	w.probes = append(w.probes, c)
	for _, path := range []string{base + "/secrets", base + "/tokens"} {
		for _, body := range []string{`{"broken":"` + c.Value(1), `{"value":"` + c.Value(1) + `"}`} {
			r := w.request(t, "POST", path, w.token, body, nil)
			catalogExpect(t, r, 400, "error", true)
			w.noLeak(t, string(r.body))
		}
	}
	// Valid JSON padded with an ignored attacker-controlled field probes a
	// request-size cap independently of metadata's per-field rune limits.
	padding := strings.Repeat("x", 2<<20)
	for _, target := range []struct {
		path, body string
		success    int
		shape      string
	}{
		{base + "/secrets", `{"scope_level":"org","scope_id":"` + w.org + `","name":"oversize-audit","class":"dev","type":"generic","provider_ref":"builtin://audit/oversize","ignored":"` + padding + `"}`, 201, "secret"},
		{base + "/tokens", `{"kind":"a","principal_id":"` + w.agent + `","scope":"org:` + w.org + `","ignored":"` + padding + `"}`, 201, "issue"},
	} {
		r := w.request(t, "POST", target.path, w.token, target.body, nil)
		if r.status == 413 {
			catalogExpect(t, r, 413, "error", true)
			t.Log("PASS oversized JSON rejected")
			continue
		}
		catalogExpect(t, r, target.success, target.shape, true)
		w.noLeak(t, string(r.body))
		if target.shape == "issue" {
			issued, err := catalogDecodeIssued(r.body)
			catalogSafe(t, err, "decode oversized issuance credential")
			w.trackToken(issued.Token, w.org)
			w.noLeak(t, fmt.Sprint(r.headers))
		}
		t.Logf("OBSERVED oversized valid JSON accepted: bytes=%d status=%d", len(target.body), r.status)
		catalogRequirement(t, "body_limit", false)
	}
	// Force a real backend failure, then restore via defer even on failure.
	_, err := w.pool.Exec(pgscratch.Context(t), `ALTER TABLE secret_versions RENAME TO audit_hidden_versions`)
	catalogSafe(t, err, "temporarily hide versions table")
	defer func() {
		_, err := w.pool.Exec(pgscratch.Context(t), `ALTER TABLE audit_hidden_versions RENAME TO secret_versions`)
		catalogSafe(t, err, "restore versions table")
	}()
	r := w.request(t, "GET", base+"/secrets/"+w.secret+"/versions", w.token, "", map[string]string{"X-Probe": c.Value(1)})
	catalogExpect(t, r, 500, "error", true)
	w.noLeak(t, string(r.body))
	if !bytes.Contains(r.body, []byte(`"message":"internal error"`)) {
		t.Fatal("backend error text is not closed")
	}
	t.Log("PASS (findings above) malformed JSON, forbidden value input, and real backend 500: no canary")
}

func (w *catalogAudit) auditCLI(t *testing.T) {
	// A loopback relay lets the unmodified CLI reach the test TLS server
	// without modifying the workstation's certificate store. All responses
	// originate at the real binary; the relay never logs requests.
	relay := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		r.URL.Scheme = "https"
		r.URL.Host = strings.TrimPrefix(w.url, "https://")
		r.RequestURI = ""
		resp, err := w.client.Do(r) //nolint:gosec // G704: destination is this test's fixed TLS listener
		if err != nil {
			rw.WriteHeader(502)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		for k, vs := range resp.Header {
			for _, v := range vs {
				rw.Header().Add(k, v)
			}
		}
		rw.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(rw, resp.Body)
	}))
	defer relay.Close()
	tokenFile := filepath.Join(t.TempDir(), "credentials")
	login := osexec.Command(w.cli, "login", "--token-file", tokenFile) //nolint:gosec // own test binary
	login.Env = catalogEnv()
	login.Stdin = strings.NewReader(w.token + "\n")
	out, err := login.CombinedOutput()
	catalogSafe(t, err, "CLI stdin login")
	w.noLeak(t, string(out))
	info, err := os.Stat(tokenFile)
	catalogSafe(t, err, "inspect token file")
	if info.Mode().Perm() != 0o600 {
		t.Fatal("token file permissions are not 0600")
	}
	stored, err := os.ReadFile(tokenFile) //nolint:gosec // G304: path created by this test
	catalogSafe(t, err, "read test credential file")
	if strings.TrimSpace(string(stored)) != w.token {
		t.Fatal("login stored different credential")
	}
	run := func(args []string, wantOK bool) {
		t.Helper()
		args = append(args, "--server", relay.URL, "--org", w.org, "--token-file", tokenFile, "--debug", "--json")
		cmd := osexec.Command(w.cli, args...) //nolint:gosec // own test binary, synthetic arguments
		cmd.Env = catalogEnv()
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		w.noLeak(t, stdout.String()+stderr.String())
		catalogSafe(t, catalogForeignCheck(stdout.String()+stderr.String(), w.otherMeta, w.otherOrg, w.otherSecret), "CLI foreign metadata/object guard")
		if (err == nil) != wantOK {
			t.Fatal("unexpected CLI exit (output suppressed)")
		}
		if wantOK && !strings.Contains(stderr.String(), "REDACTED") {
			t.Fatal("debug redaction positive control absent")
		}
		if wantOK && stdout.Len() == 0 {
			t.Fatal("CLI positive control empty")
		}
	}
	scope := []string{"--scope-level", "org", "--scope-id", w.org}
	run(append([]string{"list"}, scope...), true)
	run(append([]string{"meta", w.meta.Value(1)}, scope...), true)
	run(append([]string{"version", w.meta.Value(1)}, scope...), true)
	run(append([]string{"create-ref", "cli-audit", "--class", "dev", "--type", "generic", "--provider-ref", "builtin://audit/cli", "--description", w.meta.Value(2)}, scope...), true)
	run(append([]string{"meta", "missing-audit"}, scope...), false)
	catalogSafe(t, os.Chmod(tokenFile, 0o644), "loosen synthetic token file") //nolint:gosec // intentional negative control
	run(append([]string{"list"}, scope...), false)
	catalogSafe(t, os.Chmod(tokenFile, 0o600), "restore synthetic token file")
	link := filepath.Join(t.TempDir(), "link")
	catalogSafe(t, os.Symlink(tokenFile, link), "create synthetic token symlink")
	cmd := osexec.Command(w.cli, "list", "--server", relay.URL, "--org", w.org, "--scope-level", "org", "--scope-id", w.org, "--token-file", link) //nolint:gosec // own test binary
	cmd.Env = catalogEnv()
	out, err = cmd.CombinedOutput()
	w.noLeak(t, string(out))
	if err == nil {
		t.Fatal("CLI accepted a token symlink")
	}
	t.Log("PASS CLI stdin login, 0600, list/meta/version/create-ref --debug, errors, loose-file and symlink refusals")
}

// TestCatalogAuditDetectors provides known-bad controls without ever printing
// the planted data. Set KEEP_CATALOG_AUDIT_RED to select an actual failing
// assertion; an ordinary run checks that every planted defect is detected.
func TestCatalogAuditDetectors(t *testing.T) {
	c := canary.New()
	for _, shape := range []string{"secret", "store", "version", "error", "result", "issue"} {
		t.Run("fields_"+shape, func(t *testing.T) {
			key := strings.Fields(catalogWireFields[shape])[0]
			good, _ := json.Marshal(map[string]string{key: "ok"})
			catalogSafe(t, catalogWireCheck(good, shape, true), "valid shape positive control")
			bad, _ := json.Marshal(map[string]string{key: "ok", "unlisted": c.Value(1)})
			if catalogWireCheck(bad, shape, true) == nil {
				t.Fatal("field detector missed injected key")
			}
		})
	}
	for _, surface := range []string{"stdout", "stderr", "journal", "header", "error", "cli"} {
		t.Run(surface, func(t *testing.T) {
			if catalogContains([]canary.Canary{c}, "safe control") {
				t.Fatal("safe control rejected")
			}
			if !catalogContains([]canary.Canary{c}, "planted "+c.Value(1)) {
				t.Fatal("raw leak positive control missed")
			}
			// Every prefix alignment, padded/raw standard and URL encoding,
			// embedded JSON, and neighboring bytes must remain detectable.
			for _, prefix := range []string{"", "x", "xx", "user:"} {
				for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
					bad := `{"header":"Basic ` + enc.EncodeToString([]byte(prefix+c.Value(1)+":tail")) + `"}`
					if !catalogContains([]canary.Canary{c}, bad) {
						t.Fatal("shifted base64 leak control missed")
					}
				}
			}
		})
	}
	if catalogWireCheck([]byte(`{"id":"ok","store":{"id":"ok","unlisted":"bad"}}`), "secret", true) == nil {
		t.Fatal("nested field detector failed")
	}
	if catalogWireCheck([]byte(`[]`), "version", true) == nil {
		t.Fatal("empty positive control accepted")
	}
	if catalogError([]byte(`{"error_class":"secret_not_found","message":"safe","request_id":"a"}`)) != catalogError([]byte(`{"error_class":"secret_not_found","message":"safe","request_id":"b"}`)) {
		t.Fatal("request id normalization failed")
	}
	if catalogError([]byte(`{"error_class":"secret_not_found","message":"safe"}`)) == catalogError([]byte(`{"error_class":"not_found","message":"safe"}`)) {
		t.Fatal("tenant oracle detector failed")
	}
	if catalogErrorClass([]byte(`{"error_class":"not_found","message":"safe"}`)) != "not_found" || catalogErrorClass([]byte(`{"error_class":"secret_not_found"}`)) == "not_found" || catalogErrorClass([]byte(`x`)) != "" {
		t.Fatal("error class reader failed")
	}

	t.Run("status", func(t *testing.T) {
		catalogSafe(t, catalogStatusCheck(200, 200), "matching status control")
		for _, pair := range [][2]int{{201, 413}, {401, 200}, {200, 401}, {200, 404}} {
			if catalogStatusCheck(pair[0], pair[1]) == nil {
				t.Fatal("status detector missed injected mismatch")
			}
		}
	})
	t.Run("foreign_metadata_objects", func(t *testing.T) {
		own, foreign := canary.New(), canary.New()
		id := uuid.NewString()
		catalogSafe(t, catalogForeignCheck(own.Value(1), foreign, id), "own metadata positive control")
		for _, raw := range []string{foreign.Value(1), foreign.Value(2), `{"id":"` + id + `"}`} {
			if catalogForeignCheck(raw, foreign, id) == nil {
				t.Fatal("foreign metadata/object detector missed injected data")
			}
		}
	})
	t.Run("scope_oracle", func(t *testing.T) {
		good := catalogReply{status: 400, body: []byte(`{"error_class":"invalid_argument","message":"safe","request_id":"a"}`)}
		same := catalogReply{status: 400, body: []byte(`{"error_class":"invalid_argument","message":"safe","request_id":"b"}`)}
		catalogSafe(t, catalogSameError(good, same), "same scope error positive control")
		for _, bad := range []catalogReply{{status: 404, body: good.body}, {status: 400, body: []byte(`{"error_class":"not_found","message":"safe"}`)}, {status: 400, body: []byte(`{`)}} {
			if catalogSameError(bad, good) == nil {
				t.Fatal("scope error oracle detector missed injected mismatch")
			}
		}
	})
	t.Run("issuance_decode", func(t *testing.T) {
		good, _ := json.Marshal(map[string]string{"token": c.Value(1), "token_id": uuid.NewString()})
		issued, err := catalogDecodeIssued(good)
		catalogSafe(t, err, "valid issuance decode control")
		if issued.Token != c.Value(1) || issued.TokenID == "" {
			t.Fatal("issuance decode positive control absent")
		}
		for _, bad := range []string{`{`, `{"token_id":"id"}`, `{"token":"","token_id":"id"}`, `{"token":"value"}`, `{"token":17,"token_id":"id"}`} {
			if _, err := catalogDecodeIssued([]byte(bad)); err == nil {
				t.Fatal("issuance decoder accepted invalid/empty credential")
			}
		}
	})
	t.Run("strict_all", func(t *testing.T) {
		bin, err := os.Executable()
		catalogSafe(t, err, "locate requirement probe binary")
		for _, check := range []string{"organization_error", "issuance_allowlist", "body_limit", "future_finding"} {
			for _, mode := range []string{"all", check, "", "unrelated"} {
				for _, satisfied := range []bool{false, true} {
					// Exercise the real catalogRequirement -> testing.T failure path,
					// not just its selector predicate. Child output stays private.
					cmd := osexec.Command(bin, "-test.run=^TestCatalogRequirementProbe$", "-test.v") //nolint:gosec // this test binary
					cmd.Env = catalogEnv("KEEP_CATALOG_REQUIREMENT_PROBE="+check, "KEEP_CATALOG_AUDIT_STRICT="+mode, fmt.Sprintf("KEEP_CATALOG_REQUIREMENT_SATISFIED=%t", satisfied))
					out, runErr := cmd.CombinedOutput()
					wantFailure := !satisfied && (mode == "all" || mode == check)
					if wantFailure {
						exit, ok := runErr.(*osexec.ExitError)
						if !ok || exit.ExitCode() != 1 || !bytes.Contains(out, []byte("--- FAIL: TestCatalogRequirementProbe")) || !bytes.Contains(out, []byte("strict contract requirement failed: "+check)) {
							t.Fatal("strict requirement did not fail its child test")
						}
					} else if runErr != nil || !bytes.Contains(out, []byte("--- PASS: TestCatalogRequirementProbe")) {
						t.Fatal("requirement positive control failed")
					}
					if bytes.Contains(out, []byte("FINDING contract requirement failed: "+check)) == satisfied {
						t.Fatal("requirement finding observation mismatch")
					}
				}
			}
		}
	})
	t.Run("child_environment", func(t *testing.T) {
		t.Setenv("CATALOG_UNRELATED_SETTING", c.Value(1))
		t.Setenv("KEEP_TEST_SETTING", c.Value(2))
		t.Setenv("TMPDIR", t.TempDir())
		child := catalogEnv("KEEP_TEST_SETTING=disposable")
		found := false
		for _, item := range child {
			key, value, _ := strings.Cut(item, "=")
			switch key {
			case "PATH", "HOME", "TMPDIR":
				if value != os.Getenv(key) {
					t.Fatal("child platform path positive control failed")
				}
				if key == "TMPDIR" {
					found = true
				}
			case "KEEP_TEST_SETTING":
				if value != "disposable" {
					t.Fatal("inherited setting displaced disposable setting")
				}
			default:
				t.Fatal("child environment inherited an unlisted setting")
			}
		}
		if !found {
			t.Fatal("child environment positive control absent")
		}
	})
	switch os.Getenv("KEEP_CATALOG_AUDIT_RED") {
	case "field":
		catalogSafe(t, catalogWireCheck([]byte(`{"id":"safe","unlisted":true}`), "secret", true), "injected extra field")
	case "log":
		if catalogContains([]canary.Canary{c}, "planted "+c.Value(1)) {
			t.Fatal("injected log canary detected (value suppressed)")
		}
	case "tenant":
		if catalogError([]byte(`{"error_class":"not_found"}`)) != catalogError([]byte(`{"error_class":"secret_not_found"}`)) {
			t.Fatal("injected tenant oracle detected")
		}
	case "status":
		catalogExpect(t, catalogReply{status: 201, body: []byte(`{"ok":true}`)}, 413, "result", true)
	case "metadata":
		catalogSafe(t, catalogForeignCheck(c.Value(1), c), "injected foreign metadata")
	case "object":
		catalogSafe(t, catalogForeignCheck(`{"id":"foreign"}`, c, "foreign"), "injected foreign object")
	case "revoke":
		catalogExpect(t, catalogReply{status: 401, body: []byte(`{"error_class":"unauthenticated"}`)}, 200, "secret", true)
	case "scope":
		catalogSafe(t, catalogSameError(catalogReply{status: 400, body: []byte(`{"error_class":"not_found"}`)}, catalogReply{status: 400, body: []byte(`{"error_class":"invalid_argument"}`)}), "injected scope oracle")
	case "decode":
		_, err := catalogDecodeIssued([]byte(`{"token":"","token_id":"id"}`))
		catalogSafe(t, err, "injected empty issuance credential")
	}
	t.Log("PASS extra field, nested field, empty list, six leak surfaces, shifted base64 encodings, tenant oracle, status, metadata/object, issuance, strict-all and child environment controls")
}

// TestCatalogEnumerationLimit runs a real server with the default burst and a
// refill of one request per minute: a token enumerating ids is answered 429
// with Retry-After once its burst is spent, and another principal of the
// tenant is not slowed down. The default refill (one per second) would let a
// slow runner earn back tokens while the loop runs and turn the count below
// into a timing measurement; the default rate itself is pinned by
// TestCatalogLimit_Defaults.
func TestCatalogEnumerationLimit(t *testing.T) {
	w := newCatalogAudit(t, "KEEP_CATALOG_RATE_PER_MINUTE=1")
	base := "/orgs/" + w.org
	query := "?scope_level=org&scope_id=" + w.org
	body, _ := json.Marshal(map[string]string{"kind": "a", "principal_id": w.agent, "scope": "org:" + w.org})
	issued := w.request(t, "POST", base+"/tokens", w.token, string(body), nil)
	catalogExpect(t, issued, 201, "issue", true)
	w.noLeak(t, string(issued.body))
	var credential struct{ Token string }
	catalogSafe(t, json.Unmarshal(issued.body, &credential), "decode burst credential")
	if credential.Token == "" {
		t.Fatal("burst credential positive control empty")
	}
	w.trackToken(credential.Token, w.org)
	w.noLeak(t, fmt.Sprint(issued.headers))
	catalogExpect(t, w.request(t, "GET", base+"/secrets"+query, credential.Token, "", nil), 200, "secret", true)
	limited := 0
	for i := 0; i < 64; i++ {
		r := w.request(t, "GET", base+"/secrets/"+uuid.NewString(), credential.Token, "", nil)
		if r.status == 429 {
			limited++
			catalogExpect(t, r, 429, "error", true)
			if r.headers.Get("Retry-After") == "" {
				t.Fatal("429 without Retry-After")
			}
			w.noLeak(t, string(r.body))
			continue
		}
		catalogExpect(t, r, 404, "error", true)
		w.noLeak(t, string(r.body))
	}
	after := w.request(t, "GET", base+"/secrets"+query, credential.Token, "", nil)
	w.noLeak(t, string(after.body))
	// The default burst is 20 and the list above spent one token; at one
	// refill per minute at most a token or two return while the loop runs.
	if limited < 30 || after.status != 429 {
		t.Fatalf("enumeration burst was not limited: requests=64 rate_limited=%d followup_status=%d", limited, after.status)
	}
	// Positive control: another principal of the tenant is unaffected.
	catalogExpect(t, w.request(t, "GET", base+"/secrets"+query, w.token, "", nil), 200, "secret", true)
	t.Logf("PASS agent enumeration burst limited: requests=64 rate_limited=%d followup_status=%d", limited, after.status)
}

// TestCatalogLimitEnvWiring starts a real server with a tiny burst and a slow
// refill set through the two variables. Each variable is proved on its own:
// the burst by the third request being refused (the default would allow 20),
// the rate by Retry-After (the default rate would say 1 second).
func TestCatalogLimitEnvWiring(t *testing.T) {
	w := newCatalogAudit(t, "KEEP_CATALOG_RATE_PER_MINUTE=1", "KEEP_CATALOG_BURST=2")
	base := "/orgs/" + w.org
	query := "?scope_level=org&scope_id=" + w.org
	body, _ := json.Marshal(map[string]string{"kind": "a", "principal_id": w.agent, "scope": "org:" + w.org})
	issued := w.request(t, "POST", base+"/tokens", w.token, string(body), nil)
	catalogExpect(t, issued, 201, "issue", true)
	w.noLeak(t, string(issued.body))
	var credential struct{ Token string }
	catalogSafe(t, json.Unmarshal(issued.body, &credential), "decode wiring credential")
	if credential.Token == "" {
		t.Fatal("wiring credential positive control empty")
	}
	w.trackToken(credential.Token, w.org)
	for i := 0; i < 2; i++ {
		catalogExpect(t, w.request(t, "GET", base+"/secrets"+query, credential.Token, "", nil), 200, "secret", true)
	}
	r := w.request(t, "GET", base+"/secrets"+query, credential.Token, "", nil)
	w.noLeak(t, string(r.body))
	if r.status != 429 {
		t.Fatalf("KEEP_CATALOG_BURST=2 was not applied: third request status=%d", r.status)
	}
	wait, err := strconv.Atoi(r.headers.Get("Retry-After"))
	if err != nil || wait < 30 {
		t.Fatalf("KEEP_CATALOG_RATE_PER_MINUTE=1 was not applied: Retry-After=%q", r.headers.Get("Retry-After"))
	}
}
