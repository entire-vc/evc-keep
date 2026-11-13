package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/builtin/orgpki"
	"github.com/entire-vc/evc-keep/internal/scopedtransfer"
	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/entire-vc/evc-keep/internal/testutil/transferfixture"
	"github.com/entire-vc/evc-keep/internal/transfercarrier"
	"github.com/entire-vc/evc-keep/internal/transferverify"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func writeRootFile(t *testing.T, dir, name string) (string, []byte) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(base64.StdEncoding.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	return p, key
}

func openLocal(t *testing.T, pool *pgxpool.Pool, keyID string, key []byte) *builtin.Local {
	t.Helper()
	l, err := builtin.NewLocal(pool, keyID, bytes.Clone(key), slog.New(slog.NewJSONHandler(io.Discard, nil)), func(builtin.KeyEvent) {})
	if err != nil {
		t.Fatal("open local")
	}
	return l
}

var fieldRE = regexp.MustCompile(`(\w+)=(\S+)`)

func fields(line string) map[string]string {
	out := map[string]string{}
	for _, m := range fieldRE.FindAllStringSubmatch(line, -1) {
		out[m[1]] = m[2]
	}
	return out
}

type e2eSource struct {
	ctx            context.Context
	dsn            string
	pool           *pgxpool.Pool
	org, workspace uuid.UUID
	rootFile       string
	rootKey        []byte
	user           string
	value          string
	secretLen      int
}

// newE2ESource builds a source installation whose key material is real: a
// fixture organisation, with its fake KEK, envelope and CA rows replaced by a
// real PKI domain and a real sealed secret under the source root.
func newE2ESource(t *testing.T, dir string, storeMode bool) e2eSource {
	t.Helper()
	ctx := context.Background()
	dsn := pgscratch.New(t, nil)
	pool := scratchPoolAt(t, ctx, dsn)
	org := uuid.New()
	transferfixture.Seed(t, ctx, pool, org, strings.ToUpper(strings.ReplaceAll(uuid.NewString(), "-", ""))[:7]+"A")
	for _, q := range []string{
		`DELETE FROM org_ca WHERE org_id = $1`,
		`DELETE FROM keep_envelope WHERE store_org = $1::text`,
		`DELETE FROM keep_kek WHERE org_id = $1::text`,
	} {
		if _, err := pool.Exec(ctx, q, org); err != nil {
			t.Fatalf("clear fake key rows: %v", q)
		}
	}
	if storeMode {
		// A native Mesh store-mode organization: Mesh's own install never
		// creates a tenancy workspace or a project. Only the synthetic test
		// source is edited; the transfer never writes a source.
		transferfixture.DropTenancyWorkspaces(t, ctx, pool, org)
	}
	// The fixture's membership uses a placeholder scope; make the admin a
	// real one so the ordinary issue-admin-token path accepts it.
	if _, err := pool.Exec(ctx, `UPDATE memberships SET scope = 'org:' || org_id::text WHERE org_id = $1`, org); err != nil {
		t.Fatal("scope membership")
	}
	rootFile, key := writeRootFile(t, dir, "src-root")
	local := openLocal(t, pool, "src-root", key)
	if _, err := orgpki.NewRepoFromLocal(pool, local).Ensure(ctx, org); err != nil {
		t.Fatal("ensure org CA")
	}
	var ws, user string
	wsQuery := `SELECT w.id::text, (SELECT id::text FROM users WHERE org_id = $1 ORDER BY id LIMIT 1) FROM workspaces w WHERE w.org_id = $1`
	if storeMode {
		// The canonical workspace is the single Mesh installation's.
		wsQuery = `SELECT w.workspace_id::text, (SELECT id::text FROM users WHERE org_id = $1 ORDER BY id LIMIT 1) FROM mesh_installations w WHERE w.org_id = $1`
	}
	if err := pool.QueryRow(ctx, wsQuery, org).Scan(&ws, &user); err != nil {
		t.Fatal("read ids")
	}
	// An ordinary source already holds credentials; they must neither block
	// the export nor travel.
	hash := make([]byte, 32)
	hash[0] = 7
	if _, err := pool.Exec(ctx, `INSERT INTO tokens (id, org_id, kind, principal_id, token_hash, last4, scope)
		VALUES ($1, $2::uuid, 'u', $3::uuid, $4, 'abcd', 'org:' || $2::text)`, uuid.New(), org, user, hash); err != nil {
		t.Fatalf("seed source token: %v", err)
	}
	sid := make([]byte, 32)
	sid[0] = 9
	if _, err := pool.Exec(ctx, `INSERT INTO console_sessions (id_hash, org_id, kind, principal_id, token_hash, csrf, expires_at)
		VALUES ($1, $2::uuid, 'u', $3::uuid, $4, $5, now() + interval '1 hour')`, sid, org, user, hash, strings.Repeat("a", 52)); err != nil {
		t.Fatalf("seed source console session: %v", err)
	}
	value := canary.New().Value(0)
	if _, err := local.Provider(org.String(), "", "", user).Write(ctx, provider.Ref{Path: "e2e-secret"}, secret.New([]byte(value))); err != nil {
		t.Fatalf("seal secret: %v", err)
	}
	return e2eSource{ctx: ctx, dsn: dsn, pool: pool, org: org, workspace: uuid.MustParse(ws), rootFile: rootFile, rootKey: key, user: user, value: value, secretLen: len(value)}
}

func useInstallation(t *testing.T, dsn, rootFile, keyID string) {
	t.Setenv("KEEP_DATABASE_URL", dsn)
	t.Setenv("KEEP_ROOT_KEY_FILE", rootFile)
	t.Setenv("KEEP_ROOT_KEY_ID", keyID)
}

// The whole path on two independent installations: every command's output is
// closed metadata, and the target ends up with a working copy under its own
// root.
func TestOfflineTransferEndToEnd(t *testing.T) {
	t.Run("tenancy workspace profile", func(t *testing.T) { offlineTransferEndToEnd(t, false) })
	t.Run("store mode profile without tenancy workspace", func(t *testing.T) { offlineTransferEndToEnd(t, true) })
}

func offlineTransferEndToEnd(t *testing.T, storeMode bool) {
	d := carrierDir(t)
	src := newE2ESource(t, d, storeMode)
	var seen strings.Builder
	run := func(args ...string) map[string]string {
		code, out, errs := runTransfer(args...)
		seen.WriteString(out + errs)
		if code != 0 {
			t.Fatalf("%s failed: %d %q", args[0], code, errs)
		}
		return fields(out)
	}

	// 1. the target creates its recipient and gives the public half out of band
	priv, pub := filepath.Join(d, "r.key"), filepath.Join(d, "r.pub")
	rcpt := run("recipient", "--private-file", priv, "--public-file", pub)

	// 2. the source exports under the pinned recipient fingerprint
	transfer, snapshot, target, source := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	bundle, cp, ap := filepath.Join(d, "b.sealed"), filepath.Join(d, "cp.json"), filepath.Join(d, "approval.json")
	useInstallation(t, src.dsn, src.rootFile, "src-root")
	if storeMode {
		// The canonical workspace is the installation's, nothing else: a
		// made-up workspace (the generated id a tenancy CreateWorkspace
		// would give) does not pin the source.
		code, _, errs := runTransfer("export", "--org", src.org.String(), "--workspace", uuid.NewString(), "--transfer", transfer,
			"--source", source, "--target", target, "--snapshot", snapshot, "--schema", strconv.FormatInt(scopedtransfer.SchemaVersion, 10),
			"--recipient-public-file", pub, "--expect-recipient-fingerprint", rcpt["recipient_fingerprint"],
			"--bundle", filepath.Join(d, "never.sealed"), "--checkpoint", filepath.Join(d, "never.json"))
		if code == 0 || !strings.Contains(errs, "reason=pin") {
			t.Fatalf("a workspace that is not the installation's must not pin the export: %d %q", code, errs)
		}
		if _, err := os.Lstat(filepath.Join(d, "never.sealed")); !os.IsNotExist(err) {
			t.Fatal("a refused export left a carrier")
		}
	}
	exp := run("export", "--org", src.org.String(), "--workspace", src.workspace.String(), "--transfer", transfer,
		"--source", source, "--target", target, "--snapshot", snapshot, "--schema", strconv.FormatInt(scopedtransfer.SchemaVersion, 10),
		"--recipient-public-file", pub, "--expect-recipient-fingerprint", rcpt["recipient_fingerprint"],
		"--bundle", bundle, "--checkpoint", cp)

	// 3. after the freeze, the final compare approves exactly that state
	fin := run("finalize", "--org", src.org.String(), "--checkpoint", cp, "--approval", ap, "--quiescence-confirmed", "true")
	if fin["closure_digest"] != exp["closure_digest"] || fin["ciphertext_checksum"] != exp["ciphertext_checksum"] {
		t.Fatal("finalize approved something other than what was exported")
	}

	// 4. the target imports under independently held pins
	ctx := context.Background()
	dstDSN := pgscratch.New(t, nil)
	dstPool := scratchPoolAt(t, ctx, dstDSN)
	dstFile, dstKey := writeRootFile(t, d, "dst-root")
	useInstallation(t, dstDSN, dstFile, "dst-root")
	approvalPin := fin["approval_checksum"]
	approvalRaw, err := os.ReadFile(ap) //nolint:gosec // G304: test path
	if err != nil {
		t.Fatal("read approval")
	}
	if sum := sha256.Sum256(approvalRaw); hex.EncodeToString(sum[:]) != approvalPin {
		t.Fatal("finalize receipt pin is not the digest of the approval carrier")
	}
	importWith := func(approval string, pin ...string) []string {
		if len(pin) == 0 {
			pin = []string{approvalPin}
		}
		return []string{"import", "--bundle", bundle, "--private-file", priv, "--public-file", pub, "--approval", approval,
			"--transfer", transfer, "--source", source, "--target", target, "--snapshot", snapshot,
			"--org", src.org.String(), "--workspace", src.workspace.String(), "--schema", strconv.FormatInt(scopedtransfer.SchemaVersion, 10),
			"--expect-checksum", fin["ciphertext_checksum"], "--expect-recipient-fingerprint", rcpt["recipient_fingerprint"],
			"--expect-approval-checksum", pin[0]}
	}
	importArgs := importWith(ap)
	privBytes, err := os.ReadFile(priv) //nolint:gosec // G304: test path
	if err != nil {
		t.Fatal("read recipient key")
	}
	// Without the source's final approval, or with one that describes another
	// export, the import is refused before any effect.
	goodApproval, err := os.ReadFile(ap) //nolint:gosec // G304: test path
	if err != nil {
		t.Fatal("read approval")
	}
	for name, mutate := range map[string]func(*transferApproval){
		"other snapshot":   func(a *transferApproval) { a.SnapshotID = uuid.NewString() },
		"other source":     func(a *transferApproval) { a.SourceID = uuid.NewString() },
		"other target":     func(a *transferApproval) { a.TargetID = uuid.NewString() },
		"other transfer":   func(a *transferApproval) { a.TransferID = uuid.NewString() },
		"other checksum":   func(a *transferApproval) { a.CiphertextChecksum = strings.Repeat("0", 64) },
		"other digest":     func(a *transferApproval) { a.ClosureDigest = "sha256:" + strings.Repeat("0", 64) },
		"other audit head": func(a *transferApproval) { a.AuditHead = "not-the-source-head" },
		"other schema":     func(a *transferApproval) { a.Schema++ },
		"not final":        func(a *transferApproval) { a.Status = "pending" },
		"no freeze":        func(a *transferApproval) { a.Quiescence = "" },
	} {
		a, ok := parseApproval(goodApproval)
		if !ok {
			t.Fatal("positive control: the real approval did not parse")
		}
		mutate(&a)
		raw, err := json.Marshal(a)
		if err != nil {
			t.Fatal("marshal approval")
		}
		bad := filepath.Join(d, "bad-"+strings.ReplaceAll(name, " ", "-")+".json")
		if err := transfercarrier.Create(bad, raw); err != nil {
			t.Fatal("write approval")
		}
		// Under the real source pin the substituted approval is a different
		// file: refused as such, with the bundle pins unchanged.
		if code, _, errs := runTransfer(importWith(bad)...); code == 0 || !strings.Contains(errs, "reason=approval_pin") {
			t.Fatalf("%s: want reason=approval_pin, got %d %q", name, code, errs)
		}
		// Even if the forger also pins their own file, the content must still
		// describe this transfer.
		forgedPin := sha256.Sum256(raw)
		if code, _, errs := runTransfer(importWith(bad, hex.EncodeToString(forgedPin[:]))...); code == 0 || !strings.Contains(errs, "reason=approval") || strings.Contains(errs, "approval_pin") {
			t.Fatalf("%s: want reason=approval, got %d %q", name, code, errs)
		}
		var n int64
		if err := dstPool.QueryRow(ctx, "SELECT count(*) FROM organizations").Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s: the target changed after a refusal", name)
		}
	}
	noApproval := importArgs[:0:0]
	for i := 0; i < len(importArgs); i++ {
		if importArgs[i] == "--approval" {
			i++
			continue
		}
		noApproval = append(noApproval, importArgs[i])
	}
	if code, _, _ := runTransfer(noApproval...); code == 0 {
		t.Fatal("an import without --approval was accepted")
	}
	imp := run(importArgs...)
	if imp["source"] != source || imp["target"] != target || imp["recipient_fingerprint"] != rcpt["recipient_fingerprint"] {
		t.Fatalf("receipt lacks the source, target or recipient identity: %v", imp)
	}
	if imp["outcome"] != "imported" || imp["audit_head_before"] != exp["audit_head"] {
		t.Fatalf("receipt does not match the export: %v", imp)
	}
	// the recipient key and the bundle together open every KEK, so a
	// committed import destroys the key
	if imp["recipient_key"] != "destroyed" {
		t.Fatalf("receipt must report the key as destroyed: %v", imp)
	}
	if _, err := os.Lstat(priv); !os.IsNotExist(err) {
		t.Fatal("recipient private key survived a committed import")
	}

	// the target opens the secret and the CA under ITS root, and its audit
	// chain verifies and continues
	local := openLocal(t, dstPool, "dst-root", dstKey)
	meta, err := local.Provider(src.org.String(), "", "", src.user).Version(ctx, provider.Ref{Path: "e2e-secret"})
	if err != nil || meta.Length != src.secretLen {
		t.Fatalf("target cannot read the transferred secret: %v", err)
	}
	v, _, err := local.Provider(src.org.String(), "", "", src.user).Resolve(ctx, provider.Ref{Path: "e2e-secret"})
	if err != nil || v.Len() != src.secretLen {
		t.Fatal("target cannot open the transferred secret under its own root")
	}
	v.Wipe()
	if _, ok, err := orgpki.NewRepoFromLocal(dstPool, local).Lookup(ctx, src.org); err != nil || !ok {
		t.Fatalf("target cannot authenticate the transferred CA: %v", err)
	}
	if res, err := audit.Verify(ctx, dstPool, src.org.String()); err != nil || !res.OK {
		t.Fatal("audit chain does not verify on the target")
	}
	// The target holds exactly the source's workspace shape: no synthetic
	// tenancy workspace is ever created for a store-mode organization.
	var tenancyWs, tenancyProj, meshWs int
	if err := dstPool.QueryRow(ctx, `SELECT (SELECT count(*) FROM workspaces), (SELECT count(*) FROM projects), (SELECT count(*) FROM mesh_installations WHERE ($1::uuid IS NOT NULL AND workspace_id = $1) OR NOT $2)`, src.workspace, storeMode).Scan(&tenancyWs, &tenancyProj, &meshWs); err != nil {
		t.Fatal("read target workspaces")
	}
	wantTenancy := 1
	if storeMode {
		wantTenancy = 0
	}
	if tenancyWs != wantTenancy || meshWs != 1 || (storeMode && tenancyProj != 0) {
		t.Fatalf("target workspace shape differs from the source: workspaces=%d projects=%d installation=%d", tenancyWs, tenancyProj, meshWs)
	}
	var tokens, sessions int
	if err := dstPool.QueryRow(ctx, `SELECT (SELECT count(*) FROM tokens), (SELECT count(*) FROM console_sessions)`).Scan(&tokens, &sessions); err != nil || tokens != 0 || sessions != 0 {
		t.Fatalf("source credentials travelled to the target: tokens=%d sessions=%d err=%v", tokens, sessions, err)
	}
	// New target credentials come from the ordinary path, for an imported
	// active admin only; a removed principal stays removed.
	var admin, removed string
	if err := dstPool.QueryRow(ctx, `SELECT (SELECT user_id::text FROM memberships WHERE org_id = $1 AND role = 'admin' LIMIT 1), (SELECT id::text FROM users WHERE org_id = $1 AND status = 'removed' LIMIT 1)`, src.org).Scan(&admin, &removed); err != nil || admin == "" || removed == "" {
		t.Fatal("imported principals missing")
	}
	tokenArgs := func(user, file string) []string {
		return []string{"--org-id", src.org.String(), "--admin-user-id", user, "--ttl", "1h", "--token-file", file}
	}
	var iout, ierr bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	tokFile := filepath.Join(d, "admin.token")
	if issueAdminToken(ctx, dstPool, logger, tokenArgs(admin, tokFile), &iout, &ierr) != 0 {
		t.Fatalf("issue-admin-token on the target failed: %s", ierr.String())
	}
	if tok, err := os.ReadFile(tokFile); err != nil || canary.Of(string(tok)).In(iout.String()+ierr.String()) { //nolint:gosec // G304: test path
		t.Fatal("token value reached output or was not written")
	}
	var rout, rerr bytes.Buffer
	if issueAdminToken(ctx, dstPool, logger, tokenArgs(removed, filepath.Join(d, "removed.token")), &rout, &rerr) == 0 {
		t.Fatal("a removed principal was given a token")
	}
	if _, err := os.Stat(filepath.Join(d, "removed.token")); err == nil {
		t.Fatal("a refused issue left a token file")
	}
	var lastAction string
	if err := dstPool.QueryRow(ctx, `SELECT action FROM audit_records WHERE org_id = $1 ORDER BY org_seq DESC LIMIT 1`, src.org.String()).Scan(&lastAction); err != nil || lastAction == "transfer.imported" {
		t.Fatalf("the next ordinary record did not follow the import: %q %v", lastAction, err)
	}
	if res, err := audit.Verify(ctx, dstPool, src.org.String()); err != nil || !res.OK {
		t.Fatal("audit chain broke after the first ordinary record")
	}
	if err := transfercarrier.Create(priv, privBytes); err != nil { // put the key back only to prove the refusal
		t.Fatal("restore recipient key")
	}
	if code, _, errs := runTransfer(importArgs...); code == 0 || !strings.Contains(errs, "reason=target_not_empty") {
		t.Fatalf("a second import must be refused: %d %q", code, errs)
	}

	// the value never reached an output or a carrier
	c := canary.Of(src.value)
	if !c.In(src.value) {
		t.Fatal("canary is blind")
	}
	if c.In(seen.String()) {
		t.Fatal("secret value reached command output")
	}
	// no key material of either root or of the recipient reaches an output, a
	// carrier or anything the target database stores about the transfer
	keys := [][]byte{src.rootKey, dstKey, privBytes}
	if !holdsKey(string(privBytes), keys) || !holdsKey(hex.EncodeToString(dstKey), keys) {
		t.Fatal("key scan is blind")
	}
	if holdsKey(seen.String(), keys) {
		t.Fatal("key material reached command output")
	}
	for _, p := range []string{bundle, cp, ap} {
		raw, err := os.ReadFile(p) //nolint:gosec // G304: test path
		if err != nil || c.In(string(raw)) || holdsKey(string(raw), keys) {
			t.Fatalf("carrier %s holds plaintext", filepath.Base(p))
		}
	}
	for _, q := range []string{
		`SELECT COALESCE(string_agg(t::text, ' '), '') FROM audit_records t WHERE org_id = $1`,
		`SELECT COALESCE(string_agg(t::text, ' '), '') FROM scoped_transfer_ledger t WHERE org_id = $1`,
	} {
		var dump string
		if err := dstPool.QueryRow(ctx, q, src.org.String()).Scan(&dump); err != nil || dump == "" {
			t.Fatalf("read target records: %v", err)
		}
		if c.In(dump) || holdsKey(dump, keys) {
			t.Fatal("the target database records hold a value or a key")
		}
	}
}

// holdsKey reports whether s contains any key in raw, hex or base64 form.
func holdsKey(s string, keys [][]byte) bool {
	for _, k := range keys {
		for _, form := range []string{
			string(k), hex.EncodeToString(k), base64.StdEncoding.EncodeToString(k),
			base64.RawStdEncoding.EncodeToString(k), base64.URLEncoding.EncodeToString(k),
			base64.RawURLEncoding.EncodeToString(k),
		} {
			if len(k) > 0 && strings.Contains(s, form) {
				return true
			}
		}
	}
	return false
}

func tamperCA(t *testing.T, src e2eSource) {
	t.Helper()
	if _, err := src.pool.Exec(src.ctx, `UPDATE org_ca SET ca_ciphertext = overlay(ca_ciphertext placing '\\x00ff'::bytea from 1 for 2) WHERE org_id = $1`, src.org); err != nil {
		t.Fatal("tamper")
	}
}

func newRecipient(t *testing.T, d string) (priv, pub, fp string) {
	t.Helper()
	priv, pub = filepath.Join(d, "r.key"), filepath.Join(d, "r.pub")
	code, out, errs := runTransfer("recipient", "--private-file", priv, "--public-file", pub)
	if code != 0 {
		t.Fatalf("recipient: %d %q", code, errs)
	}
	return priv, pub, fields(out)["recipient_fingerprint"]
}

func schemaArg() string { return strconv.FormatInt(scopedtransfer.SchemaVersion, 10) }

// A source whose CA does not authenticate is refused at export, before any
// bundle exists.
func TestOfflineTransferExportRefusesATamperedCA(t *testing.T) {
	d := carrierDir(t)
	src := newE2ESource(t, d, false)
	tamperCA(t, src)
	_, pub, fp := newRecipient(t, d)
	useInstallation(t, src.dsn, src.rootFile, "src-root")
	code, _, errs := runTransfer("export", "--org", src.org.String(), "--workspace", src.workspace.String(), "--transfer", uuid.NewString(),
		"--source", uuid.NewString(), "--target", uuid.NewString(), "--snapshot", uuid.NewString(), "--schema", schemaArg(),
		"--recipient-public-file", pub, "--expect-recipient-fingerprint", fp,
		"--bundle", filepath.Join(d, "b.sealed"), "--checkpoint", filepath.Join(d, "cp.json"))
	if code == 0 || !strings.Contains(errs, "reason=pki") {
		t.Fatalf("a tampered CA must be refused at export: %d %q", code, errs)
	}
	for _, n := range []string{"b.sealed", "cp.json"} {
		if _, err := os.Stat(filepath.Join(d, n)); err == nil {
			t.Fatalf("a refused export left %s", n)
		}
	}
}

// The operator's workspace and schema pins are compared with what the source
// really holds; a mismatch refuses before any carrier is written.
func TestOfflineTransferExportRefusesWrongSourcePins(t *testing.T) {
	d := carrierDir(t)
	src := newE2ESource(t, d, false)
	_, pub, fp := newRecipient(t, d)
	useInstallation(t, src.dsn, src.rootFile, "src-root")
	export := func(workspace, schema string) (int, string) {
		code, _, errs := runTransfer("export", "--org", src.org.String(), "--workspace", workspace, "--transfer", uuid.NewString(),
			"--source", uuid.NewString(), "--target", uuid.NewString(), "--snapshot", uuid.NewString(), "--schema", schema,
			"--recipient-public-file", pub, "--expect-recipient-fingerprint", fp,
			"--bundle", filepath.Join(d, "b.sealed"), "--checkpoint", filepath.Join(d, "cp.json"))
		return code, errs
	}
	for name, c := range map[string]struct{ ws, schema string }{
		"other workspace": {uuid.NewString(), schemaArg()},
		"other schema":    {src.workspace.String(), strconv.FormatInt(scopedtransfer.SchemaVersion+1, 10)},
	} {
		if code, errs := export(c.ws, c.schema); code == 0 || !strings.Contains(errs, "reason=pin") {
			t.Fatalf("%s must be refused as a pin: %d %q", name, code, errs)
		}
	}
	for _, n := range []string{"b.sealed", "cp.json"} {
		if _, err := os.Stat(filepath.Join(d, n)); err == nil {
			t.Fatalf("a refused export left %s", n)
		}
	}
	if code, errs := export(src.workspace.String(), schemaArg()); code != 0 {
		t.Fatalf("positive control: the true pins were refused: %d %q", code, errs)
	}
}

// A hostile or buggy source can still hand over a sealed bundle whose CA is
// not authentic; the target refuses it before writing anything.
func TestOfflineTransferImportRefusesATamperedCA(t *testing.T) {
	d := carrierDir(t)
	src := newE2ESource(t, d, false)
	tamperCA(t, src)
	priv, pub, fp := newRecipient(t, d)
	rows, err := store.ReadTransferRows(src.ctx, src.pool, src.org)
	if err != nil {
		t.Fatal("read rows")
	}
	digest, err := transferverify.ClosureDigest(rows)
	if err != nil {
		t.Fatal("digest")
	}
	counts := rows.CopiedCounts()
	var tables []scopedtransfer.TableCount
	for _, p := range scopedtransfer.TablePolicies() {
		tables = append(tables, scopedtransfer.TableCount{Name: p.Name, Rows: counts[p.Name]})
	}
	transfer, snapshot, target, source := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	m := scopedtransfer.Manifest{
		Version: scopedtransfer.ManifestVersion, ProfileVersion: scopedtransfer.ProfileVersion, TransferID: transfer,
		OrgID: src.org.String(), WorkspaceID: src.workspace.String(), SchemaVersion: scopedtransfer.SchemaVersion,
		MigrationSetID: scopedtransfer.MigrationSetID, RecipientID: target, SnapshotID: snapshot, ClosureDigest: digest, Tables: tables,
	}
	pubRaw, err := os.ReadFile(pub) //nolint:gosec // G304: test path
	if err != nil {
		t.Fatal("read pub")
	}
	tc := builtin.TransferContext{Protocol: transferProtocol, Transfer: transfer, Source: source, Target: target, Snapshot: snapshot,
		Org: src.org.String(), Workspace: src.workspace.String(), Schema: uint64(scopedtransfer.SchemaVersion), RecipientPub: pubRaw}
	root, err := builtin.OpenTransferRoot(src.rootFile, "src-root")
	if err != nil {
		t.Fatal("open root")
	}
	sealed, err := builtin.BuildTransferBundle(pubRaw, tc, m, rows, root)
	if err != nil {
		t.Fatal("build hostile bundle")
	}
	bundle := filepath.Join(d, "b.sealed")
	if err := os.WriteFile(bundle, sealed, 0o600); err != nil { //nolint:gosec // G703: test path
		t.Fatal(err)
	}
	sum := sha256.Sum256(sealed)
	ap := filepath.Join(d, "approval.json")
	apRaw, err := json.Marshal(transferApproval{transferCheckpoint: transferCheckpoint{
		Version: 1, OrgID: src.org.String(), WorkspaceID: src.workspace.String(), TransferID: transfer, SnapshotID: snapshot,
		SourceID: source, TargetID: target, Schema: scopedtransfer.SchemaVersion, ClosureDigest: digest,
		AuditHead: auditHeadOf(rows), Rows: 1, CiphertextChecksum: hex.EncodeToString(sum[:]),
	}, Quiescence: "asserted", Status: "final"})
	if err != nil {
		t.Fatal("marshal approval")
	}
	if err := transfercarrier.Create(ap, apRaw); err != nil {
		t.Fatal("write approval")
	}
	apSum := sha256.Sum256(apRaw)
	dstDSN := pgscratch.New(t, nil)
	dstPool := scratchPoolAt(t, src.ctx, dstDSN)
	dstFile, _ := writeRootFile(t, d, "dst-root")
	useInstallation(t, dstDSN, dstFile, "dst-root")
	code, _, errs := runTransfer("import", "--bundle", bundle, "--private-file", priv, "--public-file", pub, "--approval", ap,
		"--transfer", transfer, "--source", source, "--target", target, "--snapshot", snapshot,
		"--org", src.org.String(), "--workspace", src.workspace.String(), "--schema", schemaArg(),
		"--expect-checksum", hex.EncodeToString(sum[:]), "--expect-recipient-fingerprint", fp,
		"--expect-approval-checksum", hex.EncodeToString(apSum[:]))
	if code == 0 || !strings.Contains(errs, "reason=pki") {
		t.Fatalf("a tampered CA must be refused as pki: %d %q", code, errs)
	}
	for _, table := range []string{"organizations", "keep_kek", "org_ca", "audit_records", "scoped_transfer_ledger"} {
		var n int64
		if err := dstPool.QueryRow(src.ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s has %d rows after the refusal", table, n)
		}
	}
}

// A native Mesh store-mode source (no tenancy workspace) is accepted only in
// exactly that shape; every other shape is refused at export, before any
// carrier exists, and the source is never written by the tool.
func TestOfflineTransferStoreModeRefusesOtherShapes(t *testing.T) {
	cases := map[string]string{
		"two tenancy workspaces":      `INSERT INTO workspaces (id, org_id, name) VALUES (gen_random_uuid(), $1, 'w-a'), (gen_random_uuid(), $1, 'w-b')`,
		"second installation":         `INSERT INTO mesh_installations (workspace_id, org_id, mesh_url, installed_by, token_signed_at, mode) SELECT gen_random_uuid(), org_id, mesh_url, installed_by, token_signed_at, mode FROM mesh_installations WHERE org_id = $1`,
		"extension mode":              `UPDATE mesh_installations SET mode = 'extension' WHERE org_id = $1`,
		"non-builtin store":           `UPDATE stores SET provider = 'vault' WHERE org_id = $1`,
		"unsupported state":           `INSERT INTO restart_requests (request_id, org_id, lane, key_version, fingerprint) VALUES (gen_random_uuid(), $1, 'lane', 'v1', 'kfp1:k1:abcdefghijklmnop')`,
		"workspace-scoped key domain": `UPDATE keep_kek SET domain_workspace = 'foreign' WHERE org_id = $1::text AND domain_key NOT LIKE 'pki:%'`,
		"workspace-scoped envelope":   `UPDATE keep_envelope SET store_workspace = 'foreign' WHERE store_org = $1::text`,
	}
	closure := map[string]bool{"workspace-scoped key domain": true, "workspace-scoped envelope": true}
	for name, mutation := range cases {
		t.Run(name, func(t *testing.T) {
			d := carrierDir(t)
			src := newE2ESource(t, d, true)
			if !canary.Of(src.value).In(src.value) {
				t.Fatal("canary is blind")
			}
			want := "reason=profile"
			if closure[name] {
				want = "reason=closure"
			}
			if _, err := src.pool.Exec(src.ctx, mutation, src.org); err != nil {
				t.Fatalf("positive control: the tamper does not apply: %v", err)
			}
			_, pub, fp := newRecipient(t, d)
			useInstallation(t, src.dsn, src.rootFile, "src-root")
			code, out, errs := runTransfer("export", "--org", src.org.String(), "--workspace", src.workspace.String(), "--transfer", uuid.NewString(),
				"--source", uuid.NewString(), "--target", uuid.NewString(), "--snapshot", uuid.NewString(), "--schema", schemaArg(),
				"--recipient-public-file", pub, "--expect-recipient-fingerprint", fp,
				"--bundle", filepath.Join(d, "b.sealed"), "--checkpoint", filepath.Join(d, "cp.json"))
			if code == 0 || !strings.Contains(errs, want) || canary.Of(src.value).In(out+errs) {
				t.Fatalf("an unsupported store-mode shape must be refused by the profile or closure, never as a pin: %d %q", code, errs)
			}
			for _, n := range []string{"b.sealed", "cp.json"} {
				if _, err := os.Stat(filepath.Join(d, n)); err == nil {
					t.Fatalf("a refused export left %s", n)
				}
			}
		})
	}
}
