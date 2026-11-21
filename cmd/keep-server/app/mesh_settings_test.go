package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/api"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/config"
	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/meshgate"
	"github.com/entire-vc/evc-keep/internal/rotation"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
)

// meshInstallWithSettings is meshInstallRequest with the settings field Mesh
// adds to the install handshake: a full snapshot of the extension's
// non-secret workspace settings, sent on every handshake.
type meshInstallWithSettings struct {
	meshInstallRequest
	Settings json.RawMessage `json:"settings,omitempty"`
}

func meshHandshakeBodyWithSettings(ws uuid.UUID, secret, settings string) []byte {
	var base meshInstallRequest
	_ = json.Unmarshal(meshHandshakeBody(ws, "keep", secret), &base)
	req := meshInstallWithSettings{meshInstallRequest: base}
	if settings != "" {
		req.Settings = json.RawMessage(settings)
	}
	b, _ := json.Marshal(req)
	return b
}

func (f *meshFixture) handshakeWithSettings(ws uuid.UUID, secret, settings string) *httptest.ResponseRecorder {
	return f.handshakeSigned(meshHandshakeBodyWithSettings(ws, secret, settings), secret, time.Now())
}

// approvalsSetting is the stored approvals_via_mesh of ws: "true", "false",
// or "unset" when Mesh never sent it.
func (f *meshFixture) approvalsSetting(ws uuid.UUID) string {
	f.t.Helper()
	var v *bool
	if err := f.pool.QueryRow(context.Background(), `SELECT approvals_via_mesh FROM mesh_installations WHERE workspace_id=$1`, ws).Scan(&v); err != nil {
		f.t.Fatalf("approvals_via_mesh: %v", err)
	}
	switch {
	case v == nil:
		return "unset"
	case *v:
		return "true"
	default:
		return "false"
	}
}

// The handshake records approvals_via_mesh from Mesh's settings snapshot on
// every path that authenticates as the workspace: a fresh binding, a repeat
// with the bound secret, and the upgrade of a store binding. The last
// snapshot wins; a handshake without the field (an older Mesh) leaves the
// setting as it is; a malformed snapshot is refused 400 and a handshake that
// does not authenticate as the workspace is the uniform 401, both writing
// nothing.
func TestMeshHandshakeRecordsApprovalsSetting(t *testing.T) {
	f := newMeshFixture(t, true)
	c := canary.New()
	secret, other := "st-"+c.Value(1), "st-"+c.Value(2)

	t.Run("bind and repeats", func(t *testing.T) {
		ws := uuid.New()
		f.mustOpenWindow(ws, secret)
		step := func(name, settings string, code int, want string) {
			t.Helper()
			if rec := f.handshakeWithSettings(ws, secret, settings); rec.Code != code {
				t.Fatalf("%s: status %d, want %d, %s", name, rec.Code, code, answerDiag(rec))
			}
			if got := f.approvalsSetting(ws); got != want {
				t.Fatalf("%s: approvals_via_mesh %s, want %s", name, got, want)
			}
		}
		step("bind with false", `{"approvals_via_mesh":false}`, http.StatusOK, "false")
		step("repeat without the field keeps it", "", http.StatusOK, "false")
		step("repeat with null is refused and keeps it", `null`, http.StatusBadRequest, "false")
		step("repeat with true", `{"approvals_via_mesh":true}`, http.StatusOK, "true")
		step("repeat with false again", `{"approvals_via_mesh":false, "other_key":"x"}`, http.StatusOK, "false")
		step("a snapshot without the key is the default", `{}`, http.StatusOK, "unset")
		step("repeat with false", `{"approvals_via_mesh":false}`, http.StatusOK, "false")
	})

	t.Run("malformed snapshot is refused and writes nothing", func(t *testing.T) {
		ws := uuid.New()
		f.mustOpenWindow(ws, secret)
		if rec := f.handshakeWithSettings(ws, secret, `{"approvals_via_mesh":false}`); rec.Code != http.StatusOK {
			t.Fatalf("bind: %d", rec.Code)
		}
		for name, s := range map[string]string{
			"null":           `null`,
			"string":         `"x"`,
			"array":          `[{"approvals_via_mesh":true}]`,
			"number":         `1`,
			"bool as string": `{"approvals_via_mesh":"true"}`,
			"bool as number": `{"approvals_via_mesh":1}`,
			"bool as null":   `{"approvals_via_mesh":null}`,
			"bool as object": `{"approvals_via_mesh":{"v":true}}`,
		} {
			rec := f.handshakeWithSettings(ws, secret, s)
			var e struct {
				ErrorClass string `json:"error_class"`
			}
			if rec.Code != http.StatusBadRequest || json.Unmarshal(rec.Body.Bytes(), &e) != nil || e.ErrorClass != "invalid_argument" {
				t.Fatalf("%s: status %d, want 400 invalid_argument, %s", name, rec.Code, answerDiag(rec))
			}
			if got := f.approvalsSetting(ws); got != "false" {
				t.Fatalf("%s: a refused snapshot changed the setting to %s", name, got)
			}
		}
	})

	t.Run("a handshake that does not authenticate writes nothing", func(t *testing.T) {
		ws := uuid.New()
		f.mustOpenWindow(ws, secret)
		if rec := f.handshakeWithSettings(ws, secret, `{"approvals_via_mesh":false}`); rec.Code != http.StatusOK {
			t.Fatalf("bind: %d", rec.Code)
		}
		lone := uuid.New()
		for _, snapshot := range []string{`{"approvals_via_mesh":true}`, `{"approvals_via_mesh":"invalid"}`, `[]`, `null`} {
			// Self-signing proves nothing about ownership, including for
			// a malformed snapshot: the refusal must stay uniform.
			if rec := f.handshakeWithSettings(ws, other, snapshot); rec.Code != http.StatusUnauthorized {
				t.Fatalf("foreign secret: status %d, want 401", rec.Code)
			}
			if rec := f.handshakeWithSettings(lone, secret, snapshot); rec.Code != http.StatusUnauthorized {
				t.Fatalf("no window: status %d, want 401", rec.Code)
			}
		}
		if got := f.approvalsSetting(ws); got != "false" {
			t.Fatalf("a refused handshake changed the setting to %s", got)
		}
		if n := f.count(`SELECT count(*) FROM mesh_installations WHERE workspace_id=$1`, lone); n != 0 {
			t.Fatal("a refused handshake wrote an installation")
		}
	})

	t.Run("another organisation's live window on a bound workspace writes nothing", func(t *testing.T) {
		ws := uuid.New()
		f.mustOpenWindow(ws, secret)
		if rec := f.handshakeWithSettings(ws, secret, `{"approvals_via_mesh":false}`); rec.Code != http.StatusOK {
			t.Fatalf("bind: %d", rec.Code)
		}
		otherOrg, err := tenancy.New(f.pool).CreateOrganization(context.Background(), t.Name()+"-other", "")
		if err != nil {
			t.Fatal(err)
		}
		// OpenPending refuses this window for a bound workspace; a row
		// from before the binding, or a broken store, must still not let
		// the other organisation set the bound workspace's channel.
		if _, err := f.pool.Exec(context.Background(), `INSERT INTO mesh_pending_installs (workspace_id, org_id, opened_by, mesh_url, secret_sha256, expires_at)
VALUES ($1, $2, $3, 'https://mesh.example.test', $4, now() + interval '10 minutes')`, ws, otherOrg.ID, uuid.New(), meshSecretSHA256(other)); err != nil {
			t.Fatal(err)
		}
		for _, snapshot := range []string{`{"approvals_via_mesh":true}`, `{"approvals_via_mesh":"invalid"}`, `[]`, `null`} {
			if rec := f.handshakeWithSettings(ws, other, snapshot); rec.Code != http.StatusUnauthorized {
				t.Fatalf("other organisation's window, %s: status %d, want 401, %s", snapshot, rec.Code, answerDiag(rec))
			}
		}
		if got := f.approvalsSetting(ws); got != "false" {
			t.Fatalf("another organisation's window changed the setting to %s", got)
		}
		if n := f.count(`SELECT count(*) FROM mesh_installations WHERE workspace_id=$1 AND org_id=$2`, ws, f.org.ID); n != 1 {
			t.Fatal("another organisation's window moved the binding")
		}
	})

	t.Run("store binding upgraded", func(t *testing.T) {
		ws := uuid.New()
		if rec := f.installStore(ws, c.Value(3)); rec.Code != http.StatusOK {
			t.Fatalf("store install: %d", rec.Code)
		}
		if got := f.approvalsSetting(ws); got != "unset" {
			t.Fatalf("store install set the setting to %s", got)
		}
		f.mustOpenWindow(ws, secret)
		if rec := f.handshakeWithSettings(ws, secret, `{"approvals_via_mesh":false}`); rec.Code != http.StatusOK {
			t.Fatalf("upgrade: %d, %s", rec.Code, answerDiag(rec))
		}
		if got := f.approvalsSetting(ws); got != "false" {
			t.Fatalf("upgrade recorded %s, want false", got)
		}
	})
	t.Run("malformed fresh snapshot leaves its window open", func(t *testing.T) {
		ws := uuid.New()
		f.mustOpenWindow(ws, secret)
		if rec := f.handshakeWithSettings(ws, secret, `{"approvals_via_mesh":"invalid"}`); rec.Code != http.StatusBadRequest {
			t.Fatalf("malformed: status %d, want 400", rec.Code)
		}
		if f.count(`SELECT count(*) FROM mesh_installations WHERE workspace_id=$1`, ws) != 0 ||
			f.count(`SELECT count(*) FROM mesh_pending_installs WHERE workspace_id=$1`, ws) != 1 {
			t.Fatal("malformed settings changed the binding or spent its window")
		}
	})
}

// Leak test (written before the feature): Keep reads only the keys it
// applies from the settings snapshot. A value under any other key, which Mesh
// should not send but might, reaches no surface: response, headers, log,
// installation rows, audit journal.
func TestMeshHandshakeSettingsValueNeverLeaks(t *testing.T) {
	f := newMeshFixture(t, true)
	secret := "sl-" + canary.New().Value(1)
	leak := canary.New()
	ws := uuid.New()
	f.mustOpenWindow(ws, secret)
	snapshot := func(i int) string {
		b, _ := json.Marshal(map[string]any{"approvals_via_mesh": false, "api_token": leak.Value(i), "nested": map[string]string{"v": leak.Value(i + 10)}})
		return string(b)
	}
	var surfaces []string
	for i, want := range []int{http.StatusOK, http.StatusOK, http.StatusUnauthorized} {
		signer := secret
		if want == http.StatusUnauthorized {
			signer = "sl-other-" + leak.Value(99)
		}
		rec := f.handshakeWithSettings(ws, signer, snapshot(i))
		if rec.Code != want {
			t.Fatalf("handshake %d: status %d, want %d", i, rec.Code, want)
		}
		surfaces = append(surfaces, rec.Body.String())
		for k, v := range rec.Header() {
			surfaces = append(surfaces, k+": "+strings.Join(v, ","))
		}
	}
	// A malformed snapshot carrying the value is refused without echoing it.
	bad := `{"approvals_via_mesh":"` + leak.Value(50) + `"}`
	rec := f.handshakeWithSettings(ws, secret, bad)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed: status %d, want 400", rec.Code)
	}
	surfaces = append(surfaces, rec.Body.String())
	for k, v := range rec.Header() {
		surfaces = append(surfaces, k+": "+strings.Join(v, ","))
	}
	if f.approvalsSetting(ws) != "false" {
		t.Fatal("the snapshot was not applied: the test proves nothing")
	}
	// The store-to-extension upgrade path: first a malformed snapshot (400,
	// the window stays open), then a well-formed one that upgrades.
	up := uuid.New()
	if rec := f.installStore(up, canary.New().Value(3)); rec.Code != http.StatusOK {
		t.Fatalf("store install: %d", rec.Code)
	}
	f.mustOpenWindow(up, secret)
	for i, tc := range []struct {
		snapshot string
		want     int
	}{
		{`{"approvals_via_mesh":"` + leak.Value(60) + `"}`, http.StatusBadRequest},
		{snapshot(5), http.StatusOK},
	} {
		rec := f.handshakeWithSettings(up, secret, tc.snapshot)
		if rec.Code != tc.want {
			t.Fatalf("upgrade %d: status %d, want %d, %s", i, rec.Code, tc.want, answerDiag(rec))
		}
		surfaces = append(surfaces, rec.Body.String())
		for k, v := range rec.Header() {
			surfaces = append(surfaces, k+": "+strings.Join(v, ","))
		}
	}
	if f.approvalsSetting(up) != "false" {
		t.Fatal("the upgrade did not apply the snapshot: the test proves nothing")
	}
	for _, q := range []string{
		`SELECT row_to_json(t)::text FROM mesh_installations t`,
		`SELECT row_to_json(t)::text FROM audit_records t`,
	} {
		rows, err := f.pool.Query(context.Background(), q)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			surfaces = append(surfaces, s)
		}
		rows.Close()
	}
	if f.logbuf.Len() == 0 {
		t.Fatal("logger captured nothing; the log check proves nothing")
	}
	// Positive control: the check sees the value when it is there.
	if !leak.In("x" + leak.Value(0) + "x") {
		t.Fatal("canary check is blind")
	}
	for i, s := range append(surfaces, f.logbuf.String()) {
		if leak.In(s) {
			t.Fatalf("settings value leaked on surface #%d (%d bytes); the surface is not printed", i, len(s))
		}
	}
}

// A settings write failure must not publish a new extension installation
// with the default true, or consume the admin's window. The same transaction
// must publish both the binding (or store upgrade) and its false setting.
func TestMeshHandshakeSettingsFailureIsAtomic(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		t.Run(fmt.Sprintf("upgrade=%t", upgrade), func(t *testing.T) {
			f := newMeshFixture(t, true)
			ws := uuid.New()
			secret := canary.New().Value(1)
			if upgrade {
				if rec := f.installStore(ws, canary.New().Value(1)); rec.Code != http.StatusOK {
					t.Fatalf("store install: %d", rec.Code)
				}
			}
			f.mustOpenWindow(ws, secret)
			// Force only this workspace's settings write to fail at the real
			// database boundary; no repository or transaction is mocked.
			suffix := strings.ReplaceAll(ws.String(), "-", "")
			fn, trigger := "settings_fail_"+suffix, "settings_trigger_"+suffix
			_, err := f.pool.Exec(context.Background(), fmt.Sprintf(`
CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
  IF NEW.workspace_id = '%s'::uuid THEN RAISE EXCEPTION 'settings test write refused'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER %s BEFORE UPDATE OF approvals_via_mesh ON mesh_installations
FOR EACH ROW EXECUTE FUNCTION %s()`, fn, ws, trigger, fn))
			if err != nil {
				t.Fatal("create settings failure trigger")
			}
			t.Cleanup(func() {
				_, _ = f.pool.Exec(context.Background(), "DROP TRIGGER IF EXISTS "+trigger+" ON mesh_installations; DROP FUNCTION IF EXISTS "+fn+"()")
			})
			if rec := f.handshakeWithSettings(ws, secret, `{"approvals_via_mesh":false}`); rec.Code < 500 {
				t.Fatalf("failed settings write: status %d, want server error", rec.Code)
			}
			if n := f.count(`SELECT count(*) FROM mesh_pending_installs WHERE workspace_id=$1`, ws); n != 1 {
				t.Fatal("settings failure consumed the install window")
			}
			if n := f.count(`SELECT count(*) FROM mesh_installations WHERE workspace_id=$1 AND mode='extension'`, ws); n != 0 {
				t.Fatal("settings failure published the extension with the default true")
			}
			if upgrade && f.approvalsSetting(ws) != "unset" {
				t.Fatal("settings failure changed the store installation")
			}
			// Positive control: the same request succeeds once the database
			// accepts the write, using the same unspent window.
			if _, err := f.pool.Exec(context.Background(), "DROP TRIGGER "+trigger+" ON mesh_installations; DROP FUNCTION "+fn+"()"); err != nil {
				t.Fatal("remove settings failure trigger")
			}
			if rec := f.handshakeWithSettings(ws, secret, `{"approvals_via_mesh":false}`); rec.Code != http.StatusOK {
				t.Fatalf("retry after write restored: status %d, want 200", rec.Code)
			}
			if f.approvalsSetting(ws) != "false" || f.count(`SELECT count(*) FROM mesh_pending_installs WHERE workspace_id=$1`, ws) != 0 {
				t.Fatal("retry did not commit the setting and spend the window")
			}
		})
	}
}

// startGatedRotation starts a prod rotation of r's secret with the Mesh gate
// over cards, for an organisation whose one extension workspace holds
// approvals_via_mesh = setting (nil: Mesh never sent it).
func startGatedRotation(t *testing.T, r *rotFixture, cards *recCards, setting *bool) uuid.UUID {
	t.Helper()
	pool := r.f.pool
	f := r.f
	// Deliver the setting through the signed install contract, as Mesh
	// does, rather than seeding the new database column in the test.
	// The rotation fixture has already sealed this organisation with r.local;
	// use that same backend for the extension's signing credential.
	f.router = api.NewRouter(f.logger, pool, api.Deps{Mesh: meshDeps(config.Config{MeshExtension: true}, pool, r.local, f.outcomes,
		meshgate.New(meshgate.NewPG(pool), nil, nil, f.logger), audit.NewJournal(pool), f.logger)})
	ws := uuid.New()
	signing := canary.New().Value(1)
	f.mustOpenWindow(ws, signing)
	snapshot := ""
	if setting != nil {
		b, _ := json.Marshal(map[string]bool{"approvals_via_mesh": *setting})
		snapshot = string(b)
	}
	if rec := f.handshakeWithSettings(ws, signing, snapshot); rec.Code != http.StatusOK {
		t.Fatalf("install handshake: %d, %s", rec.Code, answerDiag(rec))
	}
	dep := deployment.NewRepo(pool, audit.NewJournal(pool))
	r.svc.(*rotation.Service).WithConfirmer(deployment.GateConfirmer{Svc: meshgate.New(meshgate.NewPG(pool), deployment.GateApprovals{Src: dep}, cards, nil)})
	origin := rotation.Origin{Actor: audit.Actor{Type: audit.ActorUser, ID: uuid.NewString(), Via: audit.ViaAPI}, Scope: "org:" + r.org.String(), Name: "rot-secret", Class: rotation.ClassProd}
	st, err := r.svc.(*rotation.Service).Start(context.Background(), rotation.Ref{OrgID: r.org, SecretID: r.secretID}, origin)
	if err != nil || st.Approval == nil {
		t.Fatalf("Start = %+v, %v", st, err)
	}
	return st.Approval.ID
}

// A request that needs approval opens a Mesh card only where the workspace
// asked for one: approvals_via_mesh false makes no card and leaves the
// approval to Keep's console; true, and a Mesh that never sent the setting,
// make exactly one.
func TestMeshGateFollowsApprovalsSetting(t *testing.T) {
	no, yes := false, true
	for _, tc := range []struct {
		name    string
		setting *bool
		cards   int
	}{
		{"false", &no, 0},
		{"true", &yes, 1},
		{"never sent", nil, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRotFixture(t, 1)
			cards := &recCards{}
			approval := startGatedRotation(t, r, cards, tc.setting)
			if got, _ := cards.snapshot(); got != tc.cards {
				t.Fatalf("cards made = %d, want %d", got, tc.cards)
			}
			var status string
			if err := r.f.pool.QueryRow(context.Background(), `SELECT status FROM approval_requests WHERE id=$1 AND org_id=$2`, approval, r.org).Scan(&status); err != nil || status != "requested" {
				t.Fatalf("approval status %q, %v: want a pending Keep approval", status, err)
			}
			var gates int
			if err := r.f.pool.QueryRow(context.Background(), `SELECT count(*) FROM mesh_gate_requests WHERE org_id=$1`, r.org).Scan(&gates); err != nil || gates != tc.cards {
				t.Fatalf("gate rows = %d, %v; want %d", gates, err, tc.cards)
			}
		})
	}
}
