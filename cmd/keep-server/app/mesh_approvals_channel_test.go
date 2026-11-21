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

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
)

// approvalsChannelRecord is one mesh.approvals_channel journal record, the
// columns the threat model §4.2.3 fixes.
type approvalsChannelRecord struct {
	Scope, ActorType, ActorID, ActorVia, Reason, Status, ErrorClass string
	SecretID, SecretName, SecretVersion, Fingerprint                string
	Length                                                          int
}

// approvalsChannelRecords lists the mesh.approvals_channel records of the
// fixture's organisation in journal order.
func (f *meshFixture) approvalsChannelRecords() []approvalsChannelRecord {
	f.t.Helper()
	rows, err := f.pool.Query(context.Background(), `
SELECT scope, actor_type, actor_id, actor_via, intent_reason, result_status, result_error_class,
       secret_id, secret_name, secret_version, result_fingerprint, result_length
  FROM audit_records WHERE org_id = $1 AND action = 'mesh.approvals_channel' ORDER BY org_seq`, f.org.ID.String())
	if err != nil {
		f.t.Fatalf("approvals channel records: %v", err)
	}
	defer rows.Close()
	var out []approvalsChannelRecord
	for rows.Next() {
		var r approvalsChannelRecord
		if err := rows.Scan(&r.Scope, &r.ActorType, &r.ActorID, &r.ActorVia, &r.Reason, &r.Status, &r.ErrorClass,
			&r.SecretID, &r.SecretName, &r.SecretVersion, &r.Fingerprint, &r.Length); err != nil {
			f.t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		f.t.Fatal(err)
	}
	return out
}

// settingsSignedAt is the stored X-Mesh-Timestamp of the last applied
// snapshot of ws, 0 when none was applied.
func (f *meshFixture) settingsSignedAt(ws uuid.UUID) int64 {
	f.t.Helper()
	var v *int64
	if err := f.pool.QueryRow(context.Background(), `SELECT settings_signed_at FROM mesh_installations WHERE workspace_id=$1`, ws).Scan(&v); err != nil {
		f.t.Fatalf("settings_signed_at: %v", err)
	}
	if v == nil {
		return 0
	}
	return *v
}

func (f *meshFixture) handshakeSettingsAt(ws uuid.UUID, secret, settings string, ts time.Time) *httptest.ResponseRecorder {
	return f.handshakeSigned(meshHandshakeBodyWithSettings(ws, secret, settings), secret, ts)
}

// A change of the stored approvals_via_mesh is journaled exactly once, as
// mesh.approvals_channel by the workspace through the Mesh plugin, with only
// the new value; a snapshot that leaves the value as it is writes no record.
// This holds on the three paths that apply a snapshot: a fresh binding, a
// repeat with the bound secret and the upgrade of a store binding.
func TestMeshHandshakeJournalsApprovalsChannel(t *testing.T) {
	f := newMeshFixture(t, true)
	c := canary.New()
	secret := "ac-" + c.Value(1)
	org := f.org.ID.String()

	expect := func(t *testing.T, ws uuid.UUID, before int, reasons ...string) {
		t.Helper()
		all := f.approvalsChannelRecords()
		got := all[before:]
		if len(got) != len(reasons) {
			t.Fatalf("records %d, want %d: %+v", len(got), len(reasons), got)
		}
		for i, r := range got {
			want := approvalsChannelRecord{Scope: "org:" + org, ActorType: "service", ActorID: ws.String(), ActorVia: "mesh-plugin",
				Reason: reasons[i], Status: "ok"}
			if r != want {
				t.Fatalf("record %d = %+v, want %+v", i, r, want)
			}
		}
	}
	step := func(t *testing.T, ws uuid.UUID, settings string, wantSetting string, reasons ...string) {
		t.Helper()
		before := len(f.approvalsChannelRecords())
		if rec := f.handshakeWithSettings(ws, secret, settings); rec.Code != http.StatusOK {
			t.Fatalf("handshake %q: status %d, %s", settings, rec.Code, answerDiag(rec))
		}
		if got := f.approvalsSetting(ws); got != wantSetting {
			t.Fatalf("handshake %q: approvals_via_mesh %s, want %s", settings, got, wantSetting)
		}
		expect(t, ws, before, reasons...)
	}

	t.Run("bind and repeats", func(t *testing.T) {
		ws := uuid.New()
		f.mustOpenWindow(ws, secret)
		step(t, ws, `{"approvals_via_mesh":false}`, "false", "approvals_via_mesh=false")
		step(t, ws, `{"approvals_via_mesh":false}`, "false")
		step(t, ws, "", "false")
		step(t, ws, `{"approvals_via_mesh":true}`, "true", "approvals_via_mesh=true")
		step(t, ws, `{"approvals_via_mesh":true, "other":"x"}`, "true")
		step(t, ws, `{}`, "unset", "approvals_via_mesh=default")
		step(t, ws, `{}`, "unset")
		step(t, ws, `{"approvals_via_mesh":false}`, "false", "approvals_via_mesh=false")
	})

	t.Run("bind with true from nothing is a change", func(t *testing.T) {
		ws := uuid.New()
		f.mustOpenWindow(ws, secret)
		step(t, ws, `{"approvals_via_mesh":true}`, "true", "approvals_via_mesh=true")
	})

	t.Run("bind without the key or without settings is no change", func(t *testing.T) {
		for _, s := range []string{`{}`, ""} {
			ws := uuid.New()
			f.mustOpenWindow(ws, secret)
			step(t, ws, s, "unset")
		}
	})

	t.Run("store binding upgraded", func(t *testing.T) {
		ws := uuid.New()
		if rec := f.installStore(ws, c.Value(3)); rec.Code != http.StatusOK {
			t.Fatalf("store install: %d", rec.Code)
		}
		f.mustOpenWindow(ws, secret)
		step(t, ws, `{"approvals_via_mesh":false}`, "false", "approvals_via_mesh=false")
		step(t, ws, `{"approvals_via_mesh":false}`, "false")
	})
}

// Leak test (written before the feature): the mesh.approvals_channel record
// carries the new value only. A value under any other key of the snapshot
// reaches no column of the journal, on any of the three paths, and no log line.
func TestMeshApprovalsChannelJournalHoldsNoSnapshotValue(t *testing.T) {
	f := newMeshFixture(t, true)
	secret := "aj-" + canary.New().Value(1)
	leak := canary.New()
	snapshot := func(i int, v any) string {
		m := map[string]any{"api_token": leak.Value(i), "nested": map[string]string{"v": leak.Value(i + 10)}, leak.Value(i + 20): true}
		if v != nil {
			m["approvals_via_mesh"] = v
		}
		b, _ := json.Marshal(m)
		return string(b)
	}
	ws := uuid.New()
	f.mustOpenWindow(ws, secret)
	for i, s := range []string{snapshot(0, false), snapshot(1, true), snapshot(2, nil)} {
		if rec := f.handshakeWithSettings(ws, secret, s); rec.Code != http.StatusOK {
			t.Fatalf("handshake %d: status %d, %s", i, rec.Code, answerDiag(rec))
		}
	}
	up := uuid.New()
	if rec := f.installStore(up, canary.New().Value(3)); rec.Code != http.StatusOK {
		t.Fatalf("store install: %d", rec.Code)
	}
	f.mustOpenWindow(up, secret)
	if rec := f.handshakeWithSettings(up, secret, snapshot(3, false)); rec.Code != http.StatusOK {
		t.Fatalf("upgrade: status %d, %s", rec.Code, answerDiag(rec))
	}
	// Positive control: the records under test exist (bind false, repeat
	// true, repeat default, upgrade false), so the absence below is not that
	// of an empty journal.
	if n := len(f.approvalsChannelRecords()); n != 4 {
		t.Fatalf("approvals channel records %d, want 4: the leak check proves nothing", n)
	}
	if !leak.In("x"+leak.Value(0)+"x") || !leak.In(fmt.Sprintf("%x", leak.Value(21))) {
		t.Fatal("canary check is blind")
	}
	if f.logbuf.Len() == 0 {
		t.Fatal("logger captured nothing; the log check proves nothing")
	}
	rows, err := f.pool.Query(context.Background(), `SELECT row_to_json(t)::text FROM audit_records t WHERE org_id = $1`, f.org.ID.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		seen++
		if leak.In(s) {
			t.Fatalf("snapshot value leaked into journal record #%d (%d bytes); the record is not printed", seen, len(s))
		}
	}
	if err := rows.Err(); err != nil || seen == 0 {
		t.Fatalf("journal rows %d, %v", seen, err)
	}
	if leak.In(f.logbuf.String()) {
		t.Fatal("snapshot value leaked into the service log; the log is not printed")
	}
}

// Snapshots are applied in the order Mesh signed them, not the order they
// arrive: one with an older X-Mesh-Timestamp than the last applied leaves the
// value, the stored time and the journal as they are. A newer snapshot with
// the same value still moves the stored time, so an older opposite snapshot
// arriving after it does not win either. Two snapshots of the same second:
// the later arrival wins (the accepted residual of §4.2.3).
func TestMeshHandshakeAppliesSnapshotsInSignedOrder(t *testing.T) {
	f := newMeshFixture(t, true)
	secret := "so-" + canary.New().Value(1)
	ws := uuid.New()
	f.mustOpenWindow(ws, secret)
	now := time.Now()
	at := func(d int) time.Time { return now.Add(time.Duration(d) * time.Second) }
	step := func(name, settings string, ts time.Time, wantSetting string, wantSignedAt time.Time, wantRecords int) {
		t.Helper()
		if rec := f.handshakeSettingsAt(ws, secret, settings, ts); rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d, %s", name, rec.Code, answerDiag(rec))
		}
		if got := f.approvalsSetting(ws); got != wantSetting {
			t.Fatalf("%s: approvals_via_mesh %s, want %s", name, got, wantSetting)
		}
		if got := f.settingsSignedAt(ws); got != wantSignedAt.Unix() {
			t.Fatalf("%s: settings_signed_at %d, want %d", name, got, wantSignedAt.Unix())
		}
		if got := len(f.approvalsChannelRecords()); got != wantRecords {
			t.Fatalf("%s: records %d, want %d", name, got, wantRecords)
		}
	}
	step("bind with false", `{"approvals_via_mesh":false}`, at(-100), "false", at(-100), 1)
	step("older true is not applied", `{"approvals_via_mesh":true}`, at(-120), "false", at(-100), 1)
	step("newer true is applied", `{"approvals_via_mesh":true}`, at(-80), "true", at(-80), 2)
	step("older default is not applied", `{}`, at(-90), "true", at(-80), 2)
	step("newer equal true moves the time", `{"approvals_via_mesh":true}`, at(-40), "true", at(-40), 2)
	step("false older than the equal true is not applied", `{"approvals_via_mesh":false}`, at(-60), "true", at(-40), 2)
	step("same second, later arrival wins", `{"approvals_via_mesh":false}`, at(-40), "false", at(-40), 3)
	step("a handshake without settings keeps the time", "", at(-10), "false", at(-40), 3)
}

// A journal failure leaves no change behind: the setting, its signed time and
// the binding or upgrade it rides on roll back together, the answer is 503,
// and a repeat of the same handshake applies the snapshot once the journal
// accepts the record. The failure is forced at the real database boundary.
func TestMeshApprovalsChannelJournalFailureRollsBack(t *testing.T) {
	for _, path := range []string{"repeat", "bind", "upgrade"} {
		t.Run(path, func(t *testing.T) {
			f := newMeshFixture(t, true)
			ws := uuid.New()
			secret := "jf-" + canary.New().Value(1)
			switch path {
			case "repeat":
				f.mustOpenWindow(ws, secret)
				if rec := f.handshakeSettingsAt(ws, secret, `{"approvals_via_mesh":false}`, time.Now().Add(-time.Minute)); rec.Code != http.StatusOK {
					t.Fatalf("bind: %d", rec.Code)
				}
			case "upgrade":
				if rec := f.installStore(ws, canary.New().Value(2)); rec.Code != http.StatusOK {
					t.Fatalf("store install: %d", rec.Code)
				}
				f.mustOpenWindow(ws, secret)
			default:
				f.mustOpenWindow(ws, secret)
			}
			records := len(f.approvalsChannelRecords())
			signedAt := int64(0)
			if path == "repeat" {
				signedAt = f.settingsSignedAt(ws)
			}
			suffix := strings.ReplaceAll(ws.String(), "-", "")
			fn, trigger := "ac_journal_fail_"+suffix, "ac_journal_trigger_"+suffix
			if _, err := f.pool.Exec(context.Background(), fmt.Sprintf(`
CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
  IF NEW.action = 'mesh.approvals_channel' AND NEW.actor_id = '%s' THEN RAISE EXCEPTION 'journal test write refused'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER %s BEFORE INSERT ON audit_records FOR EACH ROW EXECUTE FUNCTION %s()`, fn, ws, trigger, fn)); err != nil {
				t.Fatalf("create journal failure trigger: %v", err)
			}
			t.Cleanup(func() {
				_, _ = f.pool.Exec(context.Background(), "DROP TRIGGER IF EXISTS "+trigger+" ON audit_records; DROP FUNCTION IF EXISTS "+fn+"()")
			})
			snapshot := `{"approvals_via_mesh":true}`
			if path != "repeat" {
				snapshot = `{"approvals_via_mesh":false}`
			}
			if rec := f.handshakeWithSettings(ws, secret, snapshot); rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("journal refused: status %d, want 503, %s", rec.Code, answerDiag(rec))
			}
			switch path {
			case "repeat":
				if f.approvalsSetting(ws) != "false" || f.settingsSignedAt(ws) != signedAt {
					t.Fatal("a refused journal record left the setting or its time changed")
				}
			case "bind":
				if f.count(`SELECT count(*) FROM mesh_installations WHERE workspace_id=$1`, ws) != 0 {
					t.Fatal("a refused journal record left the binding in place")
				}
			case "upgrade":
				if f.count(`SELECT count(*) FROM mesh_installations WHERE workspace_id=$1 AND mode='store'`, ws) != 1 || f.approvalsSetting(ws) != "unset" {
					t.Fatal("a refused journal record left the upgrade or its setting in place")
				}
			}
			if path != "repeat" && f.count(`SELECT count(*) FROM mesh_pending_installs WHERE workspace_id=$1`, ws) != 1 {
				t.Fatal("a refused journal record spent the install window")
			}
			if got := len(f.approvalsChannelRecords()); got != records {
				t.Fatalf("records %d after a refused write, want %d", got, records)
			}
			// Positive control: the same handshake applies once the journal
			// accepts the record.
			if _, err := f.pool.Exec(context.Background(), "DROP TRIGGER "+trigger+" ON audit_records; DROP FUNCTION "+fn+"()"); err != nil {
				t.Fatal("remove journal failure trigger")
			}
			if rec := f.handshakeWithSettings(ws, secret, snapshot); rec.Code != http.StatusOK {
				t.Fatalf("retry: status %d, %s", rec.Code, answerDiag(rec))
			}
			if got := len(f.approvalsChannelRecords()); got != records+1 {
				t.Fatalf("records %d after the retry, want %d", got, records+1)
			}
		})
	}
}

// A bind or upgrade that carries a settings change journals it only after
// seal. seal waits for the organisation's key-level lock; a key-level change
// holds that lock exclusively and journals its request while holding it. If
// the handshake took the audit chain head first, the two would wait for each
// other until the key-level change gives up. Here a connection holds the
// key-level lock as ChangeLevel does, waits until the handshake really
// queues for it, journals a request like ChangeLevel's within a bounded lock
// wait, and only then lets the handshake go on.
//
// Every wait here is bounded and the lock-queue probe runs on the
// connection that holds the key-level lock: a handshake stuck behind that
// lock keeps its own pool connections, and on a small pool (pgxpool sizes it
// by CPU count, 4 on a CI runner) a probe that acquired one more would wait
// for ever instead of failing.
func TestMeshApprovalsChannelJournalAfterSealUnderKeyLevelChange(t *testing.T) {
	for _, path := range []string{"bind", "upgrade"} {
		t.Run(path, func(t *testing.T) {
			f := newMeshFixture(t, true)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			ws := uuid.New()
			secret := "lo-" + canary.New().Value(1)
			if path == "upgrade" {
				if rec := f.installStore(ws, canary.New().Value(2)); rec.Code != http.StatusOK {
					t.Fatalf("store install: %d", rec.Code)
				}
			}
			f.mustOpenWindow(ws, secret)
			records := len(f.approvalsChannelRecords())

			c, err := f.pool.Acquire(ctx)
			if err != nil {
				t.Fatalf("acquire key-level connection: %v", err)
			}
			defer c.Release()
			key := "keep_org_key_level:" + f.org.ID.String()
			if _, err := c.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended($1, 0))`, key); err != nil {
				t.Fatalf("hold key-level lock: %v", err)
			}
			held := true
			release := func() {
				if held {
					uctx, ucancel := context.WithTimeout(context.Background(), 10*time.Second)
					_, _ = c.Exec(uctx, `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, key)
					ucancel()
					held = false
				}
			}
			defer release()

			done := make(chan int, 1)
			go func() { done <- f.handshakeWithSettings(ws, secret, `{"approvals_via_mesh":false}`).Code }()

			// The handshake must be queued on the key-level lock, or the
			// journal write below proves nothing about the order.
			deadline := time.Now().Add(10 * time.Second)
			for {
				var n int
				if err := c.QueryRow(ctx, `
SELECT count(*) FROM pg_stat_activity
 WHERE $1 = ANY(pg_blocking_pids(pid)) AND query LIKE '%pg_advisory_xact_lock_shared%'`,
					int64(c.Conn().PgConn().PID())).Scan(&n); err != nil {
					t.Fatalf("inspect lock wait: %v", err)
				}
				if n > 0 {
					break
				}
				if time.Now().After(deadline) {
					release()
					select {
					case <-done:
					case <-time.After(10 * time.Second):
					}
					t.Fatal("the handshake never waited for the key-level lock")
				}
				time.Sleep(10 * time.Millisecond)
			}

			tx, err := c.Begin(ctx)
			if err != nil {
				t.Fatalf("begin key-level journal transaction: %v", err)
			}
			if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '2s'`); err != nil {
				t.Fatalf("bound the lock wait: %v", err)
			}
			_, journalErr := audit.NewJournal(f.pool).AppendTx(ctx, tx, audit.Record{
				RequestID: "lock-order-" + path,
				OrgID:     f.org.ID.String(),
				Scope:     "org:" + f.org.ID.String(),
				Actor:     audit.Actor{Type: audit.ActorUser, ID: uuid.NewString(), Via: audit.ViaAPI},
				Action:    audit.ActionOrgKeyLevelRequested,
				Result:    audit.Result{Status: audit.StatusPending},
			})
			_ = tx.Rollback(ctx)
			release()

			select {
			case code := <-done:
				if code != http.StatusOK {
					t.Errorf("%s: status %d after the key-level lock was released", path, code)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("%s: the handshake did not finish after the key-level lock was released", path)
			}
			if journalErr != nil {
				t.Fatalf("%s: a key-level change holding its lock could not journal while the handshake waited for that lock: the handshake holds the audit chain head before seal", path)
			}
			if got := len(f.approvalsChannelRecords()); got != records+1 {
				t.Fatalf("%s: approvals channel records %d, want %d", path, got, records+1)
			}
			if f.approvalsSetting(ws) != "false" {
				t.Fatalf("%s: setting %s, want false", path, f.approvalsSetting(ws))
			}
		})
	}
}
