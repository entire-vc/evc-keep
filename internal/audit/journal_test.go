package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

func newRecord(orgID string, mutate func(*Record)) Record {
	r := Record{
		OrgID:     orgID,
		RequestID: "req-1",
		Scope:     "proj:demo",
		Actor:     Actor{Type: ActorAgent, ID: "agent-1", SponsorID: "user-1", Via: ViaAPI},
		Intent:    Intent{TaskRef: "task-1", SessionRef: "sess-1", Reason: "test append"},
		Action:    "secret.create_ref",
		Secret:    SecretRef{ID: "sec-1", Name: "demo", Version: "v1"},
		Result:    Result{Status: StatusOK, Fingerprint: "kfp1:k1:abcdefghijklmnop", Length: 40},
	}
	if mutate != nil {
		mutate(&r)
	}
	return r
}

func TestAppend_FirstRecordChainsFromGenesis(t *testing.T) {
	pool := testPool(t)
	j := NewJournal(pool)
	ctx := context.Background()

	stored, err := j.Append(ctx, newRecord("org-genesis", nil))
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if stored.ID == "" {
		t.Error("Append did not fill ID")
	}
	if stored.TS.IsZero() {
		t.Error("Append did not fill TS")
	}
	if stored.PrevHash != GenesisHash {
		t.Errorf("first record's PrevHash = %q, want GenesisHash", stored.PrevHash)
	}

	res, err := Verify(ctx, pool, "org-genesis")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK {
		t.Errorf("Verify after one Append: OK=false, broken at %s/%d", res.BrokenID, res.BrokenPosition)
	}
	if res.Checked != 1 {
		t.Errorf("Checked = %d, want 1", res.Checked)
	}
}

func TestAppend_CallerSuppliedIDAndPrevHashAreIgnored(t *testing.T) {
	pool := testPool(t)
	j := NewJournal(pool)
	ctx := context.Background()

	r := newRecord("org-ignore-caller-fields", func(r *Record) {
		r.ID = "caller-supplied-id"
		r.PrevHash = "caller-supplied-prev-hash-not-genesis-and-not-real"
	})
	stored, err := j.Append(ctx, r)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if stored.ID == "caller-supplied-id" {
		t.Error("Append trusted a caller-supplied ID")
	}
	if stored.PrevHash != GenesisHash {
		t.Errorf("Append trusted a caller-supplied PrevHash: got %q", stored.PrevHash)
	}
}

// TestAppend_ChainsAcrossMultipleRecords is the green counterpart to
// verify_test.go's tamper/delete red runs: a normal sequence of appends
// must verify clean.
func TestAppend_ChainsAcrossMultipleRecords(t *testing.T) {
	pool := testPool(t)
	j := NewJournal(pool)
	ctx := context.Background()
	org := "org-chain"

	var lastHash string
	for i := 0; i < 5; i++ {
		stored, err := j.Append(ctx, newRecord(org, func(r *Record) {
			r.Intent.Reason = fmt.Sprintf("step %d", i)
		}))
		if err != nil {
			t.Fatalf("Append #%d: %v", i, err)
		}
		if i == 0 {
			if stored.PrevHash != GenesisHash {
				t.Fatalf("record 0 PrevHash = %q, want genesis", stored.PrevHash)
			}
		} else if stored.PrevHash != lastHash {
			t.Fatalf("record %d PrevHash = %q, want previous record's hash %q", i, stored.PrevHash, lastHash)
		}
		h, err := computeHash(stored.PrevHash, stored)
		if err != nil {
			t.Fatalf("recompute hash for record %d: %v", i, err)
		}
		lastHash = h
	}

	res, err := Verify(ctx, pool, org)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK {
		t.Errorf("Verify: OK=false, broken at %s/%d", res.BrokenID, res.BrokenPosition)
	}
	if res.Checked != 5 {
		t.Errorf("Checked = %d, want 5", res.Checked)
	}
}

// TestAppend_ConcurrentAcrossOrgsKeepsBothChainsIntact is the green run
// required: 1000 records across two organizations,
// concurrently, both chains intact, with -race enabled (see .gitlab-ci.yml:
// `go test ./... -race`). -race covers the Go side (the ULID entropy
// source); what proves audit_chain_heads' row lock (the ON CONFLICT upsert
// in Append) serializes same-org appends is Verify over every record of
// both chains afterwards.
func TestAppend_ConcurrentAcrossOrgsKeepsBothChainsIntact(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 1000-record concurrency test in -short mode")
	}
	pool := testPool(t)
	j := NewJournal(pool)
	ctx := context.Background()

	const perOrg = 500
	orgs := []string{"org-race-a", "org-race-b"}

	var wg sync.WaitGroup
	errCh := make(chan error, len(orgs)*perOrg)
	for _, org := range orgs {
		for i := 0; i < perOrg; i++ {
			wg.Add(1)
			go func(org string, i int) {
				defer wg.Done()
				_, err := j.Append(ctx, newRecord(org, func(r *Record) {
					r.Intent.Reason = fmt.Sprintf("race %d", i)
				}))
				if err != nil {
					errCh <- err
				}
			}(org, i)
		}
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("Append failed under concurrency: %v", err)
	}

	for _, org := range orgs {
		res, err := Verify(ctx, pool, org)
		if err != nil {
			t.Fatalf("Verify(%s): %v", org, err)
		}
		if !res.OK {
			t.Errorf("Verify(%s): OK=false, broken at %s/%d", org, res.BrokenID, res.BrokenPosition)
		}
		if res.Checked != perOrg {
			t.Errorf("Verify(%s): Checked = %d, want %d", org, res.Checked, perOrg)
		}
	}
}

// TestAppend_CanaryOnlySurvivesInItsOwnField is the leak test written before
// the feature code: a canary is placed in every string field a caller can
// reach, appended, read back from the database directly (bypassing
// Record/Journal's own field mapping, so a leak into an unintended COLUMN
// is caught too, not just an unintended Go field), and must be found only
// in the columns it was placed into.
func TestAppend_CanaryOnlySurvivesInItsOwnField(t *testing.T) {
	pool := testPool(t)
	j := NewJournal(pool)
	ctx := context.Background()
	org := "org-canary"

	c := canary.New()
	secretName := c.Value(1)
	reason := c.Value(2)
	targetPath := c.Value(3)
	host := c.Value(4)

	stored, err := j.Append(ctx, newRecord(org, func(r *Record) {
		r.Secret.Name = secretName
		r.Intent.Reason = reason
		r.Target.Path = targetPath
		r.Target.Host = host
	}))
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	rows, err := pool.Query(ctx, `
		SELECT column_name, value
		FROM audit_records, LATERAL (
			SELECT column_name, (to_jsonb(audit_records) ->> column_name) AS value
			FROM information_schema.columns
			WHERE table_name = 'audit_records' AND table_schema = 'public'
		) cols
		WHERE audit_records.id = $1
	`, stored.ID)
	if err != nil {
		t.Fatalf("query all columns: %v", err)
	}
	defer rows.Close()

	placements := map[string]string{
		"secret_name":   secretName,
		"intent_reason": reason,
		"target_path":   targetPath,
		"target_host":   host,
	}

	var checked int
	for rows.Next() {
		var col string
		var val *string
		if err := rows.Scan(&col, &val); err != nil {
			t.Fatalf("scan column: %v", err)
		}
		checked++
		if val == nil {
			continue
		}
		if c.In(*val) {
			want, isPlacement := placements[col]
			if !isPlacement {
				t.Errorf("canary leaked into unexpected column %q: %q", col, *val)
				continue
			}
			if *val != want {
				t.Errorf("column %q carries a canary but not the one placed there: got %q, want %q", col, *val, want)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read columns: %v", err)
	}
	// Positive control: the walker actually visited columns — an empty
	// result would make the loop above vacuously pass.
	if checked < 20 {
		t.Fatalf("only inspected %d columns — the column walker is broken, not the row clean", checked)
	}
}

// TestAppend_ServiceLogCarriesOnlyIDActionRequestID is the threat model's
// §4.2 guard — "the service log line for a journal write carries no record
// fields other than id, action and request_id" — on the real Journal.Append
// (not a test wrapper), through internal/obs's allow-list (§4.4). The line is
// parsed and its key set compared exactly: internal/obs lets any "*_id" or
// "*_name" key through, so a canary check alone would stay green after
// `slog.String("reason_id", r.Intent.Reason)` was added to the line as long
// as the canary sat in a field nobody logged. Every free-text field of the
// record therefore carries its own canary, and the closed fields carry
// non-empty values whose spelling must not appear either.
func TestAppend_ServiceLogCarriesOnlyIDActionRequestID(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	var logBuf strings.Builder
	logger := obs.New(&logBuf)

	c := canary.New()
	var planted []string
	plant := func(dst *string) {
		v := c.Value(len(planted))
		planted = append(planted, v)
		*dst = v
	}

	j := NewJournal(pool).WithLogger(logger)
	stored, err := j.Append(ctx, newRecord("org-logtest", func(r *Record) {
		r.RequestID = "req-log-1"
		r.Result.ErrorClass = ErrClassProviderError
		r.Result.Health = HealthSkipped
		r.Policy.Decision = DecisionApprovalRequired
		r.Actor.Via = ViaMeshPlugin
		for _, f := range []*string{
			&r.Scope, &r.Actor.ID, &r.Actor.SponsorID,
			&r.Intent.TaskRef, &r.Intent.SessionRef, &r.Intent.Reason,
			&r.Secret.ID, &r.Secret.Name, &r.Secret.Version,
			&r.Target.RunnerID, &r.Target.Host, &r.Target.Kind, &r.Target.Path,
			&r.Policy.RuleID, &r.Approval.ID, &r.Approval.ApproverID,
		} {
			plant(f)
		}
	}))
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if len(planted) != 16 {
		t.Fatalf("planted %d canaries, want one per free-text field (16)", len(planted))
	}

	logged := logBuf.String()
	if n := strings.Count(strings.TrimRight(logged, "\n"), "\n") + 1; n != 1 {
		t.Fatalf("Append wrote %d log lines, want exactly 1: %s", n, logged)
	}
	if c.In(logged) {
		t.Errorf("a canary from the record leaked into the append log line: %s", logged)
	}
	for _, v := range []string{"provider_error", "approval_required", "mesh-plugin", "skipped", "org-logtest", "kfp1:"} {
		if strings.Contains(logged, v) {
			t.Errorf("the log line carries record content %q: %s", v, logged)
		}
	}

	var line map[string]any
	if err := json.Unmarshal([]byte(logged), &line); err != nil {
		t.Fatalf("log line is not one JSON object: %v: %s", err, logged)
	}
	got := make([]string, 0, len(line))
	for k := range line {
		got = append(got, k)
	}
	sort.Strings(got)
	want := []string{"action", "id", "level", "msg", "request_id", "time"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("log line keys = %v, want exactly %v: %s", got, want, logged)
	}
	for k, want := range map[string]string{"id": stored.ID, "action": string(stored.Action), "request_id": stored.RequestID} {
		if line[k] != want {
			t.Errorf("log line %s = %v, want %q", k, line[k], want)
		}
	}
}
