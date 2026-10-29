package audit

import (
	"testing"
	"time"
)

// pinnedRecord is a fully populated record with every value fixed, so the
// canonical JSON and the hash of it are exact, reviewable constants.
func pinnedRecord() Record {
	return Record{
		ID:        "01J8ZZZZZZZZZZZZZZZZZZZZZZ",
		TS:        time.Date(2026, 9, 24, 12, 0, 0, 123456000, time.UTC),
		RequestID: "req-1",
		OrgID:     "org-1",
		Scope:     "proj:demo",
		Actor:     Actor{Type: ActorAgent, ID: "agent-1", SponsorID: "user-1", Via: ViaMCP},
		Intent:    Intent{TaskRef: "task-1", SessionRef: "sess-1", Reason: "rotate — été"},
		Action:    "secret.rotate.*",
		Secret:    SecretRef{ID: "sec-1", Name: "db", Version: "v3"},
		Target:    Target{RunnerID: "runner-1", Host: "host-1", Kind: "file", Path: "/srv/app/.env"},
		Policy:    Policy{Decision: DecisionApprovalRequired, RuleID: "rule-1"},
		Approval:  Approval{ID: "appr-1", ApproverID: "user-2", DecidedAt: time.Date(2026, 9, 24, 11, 0, 0, 500000000, time.UTC)},
		Result:    Result{Status: StatusOK, Fingerprint: "kfp1:k1:abcdefghijklmnop", Length: 40, Health: HealthOK},
		PrevHash:  GenesisHash,
	}
}

const (
	pinnedCanonicalJSON = `{"action":"secret.rotate.*","actor":{"id":"agent-1","sponsor_id":"user-1","type":"agent","via":"mcp"},"approval":{"approver_id":"user-2","decided_at":"2026-09-24T11:00:00.5Z","id":"appr-1"},"id":"01J8ZZZZZZZZZZZZZZZZZZZZZZ","intent":{"reason":"rotate — été","session_ref":"sess-1","task_ref":"task-1"},"org_id":"org-1","policy":{"decision":"approval_required","rule_id":"rule-1"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","request_id":"req-1","result":{"error_class":"","fingerprint":"kfp1:k1:abcdefghijklmnop","health":"ok","length":40,"status":"ok"},"scope":"proj:demo","secret":{"id":"sec-1","name":"db","version":"v3"},"target":{"host":"host-1","kind":"file","path":"/srv/app/.env","runner_id":"runner-1"},"ts":"2026-09-24T12:00:00.123456Z"}`
	pinnedHash          = "778eceab59dcc9de4563d59908d25a01ba02133e3aa433305f3a33fd13cedf14"
)

// TestHashFormatIsPinned fixes the exact bytes that are hashed. Records
// already stored were hashed with this format: a change to key order,
// escaping, the timestamp form, a field's name, or the prev_hash prefix
// changes every hash on write and on verify at once, so nothing else would
// notice — existing chains would simply stop verifying in production. If
// this test fails on purpose (a format version bump), the new constants are
// part of that reviewed change.
func TestHashFormatIsPinned(t *testing.T) {
	r := pinnedRecord()
	body, err := canonicalJSON(r)
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	if string(body) != pinnedCanonicalJSON {
		t.Errorf("canonical JSON changed:\n got: %s\nwant: %s", body, pinnedCanonicalJSON)
	}
	h, err := computeHash(GenesisHash, r)
	if err != nil {
		t.Fatalf("computeHash: %v", err)
	}
	if h != pinnedHash {
		t.Errorf("hash changed: got %s, want %s", h, pinnedHash)
	}
}
