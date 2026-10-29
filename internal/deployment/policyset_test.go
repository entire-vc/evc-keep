package deployment

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDecodePolicyIsStrict(t *testing.T) {
	if p, err := DecodePolicy([]byte(`{"rules":[],"exec_rules":[]}` + "\n")); err != nil || p.Rules == nil {
		t.Fatalf("one policy object refused: %v", err)
	}
	for name, in := range map[string]string{
		"unknown field":       `{"rules":[],"allow_all":true}`,
		"unknown rule field":  `{"rules":[{"secret_id":"` + uuid.NewString() + `","runner_id":"r","kind":"file","path_prefix":"/a","any":1}]}`,
		"second object":       `{"rules":[]} {"rules":[]}`,
		"trailing brace":      `{"rules":[]}}`,
		"trailing garbage":    `{"rules":[]} x`,
		"not an object":       `[]`,
		"null":                `null`,
		"null after space":    " \n null",
		"empty":               ``,
		"truncated":           `{"rules":[`,
		"wrong type of rules": `{"rules":{}}`,
	} {
		if _, err := DecodePolicy([]byte(in)); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: err %v, want ErrInvalidArgument", name, err)
		}
	}
}

func TestPolicyChangeReasonBoundedWithCount(t *testing.T) {
	short := PolicyChangeReason(PolicyChangeResult{PrevRevision: 0, Revision: 1, PrevMaxPerHour: 10, MaxPerHour: 10, Added: []string{"a"}, Removed: []string{"b"}})
	if short != "revision=0->1 max_per_hour=10->10 +a -b" {
		t.Fatalf("reason %q", short)
	}
	var added, removed []string
	for i := 0; i < 40; i++ {
		added = append(added, uuid.NewString()+"/"+uuid.NewString()+"/file//srv/app")
		removed = append(removed, uuid.NewString()+"/env-file//srv/x")
	}
	long := PolicyChangeReason(PolicyChangeResult{PrevRevision: 7, Revision: 8, PrevMaxPerHour: 10, MaxPerHour: 1000, Added: added, Removed: removed})
	if utf8.RuneCountInString(long) > 200 || !strings.HasPrefix(long, "revision=7->8 max_per_hour=10->1000 +") {
		t.Fatalf("reason %q (%d runes), want at most 200 starting with the revisions", long, utf8.RuneCountInString(long))
	}
	shown := strings.Count(long, " +") + strings.Count(long, " -")
	if !strings.HasSuffix(long, " (+"+strconv.Itoa(80-shown)+" more)") {
		t.Fatalf("reason %q shows %d keys, want the other %d counted", long, shown, 80-shown)
	}
}

func TestPolicyKeysAndDiff(t *testing.T) {
	s := uuid.MustParse("01a17b59-c0ef-7000-8000-000000000001")
	p := Policy{
		Rules:     []Rule{{SecretID: s, RunnerID: "r1", Labels: map[string]string{"platform": "linux", "environment": "staging"}, Kind: "file", PathPrefix: "/srv/a"}},
		ExecRules: []ExecRule{{SecretID: s, TemplateID: "t1", Labels: map[string]string{"platform": "darwin"}}},
	}
	keys := policyKeys(p)
	want := []string{s.String() + "/r1|environment=staging|platform=linux/file//srv/a", "exec:" + s.String() + "/platform=darwin/t1"}
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Fatalf("keys %q, want %q", keys, want)
	}
	added, removed := diffKeys([]string{"a", "b", "b"}, []string{"b", "c", "c"})
	if strings.Join(added, ",") != "c" || strings.Join(removed, ",") != "a" {
		t.Fatalf("diff +%q -%q, want +c -a", added, removed)
	}
}

// Racing first writers that all expect no policy: the organization row lock
// lets exactly one store revision 1, the others see a conflict.
//
// The race is forced, not left to timing: a separate transaction holds the
// organization row while every writer starts, and lets it go only once all n
// writers wait on a lock. With the lock each writer waits before it reads the
// policy row; without it they all read "no policy" and then wait at the
// insert (its foreign key needs the same row), so all of them write. Each
// writer has a connection of its own, so none waits for the pool instead.
func TestSetPolicyConcurrentFirstWriteOneWinner(t *testing.T) {
	f := newFixture(t)
	p := Policy{Rules: []Rule{{SecretID: f.secret, RunnerID: f.runner.String(), Kind: "file", PathPrefix: "/srv/app"}}}
	const n = 8
	app := "keep-policy-race-" + uuid.NewString()[:8]
	cfg := f.pool.Config()
	cfg.MaxConns, cfg.MinConns = n+1, 0
	cfg.ConnConfig.RuntimeParams["application_name"] = app
	pool, err := pgxpool.NewWithConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal("open writer pool")
	}
	defer pool.Close()
	repo := NewRepo(pool, audit.NewJournal(pool))
	hold, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hold.Rollback(f.ctx) }()
	if _, err = hold.Exec(f.ctx, `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, f.org); err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			_, err := repo.SetPolicy(f.ctx, PolicyChange{OrgID: f.org, Policy: p, ExpectRevision: 0,
				Actor: audit.Actor{Type: audit.ActorSystem, ID: "keep-server-set-deploy-policy", Via: audit.ViaCLI}})
			errs <- err
		}()
	}
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		var waiting int
		if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock'`, app).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting == n {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d writers wait on a lock while the organization row is held; the race is not forced", waiting, n)
		}
	}
	if err = hold.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	ok, conflicts := 0, 0
	for i := 0; i < n; i++ {
		switch err := <-errs; {
		case err == nil:
			ok++
		case errors.Is(err, ErrRevisionMismatch):
			conflicts++
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	var rev int64
	var records int
	if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT revision FROM deployment_policies WHERE org_id=$1), (SELECT count(*) FROM audit_records WHERE org_id=$2 AND action='deploy.policy_set')`, f.org, f.org.String()).Scan(&rev, &records); err != nil {
		t.Fatal(err)
	}
	if ok != 1 || conflicts != n-1 || rev != 1 || records != 1 {
		t.Fatalf("ok %d, conflicts %d, revision %d, journal records %d; want one winner at revision 1 with one record", ok, conflicts, rev, records)
	}
}
