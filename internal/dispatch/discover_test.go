package dispatch

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/enrolltoken"
	"github.com/entire-vc/evc-keep/internal/mtls"
	"github.com/entire-vc/evc-keep/internal/registry"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

// discoverFixture is the dispatch fixture with its deploy job already
// claimed, plus one queued discover job for the same runner.
type discoverFixture struct {
	fixture
	job     runnerproto.Job
	request string
}

func newDiscoverFixture(t *testing.T) discoverFixture {
	t.Helper()
	f := newFixture(t)
	ctx := context.Background()
	if _, ok, err := f.service.Poll(ctx, f.peer); err != nil || !ok {
		t.Fatal("claim the deploy job")
	}
	var store uuid.UUID
	if err := f.pool.QueryRow(ctx, `SELECT id FROM stores WHERE org_id=$1`, f.peer.OrgID).Scan(&store); err != nil {
		t.Fatal("store")
	}
	user, err := uuid.NewV7()
	if err != nil {
		t.Fatal("id")
	}
	request, err := uuid.NewV7()
	if err != nil {
		t.Fatal("id")
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO users(id,org_id,email) VALUES($1,$2,'d@example.invalid')`, user, f.peer.OrgID); err != nil {
		t.Fatal("user")
	}
	rep, err := deployment.NewRepo(f.pool, audit.NewJournal(f.pool)).SubmitDiscover(ctx, deployment.DiscoverRequest{OrgID: f.peer.OrgID, RunnerID: f.peer.RunnerID, StoreID: store,
		RequestID: request.String(), Actor: audit.Actor{Type: audit.ActorUser, ID: user.String(), Via: audit.ViaAPI}})
	if err != nil || rep.State != deployment.DiscoverPending {
		t.Fatalf("submit discover: %+v %v", rep, err)
	}
	signed, ok, err := f.service.Poll(ctx, f.peer)
	if err != nil || !ok {
		t.Fatal("discover job not delivered")
	}
	job, err := runnerproto.DecodeJob(signed.Payload)
	if err != nil || job.Action != runnerproto.ActionDiscover {
		t.Fatalf("delivered %+v %v", job, err)
	}
	return discoverFixture{fixture: f, job: job, request: request.String()}
}

func body(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal("marshal")
	}
	return b
}

func lines(t *testing.T, f discoverFixture) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM discovery_observations`).Scan(&n); err != nil {
		t.Fatal("count")
	}
	return n
}

func TestDiscoverJobIsDeliveredOnceAndKeyIsIssuedOnce(t *testing.T) {
	f := newDiscoverFixture(t)
	ctx := context.Background()
	second, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel()
	if _, ok, err := f.service.Poll(second, f.peer); ok || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("an issued discover job was delivered again")
	}
	env, err := f.service.Material(ctx, f.peer, f.job.JobID)
	if err != nil || env.JobID != f.job.JobID || len(env.Sealed) != 0 || len(env.SealedFingerprintKey) == 0 {
		t.Fatalf("discover key envelope: %+v %v", env, err)
	}
	if _, err = f.service.Material(ctx, f.peer, f.job.JobID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a second key issuance = %v", err)
	}
}

func TestDiscoverResultRoutesByJobAndKeepsShapes(t *testing.T) {
	f := newDiscoverFixture(t)
	ctx := context.Background()
	good := body(t, runnerproto.DiscoverResult{OK: true, Findings: []runnerproto.DiscoverFinding{{Path: "/srv/x.env", Name: "DB_PASSWORD", Fingerprint: "kfp1:key:abcdefghijklmnop", Len: 12}}})
	// No key was issued yet: a success cannot have scanned anything.
	if err := f.service.ResultBody(ctx, f.peer, f.job.JobID, good); !errors.Is(err, ErrNotFound) {
		t.Fatalf("success before key issuance = %v", err)
	}
	if _, err := f.service.Material(ctx, f.peer, f.job.JobID); err != nil {
		t.Fatal(err)
	}
	// Shapes belong to the job: a deploy result for a discover job and the reverse are refused.
	if err := f.service.ResultBody(ctx, f.peer, f.job.JobID, body(t, runnerproto.Result{ErrorClass: runnerproto.ErrClassInternal})); !errors.Is(err, ErrInvalidBody) {
		t.Fatalf("deploy-shaped body for a discover job = %v", err)
	}
	if err := f.service.ResultBody(ctx, f.peer, f.jobID, good); !errors.Is(err, ErrInvalidBody) {
		t.Fatalf("discover-shaped body for a deploy job = %v", err)
	}
	if err := f.service.ResultBody(ctx, f.peer, f.jobID, []byte(`{"ok":false,"error_class":"internal"`+strings.Repeat(" ", MaxResultBody)+`}`)); !errors.Is(err, ErrInvalidBody) {
		t.Fatalf("oversized deploy result = %v", err)
	}
	if err := f.service.ResultBody(ctx, f.peer, f.job.JobID, good); err != nil {
		t.Fatalf("discover report: %v", err)
	}
	if lines(t, f) != 1 {
		t.Fatalf("lines = %d", lines(t, f))
	}
	if err := f.service.ResultBody(ctx, f.peer, f.job.JobID, good); err != nil {
		t.Fatalf("an exact retry must be acknowledged: %v", err)
	}
	other := body(t, runnerproto.DiscoverResult{OK: true, Findings: []runnerproto.DiscoverFinding{}})
	if err := f.service.ResultBody(ctx, f.peer, f.job.JobID, other); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a different report after a terminal one = %v", err)
	}
	if lines(t, f) != 1 {
		t.Fatalf("a retry changed the lines: %d", lines(t, f))
	}
	var n int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM audit_records WHERE action='carrier.discover' AND result_status='ok'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("result journal records = %d %v", n, err)
	}
}

func TestDiscoverReportUnderForeignKeyIsFailedScanWithNoLines(t *testing.T) {
	f := newDiscoverFixture(t)
	ctx := context.Background()
	if _, err := f.service.Material(ctx, f.peer, f.job.JobID); err != nil {
		t.Fatal(err)
	}
	foreign := body(t, runnerproto.DiscoverResult{OK: true, Findings: []runnerproto.DiscoverFinding{{Path: "/srv/x.env", Name: "A", Fingerprint: "kfp1:other:abcdefghijklmnop", Len: 3}}})
	if err := f.service.ResultBody(ctx, f.peer, f.job.JobID, foreign); err != nil {
		t.Fatal(err)
	}
	var status, class string
	if err := f.pool.QueryRow(ctx, `SELECT status,result->>'error_class' FROM discovery_jobs WHERE org_id=$1`, f.peer.OrgID).Scan(&status, &class); err != nil || status != "failed" || class != "discovery_failed" {
		t.Fatalf("job after a broken report: %q %q %v", status, class, err)
	}
	if lines(t, f) != 0 {
		t.Fatal("a broken report left lines")
	}
}

func TestDiscoverFailureIsOneClassWithNoLines(t *testing.T) {
	f := newDiscoverFixture(t)
	failed := body(t, runnerproto.DiscoverResult{ErrorClass: runnerproto.ErrClassDiscoveryFailed, Findings: []runnerproto.DiscoverFinding{}})
	if err := f.service.ResultBody(context.Background(), f.peer, f.job.JobID, failed); err != nil {
		t.Fatalf("a failed scan before the key is a valid report: %v", err)
	}
	if lines(t, f) != 0 {
		t.Fatal("failed scan left lines")
	}
}

func TestDiscoverJobOfAnotherRunnerIsInvisible(t *testing.T) {
	f := newDiscoverFixture(t)
	ctx := context.Background()
	enroll := func(org uuid.UUID) mtls.Principal {
		t.Helper()
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal("key")
		}
		id := uuid.New()
		no := false
		if err := registry.NewRepo(f.pool).CreateEnrolled(ctx, org, id, "other-host", "2", time.Now().Add(time.Hour), registry.Enrollment{HPKEPublicKey: key.PublicKey().Bytes(), HostAttrs: &enrolltoken.HostAttrs{UIDShared: &no}}); err != nil {
			t.Fatal("enroll")
		}
		return mtls.Principal{OrgID: org, RunnerID: id, Serial: "2"}
	}
	sameOrg := enroll(f.peer.OrgID)
	otherOrgID := uuid.New()
	if _, err := f.pool.Exec(ctx, `INSERT INTO organizations(id,name) VALUES($1,'other')`, otherOrgID); err != nil {
		t.Fatal("org")
	}
	otherOrg := enroll(otherOrgID)
	// The foreign org's runner presents the job's own org id too: only the
	// stored runner and org, never the caller's claim, may reach the job.
	spoof := otherOrg
	spoof.OrgID = f.peer.OrgID
	failed := body(t, runnerproto.DiscoverResult{ErrorClass: runnerproto.ErrClassDiscoveryFailed, Findings: []runnerproto.DiscoverFinding{}})
	for name, peer := range map[string]mtls.Principal{"same org runner": sameOrg, "other org runner": otherOrg, "runner of another org under this org": spoof} {
		if _, err := f.service.Material(ctx, peer, f.job.JobID); err == nil {
			t.Errorf("%s got the key", name)
		}
		if err := f.service.ResultBody(ctx, peer, f.job.JobID, failed); err == nil {
			t.Errorf("%s reported the scan", name)
		}
	}
	var status string
	var issued bool
	if err := f.pool.QueryRow(ctx, `SELECT status,material_issued_at IS NOT NULL FROM discovery_jobs WHERE org_id=$1`, f.peer.OrgID).Scan(&status, &issued); err != nil || status != "issued" || issued {
		t.Fatalf("a foreign caller changed the job: %q %v %v", status, issued, err)
	}
	if _, err := f.service.Material(ctx, f.peer, f.job.JobID); err != nil {
		t.Fatalf("the job's own runner lost its key: %v", err)
	}
}

func TestDiscoverFailedSealLeavesNoIssuanceMark(t *testing.T) {
	f := newDiscoverFixture(t)
	ctx := context.Background()
	f.issuer.fail = true
	if _, err := f.service.Material(ctx, f.peer, f.job.JobID); err == nil {
		t.Fatal("a failed seal must fail the request")
	}
	good := body(t, runnerproto.DiscoverResult{OK: true, Findings: []runnerproto.DiscoverFinding{{Path: "/srv/x.env", Name: "A", Fingerprint: "kfp1:key:abcdefghijklmnop", Len: 3}}})
	if err := f.service.ResultBody(ctx, f.peer, f.job.JobID, good); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a success without an issued key = %v", err)
	}
	f.issuer.fail = false
	if _, err := f.service.Material(ctx, f.peer, f.job.JobID); err != nil {
		t.Fatalf("the key is still issuable after a failed seal: %v", err)
	}
}

// The report cap must admit the largest report the contract allows: 4096
// findings with the longest path and name, in characters json.Marshal expands
// to six bytes. A cap below it refuses a valid report on the HTTP route.
func TestMaxDiscoverBodyAdmitsLargestValidReport(t *testing.T) {
	r := runnerproto.DiscoverResult{OK: true, Findings: make([]runnerproto.DiscoverFinding, 0, runnerproto.MaxDiscoverFindings)}
	for i := 0; i < runnerproto.MaxDiscoverFindings; i++ {
		p := fmt.Sprintf("/%04d/", i) + strings.Repeat("&", 1012) + "/.e"
		r.Findings = append(r.Findings, runnerproto.DiscoverFinding{Path: p, Name: strings.Repeat("A", 128), Fingerprint: "kfp1:store1:aaaaaaaaaaaaaaaa", Len: 1 << 20})
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("worst-case report is not valid, test is void: %v", err)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) <= 1<<20 {
		t.Fatalf("worst-case report is %d bytes: not larger than the old 1 MiB cap, test is void", len(b))
	}
	if len(b) > MaxDiscoverBody {
		t.Fatalf("a valid report of %d bytes exceeds MaxDiscoverBody %d", len(b), MaxDiscoverBody)
	}
}
