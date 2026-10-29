package api

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"net/http"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/rotation"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
)

// journalDump is every column of every journal row of the organization as
// JSON text: what an auditor, and an attacker who reads the table, sees.
func (f *rotateFixture) journalDump() string {
	f.t.Helper()
	var out string
	if err := f.pool.QueryRow(f.ctx, `SELECT coalesce(string_agg(row_to_json(a)::text, E'\n' ORDER BY org_seq), '') FROM audit_records a WHERE org_id=$1`, f.org.ID.String()).Scan(&out); err != nil {
		f.t.Fatalf("read journal: %v", err)
	}
	return out
}

type rotateRecord struct {
	Action, Status, Decision, Version, Fingerprint, ErrClass, ApprovalID, Name, Request string
	Length                                                                              int
}

func (f *rotateFixture) records(action string) []rotateRecord {
	f.t.Helper()
	rows, err := f.pool.Query(f.ctx, `SELECT action,result_status,policy_decision,secret_version,result_fingerprint,result_error_class,approval_id,secret_name,request_id,result_length
		FROM audit_records WHERE org_id=$1 AND action=$2 ORDER BY org_seq`, f.org.ID.String(), action)
	if err != nil {
		f.t.Fatalf("read journal: %v", err)
	}
	defer rows.Close()
	var out []rotateRecord
	for rows.Next() {
		var r rotateRecord
		if err := rows.Scan(&r.Action, &r.Status, &r.Decision, &r.Version, &r.Fingerprint, &r.ErrClass, &r.ApprovalID, &r.Name, &r.Request, &r.Length); err != nil {
			f.t.Fatalf("scan journal: %v", err)
		}
		out = append(out, r)
	}
	return out
}

func journaledService(f *rotateFixture, fakes *engineFakes) *rotation.Service {
	svc := rotation.NewService(rotation.New(f.pool, fakes.deps())).WithJournal(audit.NewJournal(f.pool))
	f.router = NewRouter(obs.New(f.logbuf), f.pool, Deps{Rotations: svc, Catalog: unlimitedCatalog, PublicURL: "https://keep.example"})
	return svc
}

func newJournaledFixture(t *testing.T, fakes *engineFakes) (*rotateFixture, *rotation.Service) {
	f := newRotateFixture(t, nil, nil)
	return f, journaledService(f, fakes)
}

// A rotation leaves a request and an outcome in the journal: names, the new
// version, its fingerprint and length. The text a failing carrier carries (it
// holds the canary) reaches no journal column.
func TestRotateAudit_OutcomeHoldsNamesAndNoValue(t *testing.T) {
	c := canary.New()
	v := c.Value(1)
	if !c.In("x"+v) || !c.In(strings.ToUpper(v)) {
		t.Fatal("canary detector is blind")
	}
	t.Run("done", func(t *testing.T) {
		f, svc := newJournaledFixture(t, &engineFakes{deployErr: map[string]error{}})
		res, _ := f.poll(startRun(t, f))
		svc.Wait()
		recs := f.records("secret.rotate")
		if !res.OK || len(recs) != 2 {
			t.Fatalf("want a request and an outcome, got %d records (%+v)", len(recs), res)
		}
		req, out := recs[0], recs[1]
		if req.Status != "pending" || req.Decision != "allow" || req.Request != res.RequestID || req.Name != "db-password" {
			t.Fatalf("request record: %+v", req)
		}
		if out.Status != "ok" || out.Version != "2" || out.Fingerprint != rotFP || out.Length != 42 || out.ErrClass != "" || out.Name != "db-password" {
			t.Fatalf("outcome record: %+v", out)
		}
		if f.logbuf.Len() == 0 {
			t.Fatal("interception saw no log; the test proves nothing")
		}
	})
	t.Run("failed carrier", func(t *testing.T) {
		f, svc := newJournaledFixture(t, &engineFakes{deployErr: map[string]error{engineCarrier(2): errors.New("deploy of " + v)}})
		res, dump := f.poll(startRun(t, f))
		svc.Wait()
		recs := f.records("secret.rotate")
		if res.OK || len(recs) != 2 {
			t.Fatalf("want a request and an outcome, got %d records (%+v)", len(recs), res)
		}
		out := recs[1]
		if out.Status != "failed" || out.ErrClass != "target_error" || out.Version != "" || out.Fingerprint != "" || out.Length != 0 {
			t.Fatalf("a failed run activates nothing and names a class only: %+v", out)
		}
		if j := f.journalDump(); c.In(j) || c.In(dump) {
			t.Fatalf("canary reached the journal or a response (%d journal bytes inspected)", len(j))
		}
	})
}

// failingJournal refuses every append: the rotation must not begin.
type failingJournal struct{ rotation.Journal }

func (failingJournal) AppendTx(context.Context, pgx.Tx, audit.Record) (audit.Record, error) {
	return audit.Record{}, errors.New("journal down")
}

func TestRotateAudit_NoRecordNoRotation(t *testing.T) {
	for name, journal := range map[string]func(*rotateFixture) rotation.Journal{
		"append fails": func(f *rotateFixture) rotation.Journal { return failingJournal{audit.NewJournal(f.pool)} },
		"no journal":   func(*rotateFixture) rotation.Journal { return nil },
	} {
		t.Run(name, func(t *testing.T) {
			fakes := &engineFakes{deployErr: map[string]error{}}
			f := newRotateFixture(t, nil, nil)
			svc := rotation.NewService(rotation.New(f.pool, fakes.deps()))
			if j := journal(f); j != nil {
				svc = svc.WithJournal(j)
			}
			f.router = NewRouter(obs.New(f.logbuf), f.pool, Deps{Rotations: svc, Catalog: unlimitedCatalog})
			rec := f.do(http.MethodPost, f.path, f.bearer, map[string]any{"mode": "generate"})
			svc.Wait()
			fakes.mu.Lock()
			prepares := fakes.prepares
			fakes.mu.Unlock()
			if rec.Code != http.StatusServiceUnavailable || prepares != 0 {
				t.Fatalf("a rotation without its journal record must not start: %d, prepares=%d", rec.Code, prepares)
			}
			var live int
			if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM rotation_runs WHERE org_id=$1 AND state NOT IN ('done','failed')`, f.org.ID).Scan(&live); err != nil || live != 0 {
				t.Fatalf("the refused run must not stay active: %d %v", live, err)
			}
			// The run row went down with the record: with a journal back, the
			// same secret rotates at once, no stuck pending run in the way.
			svc = svc.WithJournal(audit.NewJournal(f.pool))
			f.router = NewRouter(obs.New(f.logbuf), f.pool, Deps{Rotations: svc, Catalog: unlimitedCatalog})
			if again := f.do(http.MethodPost, f.path, f.bearer, map[string]any{"mode": "generate"}); again.Code != http.StatusAccepted {
				t.Fatalf("a retry after the refused rotation must start, got %d", again.Code)
			}
			svc.Wait()
		})
	}
}

type prodFixture struct {
	*rotateFixture
	svc      *rotation.Service
	fakes    *engineFakes
	approver tenancy.User
	admin    uuid.UUID
}

func newProdFixture(t *testing.T) *prodFixture {
	t.Helper()
	fakes := &engineFakes{deployErr: map[string]error{}}
	f, svc := newJournaledFixture(t, fakes)
	var storeID uuid.UUID
	if err := f.pool.QueryRow(f.ctx, `SELECT id FROM stores WHERE org_id=$1 LIMIT 1`, f.org.ID).Scan(&storeID); err != nil {
		t.Fatalf("find the store: %v", err)
	}
	ref, err := f.cat.CreateRef(f.ctx, catalog.CreateRefInput{Org: f.org.ID, Scope: tenancy.Org(f.org.ID), Name: "prod-db-password", Class: "prod", Type: "generic", ProviderRef: "builtin://default/prod-db-password", StoreID: storeID})
	if err != nil {
		t.Fatalf("create prod ref: %v", err)
	}
	var admin uuid.UUID
	if err := f.pool.QueryRow(f.ctx, `SELECT id FROM users WHERE org_id=$1 AND email=$2`, f.org.ID, "admin@example.test").Scan(&admin); err != nil {
		t.Fatalf("find the requester: %v", err)
	}
	f.path = "/orgs/" + f.org.ID.String() + "/secrets/" + ref.ID.String() + "/rotate"
	return &prodFixture{rotateFixture: f, svc: svc, fakes: fakes, approver: f.mustUser("approver"), admin: admin}
}

func (p *prodFixture) requestApproval() (RotateResult, string) {
	p.t.Helper()
	rec := p.do(http.MethodPost, p.path, p.bearer, map[string]any{"mode": "generate"})
	var got RotateResult
	if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.Approval == nil {
		p.t.Fatalf("a prod rotation answers 202 with its approval: %d %s", rec.Code, rec.Body.String())
	}
	return got, p.dump(rec, rec.Body.String())
}

func (p *prodFixture) decide(id string, approver uuid.UUID, human, approve bool, hash string) (deployment.DecideResult, error) {
	p.t.Helper()
	aid, _ := uuid.Parse(id)
	return p.svc.DecideRotation(p.ctx, deployment.DecideInput{OrgID: p.org.ID, ApprovalID: aid, ApproverID: approver, ApproverIsUser: human, Approve: approve, Reason: "checked", BindingHash: hash})
}

func (p *prodFixture) hashOf(id string) string {
	p.t.Helper()
	aid, _ := uuid.Parse(id)
	a, err := p.svc.GetRotationApproval(p.ctx, p.org.ID, aid)
	if err != nil {
		p.t.Fatalf("read the approval: %v", err)
	}
	return a.BindingHash
}

func (p *prodFixture) runs() int {
	var n int
	if err := p.pool.QueryRow(p.ctx, `SELECT count(*) FROM rotation_runs WHERE org_id=$1`, p.org.ID).Scan(&n); err != nil {
		p.t.Fatalf("count runs: %v", err)
	}
	return n
}

func (p *prodFixture) prepares() int {
	p.fakes.mu.Lock()
	defer p.fakes.mu.Unlock()
	return p.fakes.prepares
}

// A prod secret waits for a human: the answer carries approval{id,status,url},
// no run exists and nothing is laid out until the approval is decided.
func TestRotateApproval_ProdWaitsForAHuman(t *testing.T) {
	p := newProdFixture(t)
	got, _ := p.requestApproval()
	if got.Approval.Status != "requested" || got.Approval.URL != "https://keep.example/console/approvals/"+got.Approval.ID || got.OK {
		t.Fatalf("approval: %+v", got)
	}
	if p.runs() != 0 || p.prepares() != 0 {
		t.Fatalf("no run and no layout before the approval: runs=%d prepares=%d", p.runs(), p.prepares())
	}
	rec := p.do(http.MethodGet, p.path+"/"+got.RequestID, p.bearer, nil)
	var st RotateResult
	if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &st) != nil || st.Approval == nil || st.Approval.Status != "requested" || st.ErrorClass != "" {
		t.Fatalf("status while waiting: %d %s", rec.Code, rec.Body.String())
	}
	if again := p.do(http.MethodPost, p.path, p.bearer, map[string]any{"mode": "generate"}); again.Code != http.StatusConflict {
		t.Fatalf("a second request while one waits: %d", again.Code)
	}
	recs := p.records("secret.rotate")
	if len(recs) != 1 || recs[0].Status != "pending" || recs[0].Decision != "approval_required" || recs[0].ApprovalID != got.Approval.ID || recs[0].Request != got.RequestID {
		t.Fatalf("request record: %+v", recs)
	}
	if n := len(p.records("approval.requested")); n != 1 {
		t.Fatalf("approval.requested records: %d", n)
	}
}

// human_input ends in a new version of the secret, so it must not be a way
// around the approval of a prod rotation: it is refused, nothing is issued.
func TestRotateApproval_HumanInputOnProdIsRefused(t *testing.T) {
	p := newProdFixture(t)
	rec := p.do(http.MethodPost, p.path, p.bearer, map[string]any{"mode": "human_input"})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "permission_denied") {
		t.Fatalf("human_input on a prod secret: %d %s", rec.Code, rec.Body.String())
	}
	if p.runs() != 0 || len(p.records("secret.rotate")) != 0 {
		t.Fatalf("a refused request leaves no run: runs=%d", p.runs())
	}
}

func TestRotateApproval_ApprovingStartsTheRunOfTheRequestID(t *testing.T) {
	p := newProdFixture(t)
	got, _ := p.requestApproval()
	hash := p.hashOf(got.Approval.ID)
	// The refusals first: each must create nothing.
	if _, err := p.decide(got.Approval.ID, p.admin, true, true, hash); !errors.Is(err, deployment.ErrSelfApproval) {
		t.Fatalf("self approval: %v", err)
	}
	if _, err := p.decide(got.Approval.ID, p.approver.ID, false, true, hash); !errors.Is(err, deployment.ErrNotHuman) {
		t.Fatalf("agent approval: %v", err)
	}
	if _, err := p.decide(got.Approval.ID, p.approver.ID, true, true, strings.Repeat("0", 64)); !errors.Is(err, deployment.ErrBindingMismatch) {
		t.Fatalf("a hash the approver did not see: %v", err)
	}
	if _, err := p.decide(uuid.NewString(), p.approver.ID, true, true, hash); !errors.Is(err, deployment.ErrNotFound) {
		t.Fatalf("an unknown approval: %v", err)
	}
	if p.runs() != 0 || p.prepares() != 0 {
		t.Fatalf("a refused decision created something: runs=%d prepares=%d", p.runs(), p.prepares())
	}
	if res, err := p.decide(got.Approval.ID, p.approver.ID, true, true, hash); err != nil || res.Status != "approved" {
		t.Fatalf("approve: %+v %v", res, err)
	}
	res, _ := p.poll(got.RequestID)
	p.svc.Wait()
	if !res.OK || res.Version != "2" || res.Approval == nil || res.Approval.Status != "approved" {
		t.Fatalf("the approved run: %+v", res)
	}
	if _, err := p.decide(got.Approval.ID, p.approver.ID, true, true, hash); !errors.Is(err, deployment.ErrAlreadyDecided) {
		t.Fatalf("a second decision: %v", err)
	}
	if p.runs() != 1 {
		t.Fatalf("one approval, one run: %d", p.runs())
	}
	recs := p.records("secret.rotate")
	if len(recs) != 2 || recs[1].Status != "ok" || recs[1].Fingerprint != rotFP || recs[1].Length != 42 || recs[1].ApprovalID != got.Approval.ID || recs[1].Request != got.RequestID {
		t.Fatalf("the outcome record names the approval: %+v", recs)
	}
	if n := len(p.records("approval.decided")); n != 1 {
		t.Fatalf("approval.decided records: %d", n)
	}
}

func TestRotateApproval_RejectionStartsNothingAndReportsDenied(t *testing.T) {
	p := newProdFixture(t)
	got, _ := p.requestApproval()
	if res, err := p.decide(got.Approval.ID, p.approver.ID, true, false, p.hashOf(got.Approval.ID)); err != nil || res.Status != "rejected" {
		t.Fatalf("reject: %+v %v", res, err)
	}
	res, dump := p.poll(got.RequestID)
	if res.OK || res.ErrorClass != "permission_denied" || res.Version != "" || res.Fingerprint != "" || res.Approval == nil || res.Approval.Status != "rejected" {
		t.Fatalf("a rejected rotation: %+v", res)
	}
	if p.runs() != 0 || p.prepares() != 0 {
		t.Fatalf("a rejected rotation started: runs=%d prepares=%d", p.runs(), p.prepares())
	}
	if strings.Contains(dump, "checked") {
		t.Fatal("the approver's reason is not part of the answer")
	}
	// A later rotation is possible: the rejected approval no longer holds the secret.
	p.requestApproval()
}

func TestRotateApproval_ExpiredApprovalCannotBeDecided(t *testing.T) {
	p := newProdFixture(t)
	got, _ := p.requestApproval()
	if _, err := p.pool.Exec(p.ctx, `ALTER TABLE approval_requests DISABLE TRIGGER approval_requests_frozen`); err != nil {
		t.Fatalf("disable the trigger for the clock: %v", err)
	}
	if _, err := p.pool.Exec(p.ctx, `UPDATE approval_requests SET expires_at=now()-interval '1 minute' WHERE id=$1`, got.Approval.ID); err != nil {
		t.Fatalf("age the approval: %v", err)
	}
	if _, err := p.pool.Exec(p.ctx, `ALTER TABLE approval_requests ENABLE TRIGGER approval_requests_frozen`); err != nil {
		t.Fatalf("restore the trigger: %v", err)
	}
	if _, err := p.decide(got.Approval.ID, p.approver.ID, true, true, p.hashOf(got.Approval.ID)); !errors.Is(err, deployment.ErrExpired) {
		t.Fatalf("an expired approval: %v", err)
	}
	res, _ := p.poll(got.RequestID)
	if res.ErrorClass != "permission_denied" || res.Approval.Status != "expired" || p.runs() != 0 {
		t.Fatalf("expired: %+v runs=%d", res, p.runs())
	}
}

// The console reads and decides both kinds of approval through one service.
func TestRotateApproval_ConsoleServiceRoutesRotationApprovals(t *testing.T) {
	p := newProdFixture(t)
	got, _ := p.requestApproval()
	if _, ok := withRotationApprovals(nil, struct{}{}).(mergedApprovals); ok {
		t.Fatal("a service with no rotation approvals changed the console")
	}
	m, ok := withRotationApprovals(nil, p.svc).(mergedApprovals)
	if !ok {
		t.Fatal("the console is not given the rotation approvals")
	}
	aid, _ := uuid.Parse(got.Approval.ID)
	a, err := m.GetApproval(p.ctx, p.org.ID, aid)
	if err != nil || !a.Rotate || a.SecretName != "prod-db-password" || a.SecretClass != "prod" || a.RequestID != got.RequestID || a.Status != "requested" {
		t.Fatalf("card: %+v %v", a, err)
	}
	list, err := m.ListApprovals(p.ctx, p.org.ID, 50)
	if err != nil || len(list) != 1 || list[0].ID != aid {
		t.Fatalf("list: %+v %v", list, err)
	}
	if _, err := m.GetApproval(p.ctx, p.org.ID, uuid.New()); !errors.Is(err, deployment.ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	if _, err := m.Decide(p.ctx, deployment.DecideInput{OrgID: p.org.ID, ApprovalID: aid, ApproverID: p.approver.ID, ApproverIsUser: true, Approve: true, Reason: "ok", BindingHash: a.BindingHash}); err != nil {
		t.Fatalf("decide through the console service: %v", err)
	}
	p.svc.Wait()
	// Another organization sees none of it.
	if _, err := m.GetApproval(p.ctx, uuid.New(), aid); !errors.Is(err, deployment.ErrNotFound) {
		t.Fatalf("another organization: %v", err)
	}
}

// The approval of a rotation never carries a value: the journal and every
// answer of the whole approval flow are clean of the canary a failing carrier holds.
func TestRotateApproval_FlowLeaksNothing(t *testing.T) {
	c := canary.New()
	p := newProdFixture(t)
	p.fakes.deployErr[engineCarrier(1)] = errors.New("deploy of " + c.Value(1))
	got, d1 := p.requestApproval()
	if _, err := p.decide(got.Approval.ID, p.approver.ID, true, true, p.hashOf(got.Approval.ID)); err != nil {
		t.Fatalf("approve: %v", err)
	}
	res, d2 := p.poll(got.RequestID)
	p.svc.Wait()
	if res.OK || res.ErrorClass != "deploy_failed" {
		t.Fatalf("the run must fail on the carrier: %+v", res)
	}
	if p.logbuf.Len() == 0 {
		t.Fatal("interception saw no log; the test proves nothing")
	}
	var all strings.Builder
	all.WriteString(d1 + d2 + p.journalDump())
	for _, tbl := range []string{"approval_requests", "rotation_runs", "rotation_steps"} {
		var rows string
		if err := p.pool.QueryRow(p.ctx, `SELECT coalesce(string_agg(row_to_json(t)::text, E'\n'), '') FROM `+tbl+` t`).Scan(&rows); err != nil {
			t.Fatalf("read %s: %v", tbl, err)
		}
		all.WriteString(rows)
	}
	if c.In(all.String()) {
		t.Fatalf("canary reached a response, the log, the journal or a table (%d bytes inspected)", all.Len())
	}
}
