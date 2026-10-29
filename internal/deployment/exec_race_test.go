package deployment

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// templateReadTracer parks the connection right after the registered-template
// SELECT so a test can interleave a template replacement with Decide.
type templateReadTracer struct {
	armed           atomic.Bool
	reached, resume chan struct{}
}

type templateReadKey struct{}

func (q *templateReadTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, templateReadKey{}, q.armed.Load() && strings.Contains(d.SQL, "SELECT template FROM exec_templates"))
}

func (q *templateReadTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryEndData) {
	if hit, _ := ctx.Value(templateReadKey{}).(bool); hit {
		close(q.reached)
		<-q.resume
	}
}

// A template replacement that lands between Decide's template read and its job
// insert must not let a job carrying the old snapshot through.
func TestExecTemplateReplacementDuringApprove(t *testing.T) {
	f := newFixture(t)
	boss := f.approver(t)
	f.putTemplate(t, netTemplate("api.github.com"))
	out, err := f.repo.SubmitExec(f.ctx, f.execRequest(t, "gh-issues", map[string]string{"path": "repos/x"}))
	if err != nil {
		t.Fatal("submit failed")
	}
	a, err := f.repo.GetApproval(f.ctx, f.org, out.ApprovalID)
	if err != nil {
		t.Fatal("approval read failed")
	}
	tr := &templateReadTracer{reached: make(chan struct{}), resume: make(chan struct{})}
	cfg := f.pool.Config()
	cfg.ConnConfig.Tracer = tr
	pool, err := pgxpool.NewWithConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal("pool setup failed")
	}
	defer pool.Close()
	f.repo.pool = pool
	tr.armed.Store(true)
	type result struct {
		r DecideResult
		e error
	}
	done := make(chan result, 1)
	go func() {
		r, e := f.repo.Decide(f.ctx, DecideInput{OrgID: f.org, ApprovalID: out.ApprovalID, ApproverID: boss, ApproverIsUser: true, Approve: true, BindingHash: a.BindingHash})
		done <- result{r, e}
	}()
	select {
	case <-tr.reached:
	case <-time.After(5 * time.Second):
		close(tr.resume)
		t.Fatal("template read not reached")
	}
	ctx, cancel := context.WithTimeout(f.ctx, time.Second)
	defer cancel()
	putErr := f.repo.PutExecTemplate(ctx, f.org, netTemplate("api.github.com", "api.changed.invalid"))
	close(tr.resume)
	var got result
	select {
	case got = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("approve did not finish")
	}
	if putErr != nil {
		// Replacement was serialized behind Decide; the approved job is the
		// one the approver saw.
		if got.e != nil || got.r.Status != "approved" || f.jobs(t) != 1 {
			t.Fatalf("approve after blocked replacement: err=%v status=%q jobs=%d", got.e, got.r.Status, f.jobs(t))
		}
		return
	}
	if got.e == nil && got.r.Status == "approved" || f.jobs(t) != 0 {
		t.Fatalf("RACE: replacement committed after template read; status=%q jobs=%d", got.r.Status, f.jobs(t))
	}
}
