package builtin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/entire-vc/evc-keep/internal/api"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/intake"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type intakeFixture struct {
	svc      *intake.Service
	provider *Provider
	ref      tenancy.SecretRef
	store    catalog.Store
	actor    audit.Actor
	ctx      context.Context
}

func newIntakeFixture(t *testing.T) *intakeFixture {
	t.Helper()
	pool := testPool(t)
	ctx := context.Background()
	org, err := tenancy.New(pool).CreateOrganization(ctx, t.Name(), "")
	if err != nil {
		t.Fatal("organization")
	}
	cat := catalog.New(pool)
	st, err := cat.CreateStore(ctx, org.ID, "builtin", "test-store", tenancy.Org(org.ID))
	if err != nil {
		t.Fatal("store")
	}
	if _, err = cat.CreateStoreBinding(ctx, org.ID, tenancy.Org(org.ID), st.ID); err != nil {
		t.Fatal("binding")
	}
	ref, err := cat.CreateRef(ctx, catalog.CreateRefInput{Org: org.ID, Scope: tenancy.Org(org.ID), Name: "test-secret", Class: "dev", Type: "generic", ProviderRef: "builtin://test-store/test-secret"})
	if err != nil {
		t.Fatal("reference")
	}
	seal, _ := testSealer(t, pool)
	p := New(pool, seal, sealer.Scope{Org: org.ID.String()}, nil)
	svc := intake.New(pool, func(catalog.Store) (intake.Receiver, error) { return p, nil }, audit.NewJournal(pool), "https://keep.example.invalid")
	return &intakeFixture{svc: svc, provider: p, ref: ref, store: st, actor: audit.Actor{Type: audit.ActorUser, ID: uuid.NewString(), Via: audit.ViaAPI}, ctx: ctx}
}
func (f *intakeFixture) issue(t *testing.T) (intake.Issued, string, intake.View) {
	t.Helper()
	link, err := f.svc.Issue(f.ctx, f.ref, f.store, f.actor, 0)
	if err != nil {
		t.Fatal("issue")
	}
	u, err := url.Parse(link.URL)
	if err != nil {
		t.Fatal("URL")
	}
	token := strings.TrimPrefix(u.Path, "/input/")
	view, err := f.svc.Read(f.ctx, token)
	if err != nil {
		t.Fatal("read")
	}
	return link, token, view
}

type rejectedIntakeJournal struct{}

func (rejectedIntakeJournal) AppendTx(context.Context, pgx.Tx, audit.Record) (audit.Record, error) {
	return audit.Record{}, errors.New("test audit failure")
}

func TestIntakeServiceCanaryAndBinding(t *testing.T) {
	f := newIntakeFixture(t)
	probe := canary.New()
	plain := []byte(probe.Value(1))
	defer clear(plain)
	if !probe.In(string(plain)) {
		t.Fatal("canary control")
	}
	link, token, view := f.issue(t)
	_, tokenB, _ := f.issue(t)
	enc, ct := intakeTestCiphertext(t, view.PublicKey, link.RequestID, plain)
	env := intake.Envelope{Enc: enc, Ciphertext: ct}
	body, err := json.Marshal(env)
	if err != nil {
		t.Fatal("ciphertext encoding")
	}
	var logs bytes.Buffer
	f.provider.log = obs.New(&logs)
	h := api.NewRouter(obs.New(&logs), f.provider.db.pool, api.Deps{Input: f.svc})
	post := func(tok string, want int) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/input/"+tok, bytes.NewReader(body)))
		if w.Code != want {
			t.Fatalf("completion status %d, want %d", w.Code, want)
		}
		if probe.In(w.Body.String()) || probe.In(w.Header().Get("Location")) || probe.In(logs.String()) {
			t.Fatal("input canary escaped to HTTP or log")
		}
		for _, vs := range w.Header() {
			for _, v := range vs {
				if probe.In(v) {
					t.Fatal("input canary escaped to header")
				}
			}
		}
		return w
	}
	post(tokenB, http.StatusBadRequest)
	w := post(token, http.StatusOK)
	var result intake.Result
	if json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Version == "" || result.Fingerprint == "" {
		t.Fatal("completion metadata")
	}
	value, meta, err := f.provider.Resolve(f.ctx, provider.Ref{Path: f.ref.ProviderRef})
	if err != nil {
		t.Fatal("resolve sealed input")
	}
	defer value.Wipe()
	fk, err := f.provider.FingerprintKey(f.ctx)
	if err != nil {
		t.Fatal("fingerprint key")
	}
	defer fk.Wipe()
	expected, err := fingerprint.Compute(fk, value)
	if err != nil || expected != result.Fingerprint {
		t.Fatal("completion fingerprint differs from sealed input")
	}
	control := secret.New(plain)
	defer control.Wipe()
	if !value.Equal(control) || meta.Version != result.Version {
		t.Fatal("resolved input mismatch")
	}
	post(token, http.StatusGone)
	for _, table := range []string{"intake_links", "secret_versions", "secrets", "audit_records"} {
		rows, err := f.provider.db.pool.Query(f.ctx, "SELECT row_to_json(x)::text FROM "+table+" x WHERE org_id::text=$1", f.ref.OrgID.String())
		if err != nil {
			t.Fatal("read outside-zone persistence")
		}
		for rows.Next() {
			var row string
			if rows.Scan(&row) != nil {
				t.Fatal("scan persistence")
			}
			if probe.In(row) {
				t.Fatal("canary persisted outside plaintext zone")
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			t.Fatal("persistence rows")
		}
	}
	if logs.Len() == 0 {
		t.Fatal("log capture not exercised")
	}
	verified, err := audit.Verify(f.ctx, f.provider.db.pool, f.ref.OrgID.String())
	if err != nil || !verified.OK {
		t.Fatal("intake audit chain")
	}
}

func TestIntakeServiceAtomicRaceAndRollback(t *testing.T) {
	f := newIntakeFixture(t)
	link, token, view := f.issue(t)
	enc, ct := intakeTestCiphertext(t, view.PublicKey, link.RequestID, []byte("synthetic input"))
	env := intake.Envelope{Enc: enc, Ciphertext: ct}
	broken := intake.New(f.provider.db.pool, func(catalog.Store) (intake.Receiver, error) { return f.provider, nil }, rejectedIntakeJournal{}, "https://keep.example.invalid")
	if _, err := broken.Complete(f.ctx, token, env); !errors.Is(err, intake.ErrUnavailable) {
		t.Fatal("audit failure accepted")
	}
	var count int
	if f.provider.db.pool.QueryRow(f.ctx, `SELECT count(*) FROM keep_envelope WHERE store_org=$1 AND secret_id=$2`, f.ref.OrgID.String(), f.ref.ProviderRef).Scan(&count) != nil || count != 0 {
		t.Fatal("audit failure committed sealed version")
	}
	var wg sync.WaitGroup
	var successes atomic.Int64
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.svc.Complete(f.ctx, token, env)
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, intake.ErrGone) {
				t.Error("unexpected race refusal")
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatal("multiple ciphertext deliveries committed")
	}
	if f.provider.db.pool.QueryRow(f.ctx, `SELECT count(*) FROM keep_envelope WHERE store_org=$1 AND secret_id=$2`, f.ref.OrgID.String(), f.ref.ProviderRef).Scan(&count) != nil || count != 1 {
		t.Fatal("race committed wrong sealed version count")
	}
}

func TestIntakeServicePathBinding(t *testing.T) {
	f := newIntakeFixture(t)
	link, token, view := f.issue(t)
	if _, err := f.provider.db.pool.Exec(f.ctx, `UPDATE secrets SET provider_ref='builtin://test-store/other' WHERE org_id=$1 AND id=$2`, f.ref.OrgID, f.ref.ID); err != nil {
		t.Fatal("alter reference")
	}
	enc, ct := intakeTestCiphertext(t, view.PublicKey, link.RequestID, []byte("synthetic input"))
	if _, err := f.svc.Complete(f.ctx, token, intake.Envelope{Enc: enc, Ciphertext: ct}); !errors.Is(err, intake.ErrGone) {
		t.Fatal("link followed altered provider path")
	}
}

func TestIntakeServiceAvailabilityChanges(t *testing.T) {
	for _, change := range []string{"disabled-secret", "moved-secret", "disabled-store"} {
		t.Run(change, func(t *testing.T) {
			f := newIntakeFixture(t)
			link, token, view := f.issue(t)
			enc, ct := intakeTestCiphertext(t, view.PublicKey, link.RequestID, []byte("synthetic input"))
			pool := f.provider.db.pool
			switch change {
			case "disabled-secret":
				if _, err := pool.Exec(f.ctx, `UPDATE secrets SET status='disabled' WHERE org_id=$1 AND id=$2`, f.ref.OrgID, f.ref.ID); err != nil {
					t.Fatal("disable secret")
				}
			case "disabled-store":
				if _, err := pool.Exec(f.ctx, `UPDATE stores SET status='disabled' WHERE org_id=$1 AND id=$2`, f.store.OrgID, f.store.ID); err != nil {
					t.Fatal("disable store")
				}
			case "moved-secret":
				ws, err := tenancy.New(pool).CreateWorkspace(f.ctx, f.ref.OrgID, "other")
				if err != nil {
					t.Fatal("workspace")
				}
				st, err := catalog.New(pool).CreateStore(f.ctx, f.ref.OrgID, "builtin", "other", tenancy.Scope{Level: tenancy.LevelWorkspace, ID: ws.ID})
				if err != nil {
					t.Fatal("other store")
				}
				if _, err := pool.Exec(f.ctx, `UPDATE secrets SET store_id=$1 WHERE org_id=$2 AND id=$3`, st.ID, f.ref.OrgID, f.ref.ID); err != nil {
					t.Fatal("move secret")
				}
			}
			if _, err := f.svc.Read(f.ctx, token); !errors.Is(err, intake.ErrGone) {
				t.Fatal("changed resource left link readable")
			}
			if _, err := f.svc.Complete(f.ctx, token, intake.Envelope{Enc: enc, Ciphertext: ct}); !errors.Is(err, intake.ErrGone) {
				t.Fatal("changed resource accepted input")
			}
			var n int
			for _, query := range []string{`SELECT count(*) FROM secret_versions WHERE org_id=$1 AND secret_id=$2`, `SELECT count(*) FROM audit_records WHERE org_id=$1 AND secret_id=$2::text AND action='intake.completed'`} {
				if pool.QueryRow(f.ctx, query, f.ref.OrgID, f.ref.ID).Scan(&n) != nil || n != 0 {
					t.Fatal("changed resource committed metadata")
				}
			}
			if pool.QueryRow(f.ctx, `SELECT count(*) FROM keep_envelope WHERE store_org=$1 AND secret_id=$2`, f.ref.OrgID.String(), f.ref.ProviderRef).Scan(&n) != nil || n != 0 {
				t.Fatal("changed resource committed sealed input")
			}
		})
	}
}
