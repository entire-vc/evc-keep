package intake

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/intake/descriptor"
	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type receiver struct{ calls atomic.Int64 }

func (r *receiver) IntakeDescriptor(_ context.Context, request string, metadata descriptor.Metadata) ([]byte, []byte, []byte, error) {
	signing, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(private)
	public := make([]byte, 32)
	return public, signing, ed25519.Sign(private, descriptor.Message(request, public, metadata)), nil
}
func (r *receiver) AcceptIntake(context.Context, pgx.Tx, string, string, []byte, []byte) (string, string, int, error) {
	r.calls.Add(1)
	return "1", "kfp1:test:abcdefghijklmnop", 20, nil
}

type failingJournal struct{}

func (failingJournal) AppendTx(context.Context, pgx.Tx, audit.Record) (audit.Record, error) {
	return audit.Record{}, errors.New("audit unavailable")
}

type fixture struct {
	ctx      context.Context
	pool     *pgxpool.Pool
	svc      *Service
	receiver *receiver
	ref      tenancy.SecretRef
	store    catalog.Store
	actor    audit.Actor
}

func setup(t *testing.T) *fixture {
	t.Helper()
	dsn := os.Getenv("KEEP_DATABASE_URL")
	if dsn == "" {
		t.Skip("KEEP_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("pool")
	}
	t.Cleanup(pool.Close)
	rp := tenancy.New(pool)
	org, err := rp.CreateOrganization(ctx, t.Name(), "")
	if err != nil {
		t.Fatal("organization")
	}
	cat := catalog.New(pool)
	st, err := cat.CreateStore(ctx, org.ID, "builtin", "sample-store", tenancy.Org(org.ID))
	if err != nil {
		t.Fatal("store")
	}
	if _, err = cat.CreateStoreBinding(ctx, org.ID, tenancy.Org(org.ID), st.ID); err != nil {
		t.Fatal("binding")
	}
	ref, err := cat.CreateRef(ctx, catalog.CreateRefInput{Org: org.ID, Scope: tenancy.Org(org.ID), Name: "sample", Class: "dev", Type: "generic", ProviderRef: "builtin://sample-store/sample"})
	if err != nil {
		t.Fatal("secret ref")
	}
	r := &receiver{}
	actor := audit.Actor{Type: audit.ActorUser, ID: uuid.NewString(), Via: audit.ViaAPI}
	return &fixture{ctx: ctx, pool: pool, svc: New(pool, func(catalog.Store) (Receiver, error) { return r, nil }, audit.NewJournal(pool), "https://keep.example.invalid"), receiver: r, ref: ref, store: st, actor: actor}
}
func (f *fixture) issue(t *testing.T) (Issued, string) {
	t.Helper()
	link, err := f.svc.Issue(f.ctx, f.ref, f.store, f.actor, 0)
	if err != nil {
		t.Fatal("issue input link")
	}
	u, err := url.Parse(link.URL)
	if err != nil {
		t.Fatal("link URL")
	}
	return link, strings.TrimPrefix(u.Path, "/input/")
}
func ciphertext(t *testing.T) Envelope {
	t.Helper()
	e := Envelope{Enc: make([]byte, 32), Ciphertext: make([]byte, 64)}
	if _, err := rand.Read(e.Enc); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(e.Ciphertext); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestSingleUseAndHashOnly(t *testing.T) {
	f := setup(t)
	link, token := f.issue(t)
	u, err := url.Parse(link.URL)
	if err != nil {
		t.Fatal("parse issued URL")
	}
	pins, err := url.ParseQuery(u.Fragment)
	if err != nil || len(pins["request"]) != 1 || pins.Get("request") != link.RequestID || len(pins["signing"]) != 1 {
		t.Fatal("issued link did not pin request and signer exactly once")
	}
	if len(token) < 22 || time.Until(link.ExpiresAt) < 29*time.Minute || time.Until(link.ExpiresAt) > 31*time.Minute {
		t.Fatal("token entropy or default TTL")
	}
	var persisted string
	if err := f.pool.QueryRow(f.ctx, `SELECT row_to_json(x)::text FROM intake_links x WHERE request_id=$1`, link.RequestID).Scan(&persisted); err != nil {
		t.Fatal("read persistence")
	}
	if strings.Contains(persisted, token) {
		t.Fatal("raw link token persisted")
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatal("token encoding")
	}
	defer clear(raw)
	wantHash := sha256.Sum256(raw)
	var saved []byte
	if f.pool.QueryRow(f.ctx, `SELECT token_hash FROM intake_links WHERE request_id=$1`, link.RequestID).Scan(&saved) != nil || !bytes.Equal(saved, wantHash[:]) {
		t.Fatal("token persisted without hashing")
	}
	if _, err := f.svc.Read(f.ctx, token); err != nil {
		t.Fatal("active link not readable")
	}
	const n = 8
	var wg sync.WaitGroup
	var successes atomic.Int64
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.svc.Complete(f.ctx, token, Envelope{Enc: make([]byte, 32), Ciphertext: make([]byte, 32)})
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, ErrGone) {
				t.Error("unexpected completion failure")
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 || f.receiver.calls.Load() != 1 {
		t.Fatal("one link admitted multiple completions")
	}
	if _, err := f.svc.Read(f.ctx, token); !errors.Is(err, ErrGone) {
		t.Fatal("consumed link did not expire")
	}
	result, err := f.svc.Status(f.ctx, f.ref.OrgID, uuid.MustParse(f.actor.ID), uuid.MustParse(link.RequestID))
	if err != nil || result.Version != "1" {
		t.Fatal("completion status")
	}
	var nrecords int
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM audit_records WHERE org_id=$1 AND action IN ('intake.link_issued','intake.completed')`, f.ref.OrgID.String()).Scan(&nrecords); err != nil || nrecords != 2 {
		t.Fatal("missing intake audit trail")
	}
}

func TestServicePersistsDescriptorSnapshot(t *testing.T) {
	f := setup(t)
	link, token := f.issue(t)
	view, err := f.svc.Read(f.ctx, token)
	if err != nil {
		t.Fatal("honest descriptor rejected")
	}
	var name, scope, storeName, class string
	err = f.pool.QueryRow(f.ctx, `SELECT COALESCE(to_jsonb(l)->>'secret_name',''),COALESCE(to_jsonb(l)->>'scope',''),COALESCE(to_jsonb(l)->>'store_name',''),COALESCE(to_jsonb(l)->>'class','') FROM intake_links l WHERE request_id=$1`, link.RequestID).Scan(&name, &scope, &storeName, &class)
	if err != nil {
		t.Fatal("read descriptor snapshot")
	}
	if name != view.SecretName || scope != view.Scope || storeName != view.StoreName || class != view.Class {
		t.Fatal("issued descriptor metadata was not persisted as one snapshot")
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE intake_links SET secret_name='different' WHERE request_id=$1`, link.RequestID); err != nil {
		t.Fatal("mutate saved descriptor snapshot")
	}
	if _, err = f.svc.Read(f.ctx, token); !errors.Is(err, ErrGone) {
		t.Fatal("changed saved snapshot remained readable")
	}
}

func TestDescriptorSnapshotMigrationPreservesHistory(t *testing.T) {
	dsn := pgscratch.New(t, nil)
	db, err := store.OpenMigrationDB(pgscratch.Context(t), dsn)
	if err != nil {
		t.Fatal("open snapshot migration database")
	}
	defer func() { _ = db.Close() }()
	migrations, err := store.NewProvider(db)
	if err != nil {
		t.Fatal("create snapshot migration provider")
	}
	if _, err := migrations.Up(pgscratch.Context(t)); err != nil {
		t.Fatal("migrate snapshot up")
	}
	t.Setenv("KEEP_DATABASE_URL", dsn)
	f := setup(t)
	link, token := f.issue(t)
	var hash []byte
	if err := f.pool.QueryRow(f.ctx, `SELECT token_hash FROM intake_links WHERE request_id=$1`, link.RequestID).Scan(&hash); err != nil {
		t.Fatal("read rollback anchor")
	}
	if _, err := migrations.DownTo(pgscratch.Context(t), 13); err != nil {
		t.Fatal("downgrade descriptor snapshot")
	}
	var version int64
	if err := f.pool.QueryRow(f.ctx, `SELECT max(version_id) FROM goose_db_version WHERE is_applied`).Scan(&version); err != nil || version != 13 {
		t.Fatal("snapshot downgrade changed a preceding migration")
	}
	var preserved []byte
	if err := f.pool.QueryRow(f.ctx, `SELECT token_hash FROM intake_links WHERE request_id=$1`, link.RequestID).Scan(&preserved); err != nil || !bytes.Equal(hash, preserved) {
		t.Fatal("snapshot downgrade lost request history")
	}
	var count int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM audit_records WHERE request_id=$1`, link.RequestID).Scan(&count); err != nil || count != 1 {
		t.Fatal("snapshot downgrade lost journal history")
	}
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM information_schema.columns WHERE table_name='intake_links' AND column_name IN ('secret_name','scope','store_name','class')`).Scan(&count); err != nil || count != 0 {
		t.Fatal("snapshot downgrade left metadata columns")
	}
	if _, err := migrations.Up(pgscratch.Context(t)); err != nil {
		t.Fatal("upgrade descriptor snapshot again")
	}
	if _, err := f.svc.Read(f.ctx, token); !errors.Is(err, ErrGone) {
		t.Fatal("upgraded historical link without snapshot remained usable")
	}
	f.issue(t)
}

func TestServiceRejectsLinksWithoutSnapshot(t *testing.T) {
	f := setup(t)
	link, token := f.issue(t)
	if _, err := f.svc.Read(f.ctx, token); err != nil {
		t.Fatal("honest descriptor rejected")
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE intake_links SET secret_name=NULL,scope=NULL,store_name=NULL,class=NULL WHERE request_id=$1`, link.RequestID); err != nil {
		t.Fatal("clear legacy snapshot")
	}
	if _, err := f.svc.Read(f.ctx, token); !errors.Is(err, ErrGone) {
		t.Fatal("legacy snapshot did not return gone")
	}
	if _, err := f.svc.Complete(f.ctx, token, ciphertext(t)); !errors.Is(err, ErrGone) {
		t.Fatal("legacy snapshot reached completion")
	}
	if f.receiver.calls.Load() != 0 {
		t.Fatal("legacy snapshot reached receiver")
	}
}

func TestServiceRejectsDescriptorTampering(t *testing.T) {
	for _, name := range []string{"name", "scope", "store", "class", "requester", "sponsor", "legacy-v1"} {
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			link, token := f.issue(t)
			view, err := f.svc.Read(f.ctx, token)
			if err != nil {
				t.Fatal("honest descriptor rejected")
			}
			switch name {
			case "name":
				_, err = f.pool.Exec(f.ctx, `UPDATE secrets SET name='different' WHERE id=$1`, f.ref.ID)
			case "scope":
				ws, e := tenancy.New(f.pool).CreateWorkspace(f.ctx, f.ref.OrgID, "different")
				if e != nil {
					t.Fatal("create alternate scope")
				}
				_, err = f.pool.Exec(f.ctx, `UPDATE secrets SET scope_level='ws',scope_id=$2 WHERE id=$1`, f.ref.ID, ws.ID)
			case "store":
				_, err = f.pool.Exec(f.ctx, `UPDATE stores SET name='different' WHERE id=$1`, f.store.ID)
			case "class":
				_, err = f.pool.Exec(f.ctx, `UPDATE secrets SET class='prod' WHERE id=$1`, f.ref.ID)
			case "requester":
				_, err = f.pool.Exec(f.ctx, `UPDATE intake_links SET actor_id=$2 WHERE request_id=$1`, link.RequestID, uuid.NewString())
			case "sponsor":
				_, err = f.pool.Exec(f.ctx, `UPDATE intake_links SET sponsor_id=$2 WHERE request_id=$1`, link.RequestID, uuid.NewString())
			case "legacy-v1":
				key, private, e := ed25519.GenerateKey(nil)
				if e != nil {
					t.Fatal("generate fixture signer")
				}
				sig := ed25519.Sign(private, []byte("keep/intake-key/v1\x00"+view.RequestID+"\x00"+base64.StdEncoding.EncodeToString(view.PublicKey)))
				clear(private)
				_, err = f.pool.Exec(f.ctx, `UPDATE intake_links SET signing_key=$2,signature=$3 WHERE request_id=$1`, link.RequestID, key, sig)
			}
			if err != nil {
				t.Fatal("mutate descriptor fixture")
			}
			if _, err = f.svc.Read(f.ctx, token); !errors.Is(err, ErrGone) {
				t.Fatal("tampered descriptor readable")
			}
			if _, err = f.svc.Complete(f.ctx, token, ciphertext(t)); !errors.Is(err, ErrGone) {
				t.Fatal("tampered descriptor completed")
			}
			if f.receiver.calls.Load() != 0 {
				t.Fatal("tampered descriptor reached receiver")
			}
		})
	}
}
func TestSweepAndIssuerIsolation(t *testing.T) {
	f := setup(t)
	link, token := f.issue(t)
	if _, err := f.svc.Status(f.ctx, uuid.New(), uuid.MustParse(f.actor.ID), uuid.MustParse(link.RequestID)); !errors.Is(err, ErrGone) {
		t.Fatal("foreign organization read status")
	}
	if _, err := f.svc.Status(f.ctx, f.ref.OrgID, uuid.New(), uuid.MustParse(link.RequestID)); !errors.Is(err, ErrGone) {
		t.Fatal("foreign issuer read status")
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE intake_links SET expires_at=clock_timestamp()-interval '1 second' WHERE request_id=$1`, link.RequestID); err != nil {
		t.Fatal("expire fixture")
	}
	for range 2 {
		if f.svc.Expire(f.ctx) != nil {
			t.Fatal("expiration sweep")
		}
	}
	if _, err := f.svc.Read(f.ctx, token); !errors.Is(err, ErrGone) {
		t.Fatal("swept link accepted")
	}
	var n int
	if f.pool.QueryRow(f.ctx, `SELECT count(*) FROM audit_records WHERE request_id=$1 AND action='intake.expired'`, link.RequestID).Scan(&n) != nil || n != 1 {
		t.Fatal("sweep journal count")
	}
}

func TestExpireInvalidDescriptor(t *testing.T) {
	f := setup(t)
	link, _ := f.issue(t)
	if _, err := f.pool.Exec(f.ctx, `UPDATE intake_links SET signature=$2,expires_at=clock_timestamp()-interval '1 second' WHERE request_id=$1`, link.RequestID, make([]byte, ed25519.SignatureSize)); err != nil {
		t.Fatal("expire invalid descriptor fixture")
	}
	if err := f.svc.Expire(f.ctx); err != nil {
		t.Fatal("sweep invalid descriptor")
	}
	var state string
	if err := f.pool.QueryRow(f.ctx, `SELECT state FROM intake_links WHERE request_id=$1`, link.RequestID).Scan(&state); err != nil || state != "expired" {
		t.Fatal("invalid descriptor blocked expiration sweep")
	}
}
func TestExpiredAndInvalidTTL(t *testing.T) {
	f := setup(t)
	for _, ttl := range []time.Duration{-time.Second, 24*time.Hour + time.Second} {
		if _, err := f.svc.Issue(f.ctx, f.ref, f.store, f.actor, ttl); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid TTL accepted")
		}
	}
	link, token := f.issue(t)
	if _, err := f.pool.Exec(f.ctx, `UPDATE intake_links SET expires_at=clock_timestamp()-interval '1 second' WHERE request_id=$1`, link.RequestID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Complete(f.ctx, token, ciphertext(t)); !errors.Is(err, ErrGone) {
		t.Fatal("expired link accepted")
	}
	if f.receiver.calls.Load() != 0 {
		t.Fatal("expired link reached receiver")
	}
	var count int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM audit_records WHERE org_id=$1 AND action='intake.expired'`, f.ref.OrgID.String()).Scan(&count); err != nil || count != 1 {
		t.Fatal("missing expiration audit")
	}
}
func TestAuditFailureDoesNotConsumeLink(t *testing.T) {
	f := setup(t)
	link, token := f.issue(t)
	f.svc.journal = failingJournal{}
	if _, err := f.svc.Complete(f.ctx, token, ciphertext(t)); !errors.Is(err, ErrUnavailable) {
		t.Fatal("audit failure accepted")
	}
	var state string
	var versions int
	if err := f.pool.QueryRow(f.ctx, `SELECT state FROM intake_links WHERE request_id=$1`, link.RequestID).Scan(&state); err != nil || state != "active" {
		t.Fatal("audit failure consumed link")
	}
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM secret_versions WHERE org_id=$1 AND secret_id=$2`, f.ref.OrgID, f.ref.ID).Scan(&versions); err != nil || versions != 0 {
		t.Fatal("audit failure committed version")
	}
	f.svc.journal = audit.NewJournal(f.pool)
	if _, err := f.svc.Complete(f.ctx, token, ciphertext(t)); err != nil {
		t.Fatal("failed completion could not retry")
	}
}

func TestIntakeWireBounds(t *testing.T) {
	f := setup(t)
	_, token := f.issue(t)
	for _, bad := range []string{token[:42], token + "A", token[:10] + "\n" + token[10:]} {
		if _, err := f.svc.Read(f.ctx, bad); !errors.Is(err, ErrGone) {
			t.Fatal("noncanonical token accepted")
		}
	}
	for _, env := range []Envelope{{Enc: make([]byte, 31), Ciphertext: make([]byte, 16)}, {Enc: make([]byte, 33), Ciphertext: make([]byte, 16)}, {Enc: make([]byte, 32), Ciphertext: make([]byte, 15)}, {Enc: make([]byte, 32), Ciphertext: make([]byte, 1048593)}} {
		if _, err := f.svc.Complete(f.ctx, token, env); !errors.Is(err, ErrRejected) {
			t.Fatal("out-of-bounds ciphertext accepted")
		}
	}
	if f.receiver.calls.Load() != 0 {
		t.Fatal("invalid wire input reached receiver")
	}
	if _, err := f.svc.Complete(f.ctx, token, Envelope{Enc: make([]byte, 32), Ciphertext: make([]byte, 1048592)}); err != nil {
		t.Fatal("wire upper-bound control rejected")
	}
}
