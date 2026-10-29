package security

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/carriers"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type carrierApproval struct {
	org, id uuid.UUID
	meta    carriers.Metadata
}

func (p carrierApproval) Approved(_ context.Context, org, id uuid.UUID, meta carriers.Metadata) (bool, error) {
	return org == p.org && id == p.id && meta == p.meta, nil
}

type carrierPolicyError struct{ err error }

func (p carrierPolicyError) Approved(context.Context, uuid.UUID, uuid.UUID, carriers.Metadata) (bool, error) {
	return false, p.err
}

type carrierAttack struct {
	db         *pgxpool.Pool
	repo       *carriers.Repository
	ctx        context.Context
	org, other uuid.UUID
	in         carriers.Registration
	key        fingerprint.Key
}

func carrierWorld(t *testing.T) carrierAttack {
	t.Helper()
	if os.Getenv("KEEP_DATABASE_URL") == "" {
		t.Fatal("carrier attacks require PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	w := carrierAttack{db: attackDB(t), ctx: ctx, org: uuid.New(), other: uuid.New(), key: mustKey(t, "carrierattack")}
	t.Cleanup(w.key.Wipe)
	for _, org := range []uuid.UUID{w.org, w.other} {
		exec(t, w.db, `INSERT INTO organizations(id,name) VALUES($1,'carrier-attack')`, org)
	}
	sid, id := uuid.New(), uuid.New()
	exec(t, w.db, `INSERT INTO stores(id,org_id,provider,name,owner_scope_level,owner_scope_id) VALUES($1,$2,'builtin','attack','org',$2)`, sid, w.org)
	exec(t, w.db, `INSERT INTO secrets(id,org_id,scope_level,scope_id,name,class,type,store_id,provider_ref) VALUES($1,$2,'org',$2,'ATTACK','test','password',$3,'attack/ref')`, id, w.org, sid)
	fp := carrierFP(t, w.key, "synthetic carrier value")
	exec(t, w.db, `INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length) VALUES($1,$2,$3,'v1',$4,23)`, uuid.New(), w.org, id, fp)
	w.in = carriers.Registration{SecretID: id, Version: "v1", LastFP: fp, Metadata: carriers.Metadata{Host: "runner.attack.test", TargetKind: runnerproto.TargetEnvFile, TargetPath: "/etc/app/runtime.env", TargetField: "PASSWORD", Consumer: "app.service", HealthcheckRef: "app-health"}}
	w.repo = carriers.New(w.db, carrierApproval{w.org, id, w.in.Metadata})
	return w
}

func carrierFP(t *testing.T, key fingerprint.Key, raw string) string {
	t.Helper()
	v := secret.New([]byte(raw))
	defer v.Wipe()
	fp, err := fingerprint.Compute(key, v)
	if err != nil {
		t.Fatal("cannot compute attack fingerprint")
	}
	return fp
}

func (w carrierAttack) register(t *testing.T) carriers.Carrier {
	t.Helper()
	c, err := w.repo.Register(w.ctx, w.org, w.in)
	if err != nil {
		t.Fatal("positive carrier registration failed")
	}
	return c
}

func (w carrierAttack) only(t *testing.T) carriers.Carrier {
	t.Helper()
	rows, err := w.repo.List(w.ctx, w.org, w.in.SecretID)
	if err != nil || len(rows) != 1 {
		t.Fatal("carrier inventory changed")
	}
	return rows[0]
}

// Registry portion of A01: unavailable means unknown; it cannot reissue,
// revoke, remove the destination, or pretend a read failure is an empty list.
// End-to-end reissue refusal remains pending on rotation.
func TestW3_A01_LostCarrierNeverReissues_Carriers(t *testing.T) {
	w := carrierWorld(t)
	c := w.register(t)
	if err := w.repo.MarkUnknown(w.ctx, w.org, c.ID); err != nil {
		t.Fatal("unknown observation failed")
	}
	got := w.only(t)
	if got.ID != c.ID || got.State != carriers.Unknown || got.LastVerifiedAt != nil || got.Version != c.Version || got.LastFP != c.LastFP {
		t.Fatal("lost carrier history changed")
	}
	var versions, enabled int
	if err := w.db.QueryRow(w.ctx, `SELECT count(*),count(*) FILTER(WHERE NOT disabled) FROM secret_versions WHERE org_id=$1 AND secret_id=$2`, w.org, w.in.SecretID).Scan(&versions, &enabled); err != nil || versions != 1 || enabled != 1 {
		t.Fatal("unknown carrier reissued or revoked a version")
	}
	dead := carriers.New(nil, nil)
	if rows, err := dead.List(w.ctx, w.org, w.in.SecretID); !errors.Is(err, carriers.ErrInternal) || rows != nil {
		t.Fatal("read failure concealed as empty inventory")
	}
}

// Registry portion of A03: the scanner supplies a full HMAC observation.
// Prefix-equivalent values must fail MarkOK and be recorded as stale.
func TestW3_A03_SamePrefixValueIsStale_Carriers(t *testing.T) {
	w := carrierWorld(t)
	c := w.register(t)
	for _, raw := range []string{"synthetic carrier valuex", "synthetic carrier valu", "synthetic carrier value ", "synthetic carrier value\n"} {
		fp := carrierFP(t, w.key, raw)
		if fp == c.LastFP {
			t.Fatal("different value produced catalog fingerprint")
		}
		if err := w.repo.MarkOK(w.ctx, w.org, c.ID, fp); !errors.Is(err, carriers.ErrFingerprint) {
			t.Fatal("prefix-equivalent value marked healthy")
		}
		if err := w.repo.MarkStale(w.ctx, w.org, c.ID, fp); err != nil {
			t.Fatal("stale observation rejected")
		}
		got := w.only(t)
		if got.State != carriers.Stale || got.LastFP != fp {
			t.Fatal("mismatch was not recorded as stale")
		}
	}
	if err := w.repo.MarkOK(w.ctx, w.org, c.ID, w.in.LastFP); err != nil {
		t.Fatal("matching observation refused")
	}
}

// Registry portion of A04: only catalog-bound keyed fingerprints are
// accepted. Inspect the stored tag, including all bare SHA-256 truncations.
func TestW3_A04_FingerprintIsKeyedHMACNotSha256_Carriers(t *testing.T) {
	w := carrierWorld(t)
	c := w.register(t)
	other := mustKey(t, "otherstore")
	defer other.Wipe()
	foreign := carrierFP(t, other, "synthetic carrier value")
	if strings.Split(foreign, ":")[2] == strings.Split(c.LastFP, ":")[2] {
		t.Fatal("fingerprint tag not store-keyed")
	}
	sum := sha256.Sum256([]byte("synthetic carrier value"))
	for n := 4; n <= len(sum); n++ {
		for _, bare := range []string{hex.EncodeToString(sum[:n]), strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:n]))} {
			if strings.Split(c.LastFP, ":")[2] == bare {
				t.Fatal("stored tag is an unkeyed hash")
			}
			if err := w.repo.MarkStale(w.ctx, w.org, c.ID, bare); !errors.Is(err, carriers.ErrFingerprint) {
				t.Fatal("bare hash observation accepted")
			}
		}
	}
	if err := w.repo.MarkStale(w.ctx, w.org, c.ID, foreign); !errors.Is(err, carriers.ErrFingerprint) {
		t.Fatal("foreign store key accepted")
	}
	if err := w.repo.MarkStale(w.ctx, w.org, c.ID, w.in.LastFP); err != nil {
		t.Fatal("valid keyed observation rejected")
	}
}

// Registry portion of A07: unsafe metadata and policy errors cannot enter
// persistence, formatted state, JSON or logs. Rotation incidents/audit are
// covered separately when rotation exists.
func TestW3_A07_NoValueInRotationStateIncidentErrors_Carriers(t *testing.T) {
	w := carrierWorld(t)
	w.register(t)
	probe := canary.New()
	if !probe.In(probe.Value(1)) {
		t.Fatal("blind canary detector")
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	previous := slog.Default()
	slog.SetDefault(logger)
	defer slog.SetDefault(previous)
	logger.Info("capture control")
	for field := 0; field < 8; field++ {
		in := w.in
		switch field {
		case 0:
			in.Host = probe.Value(1) + ".attack.test"
		case 1:
			in.TargetPath = "/etc/" + probe.Value(1)
		case 2:
			in.TargetField = probe.Value(1)
		case 3:
			in.Consumer = probe.Value(1)
		case 4:
			in.HealthcheckRef = probe.Value(1)
		case 5:
			in.TargetKind = runnerproto.TargetKind(probe.Value(1))
		case 6:
			in.Version = probe.Value(1)
		case 7:
			in.LastFP = probe.Value(1)
		}
		_, err := w.repo.Register(w.ctx, w.org, in)
		if err == nil || probe.In(fmt.Sprintf("%v %+v %#v", err, err, err)) {
			t.Fatal("unsafe registration error")
		}
		encoded, encodeErr := json.Marshal(in)
		if encodeErr != nil || probe.In(string(encoded)) || probe.In(fmt.Sprintf("%v %+v %#v", in, in, in)) {
			t.Fatal("canary in formatted registration")
		}
		logger.Info("registration refused", "registration", in, "error", err)
	}
	bad := carriers.New(w.db, carrierPolicyError{fmt.Errorf("synthetic policy: %s", probe.Value(1))})
	_, err := bad.Register(w.ctx, w.org, w.in)
	if !errors.Is(err, carriers.ErrMetadata) || errors.Unwrap(err) != nil || probe.In(fmt.Sprint(err)) {
		t.Fatal("policy error leaked")
	}
	logger.Info("policy refused", "error", err, "carrier", w.only(t))
	if !strings.Contains(logs.String(), "capture control") || probe.In(logs.String()) {
		t.Fatal("canary in log output")
	}
	dump := dumpDB(t, w.db)
	if !strings.Contains(dump, w.in.Host) || probe.In(dump) {
		t.Fatal("unsafe database inventory")
	}
}

// Registry portion of A10: a foreign UUID must be indistinguishable from
// an absent UUID on reads and writes; the owned carrier remains unchanged.
func TestW3_A10_ForeignTenantCarriersInvisible_Carriers(t *testing.T) {
	w := carrierWorld(t)
	c := w.register(t)
	for _, id := range []uuid.UUID{w.in.SecretID, uuid.New()} {
		if rows, err := w.repo.List(w.ctx, w.other, id); !errors.Is(err, carriers.ErrNotFound) || rows != nil {
			t.Fatal("foreign inventory visible")
		}
	}
	if _, err := w.repo.Register(w.ctx, w.other, w.in); !errors.Is(err, carriers.ErrNotFound) {
		t.Fatal("foreign registration accepted")
	}
	for _, id := range []uuid.UUID{c.ID, uuid.New()} {
		for _, op := range []func() error{
			func() error { return w.repo.MarkOK(w.ctx, w.other, id, w.in.LastFP) },
			func() error { return w.repo.MarkStale(w.ctx, w.other, id, w.in.LastFP) },
			func() error { return w.repo.MarkUnknown(w.ctx, w.other, id) },
			func() error { return w.repo.Remove(w.ctx, w.other, id) },
		} {
			if !errors.Is(op(), carriers.ErrNotFound) {
				t.Fatal("foreign mutation accepted or distinguishable")
			}
		}
	}
	if got := w.only(t); got.ID != c.ID || got.State != c.State || got.LastFP != c.LastFP {
		t.Fatal("foreign operation changed owned carrier")
	}
}

// Registry portion of A11: guessed agent-writable paths require a complete
// approved descriptor. Rate limits, file reads and verify responses remain
// pending on scanner; syntactically plausible guesses cannot register.
func TestW3_A11_CarrierGuessOracleBlocked_Carriers(t *testing.T) {
	w := carrierWorld(t)
	w.register(t)
	for _, path := range []string{"/tmp/guess.env", "/home/agent/guess.env"} {
		in := w.in
		in.TargetPath = path
		if _, err := w.repo.Register(w.ctx, w.org, in); !errors.Is(err, carriers.ErrMetadata) {
			t.Fatal("unapproved guessed carrier accepted")
		}
	}
	if got := w.only(t); got.TargetPath != w.in.TargetPath {
		t.Fatal("guess changed approved destination")
	}
}
