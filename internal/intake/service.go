// Package intake manages single-use ciphertext delivery capabilities. It never
// imports or receives the plaintext secret type.
package intake

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/intake/descriptor"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrGone        = errors.New("input link is unavailable")
	ErrRejected    = errors.New("input ciphertext rejected")
	ErrInvalid     = errors.New("invalid input link request")
	ErrUnavailable = errors.New("input service unavailable")
	ErrPending     = errors.New("input is pending")
)

// Receiver is implemented inside the plaintext zone. Only ciphertext enters;
// public keys and metadata leave. AcceptIntake must use the supplied transaction.
type Receiver interface {
	IntakeDescriptor(context.Context, string, descriptor.Metadata) ([]byte, []byte, []byte, error)
	AcceptIntake(context.Context, pgx.Tx, string, string, []byte, []byte) (string, string, int, error)
}
type Factory func(catalog.Store) (Receiver, error)
type Journal interface {
	AppendTx(context.Context, pgx.Tx, audit.Record) (audit.Record, error)
}
type Service struct {
	pool    *pgxpool.Pool
	factory Factory
	journal Journal
	origin  string
	onRot   func(context.Context, Completed)
}

func New(pool *pgxpool.Pool, factory Factory, journal Journal, origin string) *Service {
	return &Service{pool: pool, factory: factory, journal: journal, origin: origin}
}

type Issued struct {
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
	RequestID string    `json:"request_id"`
}
type Envelope struct {
	Enc        []byte `json:"enc"`
	Ciphertext []byte `json:"ciphertext"`
}
type Result struct {
	Version     string `json:"version"`
	Fingerprint string `json:"fingerprint"`
}
type View struct {
	RequestID, SecretName, Scope, StoreName, Class, RequestedBy, Sponsor string
	PublicKey, SigningKey, Signature                                     []byte
}

// Completed names a finished input that a rotation asked for: ids, version
// label and fingerprint, never the value.
type Completed struct {
	Org, Secret uuid.UUID
	Request     uuid.UUID
	Version     string
	Fingerprint string
}

// OnRotationInput sets the hook Complete calls, after commit, for links issued
// by IssueRotation. Call it before the service takes requests. A hook cannot
// fail the completion: the value is sealed by then.
func (s *Service) OnRotationInput(fn func(context.Context, Completed)) { s.onRot = fn }

func (s *Service) Issue(ctx context.Context, ref tenancy.SecretRef, st catalog.Store, actor audit.Actor, ttl time.Duration) (Issued, error) {
	return s.issue(ctx, ref, st, actor, ttl, "input")
}

// IssueRotation issues a link whose completion starts the rotation layout.
func (s *Service) IssueRotation(ctx context.Context, ref tenancy.SecretRef, st catalog.Store, actor audit.Actor, ttl time.Duration) (Issued, error) {
	return s.issue(ctx, ref, st, actor, ttl, "rotate")
}

func (s *Service) issue(ctx context.Context, ref tenancy.SecretRef, st catalog.Store, actor audit.Actor, ttl time.Duration, purpose string) (Issued, error) {
	if ttl == 0 {
		ttl = 30 * time.Minute
	}
	if ttl < 0 || ttl > 24*time.Hour || st.Provider != "builtin" || st.Status != "active" || st.OrgID != ref.OrgID || st.ID != ref.StoreID || !strings.HasPrefix(ref.ProviderRef, "builtin://") {
		return Issued{}, ErrInvalid
	}
	if s.factory == nil || s.journal == nil {
		return Issued{}, ErrUnavailable
	}
	receiver, err := s.factory(st)
	if err != nil {
		return Issued{}, ErrUnavailable
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Issued{}, ErrUnavailable
	}
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return Issued{}, ErrUnavailable
	}
	defer clear(raw)
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256(raw)
	expires := time.Now().UTC().Add(ttl).Truncate(time.Microsecond)
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Issued{}, ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Read the same catalog fields as loadHash while holding their row locks.
	// Caller-supplied or stale metadata must never authorize the displayed text.
	v := View{RequestID: id.String(), RequestedBy: string(actor.Type) + " " + actor.ID, Sponsor: actor.SponsorID}
	err = tx.QueryRow(ctx, `SELECT s.name,s.scope_level||':'||s.scope_id::text,st.name,s.class
 FROM secrets s JOIN stores st ON st.org_id=s.org_id AND st.id=s.store_id
 WHERE s.org_id=$1 AND s.id=$2 AND s.store_id=$3 AND s.status='active' AND st.provider='builtin' AND st.status='active' AND s.provider_ref=$4 FOR SHARE OF s,st`, ref.OrgID, ref.ID, st.ID, ref.ProviderRef).Scan(&v.SecretName, &v.Scope, &v.StoreName, &v.Class)
	if err != nil {
		return Issued{}, ErrUnavailable
	}
	public, signing, signature, err := receiver.IntakeDescriptor(ctx, id.String(), v.metadata())
	v.PublicKey, v.SigningKey, v.Signature = public, signing, signature
	if err != nil || !validDescriptor(v) {
		return Issued{}, ErrUnavailable
	}
	tag, err := tx.Exec(ctx, `INSERT INTO intake_links(request_id,org_id,secret_id,store_id,provider_ref,token_hash,actor_type,actor_id,sponsor_id,public_key,signing_key,signature,expires_at,secret_name,scope,store_name,class)
 SELECT $1,$2,$3,$4,s.provider_ref,$5,$6,$7,$8,$9,$10,$11,$12,$14,$15,$16,$17 FROM secrets s JOIN stores st ON st.org_id=s.org_id AND st.id=s.store_id
 WHERE s.org_id=$2 AND s.id=$3 AND s.store_id=$4 AND s.status='active' AND st.provider='builtin' AND st.status='active' AND s.provider_ref=$13 FOR SHARE OF s,st`, id, ref.OrgID, ref.ID, st.ID, hash[:], string(actor.Type), actor.ID, actor.SponsorID, public, signing, signature, expires, ref.ProviderRef, v.SecretName, v.Scope, v.StoreName, v.Class)
	if err != nil || tag.RowsAffected() != 1 {
		return Issued{}, ErrUnavailable
	}
	if purpose == "rotate" {
		if _, err = tx.Exec(ctx, `INSERT INTO intake_rotation_links(org_id,request_id) VALUES($1,$2)`, ref.OrgID, id); err != nil {
			return Issued{}, ErrUnavailable
		}
	}
	_, err = s.journal.AppendTx(ctx, tx, audit.Record{OrgID: ref.OrgID.String(), RequestID: id.String(), Scope: ref.Scope.String(), Actor: actor, Action: audit.ActionIntakeIssued, Secret: audit.SecretRef{ID: ref.ID.String(), Name: ref.Name}, Result: audit.Result{Status: audit.StatusOK}})
	if err != nil {
		return Issued{}, ErrUnavailable
	}
	if err = tx.Commit(ctx); err != nil {
		return Issued{}, ErrUnavailable
	}
	return Issued{URL: strings.TrimRight(s.origin, "/") + "/input/" + token + "#signing=" + base64.RawURLEncoding.EncodeToString(signing) + "&request=" + id.String(), ExpiresAt: expires, RequestID: id.String()}, nil
}

type linkRow struct {
	id, org, secret, store   uuid.UUID
	view                     View
	path, state, version, fp string
	rotation                 bool
	actor                    audit.Actor
	expired                  bool
	available                bool
}

func tokenHash(token string) ([]byte, error) {
	if len(token) != 43 {
		return nil, ErrGone
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(raw) != 32 {
		return nil, ErrGone
	}
	defer clear(raw)
	sum := sha256.Sum256(raw)
	return sum[:], nil
}

func (s *Service) load(ctx context.Context, tx pgx.Tx, token string) (linkRow, error) {
	hash, err := tokenHash(token)
	if err != nil {
		return linkRow{}, err
	}
	return s.loadHash(ctx, tx, hash)
}
func (s *Service) loadHash(ctx context.Context, tx pgx.Tx, hash []byte) (linkRow, error) {
	var row linkRow
	err := tx.QueryRow(ctx, `SELECT l.request_id,l.org_id,l.secret_id,l.store_id,l.actor_type,l.actor_id,l.sponsor_id,l.public_key,l.signing_key,l.signature,
 l.state,l.version,l.fingerprint,l.expires_at<=clock_timestamp(),COALESCE(l.secret_name,''),COALESCE(l.scope,''),COALESCE(l.class,''),COALESCE(l.store_name,''),l.provider_ref,EXISTS(SELECT 1 FROM intake_rotation_links r WHERE r.org_id=l.org_id AND r.request_id=l.request_id),COALESCE((s.provider_ref=l.provider_ref AND s.store_id=l.store_id AND s.name=l.secret_name AND s.scope_level||':'||s.scope_id::text=l.scope AND s.class=l.class AND st.name=l.store_name AND s.status='active' AND st.status='active'),false)
 FROM intake_links l JOIN secrets s ON s.org_id=l.org_id AND s.id=l.secret_id
 JOIN stores st ON st.org_id=l.org_id AND st.id=l.store_id
 WHERE l.token_hash=$1 AND st.provider='builtin' FOR UPDATE OF l FOR SHARE OF s,st`, hash).Scan(
		&row.id, &row.org, &row.secret, &row.store, &row.actor.Type, &row.actor.ID, &row.actor.SponsorID, &row.view.PublicKey, &row.view.SigningKey, &row.view.Signature,
		&row.state, &row.version, &row.fp, &row.expired, &row.view.SecretName, &row.view.Scope, &row.view.Class, &row.view.StoreName, &row.path, &row.rotation, &row.available)
	if errors.Is(err, pgx.ErrNoRows) {
		return linkRow{}, ErrGone
	}
	if err != nil {
		return linkRow{}, ErrUnavailable
	}
	row.view.RequestID = row.id.String()
	row.view.RequestedBy = string(row.actor.Type) + " " + row.actor.ID
	row.view.Sponsor = row.actor.SponsorID
	row.actor.Via = audit.ViaAPI
	return row, nil
}
func (s *Service) record(ctx context.Context, tx pgx.Tx, row linkRow, action audit.Action, result Result) error {
	if s.journal == nil {
		return ErrUnavailable
	}
	_, err := s.journal.AppendTx(ctx, tx, audit.Record{OrgID: row.org.String(), RequestID: row.id.String(), Scope: row.view.Scope, Actor: row.actor, Action: action, Secret: audit.SecretRef{ID: row.secret.String(), Name: row.view.SecretName, Version: result.Version}, Result: audit.Result{Status: audit.StatusOK, Fingerprint: result.Fingerprint}})
	if err != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *Service) active(ctx context.Context, tx pgx.Tx, row linkRow) error {
	if row.state != "active" {
		return ErrGone
	}
	if !row.expired {
		// Invalid and legacy descriptors cannot authorize input. Expired links
		// still transition below, so they cannot starve the bounded sweep.
		if !validDescriptor(row.view) || !row.available || !strings.HasPrefix(row.path, "builtin://") {
			return ErrGone
		}
		return nil
	}
	if _, err := tx.Exec(ctx, `UPDATE intake_links SET state='expired' WHERE org_id=$1 AND request_id=$2`, row.org, row.id); err != nil {
		return ErrUnavailable
	}
	if err := s.record(ctx, tx, row, audit.ActionIntakeExpired, Result{}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return ErrUnavailable
	}
	return ErrGone
}
func (s *Service) Read(ctx context.Context, token string) (View, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return View{}, ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	row, err := s.load(ctx, tx, token)
	if err != nil {
		return View{}, err
	}
	if err = s.active(ctx, tx, row); err != nil {
		return View{}, err
	}
	return row.view, nil
}
func (s *Service) Complete(ctx context.Context, token string, env Envelope) (Result, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Result{}, ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	row, err := s.load(ctx, tx, token)
	if err != nil {
		return Result{}, err
	}
	if err = s.active(ctx, tx, row); err != nil {
		return Result{}, err
	}
	if len(env.Enc) != 32 || len(env.Ciphertext) < 16 || len(env.Ciphertext) > 1048592 {
		return Result{}, ErrRejected
	}
	// Look up the authoritative owner scope while the capability is locked.
	var st catalog.Store
	err = tx.QueryRow(ctx, `SELECT id,org_id,provider,name,owner_scope_level,owner_scope_id,status FROM stores WHERE org_id=$1 AND id=$2 AND status='active' FOR SHARE`, row.org, row.store).Scan(&st.ID, &st.OrgID, &st.Provider, &st.Name, &st.OwnerScope.Level, &st.OwnerScope.ID, &st.Status)
	if err != nil || s.factory == nil {
		return Result{}, ErrUnavailable
	}
	receiver, err := s.factory(st)
	if err != nil {
		return Result{}, ErrUnavailable
	}
	version, fp, length, err := receiver.AcceptIntake(ctx, tx, row.id.String(), row.path, env.Enc, env.Ciphertext)
	if err != nil {
		return Result{}, ErrRejected
	}
	result := Result{Version: version, Fingerprint: fp}
	if _, err = tx.Exec(ctx, `INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length) VALUES($1,$2,$3,$4,$5,$6)`, uuid.New(), row.org, row.secret, version, fp, length); err != nil {
		return Result{}, ErrUnavailable
	}
	if _, err = tx.Exec(ctx, `UPDATE intake_links SET state='completed',version=$3,fingerprint=$4 WHERE org_id=$1 AND request_id=$2`, row.org, row.id, version, fp); err != nil {
		return Result{}, ErrUnavailable
	}
	// A plain link finished while a run of the secret is active: the value is
	// newer than the run's version, and nothing would lay it out, so the run
	// would end with two active versions. It gets the same pending mark a
	// rotation link has, and is laid out once the run is over.
	late := false
	if !row.rotation {
		tag, err := tx.Exec(ctx, `INSERT INTO intake_rotation_links(org_id,request_id)
 SELECT $1,$2 WHERE EXISTS(SELECT 1 FROM rotation_runs WHERE org_id=$1 AND secret_id=$3 AND state NOT IN ('done','failed'))`, row.org, row.id, row.secret)
		if err != nil {
			return Result{}, ErrUnavailable
		}
		late = tag.RowsAffected() == 1
	}
	if err = s.record(ctx, tx, row, audit.ActionIntakeCompleted, result); err != nil {
		return Result{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Result{}, ErrUnavailable
	}
	if (row.rotation || late) && s.onRot != nil {
		s.runHook(ctx, Completed{Org: row.org, Secret: row.secret, Request: row.id, Version: version, Fingerprint: fp})
	}
	return result, nil
}

// runHook calls the rotation hook after the commit. The value is sealed and the
// link is used up, so nothing the hook does (a panic, a stuck database) may turn
// the completion into an error or hold the response.
func (s *Service) runHook(ctx context.Context, c Completed) {
	defer func() { _ = recover() }()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	s.onRot(ctx, c)
}
func (s *Service) Status(ctx context.Context, org, actor, request uuid.UUID) (Result, error) {
	var state string
	var result Result
	var expired bool
	err := s.pool.QueryRow(ctx, `SELECT state,version,fingerprint,expires_at<=clock_timestamp() FROM intake_links WHERE org_id=$1 AND actor_id=$2 AND request_id=$3`, org, actor.String(), request).Scan(&state, &result.Version, &result.Fingerprint, &expired)
	if errors.Is(err, pgx.ErrNoRows) {
		return Result{}, ErrGone
	}
	if err != nil {
		return Result{}, ErrUnavailable
	}
	if state == "completed" {
		return result, nil
	}
	if expired || state == "expired" {
		return Result{}, ErrGone
	}
	return Result{}, ErrPending
}

// Expire records unused expired links in bounded batches. Call periodically;
// reads and submissions also perform the same expiration transition.
func (s *Service) Expire(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `SELECT token_hash FROM intake_links WHERE state='active' AND expires_at<=clock_timestamp() ORDER BY expires_at LIMIT 100`)
	if err != nil {
		return ErrUnavailable
	}
	var hashes [][]byte
	for rows.Next() {
		var hash []byte
		if err := rows.Scan(&hash); err != nil {
			rows.Close()
			return ErrUnavailable
		}
		hashes = append(hashes, hash)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return ErrUnavailable
	}
	for _, hash := range hashes {
		tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if err != nil {
			return ErrUnavailable
		}
		row, err := s.loadHash(ctx, tx, hash)
		if err == nil {
			err = s.active(ctx, tx, row)
		}
		_ = tx.Rollback(ctx)
		if err != nil && !errors.Is(err, ErrGone) {
			return err
		}
	}
	return nil
}
