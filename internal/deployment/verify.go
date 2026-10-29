package deployment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	// ErrTooManyCarriers: one verification covers at most MaxVerifyCarriers.
	ErrTooManyCarriers = errors.New("deployment: too many carriers to verify at once")
	// ErrVerifyRateLimited: the secret already had MaxVerifiesPerHour requests.
	ErrVerifyRateLimited = errors.New("deployment: verify rate limit reached")
)

const (
	// MaxVerifyCarriers bounds the jobs one verify request creates.
	MaxVerifyCarriers = 100
	// MaxVerifiesPerHour bounds verify requests per secret, so a caller
	// cannot keep a runner busy re-reading files.
	MaxVerifiesPerHour = 60
)

// VerifyState is a carrier's state in one verification, a closed list.
type VerifyState string

const (
	VerifyPending     VerifyState = "pending"
	VerifyMatch       VerifyState = "match"
	VerifyMismatch    VerifyState = "mismatch"
	VerifyUnreachable VerifyState = "unreachable"
	VerifyFailed      VerifyState = "failed"
)

// VerifyRequest is authenticated metadata only. The expected fingerprint is
// never supplied: it is the catalog's current version, read under the lock.
type VerifyRequest struct {
	OrgID     uuid.UUID
	Scope     tenancy.Scope
	SecretID  uuid.UUID
	RequestID string
	Actor     audit.Actor
}

// VerifyItem is one carrier's line of a verification. No value, path content
// or runner text: the destination as registered, a state and a timestamp.
type VerifyItem struct {
	CarrierID      uuid.UUID
	RunnerID       uuid.UUID
	Host           string
	TargetKind     runnerproto.TargetKind
	TargetPath     string
	State          VerifyState
	ErrorClass     runnerproto.ErrorClass
	LastVerifiedAt *time.Time
}

// VerifyReport is the durable state of one verification.
type VerifyReport struct {
	SecretID    uuid.UUID
	Scope       tenancy.Scope
	Version     string
	Fingerprint string
	// Created is true only for the call that stored the verification.
	Created bool
	Items   []VerifyItem
}

// Done is true when no carrier is still waiting for its runner.
func (r VerifyReport) Done() bool {
	for _, it := range r.Items {
		if it.State == VerifyPending {
			return false
		}
	}
	return true
}

// verifyTarget is what a verify job names. Mode, UID and GID are required by
// the job structure but a verify job never writes, so they carry fixed,
// non-owner values instead of anything read from the carrier.
func verifyTarget(kind runnerproto.TargetKind, path, field string) runnerproto.Target {
	return runnerproto.Target{Kind: kind, Path: path, Field: field, Mode: 0o600}
}

type verifyCarrier struct {
	id                      uuid.UUID
	host, kind, path, field string
	runner                  uuid.UUID
	target                  runnerproto.Target
	state                   VerifyState
	jobID                   uuid.UUID
	failedStructure         bool
}

// SubmitVerify creates one verification: a signed-at-pull verify job per
// carrier of the secret whose host has a live enrolled runner. A carrier with
// no such runner is recorded as unreachable at once. A second call with the
// same request id returns the first verification; a different secret under the
// same id is ErrConflict.
func (r *Repo) SubmitVerify(ctx context.Context, in VerifyRequest) (VerifyReport, error) {
	if r == nil || r.pool == nil || r.journal == nil || r.trust == nil {
		return VerifyReport{}, ErrUnavailable
	}
	if in.OrgID == uuid.Nil || in.SecretID == uuid.Nil || in.Scope.ID == uuid.Nil || !reqid.Valid(in.RequestID) || in.Actor.ID == "" || !knownActor(in.Actor) {
		return VerifyReport{}, ErrInvalidArgument
	}
	hash := bindHash("keep/verify/request/v1", in.OrgID.String(), in.SecretID.String(), in.Scope.String())
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return VerifyReport{}, ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var org uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, in.OrgID).Scan(&org); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return VerifyReport{}, ErrNotFound
		}
		return VerifyReport{}, ErrUnavailable
	}
	var stored []byte
	err = tx.QueryRow(ctx, `SELECT request_hash FROM carrier_verifications WHERE org_id=$1 AND request_id=$2`, in.OrgID, in.RequestID).Scan(&stored)
	switch {
	case err == nil:
		if !equalHash(stored, hash[:]) {
			return VerifyReport{}, ErrConflict
		}
		return readVerify(ctx, tx, in.OrgID, in.RequestID)
	case !errors.Is(err, pgx.ErrNoRows):
		return VerifyReport{}, ErrUnavailable
	}
	var versionID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id FROM secret_versions WHERE org_id=$1 AND secret_id=$2 AND NOT disabled ORDER BY seal_seq DESC LIMIT 1`, in.OrgID, in.SecretID).Scan(&versionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return VerifyReport{}, ErrNotFound
	}
	if err != nil {
		return VerifyReport{}, ErrUnavailable
	}
	secret, err := loadSecret(ctx, tx, Request{OrgID: in.OrgID, Scope: in.Scope, SecretID: in.SecretID, VersionID: versionID})
	if err != nil {
		return VerifyReport{}, err
	}
	var recent int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM carrier_verifications WHERE org_id=$1 AND secret_id=$2 AND created_at > clock_timestamp()-interval '1 hour'`, in.OrgID, in.SecretID).Scan(&recent); err != nil {
		return VerifyReport{}, ErrUnavailable
	}
	if recent >= MaxVerifiesPerHour {
		return VerifyReport{}, ErrVerifyRateLimited
	}
	list, err := loadVerifyCarriers(ctx, tx, in.OrgID, in.SecretID)
	if err != nil {
		return VerifyReport{}, err
	}
	verificationID, err := uuid.NewV7()
	if err != nil {
		return VerifyReport{}, ErrUnavailable
	}
	if _, err = tx.Exec(ctx, `INSERT INTO carrier_verifications(id,org_id,request_id,request_hash,secret_id,secret_scope_level,secret_scope_id,expected_version,expected_fingerprint,created_at)
	 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,clock_timestamp())`, verificationID, in.OrgID, in.RequestID, hash[:], in.SecretID, secret.secretScopeLevel, secret.secretScopeID, secret.providerVersion, secret.fingerprint); err != nil {
		return VerifyReport{}, ErrUnavailable
	}
	for i := range list {
		c := &list[i]
		if c.failedStructure {
			c.state = VerifyFailed
		} else if c.runner, err = liveRunner(ctx, tx, in.OrgID, c.host); err != nil {
			return VerifyReport{}, err
		}
		if c.runner != uuid.Nil {
			if _, terr := r.trust(ctx, tx, in.OrgID, c.runner); terr != nil {
				c.runner = uuid.Nil
			}
		}
		if c.state == "" && c.runner == uuid.Nil {
			c.state = VerifyUnreachable
		}
		if c.state == "" {
			if c.jobID, err = insertVerifyJob(ctx, tx, in, verificationID, c, secret, versionID); err != nil {
				return VerifyReport{}, err
			}
			c.state = VerifyPending
		}
		var runner, job any
		if c.jobID != uuid.Nil {
			runner, job = c.runner, c.jobID
		}
		var completed any
		if c.state != VerifyPending {
			completed = time.Now().UTC()
		}
		if _, err = tx.Exec(ctx, `INSERT INTO carrier_verification_items(verification_id,org_id,carrier_id,runner_id,job_id,state,completed_at) VALUES($1,$2,$3,$4,$5,$6,$7)`,
			verificationID, in.OrgID, c.id, runner, job, string(c.state), completed); err != nil {
			return VerifyReport{}, ErrUnavailable
		}
	}
	record := audit.Record{OrgID: in.OrgID.String(), RequestID: in.RequestID, Scope: in.Scope.String(), Actor: in.Actor, Action: audit.ActionCarrierVerify,
		Secret: audit.SecretRef{ID: in.SecretID.String(), Name: secret.name, Version: secret.providerVersion},
		Policy: audit.Policy{Decision: audit.DecisionAllow}, Result: audit.Result{Status: audit.StatusPending, Fingerprint: secret.fingerprint}}
	appended, err := r.journal.AppendTx(ctx, tx, record)
	if err != nil {
		return VerifyReport{}, ErrUnavailable
	}
	rep, err := readVerify(ctx, tx, in.OrgID, in.RequestID)
	if err != nil {
		return VerifyReport{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return VerifyReport{}, ErrUnavailable
	}
	r.journal.LogCommitted(ctx, appended)
	rep.Created = true
	return rep, nil
}

func loadVerifyCarriers(ctx context.Context, tx pgx.Tx, org, secretID uuid.UUID) ([]verifyCarrier, error) {
	rows, err := tx.Query(ctx, `SELECT id,host,target_kind,target_path,target_field FROM carriers WHERE org_id=$1 AND secret_id=$2 ORDER BY host,target_kind,target_path,target_field,id LIMIT $3`, org, secretID, MaxVerifyCarriers+1)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	var out []verifyCarrier
	for rows.Next() {
		var c verifyCarrier
		if rows.Scan(&c.id, &c.host, &c.kind, &c.path, &c.field) != nil {
			return nil, ErrUnavailable
		}
		c.target = verifyTarget(runnerproto.TargetKind(c.kind), c.path, c.field)
		// A registered carrier that no longer passes the job's own structure
		// or looks like a network destination is reported, not dispatched.
		c.failedStructure = c.target.Validate() != nil || networkTarget(c.target)
		out = append(out, c)
	}
	if rows.Err() != nil {
		return nil, ErrUnavailable
	}
	if len(out) > MaxVerifyCarriers {
		return nil, ErrTooManyCarriers
	}
	return out, nil
}

// liveRunner picks the most recently enrolled live runner of a host.
func liveRunner(ctx context.Context, tx pgx.Tx, org uuid.UUID, host string) (uuid.UUID, error) {
	var id uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM runners WHERE org_id=$1 AND host=$2 AND revoked_at IS NULL AND cert_not_after>clock_timestamp() ORDER BY enrolled_at DESC,id DESC LIMIT 1`, org, host).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, nil
	}
	if err != nil {
		return uuid.Nil, ErrUnavailable
	}
	return id, nil
}

// insertVerifyJob stores the request row and the job for one carrier. The
// request row is keyed by a hash of the verification and the carrier, so it
// cannot collide with a caller-chosen deployment request id.
func insertVerifyJob(ctx context.Context, tx pgx.Tx, in VerifyRequest, verificationID uuid.UUID, c *verifyCarrier, secret frozenSecret, versionID uuid.UUID) (uuid.UUID, error) {
	rowID, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, ErrUnavailable
	}
	sum := sha256.Sum256([]byte(in.RequestID + "/" + c.id.String()))
	requestID := "vf-" + hex.EncodeToString(sum[:16])
	targetJSON, err := json.Marshal(c.target)
	if err != nil {
		return uuid.Nil, ErrInvalidArgument
	}
	hash := bindHash("keep/verify/job/v1", in.OrgID.String(), verificationID.String(), c.id.String())
	key := bindHash("keep/verify/target/v1", in.OrgID.String(), in.SecretID.String(), c.runner.String(), string(targetJSON))
	if _, err = tx.Exec(ctx, `INSERT INTO deployment_requests(id,org_id,request_id,request_hash,target_key,secret_id,version_id,runner_id,secret_scope_level,secret_scope_id,target,decision,created_at)
	 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'queued',clock_timestamp())`, rowID, in.OrgID, requestID, hash[:], key[:], in.SecretID, versionID, c.runner, secret.secretScopeLevel, secret.secretScopeID, targetJSON); err != nil {
		return uuid.Nil, ErrUnavailable
	}
	return storeJob(ctx, tx, in.OrgID, c.runner, rowID, requestID, in.SecretID, versionID, secret, runnerproto.ActionVerify, c.target, nil)
}

type querier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

// VerifyReport reads one verification of org. A request id the organization
// never created is ErrNotFound, indistinguishable from another organization's.
func (r *Repo) VerifyReport(ctx context.Context, org uuid.UUID, requestID string) (VerifyReport, error) {
	if r == nil || r.pool == nil {
		return VerifyReport{}, ErrUnavailable
	}
	if org == uuid.Nil || !reqid.Valid(requestID) {
		return VerifyReport{}, ErrNotFound
	}
	return readVerify(ctx, r.pool, org, requestID)
}

// readVerify derives a pending item whose job is past its deadline as
// unreachable, so a runner that never answered is visible without a sweeper.
func readVerify(ctx context.Context, q querier, org uuid.UUID, requestID string) (VerifyReport, error) {
	var rep VerifyReport
	var id uuid.UUID
	var level string
	err := q.QueryRow(ctx, `SELECT id,secret_id,secret_scope_level,secret_scope_id,expected_version,expected_fingerprint FROM carrier_verifications WHERE org_id=$1 AND request_id=$2`, org, requestID).
		Scan(&id, &rep.SecretID, &level, &rep.Scope.ID, &rep.Version, &rep.Fingerprint)
	if errors.Is(err, pgx.ErrNoRows) {
		return VerifyReport{}, ErrNotFound
	}
	if err != nil {
		return VerifyReport{}, ErrUnavailable
	}
	rep.Scope.Level = tenancy.Level(level)
	rows, err := q.Query(ctx, `SELECT i.carrier_id,i.runner_id,c.host,c.target_kind,c.target_path,
	 CASE WHEN i.state='pending' AND j.expires_at<clock_timestamp() THEN 'unreachable' ELSE i.state END,
	 CASE WHEN i.state='pending' AND j.expires_at<clock_timestamp() THEN 'job_expired' ELSE i.error_class END,
	 i.completed_at
	 FROM carrier_verification_items i
	 JOIN carriers c ON c.org_id=i.org_id AND c.id=i.carrier_id
	 LEFT JOIN deployment_jobs j ON j.org_id=i.org_id AND j.id=i.job_id
	 WHERE i.org_id=$1 AND i.verification_id=$2
	 ORDER BY c.host,c.target_kind,c.target_path,c.target_field,c.id`, org, id)
	if err != nil {
		return VerifyReport{}, ErrUnavailable
	}
	defer rows.Close()
	for rows.Next() {
		var it VerifyItem
		var runner *uuid.UUID
		var state, class, kind string
		if rows.Scan(&it.CarrierID, &runner, &it.Host, &kind, &it.TargetPath, &state, &class, &it.LastVerifiedAt) != nil {
			return VerifyReport{}, ErrUnavailable
		}
		if runner != nil {
			it.RunnerID = *runner
		}
		it.TargetKind, it.State, it.ErrorClass = runnerproto.TargetKind(kind), VerifyState(state), runnerproto.ErrorClass(class)
		rep.Items = append(rep.Items, it)
	}
	if rows.Err() != nil {
		return VerifyReport{}, ErrUnavailable
	}
	return rep, nil
}

// verifyOutcome maps a runner's closed result onto a carrier state.
func verifyOutcome(res runnerproto.Result) (VerifyState, runnerproto.ErrorClass) {
	if res.OK {
		return VerifyMatch, ""
	}
	switch res.ErrorClass {
	case runnerproto.ErrClassFingerprintMismatch:
		return VerifyMismatch, res.ErrorClass
	case runnerproto.ErrClassPolicyDenied, runnerproto.ErrClassSignature, runnerproto.ErrClassWrongRunner,
		runnerproto.ErrClassReplay, runnerproto.ErrClassInvalidJob, runnerproto.ErrClassRateLimited:
		return VerifyFailed, res.ErrorClass
	default:
		return VerifyUnreachable, res.ErrorClass
	}
}

// ApplyVerifyResultTx records a runner's report of a verify job inside the
// caller's transaction: the carrier's line of its verification and, only
// while the job's fingerprint is still the catalog's current one, the carrier
// itself. A match marks it registered, a mismatch stale, an unreachable host
// unknown; a refused job changes nothing. It reports whether the job belonged
// to a verification, and the state it recorded.
func ApplyVerifyResultTx(ctx context.Context, tx pgx.Tx, org uuid.UUID, job runnerproto.Job, res runnerproto.Result) (VerifyState, bool, error) {
	state, class := verifyOutcome(res)
	observed := ""
	if state == VerifyMismatch && fingerprint.Valid(res.Fingerprint) {
		expected, eerr := fingerprint.Parse(job.ExpectedFingerprint)
		got, gerr := fingerprint.Parse(res.Fingerprint)
		if eerr == nil && gerr == nil && expected.KeyID == got.KeyID {
			observed = res.Fingerprint
		}
	}
	jobID, err := uuid.Parse(job.JobID)
	if err != nil {
		return "", false, ErrUnavailable
	}
	var carrierID uuid.UUID
	err = tx.QueryRow(ctx, `UPDATE carrier_verification_items SET state=$3,error_class=$4,observed_fingerprint=NULLIF($5,''),completed_at=clock_timestamp()
	 WHERE org_id=$1 AND job_id=$2 AND state='pending' RETURNING carrier_id`, org, jobID, string(state), string(class), observed).Scan(&carrierID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, ErrUnavailable
	}
	const current = ` AND (SELECT v.fingerprint FROM secret_versions v WHERE v.org_id=c.org_id AND v.secret_id=c.secret_id AND NOT v.disabled ORDER BY v.seal_seq DESC LIMIT 1)=$3`
	switch {
	case state == VerifyMatch:
		_, err = tx.Exec(ctx, `UPDATE carriers c SET state='registered',version=$4,last_fp=$3,last_verified_at=clock_timestamp(),updated_at=clock_timestamp() WHERE c.org_id=$1 AND c.id=$2`+current,
			org, carrierID, job.ExpectedFingerprint, job.ExpectedVersion)
	case state == VerifyMismatch && observed != "":
		_, err = tx.Exec(ctx, `UPDATE carriers c SET state='stale',last_fp=$4,last_verified_at=clock_timestamp(),updated_at=clock_timestamp() WHERE c.org_id=$1 AND c.id=$2`+current,
			org, carrierID, job.ExpectedFingerprint, observed)
	case state == VerifyUnreachable:
		_, err = tx.Exec(ctx, `UPDATE carriers c SET state='unknown',last_verified_at=NULL,updated_at=clock_timestamp() WHERE c.org_id=$1 AND c.id=$2`+current,
			org, carrierID, job.ExpectedFingerprint)
	}
	if err != nil {
		return "", false, ErrUnavailable
	}
	return state, true, nil
}
