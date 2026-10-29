package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// VerifyResult is the outcome of walking one organization's chain. It
// never carries any Record field — only enough to locate the break for a
// human or a follow-up query — because keep-server audit verify's whole
// point is that a caller can run it without ever seeing a record's
// content; see the threat model's §4.2 and cmd/keep-server's "audit
// verify" subcommand.
type VerifyResult struct {
	OK bool
	// Checked is how many records were walked before OK was decided —
	// the full chain length on a clean chain, or the number walked up to
	// and including the broken record otherwise.
	Checked int64
	// BrokenID and BrokenPosition identify the first record that fails a
	// check (see BreakKind); for a BreakHead failure there is no such
	// record, BrokenID is empty and BrokenPosition is the position the
	// journal head says the chain should have reached. Both are the zero
	// value when OK is true.
	BrokenID       string
	BrokenPosition int64
	// BreakKind says which check failed — a closed set, never text taken
	// from a record. Empty when OK is true.
	BreakKind BreakKind
}

// ulidRe is the shape of a record id Append generates. A record id is an
// arbitrary TEXT column, and a writer with INSERT on audit_records can put
// anything in it; Verify's output is read by operators and agents (and
// pasted into terminals and CI logs), so an id is only ever returned when it
// has this shape.
var ulidRe = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)

// MalformedID stands in for a record id that does not have the shape of a
// ULID.
const MalformedID = "(malformed id)"

func safeRecordID(id string) string {
	if ulidRe.MatchString(id) {
		return id
	}
	return MalformedID
}

// BreakKind is the closed set of reasons Verify can report a chain broken.
type BreakKind string

const (
	// BreakHash: a record's stored hash is not the hash of its own stored
	// fields (edited in place).
	BreakHash BreakKind = "hash"
	// BreakLink: a record's prev_hash is not the previous record's hash
	// (deleted or reordered records, or a first record that does not start
	// at GenesisHash).
	BreakLink BreakKind = "link"
	// BreakSequence: org_seq is not 1, 2, 3, … without a gap.
	BreakSequence BreakKind = "sequence"
	// BreakHead: the chain does not end where audit_chain_heads says it
	// does (records cut off the end, or a whole organization wiped).
	BreakHead BreakKind = "head"
)

// Verify walks org's chain in insertion order (audit_records.org_seq) and
// recomputes each record's hash from its own stored fields and stored
// prev_hash, comparing it against that record's stored hash column — this
// catches a record edited in place, since its content and its stored hash
// then disagree. Separately, it checks that each record's stored prev_hash
// equals the previous surviving record's stored hash — this catches a
// record deleted from the middle, since the next surviving record's
// prev_hash then points at a hash no longer reachable by walking the table
// in order. See doc.go and verify_test.go for both cases with a red run.
//
// It also checks that org_seq runs 1, 2, 3, … without a gap, and — after
// the walk, in the same read-only snapshot — that the chain ends at the
// position and hash audit_chain_heads records, which is what catches
// records cut off the end or a whole organization wiped: neither leaves a
// surviving record whose link is wrong.
//
// What this does NOT prove: the hash is unkeyed and its formula is public,
// so anyone able to write both audit_records and audit_chain_heads can
// rewrite a suffix of the chain, recompute every hash, and Verify will say
// OK. Verify detects accidental damage and tampering by a writer who does
// not also forge the chain; it is not a defence against the database
// superuser or a fully compromised application role. See doc.go.
//
// An organization with no records and no head row verifies OK with
// Checked == 0 — there is nothing to break yet.
func Verify(ctx context.Context, pool *pgxpool.Pool, orgID string) (VerifyResult, error) {
	// One read-only REPEATABLE READ snapshot for the records and the head:
	// an Append committing between the two reads would otherwise make an
	// honest chain look truncated.
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return VerifyResult{}, dbErr("verify: begin", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx, `
		SELECT
			id, org_seq, ts, request_id, scope,
			actor_type, actor_id, actor_sponsor_id, actor_via,
			intent_task_ref, intent_session_ref, intent_reason,
			action,
			secret_id, secret_name, secret_version,
			target_runner_id, target_host, target_kind, target_path,
			policy_decision, policy_rule_id,
			approval_id, approval_approver_id, approval_decided_at,
			result_status, result_fingerprint, result_length, result_health, result_error_class,
			prev_hash, hash
		FROM audit_records
		WHERE org_id = $1
		ORDER BY org_seq ASC
	`, orgID)
	if err != nil {
		return VerifyResult{}, dbErr("verify: query chain", err)
	}
	defer rows.Close()

	expectedPrev := GenesisHash
	var walked int64

	for rows.Next() {
		var (
			rec           Record
			seq           int64
			storedHash    string
			approvalDecAt sql.NullTime
		)
		if err := rows.Scan(
			&rec.ID, &seq, &rec.TS, &rec.RequestID, &rec.Scope,
			(*string)(&rec.Actor.Type), &rec.Actor.ID, &rec.Actor.SponsorID, (*string)(&rec.Actor.Via),
			&rec.Intent.TaskRef, &rec.Intent.SessionRef, &rec.Intent.Reason,
			(*string)(&rec.Action),
			&rec.Secret.ID, &rec.Secret.Name, &rec.Secret.Version,
			&rec.Target.RunnerID, &rec.Target.Host, &rec.Target.Kind, &rec.Target.Path,
			(*string)(&rec.Policy.Decision), &rec.Policy.RuleID,
			&rec.Approval.ID, &rec.Approval.ApproverID, &approvalDecAt,
			(*string)(&rec.Result.Status), &rec.Result.Fingerprint, &rec.Result.Length, (*string)(&rec.Result.Health), (*string)(&rec.Result.ErrorClass),
			&rec.PrevHash, &storedHash,
		); err != nil {
			return VerifyResult{}, dbErr("verify: scan record", err)
		}
		// pgx returns a timestamptz column decoded into the Go process's
		// local time.Location, not UTC — confirmed empirically (the same
		// instant Append hashed as "...T21:40:08Z" round-tripped here as
		// "...T00:40:08+03:00" on a machine in MSK). Same instant,
		// different RFC3339 string, different canonical JSON, different
		// hash — every chain would fail to verify outside a UTC host
		// without this normalization. Append always hashes r.TS.UTC()
		// (see journal.go), so recomputing must start from the same
		// representation.
		rec.TS = rec.TS.UTC()
		if approvalDecAt.Valid {
			rec.Approval.DecidedAt = approvalDecAt.Time.UTC()
		}
		rec.OrgID = orgID
		walked++

		recomputed, err := computeHash(rec.PrevHash, rec)
		if err != nil {
			return VerifyResult{}, fmt.Errorf("audit: verify: recompute hash at position %d: %w", seq, err)
		}

		broken := func(kind BreakKind) (VerifyResult, error) {
			return VerifyResult{Checked: walked, BrokenID: safeRecordID(rec.ID), BrokenPosition: seq, BreakKind: kind}, nil
		}
		if seq != walked {
			return broken(BreakSequence)
		}
		if recomputed != storedHash {
			return broken(BreakHash)
		}
		if rec.PrevHash != expectedPrev {
			return broken(BreakLink)
		}
		expectedPrev = storedHash
	}
	if err := rows.Err(); err != nil {
		return VerifyResult{}, dbErr("verify: read chain", err)
	}
	rows.Close()

	var headPos int64
	var headHash string
	err = tx.QueryRow(ctx, `SELECT position, hash FROM audit_chain_heads WHERE org_id = $1`, orgID).Scan(&headPos, &headHash)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// No head row: fine for an organization that never appended, but
		// records with no head mean the head row was deleted.
		if walked > 0 {
			return VerifyResult{Checked: walked, BrokenPosition: walked, BreakKind: BreakHead}, nil
		}
		return VerifyResult{OK: true}, nil
	case err != nil:
		return VerifyResult{}, dbErr("verify: read chain head", err)
	}
	if headPos != walked || headHash != expectedPrev {
		return VerifyResult{Checked: walked, BrokenPosition: headPos, BreakKind: BreakHead}, nil
	}

	return VerifyResult{OK: true, Checked: walked}, nil
}
