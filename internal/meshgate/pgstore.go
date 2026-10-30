package meshgate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PG is the PostgreSQL Store.
type PG struct {
	pool *pgxpool.Pool
	// settleSlots bounds the connections held by Settle to one fewer than the
	// pool has. The holder of a gate lock runs its queries on a second
	// connection; without the bound, as many answers waiting for that lock as
	// pool connections would each hold one and the holder would wait forever.
	settleSlots chan struct{}
}

// settleWait is how long an answer may wait for a Settle slot before it gives
// up with an error instead of queueing indefinitely.
const settleWait = 30 * time.Second

// ErrPoolTooSmall is returned by Settle over a pool of fewer than two
// connections: the lock holder needs a second one, so it could never finish.
var ErrPoolTooSmall = errors.New("meshgate: settle needs a pool of at least two connections")

// NewPG returns a Store over pool.
func NewPG(pool *pgxpool.Pool) *PG {
	n := 0
	if pool != nil {
		if m := int(pool.Config().MaxConns) - 1; m > n {
			n = m
		}
	}
	return &PG{pool: pool, settleSlots: make(chan struct{}, n)}
}

var (
	_ Store   = (*PG)(nil)
	_ TxStore = (*PG)(nil)
)

const gateColumns = `workspace_id,task_id,org_id,approval_id,request_hash,initiator_ref,status,expires_at,card_cancelled`

func scanGate(row pgx.Row) (Gate, error) {
	var g Gate
	var h []byte
	if err := row.Scan(&g.Workspace, &g.TaskID, &g.Org, &g.Approval, &h, &g.InitiatorRef, &g.Status, &g.ExpiresAt, &g.CardCancel); err != nil {
		return Gate{}, err
	}
	copy(g.Hash[:], h)
	return g, nil
}

// Insert implements Store.
func (p *PG) Insert(ctx context.Context, g Gate) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO mesh_gate_requests (`+gateColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		g.Workspace, g.TaskID, g.Org, g.Approval, g.Hash[:], g.InitiatorRef, g.Status, g.ExpiresAt, g.CardCancel)
	return err
}

// WorkspacesOfTx implements TxStore.
func (p *PG) WorkspacesOfTx(ctx context.Context, tx pgx.Tx, org uuid.UUID) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT workspace_id FROM mesh_installations WHERE org_id=$1 AND mode='extension' ORDER BY workspace_id LIMIT 2`, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var w uuid.UUID
		if err := rows.Scan(&w); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// InsertTx implements TxStore.
func (p *PG) InsertTx(ctx context.Context, tx pgx.Tx, g Gate) error {
	_, err := tx.Exec(ctx, `INSERT INTO mesh_gate_requests (`+gateColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		g.Workspace, g.TaskID, g.Org, g.Approval, g.Hash[:], g.InitiatorRef, g.Status, g.ExpiresAt, g.CardCancel)
	return err
}

// ByApproval implements Store.
func (p *PG) ByApproval(ctx context.Context, org, approval uuid.UUID) (Gate, bool, error) {
	g, err := scanGate(p.pool.QueryRow(ctx, `SELECT `+gateColumns+` FROM mesh_gate_requests WHERE org_id=$1 AND approval_id=$2`, org, approval))
	if errors.Is(err, pgx.ErrNoRows) {
		return Gate{}, false, nil
	}
	return g, err == nil, err
}

// LinkedUser implements Store. A link to a removed user links nobody.
func (p *PG) LinkedUser(ctx context.Context, org, workspace, meshUser uuid.UUID) (uuid.UUID, bool, error) {
	var u uuid.UUID
	err := p.pool.QueryRow(ctx, `SELECT l.user_id FROM mesh_user_links l JOIN users u ON u.org_id=l.org_id AND u.id=l.user_id AND u.status='active'
	 WHERE l.workspace_id=$1 AND l.mesh_user_id=$2 AND l.org_id=$3`, workspace, meshUser, org).Scan(&u)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, nil
	}
	return u, err == nil, err
}

// Link records that meshUser of workspace is the Keep user of org.
func (p *PG) Link(ctx context.Context, workspace, meshUser, org, user uuid.UUID) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO mesh_user_links (workspace_id,mesh_user_id,org_id,user_id) VALUES ($1,$2,$3,$4)
	 ON CONFLICT (workspace_id,mesh_user_id) DO UPDATE SET org_id=EXCLUDED.org_id, user_id=EXCLUDED.user_id, linked_at=now()`,
		workspace, meshUser, org, user)
	return err
}

// Settle implements Store: the gate row is locked for the whole of fn, so two
// answers for one card are applied one after the other.
func (p *PG) Settle(ctx context.Context, workspace, task uuid.UUID, fn func(Gate) (Settlement, error)) error {
	if cap(p.settleSlots) == 0 {
		return ErrPoolTooSmall
	}
	wait, cancel := context.WithTimeout(ctx, settleWait)
	select {
	case p.settleSlots <- struct{}{}:
		cancel()
	case <-wait.Done():
		cancel()
		return fmt.Errorf("meshgate: wait for settle slot: %w", wait.Err())
	}
	defer func() { <-p.settleSlots }()
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	g, err := scanGate(tx.QueryRow(ctx, `SELECT `+gateColumns+` FROM mesh_gate_requests WHERE workspace_id=$1 AND task_id=$2 FOR UPDATE`, workspace, task))
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrUnknownGate
	}
	if err != nil {
		return err
	}
	st, err := fn(g)
	if err != nil {
		return err
	}
	if st.Status != "" {
		if _, err = tx.Exec(ctx, `UPDATE mesh_gate_requests SET status=$3, decided_by_mesh=$4, decided_event=$5, decided_at=$6 WHERE workspace_id=$1 AND task_id=$2`,
			workspace, task, st.Status, st.MeshUser, st.EventID, st.DecidedAt); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// Lapsed implements Store.
func (p *PG) Lapsed(ctx context.Context, now time.Time) ([]Gate, error) {
	if _, err := p.pool.Exec(ctx, `UPDATE mesh_gate_requests SET status='expired'
	 WHERE status='pending' AND expires_at <= $1`, now); err != nil {
		return nil, err
	}
	rows, err := p.pool.Query(ctx, `SELECT `+gateColumns+` FROM mesh_gate_requests WHERE status='expired' AND NOT card_cancelled ORDER BY expires_at LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Gate
	for rows.Next() {
		g, err := scanGate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// CardCancelled implements Store.
func (p *PG) CardCancelled(ctx context.Context, workspace, task uuid.UUID) error {
	_, err := p.pool.Exec(ctx, `UPDATE mesh_gate_requests SET card_cancelled=true WHERE workspace_id=$1 AND task_id=$2`, workspace, task)
	return err
}
