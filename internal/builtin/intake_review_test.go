package builtin

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	"github.com/entire-vc/evc-keep/internal/intake/descriptor"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/jackc/pgx/v5"
)

type intakePostOpenProbe struct {
	pgx.Tx
	fingerprintRead bool
}

func (p *intakePostOpenProbe) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if strings.Contains(sql, "FROM keep_envelope") && len(args) == 6 && args[4] == fpKeySecretID {
		p.fingerprintRead = true
	}
	return p.Tx.QueryRow(ctx, sql, args...)
}

func TestIntakePostDecryptErrorsAreRedacted(t *testing.T) {
	for _, cause := range []string{"missing-fingerprint", "insert-conflict"} {
		t.Run(cause, func(t *testing.T) {
			ctx := context.Background()
			pool := testPool(t)
			seal, _ := testSealer(t, pool)
			var logs bytes.Buffer
			p := New(pool, seal, sealer.Scope{Org: randID(t, "post-open"), User: "alice"}, slog.New(slog.NewJSONHandler(&logs, nil)))
			const request = "019a0000-0000-7000-8000-000000000001"
			public, _, _, err := p.IntakeDescriptor(ctx, request, descriptor.Metadata{})
			if err != nil {
				t.Fatal("prepare post-decrypt descriptor")
			}
			c := canary.New()
			plain := []byte(c.Value(1))
			defer clear(plain)
			if !c.In(fmt.Sprintf("%+v", fmt.Errorf("probe: %s", plain))) {
				t.Fatal("post-decrypt detector positive control failed")
			}
			enc, ct := intakeTestCiphertext(t, public, request, plain)
			tx, err := pool.BeginTx(ctx, readCommitted)
			if err != nil {
				t.Fatal("begin post-decrypt probe")
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if cause == "missing-fingerprint" {
				_, err = tx.Exec(ctx, `DELETE FROM keep_envelope WHERE store_org=$1 AND secret_id=$2`, p.scope.Org, fpKeySecretID)
			} else {
				// RETURN NULL causes a real successful INSERT with zero affected
				// rows; it isolates !inserted from the independent error guard.
				_, err = tx.Exec(ctx, `CREATE FUNCTION intake_refuse_review_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.secret_id='post-decrypt-conflict' THEN RETURN NULL; END IF; RETURN NEW; END $$;
				CREATE TRIGGER intake_refuse_review_insert BEFORE INSERT ON keep_envelope FOR EACH ROW EXECUTE FUNCTION intake_refuse_review_insert()`)
			}
			if err != nil {
				t.Fatal("prepare post-decrypt refusal")
			}
			probe := &intakePostOpenProbe{Tx: tx}
			version, fp, length, err := p.AcceptIntake(ctx, probe, request, "post-decrypt-conflict", enc, ct)
			if !probe.fingerprintRead {
				t.Fatal("post-decrypt failure stage not reached")
			}
			if err == nil || version != "" || fp != "" || length != 0 {
				t.Fatal("post-decrypt refusal accepted")
			}
			if c.In(fmt.Sprintf("%+v", err)) || c.In(logs.String()) {
				t.Fatal("post-decrypt error leaked plaintext")
			}
			if err.Error() != "builtin: intake rejected" {
				t.Fatal("post-decrypt error was not fixed")
			}
			if err := tx.Rollback(ctx); err != nil {
				t.Fatal("rollback refusal")
			}
			// Positive control: identical valid transport is accepted when
			// the post-open failure is absent.
			good, err := pool.BeginTx(ctx, readCommitted)
			if err != nil {
				t.Fatal("begin positive control")
			}
			defer func() { _ = good.Rollback(ctx) }()
			if _, _, n, err := p.AcceptIntake(ctx, good, request, "post-decrypt-control", enc, ct); err != nil || n != len(plain) {
				t.Fatal("post-decrypt acceptance positive control failed")
			}
		})
	}
}

func TestIntakeBundleLength(t *testing.T) {
	for _, n := range []int{95, 96, 97} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			ctx := context.Background()
			pool := testPool(t)
			seal, _ := testSealer(t, pool)
			p := New(pool, seal, sealer.Scope{Org: randID(t, "bundle-length"), User: "alice"}, nil)
			const request = "019a0000-0000-7000-8000-000000000001"
			public, _, _, err := p.IntakeDescriptor(ctx, request, descriptor.Metadata{})
			if err != nil {
				t.Fatal("prepare bundle descriptor")
			}
			plain := []byte(canary.New().Value(1))
			defer clear(plain)
			enc, ct := intakeTestCiphertext(t, public, request, plain)
			key, err := p.intakeKeys(ctx)
			if err != nil {
				t.Fatal("read bundle control")
			}
			defer key.Wipe()
			bundle := make([]byte, n)
			defer clear(bundle)
			secret.Expose(key, func(raw []byte) { copy(bundle, raw) })
			value := secret.New(bundle)
			defer value.Wipe()
			env, err := seal.Seal(ctx, sealer.Ref{Store: p.scope, SecretID: intakeKeySecretID, Name: intakeKeyName, Version: "1"}, value)
			if err != nil {
				t.Fatal("seal malformed authenticated bundle")
			}
			_, err = pool.Exec(ctx, `UPDATE keep_envelope SET kek_id=$1, wrapped_dek=$2, ciphertext=$3 WHERE store_org=$4 AND secret_id=$5`, env.KEKID, env.WrappedDEK, env.Ciphertext, p.scope.Org, intakeKeySecretID)
			if err != nil {
				t.Fatal("replace bundle")
			}
			tx, err := pool.BeginTx(ctx, readCommitted)
			if err != nil {
				t.Fatal("begin bundle probe")
			}
			defer func() { _ = tx.Rollback(ctx) }()
			_, _, _, err = p.AcceptIntake(ctx, tx, request, "bundle-probe", enc, ct)
			if n == 96 && err != nil {
				t.Fatal("valid bundle positive control rejected")
			}
			if n != 96 && err == nil {
				t.Fatal("invalid bundle length accepted")
			}
		})
	}
}

func TestIntakeNilTransaction(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	seal, _ := testSealer(t, pool)
	p := New(pool, seal, sealer.Scope{Org: randID(t, "nil-tx"), User: "alice"}, nil)
	defer func() {
		if recover() != nil {
			t.Error("nil intake transaction reached backend")
		}
	}()
	_, _, _, err := p.AcceptIntake(ctx, nil, "019a0000-0000-7000-8000-000000000001", "probe", make([]byte, 32), make([]byte, 16))
	if err == nil || err.Error() != "builtin: intake rejected" {
		t.Fatal("nil intake transaction accepted")
	}
}
