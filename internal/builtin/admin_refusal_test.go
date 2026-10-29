package builtin

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

func TestChangeLevel_CorruptEnvelopeIdentifiesVersionAndEraseRecovers(t *testing.T) {
	for _, attack := range []string{"corrupt", "substitute", "same-kek"} {
		t.Run(attack, func(t *testing.T) {
			ctx := context.Background()
			pool := testPool(t)
			seal, audit := testSealer(t, pool)
			org := randID(t, "org")
			scope := sealer.Scope{Org: org, User: "alice"}
			p := New(pool, seal, scope, nil)
			var logs bytes.Buffer
			admin := NewAdmin(pool, seal, org, slog.New(obs.NewHandler(&logs, slog.LevelDebug)))
			c := canary.New()
			if !c.In(c.Value(1)) {
				t.Fatal("blind canary detector")
			}
			for i := 1; i <= 2; i++ {
				if _, err := p.Write(ctx, providerRef("blocked"), secretOf(c.Value(i))); err != nil {
					t.Fatal(err)
				}
			}
			v, _, err := p.Resolve(ctx, providerRefVersion("blocked", "1"))
			if err != nil || !v.Equal(secretOf(c.Value(1))) {
				t.Fatal("original envelope positive control failed")
			}
			to := sealer.LevelOrg
			if attack == "same-kek" {
				to = sealer.LevelUser
			}
			row, err := p.db.byVersion(ctx, scope, "blocked", 1)
			if err != nil {
				t.Fatal(err)
			}
			bad := append([]byte(nil), row.wrapped...)
			if attack == "substitute" {
				other, err := p.db.byVersion(ctx, scope, "blocked", 2)
				if err != nil {
					t.Fatal(err)
				}
				bad = other.wrapped
			} else {
				bad[len(bad)-1] ^= 1
			}
			tag, err := pool.Exec(ctx, `UPDATE keep_envelope SET wrapped_dek=$1 WHERE store_org=$2 AND secret_id='blocked' AND version=1`, bad, org)
			if err != nil || tag.RowsAffected() != 1 {
				t.Fatal("SQL attack did not affect exactly one row")
			}
			_, err = admin.ChangeLevel(ctx, to, "admin", true)
			if err == nil {
				t.Fatal("tampered envelope accepted")
			}
			if !errors.Is(err, sealer.ErrRewrapIncomplete) || !errors.Is(err, sealer.ErrUnwrap) {
				t.Fatal("lost rewrap/unwrap error classes")
			}
			for _, marker := range []string{"rewrap_incomplete", `secret_id="blocked"`, `version="1"`} {
				if !strings.Contains(err.Error(), marker) {
					t.Errorf("error missing %s", marker)
				}
			}
			if len(audit.events) != 1 {
				t.Fatalf("got %d audit events, want one", len(audit.events))
			}
			b, marshalErr := json.Marshal(audit.events[0])
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			var event map[string]any
			if err := json.Unmarshal(b, &event); err != nil {
				t.Fatal(err)
			}
			if event["SecretID"] != "blocked" || event["Version"] != "1" || event["Reason"] != "rewrap_incomplete" {
				t.Error("audit missing blocking identifiers")
			}
			for field := range event {
				switch field {
				case "Action", "Org", "Actor", "SecretID", "Version", "From", "To", "Rewrapped", "Unchanged", "Retired", "Purged", "Reason", "RequestID":
				default:
					t.Fatalf("unexpected audit field %s", field)
				}
			}
			if logs.Len() == 0 {
				t.Fatal("log capture is empty")
			}
			if c.In(string(b)) || c.In(logs.String()) || c.In(fmt.Sprintf("%v %+v %#v", err, err, err)) {
				t.Fatal("value leaked on admin surface")
			}
			queue := []error{err}
			for len(queue) != 0 {
				cause := queue[0]
				queue = queue[1:]
				if many, ok := cause.(interface{ Unwrap() []error }); ok {
					queue = append(queue, many.Unwrap()...)
				} else if next := errors.Unwrap(cause); next != nil {
					queue = append(queue, next)
				}
				if c.In(fmt.Sprintf("%v %+v %#v", cause, cause, cause)) {
					t.Fatal("value leaked in error chain")
				}
			}
			for _, material := range [][]byte{row.wrapped, bad, row.cipher} {
				for _, encoded := range []string{string(material), hex.EncodeToString(material), base64.StdEncoding.EncodeToString(material), base64.RawURLEncoding.EncodeToString(material)} {
					if strings.Contains(string(b)+logs.String()+fmt.Sprintf("%v %+v %#v", err, err, err), encoded) {
						t.Fatal("envelope bytes leaked")
					}
				}
			}
			if err := p.Erase(ctx, providerRefVersion("blocked", "1")); err != nil {
				t.Fatal(err)
			}
			if _, err := admin.ChangeLevel(ctx, to, "admin", true); err != nil {
				t.Fatal(err)
			}
			v, _, err = p.Resolve(ctx, providerRefVersion("blocked", "2"))
			if err != nil || !v.Equal(secretOf(c.Value(2))) {
				t.Fatal("healthy version no longer resolves")
			}
		})
	}
}
