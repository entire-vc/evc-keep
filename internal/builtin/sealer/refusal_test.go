package sealer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestEarlyRefusalsAreAudited(t *testing.T) {
	for _, tc := range []struct {
		name, org, actor, reason string
		to                       Level
		purge                    bool
		want                     error
	}{
		{"change-invalid-level", org, "admin", "invalid_level", 0, false, ErrInvalidLevel},
		{"change-empty-org", "", "admin", "invalid_scope", LevelOrg, false, ErrInvalidScope},
		{"change-no-actor", org, "", "no_actor", LevelOrg, false, ErrNoActor},
		{"purge-empty-org", "", "admin", "invalid_scope", 0, true, ErrInvalidScope},
		{"purge-no-actor", org, "", "no_actor", 0, true, ErrNoActor},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, a := newSealer(t)
			st := newMemStore()
			var err error
			action := "key_level_change_denied"
			if tc.purge {
				_, err = s.Purge(context.Background(), tc.org, tc.actor, st)
				action = "kek_purge_failed"
			} else {
				_, err = s.ChangeLevel(context.Background(), LevelChange{RequestID: "req-early", Org: tc.org, Actor: tc.actor, To: tc.to, ConfirmWeakening: true}, st)
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("error = %v, want %v", err, tc.want)
			}
			if len(a.events) != 1 {
				t.Fatalf("got %d audit events, want one", len(a.events))
			}
			e := a.events[0]
			if e.Action != action || e.Reason != tc.reason || e.Org != tc.org || e.Actor != tc.actor || e.From != 0 || e.To != tc.to {
				t.Errorf("wrong early-refusal event: %+v", e)
			}
			if !tc.purge && e.RequestID != "req-early" {
				t.Errorf("refusal names request id %q; want the id of the request it answers", e.RequestID)
			}
			b, err := json.Marshal(e)
			if err != nil || len(b) == 0 {
				t.Fatal("audit capture failed")
			}
			if len(s.store.(*memKEKStore).levels) != 0 {
				t.Fatal("early refusal changed level")
			}
		})
	}
}

func TestRewrapFailureNamesOnlyBlockingIdentifiers(t *testing.T) {
	ctx := context.Background()
	for _, same := range []bool{false, true} {
		t.Run(fmt.Sprint(same), func(t *testing.T) {
			w := newWorld(t)
			r := w.alice[1].ref
			e := w.st.get(r)
			e.WrappedDEK[len(e.WrappedDEK)-1] ^= 1
			w.st.put(r, e)
			to := LevelOrg
			if same {
				to = LevelUser
			}
			_, err := w.s.ChangeLevel(ctx, LevelChange{RequestID: "req-rewrap", Org: org, To: to, Actor: "admin", ConfirmWeakening: true}, w.st)
			if !errors.Is(err, ErrUnwrap) || !errors.Is(err, ErrRewrapIncomplete) {
				t.Fatalf("wrong error class: %v", err)
			}
			if !strings.Contains(err.Error(), `secret_id="a2" version="1"`) {
				t.Fatal("error missing blocking identifiers")
			}
			ev := w.audit.last(t)
			if ev.SecretID != r.SecretID || ev.Version != r.Version || ev.Reason != "rewrap_incomplete" || ev.RequestID != "req-rewrap" {
				t.Fatal("audit missing blocking identifiers")
			}
		})
	}
}
