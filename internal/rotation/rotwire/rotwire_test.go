package rotwire

import (
	"context"
	"testing"

	"github.com/entire-vc/evc-keep/internal/carriers"
	"github.com/entire-vc/evc-keep/internal/rotation"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

const carrierID = "00000000-0000-4000-8000-000000000001"

// The layout of the old version during a rollback must not reuse the layout's
// request id: the deployment store would answer with the finished layout of the
// new version and nothing would be put back.
func TestRollbackDeployIsARequestOfItsOwn(t *testing.T) {
	run := uuid.New()
	plain := deployRequestID(context.Background(), run, carrierID)
	back := deployRequestID(rotation.WithRollback(context.Background()), run, carrierID)
	if plain == back {
		t.Fatal("a rollback layout reuses the id of the layout it undoes")
	}
	if again := deployRequestID(rotation.WithRollback(context.Background()), run, carrierID); again != back {
		t.Fatal("the rollback layout id is not stable, a resumed run would submit it twice")
	}
	if other := deployRequestID(rotation.WithRollback(context.Background()), run, "00000000-0000-4000-8000-000000000002"); other == back {
		t.Fatal("two carriers share a rollback layout id")
	}
	if plain != uuid.NewSHA1(run, []byte("deploy/"+carrierID)).String() {
		t.Fatal("the id of an ordinary layout changed; runs in flight would lay out again")
	}
}

// The read-back of a rollback is pinned to the old version; an ordinary one is
// not pinned and keeps its id.
func TestRollbackVerifyIsPinnedToTheVersionPutBack(t *testing.T) {
	run := uuid.New()
	id, pin := verifyRequestID(context.Background(), run, "2")
	if pin != "" || id != uuid.NewSHA1(run, []byte("verify")).String() {
		t.Fatal("an ordinary verification changed")
	}
	rid, rpin := verifyRequestID(rotation.WithRollback(context.Background()), run, "1")
	if rpin != "1" || rid == id {
		t.Fatal("the rollback verification is not pinned to the old version or reuses the id")
	}
}

// Only a rollback layout carries the marker that gives it headroom above the
// hourly limit; a forward layout never does.
func TestDeployRequestMarksOnlyTheRollbackLayout(t *testing.T) {
	ref := rotation.Ref{OrgID: uuid.New(), SecretID: uuid.New()}
	if deployRequest(context.Background(), ref, secretFacts{}, carriers.Carrier{}, "r", runnerproto.Target{}).Rollback {
		t.Fatal("a forward layout was marked as a rollback")
	}
	if !deployRequest(rotation.WithRollback(context.Background()), ref, secretFacts{}, carriers.Carrier{}, "r", runnerproto.Target{}).Rollback {
		t.Fatal("a rollback layout was not marked")
	}
}
