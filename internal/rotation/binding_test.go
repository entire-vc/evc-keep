package rotation

import (
	"testing"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/google/uuid"
)

// The approval binding names the whole request: a change in any field is a
// different hash, bytes moved between fields are a different hash, and the
// rotation binding is never the target key or a deployment binding.
func TestRotationBinding_CoversEveryFieldAndIsUnambiguous(t *testing.T) {
	org, sec, run := uuid.New(), uuid.New(), uuid.New()
	a := audit.Actor{Type: audit.ActorUser, ID: "u1", SponsorID: "s1", Via: audit.ViaAPI}
	base := rotationBinding(org, sec, run, a)
	if base != rotationBinding(org, sec, run, a) {
		t.Fatal("the binding is not deterministic")
	}
	variants := map[string][32]byte{
		"org":     rotationBinding(uuid.New(), sec, run, a),
		"secret":  rotationBinding(org, uuid.New(), run, a),
		"run":     rotationBinding(org, sec, uuid.New(), a),
		"type":    rotationBinding(org, sec, run, audit.Actor{Type: audit.ActorAgent, ID: "u1", SponsorID: "s1", Via: audit.ViaAPI}),
		"id":      rotationBinding(org, sec, run, audit.Actor{Type: audit.ActorUser, ID: "u2", SponsorID: "s1", Via: audit.ViaAPI}),
		"sponsor": rotationBinding(org, sec, run, audit.Actor{Type: audit.ActorUser, ID: "u1", SponsorID: "s2", Via: audit.ViaAPI}),
		"via":     rotationBinding(org, sec, run, audit.Actor{Type: audit.ActorUser, ID: "u1", SponsorID: "s1", Via: audit.ViaMCP}),
		"target":  rotationTargetKey(org, sec),
	}
	for name, h := range variants {
		if h == base {
			t.Fatalf("the binding ignores %s", name)
		}
	}
	if bind("d", "ab", "c") == bind("d", "a", "bc") {
		t.Fatal("bytes moved between fields give the same hash")
	}
	if bind("keep/rotate/request/v1", "x") == bind("keep/deploy/request/v1", "x") {
		t.Fatal("a rotation and a deployment binding share a hash")
	}
}
