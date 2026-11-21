package rotwire

import (
	"context"
	"errors"
	"testing"

	"github.com/entire-vc/evc-keep/internal/carriers"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

func TestYAMLRotationRefusesBeforeLookingForWriteEvidence(t *testing.T) {
	d := &Deployer{}
	_, err := d.lastTarget(context.Background(), carriers.Carrier{Metadata: carriers.Metadata{TargetKind: runnerproto.TargetYAMLScalar}})
	if !errors.Is(err, ErrRefused) {
		t.Fatal("read-only YAML carrier accepted for rotation")
	}
}
