package memory_test

import (
	"log/slog"
	"testing"

	"github.com/entire-vc/evc-keep/pkg/provider/memory"
	"github.com/entire-vc/evc-keep/pkg/provider/providertest"
)

func TestConformance(t *testing.T) {
	providertest.Run(t, func(log *slog.Logger) providertest.Harness {
		p := memory.New(log)
		return providertest.Harness{Provider: p, SetUnavailable: p.SetUnavailable}
	})
}
