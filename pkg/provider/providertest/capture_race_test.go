package providertest

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"testing"

	"github.com/entire-vc/evc-keep/pkg/provider/memory"
)

// Concurrent process output must not race with a conformance check. Only
// harmless fixed markers are printed; the provider never prints values.
func TestCaptureStdio_ConcurrentCheckAndPrint(t *testing.T) {
	// A variable-swap mutant may close the writer a parallel print retained.
	// Let the race detector report the fault instead of dying with SIGPIPE.
	signal.Ignore(syscall.SIGPIPE)
	t.Cleanup(func() { signal.Reset(syscall.SIGPIPE) })
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for range 5000 {
			_, _ = fmt.Fprint(os.Stdout, "parallel-output-marker\n")
			_, _ = fmt.Fprint(os.Stderr, "parallel-error-marker\n")
			runtime.Gosched()
		}
	}()
	close(start)
	for range 20 {
		for _, res := range Check(context.Background(), func(l *slog.Logger) Harness {
			p := memory.New(l)
			return Harness{Provider: p, SetUnavailable: p.SetUnavailable}
		}) {
			if res.Failed() || res.Skipped != "" {
				t.Errorf("reference provider check %s failed or skipped", res.Check)
			}
		}
	}
	wg.Wait()
}
