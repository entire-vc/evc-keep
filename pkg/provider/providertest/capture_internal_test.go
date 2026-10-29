package providertest

import (
	"context"
	"fmt"
	"github.com/entire-vc/evc-keep/internal/testutil/fdredirect"
	"log/slog"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Keep independent duplicates so a broken restore produces a named test
// failure after diagnostics have been reconnected, rather than EPIPE.
func backupStdio(t *testing.T) func() {
	t.Helper()
	out, err := syscall.Dup(1)
	if err != nil {
		t.Fatal("backup fd1 failed")
	}
	inErr, err := syscall.Dup(2)
	if err != nil {
		_ = syscall.Close(out)
		t.Fatal("backup fd2 failed")
	}
	var once sync.Once
	restore := func() {
		once.Do(func() {
			_ = fdredirect.Dup2(out, 1)
			_ = fdredirect.Dup2(inErr, 2)
			_ = syscall.Close(out)
			_ = syscall.Close(inErr)
		})
	}
	t.Cleanup(restore)
	return restore
}

func sameFD(a, b syscall.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Rdev == b.Rdev
}

func TestCaptureStdio_RestoresDescriptors(t *testing.T) {
	for _, panics := range []bool{false, true} {
		for _, fd := range []int{1, 2} {
			name := fmt.Sprintf("fd%d/panic_%t", fd, panics)
			t.Run(name, func(t *testing.T) {
				restore := backupStdio(t)
				var before, after syscall.Stat_t
				if err := syscall.Fstat(fd, &before); err != nil {
					t.Fatal("fstat before failed")
				}
				recovered := false
				func() {
					defer func() {
						if recover() != nil {
							recovered = true
						}
					}()
					_, _ = captureStdio(func() {
						if panics {
							panic("fixed panic marker")
						}
					})
				}()
				err := syscall.Fstat(fd, &after)
				restore()
				if err != nil || !sameFD(before, after) {
					t.Errorf("fd%d was not restored", fd)
				}
				if recovered != panics {
					t.Error("panic behavior changed")
				}
			})
		}
	}
}

func TestCaptureStdio_StderrOnly(t *testing.T) {
	restore := backupStdio(t)
	out, ok := captureStdio(func() { _, _ = syscall.Write(2, []byte("stderr-only-marker")) })
	restore()
	if !ok || !strings.Contains(out, "stderr-only-marker") {
		t.Fatal("stderr-only output was not captured")
	}
}

// The second setup must remain blocked for the entire first window. Its
// pipe seam fails without touching fds, keeping a missing-lock mutant safe.
func TestCaptureStdio_SecondCaptureBlocks(t *testing.T) {
	restore := backupStdio(t)
	firstEntered, release, firstDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() { _, _ = captureStdio(func() { close(firstEntered); <-release }); close(firstDone) }()
	<-firstEntered
	secondEntered, secondDone := make(chan struct{}), make(chan struct{})
	go func() {
		_, _ = captureStdioWithOps(func() {}, func() (*os.File, *os.File, error) {
			close(secondEntered)
			return nil, nil, fmt.Errorf("planted pipe failure")
		}, redirectFD)
		close(secondDone)
	}()
	overlapped := false
	select {
	case <-secondEntered:
		overlapped = true
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	<-firstDone
	<-secondDone
	restore()
	if overlapped {
		t.Fatal("second capture entered setup while first window was open")
	}
}

// TestCaptureStdio_SerializesConcurrentCaptures is the red run for stdioMu:
// comment out its Lock/Unlock in captureStdio and this test flakes (a
// capture's returned string picks up another goroutine's marker, or misses
// its own) because two goroutines redirect fd 1 out from under each other.
func TestCaptureStdio_SerializesConcurrentCaptures(t *testing.T) {
	const n = 8
	results := make([]string, n)
	oks := make([]bool, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			marker := fmt.Sprintf("marker-%d-only", i)
			out, ok := captureStdio(func() { fmt.Println(marker) })
			results[i], oks[i] = out, ok
		}(i)
	}
	wg.Wait()

	for i, out := range results {
		if !oks[i] {
			t.Errorf("capture %d: setup or drain failed", i)
			continue
		}
		want := fmt.Sprintf("marker-%d-only", i)
		if !strings.Contains(out, want) {
			t.Errorf("capture %d: missing its own marker in %q", i, out)
		}
		for j := range results {
			if j == i {
				continue
			}
			other := fmt.Sprintf("marker-%d-only", j)
			if strings.Contains(out, other) {
				t.Errorf("capture %d: captured goroutine %d's marker %q — concurrent fd redirection is not serialized", i, j, other)
			}
		}
	}
}

// TestCaptureStdio_DrainsLargeOutput is the red run for reading the pipe
// only after fn returns instead of concurrently while it runs: a write
// larger than the OS pipe buffer (commonly 64KB) would then deadlock (the
// provider blocks writing into a full pipe nobody is draining yet) or, with
// a naive one-shot ReadAll, silently truncate.
func TestCaptureStdio_DrainsLargeOutput(t *testing.T) {
	const size = 256 * 1024
	blockOut := strings.Repeat("O", size)
	blockErr := strings.Repeat("E", size)

	done := make(chan struct{})
	var out string
	var ok bool
	go func() {
		out, ok = captureStdio(func() {
			_, _ = fmt.Fprint(os.Stdout, blockOut)
			_, _ = fmt.Fprint(os.Stderr, blockErr)
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("captureStdio deadlocked on output larger than the pipe buffer")
	}

	if !ok {
		t.Fatal("capture reported failure")
	}
	if !strings.Contains(out, blockOut) {
		t.Error("stdout output larger than the pipe buffer was truncated or lost")
	}
	if !strings.Contains(out, blockErr) {
		t.Error("stderr output larger than the pipe buffer was truncated or lost")
	}
}

// TestCaptureStdio_BoundedTimeoutOnStuckDrain is the red run for the
// timeout itself: without it, a pipe write end that outlives fn (a
// goroutine fn spawned and didn't wait for, or a child process fn started
// with its stdio wired to the redirected fd) blocks the drain forever —
// captureStdio must instead report failure within stdioDrainTimeout.
func TestCaptureStdio_BoundedTimeoutOnStuckDrain(t *testing.T) {
	restore := backupStdio(t)
	orig := stdioDrainTimeout
	stdioDrainTimeout = 100 * time.Millisecond
	defer func() { stdioDrainTimeout = orig }()
	fdReady := make(chan int, 1)
	done := make(chan bool, 1)
	start := time.Now()
	go func() {
		_, ok := captureStdio(func() {
			fd, err := syscall.Dup(1)
			if err != nil {
				fd = -1
			}
			fdReady <- fd
		})
		done <- ok
	}()
	fd := <-fdReady
	timedOut := false
	var ok bool
	select {
	case ok = <-done:
	case <-time.After(time.Second):
		timedOut = true
		if fd >= 0 {
			_ = syscall.Close(fd)
			fd = -1
		}
		select {
		case ok = <-done:
		case <-time.After(time.Second):
			restore()
			t.Fatal("capture did not recover after watchdog released writer")
		}
	}
	if fd >= 0 {
		_ = syscall.Close(fd)
	}
	restore()
	if timedOut {
		t.Fatal("drain watchdog fired: timeout did not bound capture")
	}
	if ok {
		t.Fatal("stuck drain reported a verified capture")
	}
	if time.Since(start) < stdioDrainTimeout {
		t.Fatal("drain returned before timeout")
	}
}

// Inspect bytes written by the factory, never Go variable identity.
func TestRunOne_FactoryRunsInsideCaptureWindow(t *testing.T) {
	var captured string
	res := runOneWithCapture(context.Background(), func(_ *slog.Logger) Harness {
		_, _ = syscall.Write(1, []byte("factory-fd1-marker"))
		_, _ = syscall.Write(2, []byte("factory-fd2-marker"))
		return Harness{}
	}, check{name: "factory-window", run: func(*env) {}}, func(fn func()) (string, bool) {
		out, ok := captureStdio(fn)
		captured = out
		return out, ok
	})
	if res.Failed() || !strings.Contains(captured, "factory-fd1-marker") || !strings.Contains(captured, "factory-fd2-marker") {
		t.Fatal("factory output escaped capture window")
	}
}
