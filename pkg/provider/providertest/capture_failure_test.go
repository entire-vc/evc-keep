package providertest

import (
	"context"
	"io"
	"log/slog"
	"os"
	"syscall"
	"testing"

	externalCanary "github.com/entire-vc/evc-keep/internal/testutil/canary"
)

func TestCaptureStdio_ReadFailureIsUnverified(t *testing.T) {
	restore := backupStdio(t)
	c := externalCanary.New()
	var r, retained *os.File
	pipe := func() (*os.File, *os.File, error) {
		var w *os.File
		var err error
		r, w, err = os.Pipe()
		if err != nil {
			return nil, nil, err
		}
		conn, err := r.SyscallConn()
		if err != nil {
			_ = r.Close()
			_ = w.Close()
			return nil, nil, err
		}
		fd := -1
		controlErr := conn.Control(func(raw uintptr) { fd, err = syscall.Dup(int(raw)) })
		if controlErr != nil || err != nil {
			_ = r.Close()
			_ = w.Close()
			if controlErr != nil {
				return nil, nil, controlErr
			}
			return nil, nil, err
		}
		retained = os.NewFile(uintptr(fd), "retained-reader")
		return r, w, nil
	}
	wrote := false
	out, ok := captureStdioWithOps(func() {
		// The duplicate keeps the pipe readable after the capture reader
		// fails, proving that a successful write can still be missed.
		_ = r.Close()
		n, err := syscall.Write(1, []byte(c.Value(1)))
		wrote = err == nil && n == len(c.Value(1))
	}, pipe, redirectFD)
	restore()
	if retained == nil {
		t.Fatal("reader failure control could not be set up")
	}
	defer func() { _ = retained.Close() }()
	missed, err := io.ReadAll(retained)
	if err != nil || !wrote || !c.In(string(missed)) || c.In(out) {
		t.Fatal("control did not prove a successful write missed by capture")
	}
	if ok {
		t.Fatal("read failure was reported as a verified capture")
	}
}

func TestCaptureStdio_RestoreFailureIsUnverified(t *testing.T) {
	restore := backupStdio(t)
	c := externalCanary.New()
	savedOut := -1
	redirect := func(fd int, to *os.File) (func() error, error) {
		if fd == 1 {
			// Reserve the next descriptor to identify redirectFD's Dup.
			probe, err := syscall.Dup(1)
			if err != nil {
				return nil, err
			}
			_ = syscall.Close(probe)
			savedOut = probe
		}
		return redirectFD(fd, to)
	}
	out, ok := captureStdioWithOps(func() {
		_, _ = syscall.Write(2, []byte(c.Value(1)))
		_ = syscall.Close(savedOut)
		_ = syscall.Close(1)
	}, os.Pipe, redirect)
	var state syscall.Stat_t
	restoreErr := syscall.Fstat(1, &state)
	restore()
	if !c.In(out) || restoreErr == nil {
		t.Fatal("control did not prove captured output and a real restore failure")
	}
	if ok {
		t.Fatal("restore failure was reported as a verified capture")
	}
}

func TestCaptureStdio_ReadRestorePositiveControl(t *testing.T) {
	restore := backupStdio(t)
	c := externalCanary.New()
	var before, after syscall.Stat_t
	if syscall.Fstat(1, &before) != nil {
		t.Fatal("cannot stat initial stdout")
	}
	out, ok := captureStdio(func() { _, _ = syscall.Write(2, []byte(c.Value(1))) })
	err := syscall.Fstat(1, &after)
	restore()
	if !ok || err != nil || !sameFD(before, after) || !c.In(out) {
		t.Fatal("valid capture failed to read output or restore stdout")
	}
}

func TestRunOne_LeakOverridesSkip(t *testing.T) {
	for _, channel := range []string{"stdout", "stderr", "logger", "control"} {
		t.Run(channel, func(t *testing.T) {
			var logger *slog.Logger
			res := runOne(context.Background(), func(l *slog.Logger) Harness {
				logger = l
				return Harness{}
			}, check{name: "leak-then-skip", run: func(e *env) {
				switch channel {
				case "stdout":
					_, _ = syscall.Write(1, []byte(e.canary.base))
				case "stderr":
					_, _ = syscall.Write(2, []byte(e.canary.base))
				case "logger":
					logger.Info("control", "value", e.canary.base)
				}
				e.skip("capability skip control")
			}})
			if channel == "control" {
				if res.Failed() || res.Skipped != "capability skip control" {
					t.Fatal("clean verified capability skip was not preserved")
				}
			} else if !res.Failed() || res.Skipped != "" {
				t.Fatal("detected leak retained a skip that hides violations in Run")
			}
		})
	}
}
