package providertest

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/entire-vc/evc-keep/pkg/provider/memory"
)

func TestRunOne_SetupFailureDoesNotRunProvider(t *testing.T) {
	for _, stage := range []string{"pipe", "fd1", "fd2"} {
		t.Run(stage, func(t *testing.T) {
			restore := backupStdio(t)
			var before, after, beforeErr, afterErr syscall.Stat_t
			if err := syscall.Fstat(1, &before); err != nil {
				t.Fatal("fstat before failed")
			}
			if err := syscall.Fstat(2, &beforeErr); err != nil {
				t.Fatal("fstat stderr before failed")
			}
			calls, runs := 0, 0
			factory := func(l *slog.Logger) Harness { calls++; return Harness{Provider: memory.New(l)} }
			pipe := func() (*os.File, *os.File, error) {
				if stage == "pipe" {
					return nil, nil, errors.New("planted pipe failure")
				}
				return os.Pipe()
			}
			redirect := func(fd int, w *os.File) (func() error, error) {
				if (stage == "fd1" && fd == 1) || (stage == "fd2" && fd == 2) {
					return nil, errors.New("planted redirect failure")
				}
				return redirectFD(fd, w)
			}
			res := runOneWithCapture(context.Background(), factory, check{name: stage, run: func(*env) { runs++ }}, func(fn func()) (string, bool) {
				return captureStdioWithOps(fn, pipe, redirect)
			})
			err := syscall.Fstat(1, &after)
			errErr := syscall.Fstat(2, &afterErr)
			restore()
			if err != nil || !sameFD(before, after) {
				t.Error("failed setup did not restore stdout")
			}
			if errErr != nil || !sameFD(beforeErr, afterErr) {
				t.Error("failed setup did not preserve stderr")
			}
			if calls != 0 || runs != 0 {
				t.Error("provider was invoked without verified stdio capture")
			}
			if !res.Failed() || !strings.Contains(strings.Join(res.Violations, " "), "stdio leak capture") || res.Skipped != "" {
				t.Error("setup failure was not classified as a capture violation")
			}
		})
	}
}

func TestRunOne_CaptureFailureIsViolation(t *testing.T) {
	for _, c := range checks {
		res := runOneWithCapture(context.Background(), func(l *slog.Logger) Harness {
			p := memory.New(l)
			return Harness{Provider: p, SetUnavailable: p.SetUnavailable}
		}, c, func(fn func()) (string, bool) {
			out, _ := captureStdio(fn)
			return out, false
		})
		if !res.Failed() || res.Skipped != "" || !strings.Contains(strings.Join(res.Violations, " "), "stdio leak capture") {
			t.Errorf("%s accepted an unverified capture", c.name)
		}
	}
}

func TestRunOne_CapturePositiveControl(t *testing.T) {
	for _, res := range Check(context.Background(), func(l *slog.Logger) Harness {
		p := memory.New(l)
		return Harness{Provider: p, SetUnavailable: p.SetUnavailable}
	}) {
		if res.Failed() || res.Skipped != "" {
			t.Errorf("%s rejected a verified reference provider", res.Check)
		}
	}
}

func TestRunOne_CaptureFailureOverridesSkip(t *testing.T) {
	for _, verified := range []bool{true, false} {
		res := runOneWithCapture(context.Background(), func(*slog.Logger) Harness { return Harness{} }, check{
			name: "skipped-capability", run: func(e *env) { e.skip("control capability skip") },
		}, func(fn func()) (string, bool) {
			out, _ := captureStdio(fn)
			return out, verified
		})
		if verified {
			if res.Failed() || res.Skipped != "control capability skip" {
				t.Error("verified capability skip was not preserved")
			}
		} else if !res.Failed() || res.Skipped != "" {
			t.Error("unverified capture retained a skip that hides the violation in Run")
		}
	}
}
