package version

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

// The production image is built from a source archive without .git, so the
// commit only reaches the binary through the Dockerfile's -X flags. These
// tests keep those flags pointed at variables that exist: a rename here
// without the Dockerfile would silently turn /version into "unknown".

// ldflagTargets returns the "<import path>.<Var>" targets of the -X flags in text.
func ldflagTargets(text string) []string {
	var out []string
	fields := strings.Fields(strings.ReplaceAll(text, "'", " "))
	for i, f := range fields {
		if f == "-X" && i+1 < len(fields) {
			target, _, _ := strings.Cut(fields[i+1], "=")
			out = append(out, target)
		}
	}
	return out
}

func wiredTo(text string, want ...string) []string {
	have := map[string]bool{}
	for _, t := range ldflagTargets(text) {
		have[t] = true
	}
	var missing []string
	for _, w := range want {
		if !have[w] {
			missing = append(missing, w)
		}
	}
	return missing
}

func TestBuildFilesInjectCommitAndDate(t *testing.T) {
	pkg := reflect.TypeOf(BuildInfo{}).PkgPath()
	want := []string{pkg + ".Commit", pkg + ".BuildDate"}
	for _, file := range []string{"../../Dockerfile", "../../Makefile"} {
		raw, err := os.ReadFile(file) //nolint:gosec // G304: file is one of two constant repository paths from the loop above
		if err != nil {
			t.Fatal(err)
		}
		// The Makefile spells the module path through a variable.
		text := strings.ReplaceAll(string(raw), "$(MODULE)", "github.com/entire-vc/evc-keep")
		if missing := wiredTo(text, want...); len(missing) > 0 {
			t.Errorf("%s does not inject %v with -ldflags -X", file, missing)
		}
	}
}

func TestDockerfileTakesCommitFromBuildArg(t *testing.T) {
	raw, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{"ARG BUILD_COMMIT", "version.Commit=${BUILD_COMMIT}", "ARG BUILD_TIME", "version.BuildDate=${BUILD_TIME}"} {
		if !strings.Contains(text, want) {
			t.Errorf("Dockerfile lacks %q", want)
		}
	}
}

// Red run: the matcher reports a flag that points at a renamed variable.
func TestLdflagTargetsRedRun(t *testing.T) {
	stale := `go build -ldflags="-s -w -X github.com/entire-vc/evc-keep/internal/version.Rev=${X}"`
	if missing := wiredTo(stale, "github.com/entire-vc/evc-keep/internal/version.Commit"); len(missing) != 1 {
		t.Fatalf("matcher accepted a flag for a variable that does not exist: %v", missing)
	}
}
