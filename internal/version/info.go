package version

import (
	"regexp"
	"runtime/debug"
	"time"
)

// Unknown is what Commit reports when no build-time value was injected and
// the Go toolchain recorded none either.
const Unknown = "unknown"

// commitPattern is the only shape Info reports for a commit: a full 40-digit
// lowercase hex object name. Anything else (a short hash, a "-dirty" suffix,
// free text) is not echoed, so the value cannot carry anything but a commit.
var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// BuildInfo is the build identity served by GET /version: the commit the
// binary was built from and when. It carries nothing else on purpose.
type BuildInfo struct {
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
}

// Info resolves the build identity. The -ldflags values win; when Commit was
// not injected it falls back to the vcs.revision the Go toolchain embeds in a
// build made inside a git checkout, and then to Unknown. BuildTime is an
// RFC 3339 timestamp or empty.
func Info() BuildInfo {
	return resolve(Commit, BuildDate, readVCS)
}

// readVCS returns the vcs.revision and vcs.time settings of the running
// binary, or empty strings when the toolchain recorded none.
func readVCS() (revision, vcsTime string) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "", ""
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.time":
			vcsTime = s.Value
		}
	}
	return revision, vcsTime
}

func resolve(commit, buildDate string, vcs func() (string, string)) BuildInfo {
	revision, vcsTime := vcs()

	out := BuildInfo{Commit: Unknown}
	switch {
	case commitPattern.MatchString(commit):
		out.Commit = commit
	case commitPattern.MatchString(revision):
		out.Commit = revision
	}

	for _, candidate := range []string{buildDate, vcsTime} {
		if _, err := time.Parse(time.RFC3339, candidate); err == nil {
			out.BuildTime = candidate
			break
		}
	}
	return out
}
