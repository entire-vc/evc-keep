// Package version carries build-time metadata injected via -ldflags.
// It never carries secret material — it is safe to log and to return
// from any API surface.
package version

var (
	// Version is the build version, set via -ldflags at release time.
	Version = "0.0.0-dev"
	// Commit is the short VCS commit hash, set via -ldflags.
	Commit = "unknown"
	// BuildDate is the RFC3339 build timestamp, set via -ldflags.
	BuildDate = "unknown"
)

// String renders a single human-readable build identifier.
func String() string {
	return Version + " (" + Commit + ", built " + BuildDate + ")"
}
