package version

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	sha1hex = "0123456789abcdef0123456789abcdef01234567"
	sha2hex = "fedcba9876543210fedcba9876543210fedcba98"
)

func vcsOf(revision, vcsTime string) func() (string, string) {
	return func() (string, string) { return revision, vcsTime }
}

func TestResolve(t *testing.T) {
	cases := []struct {
		name      string
		commit    string
		buildDate string
		vcs       func() (string, string)
		want      BuildInfo
	}{
		{"injected wins over vcs", sha1hex, "2026-10-26T01:02:03Z", vcsOf(sha2hex, "2020-01-01T00:00:00Z"),
			BuildInfo{Commit: sha1hex, BuildTime: "2026-10-26T01:02:03Z"}},
		{"vcs fallback when not injected", Unknown, Unknown, vcsOf(sha2hex, "2020-01-01T00:00:00Z"),
			BuildInfo{Commit: sha2hex, BuildTime: "2020-01-01T00:00:00Z"}},
		{"nothing known", Unknown, Unknown, vcsOf("", ""),
			BuildInfo{Commit: Unknown, BuildTime: ""}},
		{"short hash is not reported", "0123abc", "", vcsOf("", ""),
			BuildInfo{Commit: Unknown}},
		{"free text is not reported", "v1.2.3-dirty", "yesterday", vcsOf("", ""),
			BuildInfo{Commit: Unknown}},
		{"uppercase hex is not reported", strings.ToUpper(sha1hex), "", vcsOf("", ""),
			BuildInfo{Commit: Unknown}},
		{"bad injected value falls back to vcs", "garbage", "garbage", vcsOf(sha2hex, ""),
			BuildInfo{Commit: sha2hex}},
		{"bad vcs revision is not reported", Unknown, Unknown, vcsOf("not-a-sha", "not-a-time"),
			BuildInfo{Commit: Unknown}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := resolve(c.commit, c.buildDate, c.vcs); got != c.want {
				t.Fatalf("resolve = %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestInfoShape(t *testing.T) {
	raw, err := json.Marshal(Info())
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 {
		t.Fatalf("BuildInfo JSON has %d keys, want exactly commit and build_time: %s", len(m), raw)
	}
	for _, k := range []string{"commit", "build_time"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("BuildInfo JSON lacks %q: %s", k, raw)
		}
	}
}
