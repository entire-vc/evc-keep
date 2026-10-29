//go:build unix

package targets

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

const samplePlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>vc.entire.keep-runner</string>
	<key>EnvironmentVariables</key>
	<dict>
		<key>OTHER</key>
		<string>untouched</string>
	</dict>
	<key>RunAtLoad</key>
	<true/>
</dict>
</plist>
`

func TestLaunchdEnvSetsKeyLeavesRestUntouched(t *testing.T) {
	dir := realDir(t)
	path := filepath.Join(dir, "vc.entire.keep-runner.plist")
	mustWriteFile(t, path, []byte(samplePlist), 0o600)

	uids, gids := noAgents()
	if _, err := Write(target(runnerproto.TargetLaunchdEnv, path, "API_KEY"), newValue("s3cr3t&<>\"'"), uids, gids, testFPKey(t)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := string(mustReadFile(t, path))
	for _, want := range []string{
		"<key>Label</key>",
		"<string>vc.entire.keep-runner</string>",
		"<key>OTHER</key>",
		"<string>untouched</string>",
		"<key>RunAtLoad</key>",
		"<true/>",
		"<key>API_KEY</key>",
		"<string>s3cr3t&amp;&lt;&gt;&#34;&#39;</string>",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("written plist missing %q; got %s", want, show([]byte(got)))
		}
	}
}

func TestLaunchdEnvReplacesExistingKey(t *testing.T) {
	dir := realDir(t)
	path := filepath.Join(dir, "x.plist")
	mustWriteFile(t, path, []byte(samplePlist), 0o600)

	uids, gids := noAgents()
	if _, err := Write(target(runnerproto.TargetLaunchdEnv, path, "OTHER"), newValue("new-value"), uids, gids, testFPKey(t)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := string(mustReadFile(t, path))
	if strings.Contains(got, "untouched") {
		t.Fatalf("old value was not replaced: %s", show([]byte(got)))
	}
	if !strings.Contains(got, "<key>OTHER</key>\n\t\t<string>new-value</string>") {
		t.Fatalf("new value not found in expected place: %s", show([]byte(got)))
	}
}

func TestLaunchdEnvMissingTargetRefused(t *testing.T) {
	dir := realDir(t)
	path := filepath.Join(dir, "nope.plist")
	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetLaunchdEnv, path, "X"), newValue("v"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrWrite, "launchd-env target does not exist")
	if !strings.Contains(err.Error(), "does not exist yet") {
		t.Fatalf("wrong reason: %v", err)
	}
}

// TestLaunchdEnvMissingTargetRefusedDirect isolates the !exists check in
// build from the rest of Write's pipeline: with the check removed, an empty
// existing content still reaches locateEnvDict, which also refuses (no
// <key>EnvironmentVariables</key> dict in empty content) — through the same
// ErrWrite sentinel, so only the message text tells the two apart. Calling
// build directly keeps that distinction meaningful without depending on the
// rest of Write (filesystem walk, temp file, read-back) to get there.
func TestLaunchdEnvMissingTargetRefusedDirect(t *testing.T) {
	_, err := launchdEnvHandler{}.build(nil, false, target(runnerproto.TargetLaunchdEnv, "/unused", "X"), newValue("v"))
	wantErr(t, err, ErrWrite, "launchd-env target does not exist")
	if !strings.Contains(err.Error(), "does not exist yet") {
		t.Fatalf("wrong reason: %v", err)
	}
}

func TestLaunchdEnvNoEnvironmentVariablesKeyRefused(t *testing.T) {
	dir := realDir(t)
	path := filepath.Join(dir, "noenv.plist")
	mustWriteFile(t, path, []byte("<plist><dict><key>Label</key><string>x</string></dict></plist>"), 0o600)
	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetLaunchdEnv, path, "X"), newValue("v"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrWrite, "plist without EnvironmentVariables key")
	if !strings.Contains(err.Error(), "has no") {
		t.Fatalf("wrong reason: %v", err)
	}
}

const plistEmptyEnvDict = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>vc.entire.keep-runner</string>
	<key>EnvironmentVariables</key>
	<dict/>
	<key>Sockets</key>
	<dict>
		<key>Listeners</key>
		<dict>
			<key>SockNodeName</key>
			<string>127.0.0.1</string>
		</dict>
	</dict>
</dict>
</plist>
`

// TestLaunchdEnvEmptyDictNotSpilledIntoNextDict: with an empty
// `<dict/>` for EnvironmentVariables, the first `<dict>` after the key is
// somebody else's (Sockets here). The value must not be written into it —
// and readBack must not then "confirm" it there, which would turn a wrong
// placement into a matching fingerprint.
func TestLaunchdEnvEmptyDictNotSpilledIntoNextDict(t *testing.T) {
	dir := realDir(t)
	path := filepath.Join(dir, "x.plist")
	mustWriteFile(t, path, []byte(plistEmptyEnvDict), 0o600)

	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetLaunchdEnv, path, "API_KEY"), newValue("the-value"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrWrite, "EnvironmentVariables is an empty <dict/>")
	if got := string(mustReadFile(t, path)); got != plistEmptyEnvDict {
		t.Fatalf("plist changed despite the refusal:\n%s", show([]byte(got)))
	}
}

// TestLaunchdEnvReadBackScopedToEnvironmentDict calls readBack directly: the
// field exists in another dict of the plist, not in EnvironmentVariables.
func TestLaunchdEnvReadBackScopedToEnvironmentDict(t *testing.T) {
	plist := `<plist><dict>
<key>EnvironmentVariables</key><dict><key>OTHER</key><string>a</string></dict>
<key>Sockets</key><dict><key>API_KEY</key><string>not-the-env-value</string></dict>
</dict></plist>`
	_, err := launchdEnvHandler{}.readBack([]byte(plist), target(runnerproto.TargetLaunchdEnv, "/x", "API_KEY"))
	wantErr(t, err, ErrWrite, "field present only outside EnvironmentVariables")
}

// TestLaunchdEnvExistingNonStringEntryRefused: a key that already exists
// with a non-string value must not be silently duplicated by appending.
func TestLaunchdEnvExistingNonStringEntryRefused(t *testing.T) {
	plist := `<plist><dict>
<key>EnvironmentVariables</key><dict><key>API_KEY</key><integer>1</integer></dict>
</dict></plist>`
	dir := realDir(t)
	path := filepath.Join(dir, "x.plist")
	mustWriteFile(t, path, []byte(plist), 0o600)
	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetLaunchdEnv, path, "API_KEY"), newValue("v"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrWrite, "existing key with a non-string value")
	if got := string(mustReadFile(t, path)); got != plist {
		t.Fatalf("plist changed despite the refusal:\n%s", show([]byte(got)))
	}
}

// TestLaunchdEnvExistingEmptyStringReplaced: `<string/>` (empty) is a
// perfectly ordinary existing value; a search for the next "<string>" would
// jump over it into the following entry.
func TestLaunchdEnvExistingEmptyStringReplaced(t *testing.T) {
	plist := `<plist><dict>
<key>EnvironmentVariables</key><dict><key>API_KEY</key><string/><key>NEXT</key><string>keep</string></dict>
</dict></plist>`
	dir := realDir(t)
	path := filepath.Join(dir, "x.plist")
	mustWriteFile(t, path, []byte(plist), 0o600)
	uids, gids := noAgents()
	if _, err := Write(target(runnerproto.TargetLaunchdEnv, path, "API_KEY"), newValue("the-value"), uids, gids, testFPKey(t)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	want := `<plist><dict>
<key>EnvironmentVariables</key><dict><key>API_KEY</key><string>the-value</string><key>NEXT</key><string>keep</string></dict>
</dict></plist>`
	if got := string(mustReadFile(t, path)); got != want {
		t.Fatalf("got %s, want %s", show([]byte(got)), show([]byte(want)))
	}
}

// TestLaunchdEnvCommentInsideDictRefused: a comment inside the dict that
// contains "</dict>" would end the dict early, and the entry would be
// written inside the comment — invisible to launchd, yet found by a text
// search on read-back.
func TestLaunchdEnvCommentInsideDictRefused(t *testing.T) {
	plist := `<plist><dict>
<key>EnvironmentVariables</key><dict><!-- </dict> --><key>OTHER</key><string>a</string></dict>
</dict></plist>`
	dir := realDir(t)
	path := filepath.Join(dir, "x.plist")
	mustWriteFile(t, path, []byte(plist), 0o600)
	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetLaunchdEnv, path, "API_KEY"), newValue("v"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrWrite, "comment inside EnvironmentVariables")
	if got := string(mustReadFile(t, path)); got != plist {
		t.Fatalf("plist changed despite the refusal:\n%s", show([]byte(got)))
	}
}

// TestLaunchdEnvDuplicateEntryRefused: two entries for the same key in the
// dict — refuse rather than choose one.
func TestLaunchdEnvDuplicateEntryRefused(t *testing.T) {
	plist := `<plist><dict>
<key>EnvironmentVariables</key><dict><key>API_KEY</key><string>a</string><key>API_KEY</key><string>b</string></dict>
</dict></plist>`
	dir := realDir(t)
	path := filepath.Join(dir, "x.plist")
	mustWriteFile(t, path, []byte(plist), 0o600)
	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetLaunchdEnv, path, "API_KEY"), newValue("v"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrWrite, "duplicate entry for the field")
	if got := string(mustReadFile(t, path)); got != plist {
		t.Fatalf("plist changed despite the refusal:\n%s", show([]byte(got)))
	}
}

// TestLaunchdEnvFingerprintRoundTripsThroughXMLEscaping: the fingerprint is
// derived from what read-back extracts from the plist, so the escaped form
// must decode to exactly the original bytes.
func TestLaunchdEnvFingerprintRoundTripsThroughXMLEscaping(t *testing.T) {
	dir := realDir(t)
	path := filepath.Join(dir, "x.plist")
	mustWriteFile(t, path, []byte(samplePlist), 0o600)
	uids, gids := noAgents()
	key := testFPKey(t)
	const val = "s3cr3t&<>\"'\n\ttail"
	fp, err := Write(target(runnerproto.TargetLaunchdEnv, path, "API_KEY"), newValue(val), uids, gids, key)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	want, err := fingerprint.Compute(key, newValue(val))
	if err != nil {
		t.Fatal(err)
	}
	if fp != want {
		t.Fatalf("fingerprint of what was read back %q != fingerprint of the value %q", fp, want)
	}
}

// TestLaunchdEnvRefusalsDoNotEchoNeighbours: every refusal in the
// EnvironmentVariables dict is exercised with a canary sitting in a
// neighbouring entry; none of the error texts may carry it.
func TestLaunchdEnvRefusalsDoNotEchoNeighbours(t *testing.T) {
	c := canary.New()
	n := c.Value(0)
	for name, plist := range map[string]string{
		"non-string": `<plist><dict><key>EnvironmentVariables</key><dict><key>NEIGH</key><string>` + n + `</string><key>API_KEY</key><integer>1</integer></dict></dict></plist>`,
		"duplicate":  `<plist><dict><key>EnvironmentVariables</key><dict><key>NEIGH</key><string>` + n + `</string><key>API_KEY</key><string>a</string><key>API_KEY</key><string>b</string></dict></dict></plist>`,
		"unclosed":   `<plist><dict><key>EnvironmentVariables</key><dict><key>NEIGH</key><string>` + n + `</string><key>API_KEY</key><string>a`,
		"comment":    `<plist><dict><key>EnvironmentVariables</key><dict><!-- ` + n + ` </dict> --></dict></dict></plist>`,
		"empty-dict": `<plist><dict><key>EnvironmentVariables</key><dict/><key>X</key><string>` + n + `</string></dict></plist>`,
		"not-a-dict": `<plist><dict><key>EnvironmentVariables</key><string>` + n + `</string></dict></plist>`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(realDir(t), "x.plist")
			mustWriteFile(t, path, []byte(plist), 0o600)
			uids, gids := noAgents()
			_, err := Write(target(runnerproto.TargetLaunchdEnv, path, "API_KEY"), newValue("v"), uids, gids, testFPKey(t))
			if err == nil {
				t.Fatal("expected a refusal")
			}
			if c.In(err.Error()) {
				t.Fatalf("neighbour content leaked into the error: %v", err)
			}
		})
	}
}

// TestLaunchdEnvKeyInsideCommentBeforeRealKeyRefused: a comment that holds a
// copy of the EnvironmentVariables key, ahead of the real one, must not be
// taken for it — the value would be written inside the comment, invisible to
// launchd, yet found by the text search on read-back with a matching
// fingerprint.
func TestLaunchdEnvKeyInsideCommentBeforeRealKeyRefused(t *testing.T) {
	plist := `<plist><dict>
<!-- <key>EnvironmentVariables</key><dict><key>OTHER</key><string>a</string></dict> -->
<key>EnvironmentVariables</key><dict><key>OTHER</key><string>b</string></dict>
</dict></plist>`
	dir := realDir(t)
	path := filepath.Join(dir, "x.plist")
	mustWriteFile(t, path, []byte(plist), 0o600)
	uids, gids := noAgents()
	if _, err := Write(target(runnerproto.TargetLaunchdEnv, path, "API_KEY"), newValue("the-value"), uids, gids, testFPKey(t)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := string(mustReadFile(t, path))
	want := `<plist><dict>
<!-- <key>EnvironmentVariables</key><dict><key>OTHER</key><string>a</string></dict> -->
<key>EnvironmentVariables</key><dict><key>OTHER</key><string>b</string><key>API_KEY</key><string>the-value</string></dict>
</dict></plist>`
	if got != want {
		t.Fatalf("value went to the wrong place:\n%s", show([]byte(got)))
	}
}

// The dict must be what follows the key, and hold plain entries only.
func TestLaunchdEnvKeyFollowedByStringRefused(t *testing.T) {
	plist := `<plist><dict><key>EnvironmentVariables</key><string>x</string><key>Sockets</key><dict><key>A</key><string>b</string></dict></dict></plist>`
	path := filepath.Join(realDir(t), "x.plist")
	mustWriteFile(t, path, []byte(plist), 0o600)
	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetLaunchdEnv, path, "API_KEY"), newValue("v"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrWrite, "EnvironmentVariables key followed by a non-dict")
	if got := string(mustReadFile(t, path)); got != plist {
		t.Fatalf("plist changed despite the refusal:\n%s", show([]byte(got)))
	}
}

func TestLaunchdEnvNestedContainerRefused(t *testing.T) {
	for name, inner := range map[string]string{
		"dict":  `<key>NESTED</key><dict><key>A</key><string>b</string></dict>`,
		"array": `<key>NESTED</key><array><string>b</string></array>`,
	} {
		t.Run(name, func(t *testing.T) {
			plist := `<plist><dict><key>EnvironmentVariables</key><dict>` + inner + `</dict></dict></plist>`
			path := filepath.Join(realDir(t), "x.plist")
			mustWriteFile(t, path, []byte(plist), 0o600)
			uids, gids := noAgents()
			_, err := Write(target(runnerproto.TargetLaunchdEnv, path, "API_KEY"), newValue("v"), uids, gids, testFPKey(t))
			wantErr(t, err, ErrWrite, "nested container in EnvironmentVariables")
			if got := string(mustReadFile(t, path)); got != plist {
				t.Fatalf("plist changed despite the refusal:\n%s", show([]byte(got)))
			}
		})
	}
}

func TestLaunchdEnvUnclosedRefused(t *testing.T) {
	for name, plist := range map[string]string{
		"dict":   `<plist><dict><key>EnvironmentVariables</key><dict><key>A</key><string>b</string>`,
		"string": `<plist><dict><key>EnvironmentVariables</key><dict><key>API_KEY</key><string>b</dict></dict></plist>`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(realDir(t), "x.plist")
			mustWriteFile(t, path, []byte(plist), 0o600)
			uids, gids := noAgents()
			_, err := Write(target(runnerproto.TargetLaunchdEnv, path, "API_KEY"), newValue("v"), uids, gids, testFPKey(t))
			wantErr(t, err, ErrWrite, "unclosed element")
			if got := string(mustReadFile(t, path)); got != plist {
				t.Fatalf("plist changed despite the refusal:\n%s", show([]byte(got)))
			}
		})
	}
}
