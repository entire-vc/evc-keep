//go:build unix

package targets

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

// The red runs below are about Write trusting its own input: the caller is
// expected to have validated the job, but a writer that appends a line, or
// splices XML, *before* noticing the Field is malformed has already done the
// damage. Each case asserts the refusal AND that the target on disk is
// byte-for-byte what it was.

func TestWriteRejectsXMLInjectionInLaunchdField(t *testing.T) {
	dir := realDir(t)
	path := filepath.Join(dir, "x.plist")
	mustWriteFile(t, path, []byte(samplePlist), 0o600)
	before := mustReadFile(t, path)

	tg := target(runnerproto.TargetLaunchdEnv, path, "X</key><string>1</string><key>Y")
	uids, gids := noAgents()
	_, err := Write(tg, newValue("v"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrPolicy, "launchd field carrying XML")
	if got := mustReadFile(t, path); !bytes.Equal(got, before) {
		t.Fatalf("plist changed despite the refusal:\n%s", show([]byte(got)))
	}
}

func TestWriteRejectsNewlineInEnvFileField(t *testing.T) {
	dir := realDir(t)
	path := filepath.Join(dir, "svc.env")
	mustWriteFile(t, path, []byte("KEEP=1\nOTHER=2\n"), 0o600)
	before := mustReadFile(t, path)

	tg := target(runnerproto.TargetEnvFile, path, "A=1\nB")
	uids, gids := noAgents()
	_, err := Write(tg, newValue("v"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrPolicy, "env-file field carrying a newline")
	if got := mustReadFile(t, path); !bytes.Equal(got, before) {
		t.Fatalf("env-file changed despite the refusal:\n%s", show([]byte(got)))
	}
}

func TestWriteRejectsNegativeOwner(t *testing.T) {
	dir := realDir(t)
	for _, tc := range []struct {
		name     string
		uid, gid int64
	}{
		{"negative-uid", -1, selfGID()},
		{"negative-gid", selfUID(), -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name)
			tg := target(runnerproto.TargetFile, path, "")
			tg.UID, tg.GID = tc.uid, tc.gid
			uids, gids := noAgents()
			_, err := Write(tg, newValue("v"), uids, gids, testFPKey(t))
			wantErr(t, err, ErrPolicy, "negative owner")
		})
	}
}

// A format that cannot represent a byte must refuse it, not store something
// else: xml.EscapeText turns a control character into U+FFFD and
// json.Marshal turns invalid UTF-8 into U+FFFD, and the fingerprint would then
// be computed from the altered value, so nothing would say the deployed
// secret is not the one that was sent.
func TestValueNotRepresentableInFormatIsRefused(t *testing.T) {
	c := canary.New()
	for name, tc := range map[string]struct {
		kind     runnerproto.TargetKind
		field    string
		file     string
		existing string
		value    string
	}{
		"launchd-control-char": {runnerproto.TargetLaunchdEnv, "API_KEY", "x.plist", samplePlist, c.Value(0) + "\x01tail"},
		"json-invalid-utf8":    {runnerproto.TargetMCPConfig, "mcpServers.s.env.KEY", "mcp.json", `{"a":"b"}`, c.Value(0) + "\xfftail"},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(realDir(t), tc.file)
			mustWriteFile(t, path, []byte(tc.existing), 0o600)
			uids, gids := noAgents()
			_, err := Write(target(tc.kind, path, tc.field), newValue(tc.value), uids, gids, testFPKey(t))
			wantErr(t, err, ErrPolicy, "value the format cannot hold byte for byte")
			if c.In(err.Error()) {
				t.Fatalf("value leaked into the error: %v", err)
			}
			if got := string(mustReadFile(t, path)); got != tc.existing {
				t.Fatalf("target changed despite the refusal:\n%s", show([]byte(got)))
			}
		})
	}
}
