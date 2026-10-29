//go:build discover_wipecheck

package discover

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/entire-vc/evc-keep/pkg/secret"
)

// Only the disposable, instrumented tree calls these observers. Retaining an
// array before cleanup makes a removed wipe observable without unsafe reads,
// production callbacks, timing assumptions, or exposing its contents.
var wipeCheck struct {
	sync.Mutex
	active  bool
	buffers [][]byte
	dirty   int
}

func observeBytes(b []byte) []byte {
	wipeCheck.Lock()
	defer wipeCheck.Unlock()
	if wipeCheck.active && cap(b) > 0 {
		wipeCheck.buffers = append(wipeCheck.buffers, b[:cap(b)])
		if !bytes.Equal(b, make([]byte, len(b))) {
			wipeCheck.dirty++
		}
	}
	return b
}
func observeAppend(old, next []byte) []byte {
	observeBytes(old)
	return observeBytes(next)
}
func observeSecret(v secret.Value) secret.Value {
	secret.Expose(v, func(b []byte) { observeBytes(b) })
	return v
}
func startWipeCheck(t *testing.T) {
	t.Helper()
	wipeCheck.Lock()
	wipeCheck.active = true
	wipeCheck.buffers = nil
	wipeCheck.dirty = 0
	wipeCheck.Unlock()
	probe := observeAppend(nil, []byte("synthetic-observer-control"))
	wipe(probe)
	v := observeSecret(secret.New([]byte("synthetic-secret-control")))
	v.Wipe()
	controlCount := len(wipeCheck.buffers)
	t.Cleanup(func() {
		wipeCheck.Lock()
		defer wipeCheck.Unlock()
		wipeCheck.active = false
		if len(wipeCheck.buffers) <= controlCount || wipeCheck.dirty == 0 {
			t.Error("buffer observer did not see its positive control")
		}
		for i, b := range wipeCheck.buffers {
			if !bytes.Equal(b, make([]byte, len(b))) {
				t.Errorf("retained buffer %d was not zeroed", i)
			}
		}
		wipeCheck.buffers = nil
	})
}

// Build independent bplist objects; repeated references can exhaust the decoded
// budget even though the on-disk value occurs only once.
func wipePlist(objects [][]byte) []byte {
	data := []byte("bplist00")
	offsets := []byte{}
	for _, object := range objects {
		offsets = binary.BigEndian.AppendUint16(offsets, uint16(len(data))) //nolint:gosec // Bounded test fixtures.
		data = append(data, object...)
	}
	table := len(data)
	data = append(data, offsets...)
	trailer := make([]byte, 32)
	trailer[6], trailer[7] = 2, 1
	binary.BigEndian.PutUint64(trailer[8:16], uint64(len(objects)))
	binary.BigEndian.PutUint64(trailer[24:32], uint64(table))
	return append(data, trailer...)
}
func fixtureByte(n int) byte {
	if n < 0 || n > 255 {
		panic("fixture exceeds one-byte object length")
	}
	return byte(n)
}
func asciiObject(s string) []byte {
	if len(s) < 15 {
		return append([]byte{0x50 | fixtureByte(len(s))}, s...)
	}
	return append([]byte{0x5f, 0x10, fixtureByte(len(s))}, s...)
}
func TestWipeLifecycle(t *testing.T) {
	k := key(t, "scan")
	long := strings.Repeat("synthetic", 40)
	for _, tc := range []struct {
		name string
		kind Kind
		body string
		bad  bool
	}{
		{"env", EnvFile, "API_KEY=" + long, false},
		{"env-error-word", EnvFile, "API_KEY=" + long + "$", true},
		{"env-error-tail", EnvFile, "API_KEY=" + long + " trailing", true},
		{"env-error-double-space", EnvFile, "API_KEY=\"" + long + "\\ tail\"", true},
		{"env-error-double-tab", EnvFile, "API_KEY=\"" + long + "\\\ttail\"", true},
		{"env-error-double-single-quote", EnvFile, "API_KEY=\"" + long + "\\'tail\"", true},
		{"env-error-partial", EnvFile, "API_KEY=" + long + "\nBROKEN", true},
		{"credential", Credential, long, false},
		{"unit", SystemdUnit, "[Service]\nEnvironment=API_KEY=" + long, false},
		{"unit-reset", SystemdUnit, "[Service]\nEnvironment=API_KEY=" + long + "\nEnvironment=\nEnvironment=API_KEY=synthetic", false},
		{"unit-error-word", SystemdUnit, "[Service]\nEnvironment=API_KEY=" + long + "%", true},
		{"unit-error-name", SystemdUnit, "[Service]\nEnvironment=123=" + long, true},
		{"json", MCPConfig, `{"mcpServers":{"a":{"env":{"API_KEY":"` + long + `\uD83D\uDD11"}}}}`, false},
		{"json-error-surrogate", MCPConfig, `{"mcpServers":{"a":{"env":{"API_KEY":"` + long + `\uD800"}}}}`, true},
		{"json-error-key", MCPConfig, `{"mcpServers":{"a":{"env":{"` + strings.Repeat("A", 257) + `":"synthetic"}}}}`, true},
		{"json-error-duplicate", MCPConfig, `{"mcpServers":{"a":{"env":{"API_KEY":"` + long + `","API_KEY":"synthetic"}}}}`, true},
		{"xml", LaunchdPlist, `<plist><dict><key>EnvironmentVariables</key><dict><key>API_KEY</key><string>` + long + `</string></dict></dict></plist>`, false},
		{"xml-error", LaunchdPlist, `<plist><dict><key>EnvironmentVariables</key><dict><key>API_KEY</key><string>` + long + `</string><key>BROKEN</key></dict></dict></plist>`, true},
		{"bplist", LaunchdPlist, string(wipePlist([][]byte{{0xd1, 1, 2}, asciiObject("EnvironmentVariables"), {0xd1, 3, 4}, asciiObject("API_KEY"), asciiObject("synthetic")})), false},
		{"bplist-error-name", LaunchdPlist, string(wipePlist([][]byte{{0xd1, 1, 2}, asciiObject("EnvironmentVariables"), {0xd1, 3, 4}, asciiObject("123"), asciiObject("synthetic")})), true},
		{"bplist-error-utf16", LaunchdPlist, string(wipePlist([][]byte{{0xd1, 1, 2}, asciiObject("EnvironmentVariables"), {0xd1, 3, 4}, asciiObject("API_KEY"), {0x63, 0, 0x61, 0, 0x62, 0xd8, 0}})), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureDir(t)
			put(t, root, "carrier", tc.body)
			startWipeCheck(t)
			got, err := Scan(context.Background(), policy(root, tc.kind, "carrier"), k)
			if tc.bad {
				if err == nil || len(got) != 0 {
					t.Fatal("error fixture accepted")
				}
			} else if err != nil || len(got) != 1 {
				t.Fatal("wipe fixture control refused")
			}
		})
	}
	// A shared long object referenced repeatedly exceeds the decoding budget.
	refs := []byte{0xdf, 0x10, 10}
	refs = append(refs, bytes.Repeat([]byte{3}, 10)...)
	refs = append(refs, bytes.Repeat([]byte{4}, 10)...)
	t.Run("bplist-error-budget", func(t *testing.T) {
		root := fixtureDir(t)
		put(t, root, "carrier", string(wipePlist([][]byte{{0xd1, 1, 2}, asciiObject("EnvironmentVariables"), refs, asciiObject("API_KEY"), asciiObject(strings.Repeat("x", 80))})))
		startWipeCheck(t)
		if got, err := Scan(context.Background(), policy(root, LaunchdPlist, "carrier"), k); err == nil || len(got) != 0 {
			t.Fatal("budget fixture accepted")
		}
	})
}

func TestWipeReadErrors(t *testing.T) {
	for _, tc := range []struct {
		name        string
		data        string
		size, limit int64
		want        error
	}{
		{"growth", "synthetic-growth", 3, 8, ErrSize},
		{"short", "synthetic", 16, 32, ErrRead},
	} {
		t.Run(tc.name, func(t *testing.T) {
			startWipeCheck(t)
			b, err := readSized(bytes.NewReader([]byte(tc.data)), tc.size, tc.limit)
			if !errors.Is(err, tc.want) || len(b) != 0 {
				t.Fatal("read error fixture accepted")
			}
		})
	}
}

// Every escape is placed exactly at a growth boundary. Long strings whose
// escapes fit spare capacity cannot witness wiping the abandoned array.
func TestWipeGrowthBoundaries(t *testing.T) {
	k := key(t, "scan")
	prefix := strings.Repeat("x", 128)
	for _, tc := range []struct{ name, escape string }{
		{"quote", `\"`}, {"backslash", `\\`}, {"slash", `\/`},
		{"backspace", `\b`}, {"formfeed", `\f`}, {"newline", `\n`}, {"return", `\r`}, {"tab", `\t`}, {"unicode", `\u0061`},
	} {
		t.Run("json-"+tc.name, func(t *testing.T) {
			root := fixtureDir(t)
			put(t, root, "carrier", `{"mcpServers":{"a":{"env":{"API_KEY":"`+prefix+tc.escape+`"}}}}`)
			startWipeCheck(t)
			if got, err := Scan(context.Background(), policy(root, MCPConfig, "carrier"), k); err != nil || len(got) != 1 {
				t.Fatal("JSON boundary fixture refused")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		object []byte
		bad    bool
	}{
		{"bplist-growth", append(append([]byte{0x6f, 0x10, 129}, bytes.Repeat([]byte{0, 'x'}, 128)...), 0, 'a'), false},
		{"bplist-error-low-surrogate", []byte{0x64, 0, 'a', 0, 'b', 0xd8, 0, 0, 'c'}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureDir(t)
			put(t, root, "carrier", string(wipePlist([][]byte{{0xd1, 1, 2}, asciiObject("EnvironmentVariables"), {0xd1, 3, 4}, asciiObject("API_KEY"), tc.object})))
			startWipeCheck(t)
			got, err := Scan(context.Background(), policy(root, LaunchdPlist, "carrier"), k)
			if tc.bad {
				if !errors.Is(err, ErrParse) || len(got) != 0 {
					t.Fatal("malformed UTF16 admitted")
				}
			} else if err != nil || len(got) != 1 {
				t.Fatal("UTF16 growth control refused")
			}
		})
	}
	t.Run("xml-growth", func(t *testing.T) {
		root := fixtureDir(t)
		// Separate character-data tokens force the second append to grow.
		put(t, root, "carrier", `<plist><dict><key>EnvironmentVariables</key><dict><key>API_KEY</key><string><![CDATA[`+prefix+`]]>a</string></dict></dict></plist>`)
		startWipeCheck(t)
		if got, err := Scan(context.Background(), policy(root, LaunchdPlist, "carrier"), k); err != nil || len(got) != 1 {
			t.Fatal("XML boundary fixture refused")
		}
	})
}
