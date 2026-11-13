//go:build unix

package transfercarrier

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

func privDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "carriers")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func mustRefuse(t *testing.T, name string, err error, reason string, secrets ...string) {
	t.Helper()
	var ce Error
	if !errors.As(err, &ce) || ce.Reason != reason {
		t.Errorf("%s: want refusal %q, got %v", name, reason, err)
		return
	}
	shown := fmt.Sprintf("%v|%+v|%#v|%s", err, err, err, err.Error())
	for _, s := range secrets {
		if strings.Contains(shown, s) {
			t.Errorf("%s: refusal reflects %q", name, s)
		}
	}
}

func TestCreateAndReadRoundTrip(t *testing.T) {
	d := privDir(t)
	c := canary.New()
	data := []byte(c.Value(0))
	p := filepath.Join(d, "recipient.key")
	if err := Create(p, data); err != nil {
		t.Fatalf("positive control failed: %v", err)
	}
	fi, err := os.Lstat(p)
	if err != nil || fi.Mode().Perm() != 0o600 || !fi.Mode().IsRegular() {
		t.Fatal("carrier is not a regular 0600 file")
	}
	got, err := Read(p, 1<<10)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("read back failed: %v", err)
	}
	left, _ := filepath.Glob(filepath.Join(d, ".keep-transfer-*"))
	if len(left) != 0 {
		t.Fatal("temporary file left behind")
	}
}

func TestCreateNeverReplacesAndNeverReflects(t *testing.T) {
	d := privDir(t)
	c := canary.New()
	secret := c.Value(0)
	other := filepath.Join(t.TempDir(), "other")
	if err := os.WriteFile(other, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	existing := filepath.Join(d, "existing")
	if err := os.WriteFile(existing, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(d, "link")
	if err := os.Symlink(other, link); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(d, "dangling")
	if err := os.Symlink(filepath.Join(d, "nowhere"), dangling); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(d, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	dirLoose := filepath.Join(t.TempDir(), "loose")
	if err := os.Mkdir(dirLoose, 0o755); err != nil { //nolint:gosec // G301: a deliberately loose directory, to prove it is refused
		t.Fatal(err)
	}
	if err := os.Chmod(dirLoose, 0o777); err != nil { //nolint:gosec // G302: a deliberately loose directory, to prove it is refused
		t.Fatal(err)
	}
	dirLink := filepath.Join(t.TempDir(), "dirlink")
	if err := os.Symlink(d, dirLink); err != nil {
		t.Fatal(err)
	}

	for name, c := range map[string]struct{ path, reason string }{
		"existing file":      {existing, "exists"},
		"symlink to file":    {link, "exists"},
		"dangling symlink":   {dangling, "exists"},
		"fifo":               {fifo, "exists"},
		"relative":           {"rel-input.bin", "path"},
		"traversal":          {d + "/../x", "path"},
		"group-writable dir": {filepath.Join(dirLoose, "x"), "directory"},
		"symlinked dir":      {filepath.Join(dirLink, "x"), "directory"},
		"missing dir":        {filepath.Join(d, "no", "x"), "directory"},
	} {
		mustRefuse(t, name, Create(c.path, []byte(secret)), c.reason, secret, c.path, d)
	}
	for path, want := range map[string]string{existing: "original", other: "original"} {
		b, _ := os.ReadFile(path) //nolint:gosec // G304: test path
		if string(b) != want {
			t.Fatal("a refused create changed an existing file")
		}
	}
	if fi, _ := os.Lstat(fifo); fi.Mode()&os.ModeNamedPipe == 0 {
		t.Fatal("fifo was replaced")
	}
	left, _ := filepath.Glob(filepath.Join(d, ".keep-transfer-*"))
	if len(left) != 0 {
		t.Fatal("temporary file left behind after refusals")
	}
}

func TestReadRefusals(t *testing.T) {
	d := privDir(t)
	good := filepath.Join(d, "good")
	if err := os.WriteFile(good, []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(good, 10); err != nil {
		t.Fatalf("positive control failed: %v", err)
	}
	groupRead := filepath.Join(d, "groupread")
	if err := os.WriteFile(groupRead, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(groupRead, 0o640); err != nil { //nolint:gosec // G302: a deliberately group-readable file, to prove it is refused
		t.Fatal(err)
	}
	link := filepath.Join(d, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(d, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		path   string
		max    int64
		reason string
	}{
		"oversize":       {good, 9, "size"},
		"group readable": {groupRead, 10, "mode"},
		"symlink":        {link, 10, "open"},
		"fifo":           {fifo, 10, "not_regular"},
		"directory":      {d, 10, "not_regular"},
		"missing":        {filepath.Join(d, "none"), 10, "open"},
		"relative":       {"good", 10, "path"},
		"bad max":        {good, 0, "path"},
	} {
		_, err := Read(c.path, c.max)
		mustRefuse(t, name, err, c.reason, c.path)
	}
}

func TestDestroyZeroesThenRemoves(t *testing.T) {
	dir := privDir(t)
	path := filepath.Join(dir, "k")
	data := []byte(canary.New().Value(0))
	if err := Create(path, data); err != nil {
		t.Fatal(err)
	}
	// A second name for the same inode shows what is left on disk.
	alias := filepath.Join(dir, "alias")
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	if err := Destroy(path); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("carrier still present")
	}
	left, err := os.ReadFile(alias) //nolint:gosec // G304: test path
	if err != nil || len(left) != len(data) || bytes.Count(left, []byte{0}) != len(data) {
		t.Fatalf("content was not zeroed before removal: %v", err)
	}
	if err := Destroy(path); err == nil {
		t.Error("destroying an absent carrier succeeded")
	}
}

func TestDestroyRefusals(t *testing.T) {
	dir := privDir(t)
	target := filepath.Join(dir, "t")
	if err := Create(target, []byte("x")); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "l")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	loose := filepath.Join(dir, "loose")
	if err := os.WriteFile(loose, []byte("x"), 0o644); err != nil { //nolint:gosec // G306: test fixture with loose mode
		t.Fatal(err)
	}
	for name, c := range map[string]struct{ path, reason string }{
		"relative": {"rel", "path"},
		"symlink":  {link, "open"},
		"mode":     {loose, "mode"},
		"dir":      {dir, "open"},
	} {
		err := Destroy(c.path)
		var e Error
		if !errors.As(err, &e) || (name != "dir" && e.Reason != c.reason) {
			t.Errorf("%s: want refusal %s, got %v", name, c.reason, err)
		}
	}
	if b, err := os.ReadFile(target); err != nil || string(b) != "x" { //nolint:gosec // G304: test path
		t.Error("a refused destroy touched the symlink target")
	}
}
