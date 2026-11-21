//go:build unix

package loop

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

func TestOutboxRefusesBadJobIDs(t *testing.T) {
	ob, err := OpenOutbox(filepath.Join(t.TempDir(), "outbox"))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", "../x", "../../etc/passwd", "a/b", "not-a-uuid", "0190f6a0-0000-4000-8000-000000000000"} {
		if ob.Begin(id) == nil || ob.Ack(id) == nil {
			t.Fatalf("job id %q accepted", id)
		}
	}
}

func TestOutboxRefusesResultOutsideContract(t *testing.T) {
	ob, _ := OpenOutbox(filepath.Join(t.TempDir(), "outbox"))
	if ob.Close(newID(t), runnerproto.Result{ErrorClass: "free-form text"}) == nil {
		t.Fatal("result with an unknown class stored")
	}
}

func TestOutboxRefusesDamagedEntries(t *testing.T) {
	good := `{"job_id":"%s","state":"closed","result":{"ok":false,"error_class":"internal"}}`
	for name, tc := range map[string]struct {
		mode os.FileMode
		body string
		link bool
	}{
		"wide-mode":     {0o644, good, false},
		"extra-field":   {0o600, `{"job_id":"%s","state":"closed","result":{"ok":false,"error_class":"internal"},"note":"x"}`, false},
		"extra-result":  {0o600, `{"job_id":"%s","state":"closed","result":{"ok":false,"error_class":"internal","detail":"x"}}`, false},
		"wrong-id":      {0o600, `{"job_id":"0190f6a0-0000-7000-8000-000000000001","state":"closed","result":{"ok":false,"error_class":"internal"}}`, false},
		"closed-no-res": {0o600, `{"job_id":"%s","state":"closed"}`, false},
		"started-res":   {0o600, `{"job_id":"%s","state":"started","result":{"ok":true}}`, false},
		"unknown-state": {0o600, `{"job_id":"%s","state":"done"}`, false},
		"trailing":      {0o600, good + `{}`, false},
		"symlink":       {0o600, good, true},
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "outbox")
			ob, err := OpenOutbox(dir)
			if err != nil {
				t.Fatal(err)
			}
			id := newID(t)
			body := []byte(sprintfID(tc.body, id))
			p := filepath.Join(dir, id+".json")
			if tc.link {
				target := filepath.Join(t.TempDir(), "elsewhere")
				if err := os.WriteFile(target, body, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, p); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(p, body, tc.mode); err != nil { //nolint:gosec // G306: deliberately unsafe fixture
				t.Fatal(err)
			}
			if err := os.Chmod(p, tc.mode); err != nil && !tc.link { //nolint:gosec // G302: fixture
				t.Fatal(err)
			}
			if _, err := ob.List(); err == nil {
				t.Fatal("damaged entry accepted")
			}
		})
	}
	// Positive control: the same shape, well formed, is read.
	dir := filepath.Join(t.TempDir(), "outbox")
	ob, _ := OpenOutbox(dir)
	id := newID(t)
	if err := ob.Close(id, runnerproto.Result{ErrorClass: runnerproto.ErrClassInternal}); err != nil {
		t.Fatal(err)
	}
	if l, err := ob.List(); err != nil || len(l) != 1 || !l[0].Closed {
		t.Fatalf("well-formed entry: %v %v", l, err)
	}
}

func TestOutboxDirectoryMustBePrivate(t *testing.T) {
	base := t.TempDir()
	wide := filepath.Join(base, "wide")
	if err := os.Mkdir(wide, 0o755); err != nil { //nolint:gosec // G301: deliberately unsafe fixture
		t.Fatal(err)
	}
	if err := os.Chmod(wide, 0o755); err != nil { //nolint:gosec // G302: fixture
		t.Fatal(err)
	}
	if _, err := OpenOutbox(wide); err == nil {
		t.Fatal("0755 outbox accepted")
	}
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenOutbox(link); err == nil {
		t.Fatal("symlinked outbox accepted")
	}
}

func sprintfID(format, id string) string {
	out := ""
	for i := 0; i < len(format); i++ {
		if i+1 < len(format) && format[i] == '%' && format[i+1] == 's' {
			out += id
			i++
			continue
		}
		out += string(format[i])
	}
	return out
}

// A valid report at the contract's size ceiling must survive a restart:
// what CloseDiscover stores, List reads. The worst case uses characters that
// json.Marshal expands to six bytes (&, <), in the longest path and name.
func TestOutboxStoresAndListsLargestValidDiscoverReport(t *testing.T) {
	ob, _ := OpenOutbox(filepath.Join(t.TempDir(), "outbox"))
	key, err := fingerprint.GenerateKey("store1")
	if err != nil {
		t.Fatal(err)
	}
	fp, err := fingerprint.Compute(key, secret.New([]byte(canary.New().Value(0))))
	if err != nil {
		t.Fatal(err)
	}
	r := runnerproto.DiscoverResult{OK: true, Findings: make([]runnerproto.DiscoverFinding, 0, runnerproto.MaxDiscoverFindings)}
	for i := 0; i < runnerproto.MaxDiscoverFindings; i++ {
		p := fmt.Sprintf("/%04d/", i) + strings.Repeat("&", 1012) + "/.e"
		r.Findings = append(r.Findings, runnerproto.DiscoverFinding{Path: p, Name: strings.Repeat("A", 128), Fingerprint: fp, Len: 1 << 20})
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("worst-case report is not valid, test is void: %v", err)
	}
	id := newID(t)
	if err := ob.CloseDiscover(id, r); err != nil {
		t.Fatalf("store: %v", err)
	}
	got, err := ob.List()
	if err != nil || len(got) != 1 || len(got[0].Discover.Findings) != runnerproto.MaxDiscoverFindings {
		t.Fatalf("List after a valid large report: %d entries, err %v", len(got), err)
	}
}

// A non-discover entry between the two caps is refused by List: the larger
// cap belongs to discover entries only.
func TestOutboxRefusesNonDiscoverEntryOverItsCap(t *testing.T) {
	ob, _ := OpenOutbox(filepath.Join(t.TempDir(), "outbox"))
	id := newID(t)
	body := `{"job_id":"` + id + `","state":"closed","result":{"ok":false,"error_class":"internal"}}` + strings.Repeat(" ", maxEntrySize)
	if err := os.WriteFile(filepath.Join(ob.dir, id+".json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ob.List(); err == nil {
		t.Fatal("non-discover entry over 64 KiB read")
	}
}
