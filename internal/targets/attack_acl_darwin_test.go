//go:build darwin

//nolint:gosec,errcheck // attack fixtures live in a temp dir, setup errors are irrelevant to the assertion, and the fuzz seed must be reproducible
package targets_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/entire-vc/evc-keep/internal/targets"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

func aclOn(t *testing.T, path, ace string) {
	t.Helper()
	if out, err := exec.Command("/bin/chmod", "+a", ace, path).CombinedOutput(); err != nil {
		t.Skipf("cannot set ACL here: %v %s", err, out)
	}
}

// R-POL-4 on macOS: an ACL that hands another principal access is refused, on
// the target's directory and on the existing target, for every writing kind.
func TestTargetsAttack_DarwinACLVariants(t *testing.T) {
	type c struct {
		name, ace string
		onDir     bool
	}
	cases := []c{
		{"dir-user-read", "user:daemon allow list,search,readattr", true},
		{"dir-user-write", "user:daemon allow add_file,delete_child", true},
		{"dir-inherit", "user:daemon allow read,file_inherit,directory_inherit", true},
		{"dir-everyone", "everyone allow read", true},
		{"file-user-read", "user:daemon allow read", false},
		{"file-everyone-write", "everyone allow write", false},
	}
	for _, kind := range []runnerproto.TargetKind{runnerproto.TargetFile, runnerproto.TargetEnvFile} {
		for _, tc := range cases {
			t.Run(string(kind)+"/"+tc.name, func(t *testing.T) {
				d := dir(t)
				p := filepath.Join(d, "svc.env")
				os.WriteFile(p, []byte("A=1\n"), 0o600)
				if tc.onDir {
					aclOn(t, d, tc.ace)
				} else {
					aclOn(t, p, tc.ace)
				}
				field := "NAME"
				if kind == runnerproto.TargetFile {
					// runnerproto.Target.Validate rejects any non-empty field on
					// TargetFile ("field is not used by file") before the write
					// reaches ACL checking at all. A hardcoded "NAME" here made
					// every file/* subtest pass for that unrelated reason instead
					// of exercising checkDirACL/checkACL, which made the ACL
					// guard on this kind untested (found reviewing MR !31).
					field = ""
				}
				_, err := targets.Write(tgt(kind, p, field), secret.New([]byte("v")), nil, nil, fpKey(t))
				got, _ := os.ReadFile(p)
				if !tc.onDir && kind == runnerproto.TargetFile {
					// `file` never reads the old file and replaces the inode: an ACL on the
					// old one dies with it, so a successful write must not carry it over.
					if err == nil {
						if out, _ := exec.Command("/bin/ls", "-le", p).Output(); len(out) > 0 && bytes.Count(out, []byte("\n")) > 1 {
							t.Errorf("new file inherited the ACL: %s", out)
						}
					}
					return
				}
				if err == nil {
					t.Errorf("write accepted with ACL %q", tc.ace)
				}
				if string(got) != "A=1\n" {
					t.Errorf("target changed despite refusal: %q", got)
				}
			})
		}
	}
}
