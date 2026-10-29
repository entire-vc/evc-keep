package execrun

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/entire-vc/evc-keep/pkg/execpolicy"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

// ErrDenied wraps every refusal made by the host. The reason inside is for
// the host's own log; the one class that leaves the host is policy_denied,
// whatever the reason (threat model 7.2).
var ErrDenied = errors.New("execrun: denied by host policy")

func denied(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrDenied, fmt.Sprintf(format, a...))
}

// Plan is a job turned into something the host may run: the real binary, its
// arguments, and the network mode, all decided by the host's own policy and
// not by the job.
type Plan struct {
	TemplateID string
	// Bin is argv[0] after symlinks, checked again.
	Bin  string
	Args []string
	// SecretEnv are the names the value is placed under.
	SecretEnv []string
	Mode      execpolicy.NetMode
	Dests     []execpolicy.Destination
}

// Prepare decides whether this host runs j and how. It works only from the
// host policy: the job names a template and fills its parameters, and
// nothing in the job can add an argument, a variable or a destination.
func Prepare(j runnerproto.Job, p runnerproto.HostPolicy) (Plan, error) {
	if err := runnerproto.Check(j, p); err != nil {
		return Plan{}, denied("job refused by host policy")
	}
	if j.Action != runnerproto.ActionExec || j.Exec == nil {
		return Plan{}, denied("not an exec job")
	}
	tpl, ok := p.ExecTemplate(j.Exec.TemplateID)
	if !ok {
		return Plan{}, denied("template is not in the host policy")
	}
	if execpolicy.Digest(tpl) != j.Exec.Digest {
		return Plan{}, denied("template digest differs from the host's copy")
	}
	// runnerproto.Check has validated the whole policy, so the template has
	// passed execpolicy.Validate. Exactly the declared parameters: an extra
	// one is a job that means something the template does not say (Expand
	// refuses a missing one).
	if len(j.Exec.Params) != len(tpl.Params) {
		return Plan{}, denied("parameters differ from the template")
	}
	argv, err := execpolicy.Expand(tpl, j.Exec.Params)
	if err != nil {
		return Plan{}, fmt.Errorf("%w: %w", ErrDenied, err)
	}
	real, err := resolveBinary(argv[0], p)
	if err != nil {
		return Plan{}, err
	}
	// The resolved name gets the checks the template name got: a link called
	// tool that leads to python3 is python3.
	again := tpl
	again.Argv = append([]string{real}, tpl.Argv[1:]...)
	if _, err := execpolicy.Validate(again); err != nil {
		return Plan{}, fmt.Errorf("%w: resolved binary: %w", ErrDenied, err)
	}
	return Plan{
		TemplateID: j.Exec.TemplateID,
		Bin:        real,
		Args:       argv[1:],
		SecretEnv:  append([]string(nil), tpl.SecretEnv...),
		Mode:       tpl.Network.Mode,
		Dests:      append([]execpolicy.Destination(nil), tpl.Network.Destinations...),
	}, nil
}

// resolveBinary follows every link in bin and requires the result to be a
// regular, executable file that nobody but its owner can write, owned by no
// agent, inside one of the policy's directories (also resolved).
func resolveBinary(bin string, p runnerproto.HostPolicy) (string, error) {
	real, err := filepath.EvalSymlinks(bin)
	if err != nil {
		return "", denied("binary cannot be resolved")
	}
	if !filepath.IsAbs(real) || filepath.Clean(real) != real {
		return "", denied("resolved path is not clean")
	}
	inside := false
	for _, d := range p.ExecBinDirs {
		rd, err := filepath.EvalSymlinks(d)
		if err != nil {
			continue
		}
		if strings.HasPrefix(real, strings.TrimRight(rd, "/")+"/") {
			inside = true
			break
		}
	}
	if !inside {
		return "", denied("binary is outside the allowed directories")
	}
	fi, err := os.Stat(real)
	if err != nil || !fi.Mode().IsRegular() {
		return "", denied("binary is not a regular file")
	}
	if fi.Mode().Perm()&0o111 == 0 {
		return "", denied("binary is not executable")
	}
	if fi.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return "", denied("binary is setuid or setgid")
	}
	if fi.Mode().IsRegular() && linkCount(fi) != 1 {
		return "", denied("binary has more than one hard link")
	}
	// The file and every directory above it must be unwritable by group and
	// others and not owned by an agent: whoever can write them can swap the
	// file between this check and the exec, or link another program under the
	// name. real is already symlink-free, so the walk is over real entries.
	for d := real; ; d = filepath.Dir(d) {
		di, err := os.Stat(d)
		if err != nil || (d != real && !di.IsDir()) {
			return "", denied("binary path cannot be inspected")
		}
		// A sticky directory (/tmp) lets only an entry's owner rename or
		// remove it, and every entry here is checked for an agent owner.
		if di.Mode().Perm()&0o022 != 0 && (!di.IsDir() || di.Mode()&os.ModeSticky == 0) {
			return "", denied("binary or a directory above it is writable by group or others")
		}
		if uid, ok := ownerUID(di); !ok || containsInt64(p.AgentUIDs, uid) {
			return "", denied("binary or a directory above it is owned by an agent or unknown")
		}
		if parent := filepath.Dir(d); parent == d {
			break
		}
	}
	return real, nil
}

func containsInt64(s []int64, v int64) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
