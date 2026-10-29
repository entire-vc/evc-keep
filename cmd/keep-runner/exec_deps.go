package main

import (
	"github.com/entire-vc/evc-keep/internal/runner/execrun"
)

// newExecDeps is the host's fixed side of exec_with_secret: the child's home
// and the namespace isolator (which enforces nothing off Linux, so there
// allowlist templates are refused and none templates run only if the policy
// says exec_net_unenforced). Whatever a crashed run left behind is removed
// first.
func newExecDeps(home string, uid, gid uint32) (*execrun.Deps, error) {
	if err := checkExecHome(home); err != nil {
		return nil, err
	}
	return &execrun.Deps{Iso: newIsolator(uid, gid), HomeRoot: home, ChildUID: uid, ChildGID: gid, CorePiped: execCorePiped, Chown: execChown}, nil
}

// execCorePiped is nil in the runner (the host is read); a test sets it, as
// its CI host may pipe core dumps to a handler.
var execCorePiped func() bool

// execChown is nil in the runner (os.Chown); a test sets it, as it cannot
// give a directory to another account.
var execChown func(string, int, int) error

// newIsolator is the host's network isolator, after removing whatever a
// crashed run left behind. A variable so a test can stand in for the kernel.
var newIsolator = func(uid, gid uint32) execrun.Isolator {
	iso := &execrun.Netns{ChildUID: uid, ChildGID: gid}
	iso.Sweep()
	return iso
}

// execSetup validates the exec flags and builds the host's side of
// exec_with_secret; a non-empty message is the fixed text to fail with.
func execSetup(uid, gid uint, home string) (*execrun.Deps, string) {
	if uid == 0 || gid == 0 {
		return nil, "-exec-uid and -exec-gid are required when the policy allows exec"
	}
	if home == "" {
		return nil, "-exec-home is required when the policy allows exec"
	}
	d, err := newExecDeps(home, uint32(uid), uint32(gid)) //nolint:gosec // G115: flag values are ids
	if err != nil {
		return nil, "exec home is unusable"
	}
	return d, ""
}
