//go:build unix

package execrun

import (
	"errors"
	"os/exec"
	"syscall"
	"time"
)

// setupProc gives the child its own process group and has a timeout kill the
// whole group, so a child that forks does not outlive the run.
func setupProc(cmd *exec.Cmd) {
	// A core file of the child would hold its environment; the runner has no
	// use for cores either, and the limit is inherited.
	_ = syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{})
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
}

// killGroup ends every process the child started and left behind.
func killGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

// dropToChild makes the child run as uid:gid with no supplementary groups.
// Only root can; anyone else keeps the runner's account, so it is refused.
func dropToChild(cmd *exec.Cmd, uid, gid uint32) error {
	if geteuid() != 0 {
		return errors.New("the host cannot give the child its own account without root")
	}
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}
	return nil
}
