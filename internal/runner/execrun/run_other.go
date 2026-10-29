//go:build !unix

package execrun

import (
	"errors"
	"os/exec"
)

func setupProc(*exec.Cmd) {}

func killGroup(*exec.Cmd) {}

func dropToChild(*exec.Cmd, uint32, uint32) error {
	return errors.New("the host cannot give the child its own account")
}
