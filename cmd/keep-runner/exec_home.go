package main

import (
	"errors"
	"os"
	"path/filepath"
)

// readDir is a variable only so a test can make the listing fail on a host
// where the tests run as root and every directory is readable.
var readDir = os.ReadDir

// ownerOf is a variable only so a test can show a foreign owner is refused.
var ownerOf = fileOwner

// checkExecHome requires the child's HOME and working directory to be an
// existing, absolute, empty directory, owned by the runner and closed to
// writing by anyone else, that the runner itself did not put
// anything in: a child with a directory full of the runner's files would
// read them.
func checkExecHome(home string) error {
	if !filepath.IsAbs(home) || filepath.Clean(home) != home {
		return errors.New("exec home must be a clean absolute path")
	}
	fi, err := os.Lstat(home)
	if err != nil || !fi.IsDir() {
		return errors.New("exec home must be an existing directory")
	}
	// The child must not be able to put anything in the root: what it left
	// there would be read by the next child, which runs with another secret.
	if fi.Mode().Perm()&0o022 != 0 {
		return errors.New("exec home must not be writable by group or others")
	}
	if uid, ok := ownerOf(fi); !ok || uid != os.Geteuid() {
		return errors.New("exec home must be owned by the runner's own account")
	}
	ents, err := readDir(home)
	if err != nil || len(ents) != 0 {
		return errors.New("exec home must be empty")
	}
	return nil
}
