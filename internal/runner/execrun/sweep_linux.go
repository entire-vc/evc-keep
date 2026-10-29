//go:build linux

package execrun

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// sweepAccount ends every process of the child's account, then removes what
// that account left in the shared temporary directories. A child that left its
// process group (setsid) is still the child's account, and a survivor would
// hold the value in its environment and could read the next child's.
func sweepAccount(uid uint32) error {
	if uid == 0 || int(uid) == os.Geteuid() {
		return errors.New("the child account is the runner's or root")
	}
	for attempt := 0; ; attempt++ {
		n := killAccount(uid)
		if n == 0 {
			break
		}
		if attempt >= 50 {
			return errors.New("processes of the child account survive")
		}
		time.Sleep(10 * time.Millisecond)
	}
	var err error
	for _, dir := range sharedDirs {
		err = errors.Join(err, removeOwned(dir, uid))
	}
	return err
}

// sharedDirs are the places any account can write to; what the child's
// account left there is removed, nested directories included (a world-writable
// subdirectory such as /tmp/.X11-unix would otherwise keep a file readable by
// the agents).
var sharedDirs = []string{"/tmp", "/var/tmp", "/dev/shm", "/run/lock", "/var/lock", "/dev/mqueue", "/var/crash"}

// accountClear fails when any process of the child's account is alive: it
// could read the next child's environment, and the sweep after the last run
// should have left none.
func accountClear(uid uint32) error {
	if uid == 0 || int(uid) == os.Geteuid() {
		return errors.New("the child account is the runner's or root")
	}
	if n := killAccountCount(uid, false); n != 0 {
		return errors.New("processes of the child account are alive before the run")
	}
	return nil
}

// corePipedToAHandler reports whether the kernel hands cores to a program
// (core_pattern starting with a pipe): the limit of 0 does not stop that, and
// systemd-coredump records the crashed process's environment in the journal.
func corePipedToAHandler() bool {
	b, err := os.ReadFile("/proc/sys/kernel/core_pattern")
	return err != nil || strings.HasPrefix(strings.TrimSpace(string(b)), "|")
}

// killAccount signals every process whose real or effective user is uid and
// returns how many there were.
func killAccount(uid uint32) int { return killAccountCount(uid, true) }

// killAccountCount counts the live processes of uid and, if kill is set,
// signals them. A zombie is not alive: it holds nothing.
func killAccountCount(uid uint32, kill bool) int {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || !hasUID(filepath.Join("/proc", e.Name(), "status"), uid) {
			continue
		}
		n++
		if kill {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
	return n
}

func hasUID(status string, uid uint32) bool {
	f, err := os.Open(status) //nolint:gosec // G304: /proc/<pid>/status
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "State:") && strings.Contains(sc.Text(), "Z") {
			return false
		}
		rest, ok := strings.CutPrefix(sc.Text(), "Uid:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) < 2 {
			return false
		}
		for _, f := range fields[:2] {
			if v, err := strconv.ParseUint(f, 10, 32); err == nil && uint32(v) == uid {
				return true
			}
		}
		return false
	}
	return false
}

// removeOwned removes what belongs to uid under dir, without following links
// and without leaving the filesystem of dir.
func removeOwned(dir string, uid uint32) error {
	root, err := os.Lstat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	rootDev := dev(root)
	var out error
	var walk func(path string)
	walk = func(path string) {
		ents, err := os.ReadDir(path)
		if err != nil {
			return
		}
		for _, e := range ents {
			p := filepath.Join(path, e.Name())
			fi, err := os.Lstat(p)
			if err != nil || dev(fi) != rootDev {
				continue
			}
			if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid == uid {
				out = errors.Join(out, os.RemoveAll(p))
				continue
			}
			if fi.IsDir() {
				walk(p)
			}
		}
	}
	walk(dir)
	return out
}

func dev(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev) //nolint:unconvert // Dev is a different width per arch
	}
	return 0
}
