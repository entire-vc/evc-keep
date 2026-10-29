//go:build unix

package targets

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// dirReachBits is read or execute (traverse): the bits that let an agent
// list or enter a directory.
const dirReachBits = 0o5

// agentSet is the uids/gids of agents on this host (HostPolicy.AgentUIDs /
// AgentGIDs). A target, or a directory on its path, reachable by one of
// them is refused: R-POL-4.
type agentSet struct {
	uids []int64
	gids []int64
}

func (a agentSet) hasUID(uid int64) bool {
	for _, u := range a.uids {
		if u == uid {
			return true
		}
	}
	return false
}

func (a agentSet) hasGID(gid int64) bool {
	for _, g := range a.gids {
		if g == gid {
			return true
		}
	}
	return false
}

// everyoneGID is macOS's built-in group "everyone", which holds every account
// on the host. Its group bits are "other" bits under another name, so a file
// or directory in that group is as open to an agent as the number of that
// agent's own group would make it, whatever gids HostPolicy lists.
const everyoneGID = 12

func isEveryoneGID(gid int64) bool { return runtime.GOOS == "darwin" && gid == everyoneGID }

// groupIsAgents: a permission granted to group gid reaches an agent.
func (a agentSet) groupIsAgents(gid int64) bool { return a.hasGID(gid) || isEveryoneGID(gid) }

// refuseWritable refuses if st — a directory anywhere on the target's path —
// is owned by an agent, or writable by an agent's group or by anyone,
// *without* the sticky bit set. A writable directory lets whoever can write
// it replace or hardlink our temporary file's name before our own rename
// runs. Checked on every directory in the walk, not just the immediate parent,
// because a writable directory higher up lets an attacker redirect a later,
// not-yet-opened component too.
//
// The sticky bit (S_ISVTX, the "t" in /tmp's usual 1777) is what makes a
// shared, world-writable directory safe for exactly this: POSIX requires
// that only a file's owner (or the directory's owner, or a privileged
// process) may rename or unlink an entry there, so a non-owning agent
// cannot swap or delete our temporary file out from under our own rename —
// the specific race this check exists to close. It does not stop an agent
// from *adding a second link* to our file's existing inode; that race is
// closed separately, by the nlink recheck in secureCreateAndWrite. A
// directory *owned by* an agent is refused regardless of the sticky bit:
// ownership gives full control over the directory irrespective of it.
func (a agentSet) refuseWritable(what string, st *unix.Stat_t) error {
	if a.hasUID(int64(st.Uid)) {
		return denied("%s is owned by an agent", what)
	}
	mode := uint32(st.Mode) & 0o777
	if st.Mode&unix.S_ISVTX != 0 {
		return nil
	}
	if mode&0o002 != 0 {
		return denied("%s would be writable by anyone", what)
	}
	if mode&0o020 != 0 && a.groupIsAgents(int64(st.Gid)) {
		return denied("%s would be writable by an agent group", what)
	}
	return nil
}

// refuseReachable refuses if st — the target's immediate parent directory —
// is owned by an agent, or readable/traversable by an agent's group
// (R-POL-4). Unlike refuseWritable this does not refuse on "anyone": a
// directory traversable by every uid on the host is completely ordinary
// (every ancestor from / down usually is, and so, commonly, is a temp or
// working directory's own mode) and does not by itself expose the target's
// content — what matters is specifically whether one of the host's known
// agents can reach it. The target file's own mode is checked separately
// (validateTargetPerm) and does refuse "readable by anyone", because there
// the file's content genuinely is exposed to whoever can read it, agent or
// not.
func (a agentSet) refuseReachable(what string, st *unix.Stat_t) error {
	if a.hasUID(int64(st.Uid)) {
		return denied("%s is owned by an agent", what)
	}
	mode := uint32(st.Mode) & 0o777
	if (mode>>3)&dirReachBits != 0 && a.groupIsAgents(int64(st.Gid)) {
		return denied("%s would be reachable by an agent group", what)
	}
	return nil
}

// refuseWritableFile refuses if st — an existing target file — can be written
// by anyone, by an agent's group, or by an agent (as owner; the owner check in
// readExisting already limits owners to the runner and the consumer, this
// covers the case where either is itself declared an agent). Unlike
// refuseWritable there is no sticky-bit exception: the sticky bit protects
// directory entries, not file content.
func (a agentSet) refuseWritableFile(what string, st *unix.Stat_t) error {
	if a.hasUID(int64(st.Uid)) {
		return denied("%s is owned by an agent", what)
	}
	mode := uint32(st.Mode) & 0o777
	if mode&0o002 != 0 {
		return denied("%s is writable by anyone", what)
	}
	if mode&0o020 != 0 && a.groupIsAgents(int64(st.Gid)) {
		return denied("%s is writable by an agent group", what)
	}
	return nil
}
