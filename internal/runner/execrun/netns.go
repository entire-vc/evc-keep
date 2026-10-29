package execrun

import "sync"

// Netns isolates a child in its own network namespace. The child runs under
// `ip netns exec`, which gives it the namespace and the hosts and resolv.conf
// files written for it, and then under `setpriv`, which drops it to an
// unprivileged account with no way back (no_new_privs, empty bounding set):
// root inside the namespace could rewrite its own firewall.
//
// None: the namespace holds a loopback and nothing else.
// Allowlist: a veth pair joins it to the host; inside, nftables drops
// everything but the pinned address:port pairs; on the host, a forward rule
// admits only those pairs from that veth, with masquerade. There is no DNS
// (resolv.conf is empty and the firewall drops port 53 anyway): the names of
// the template are in a fixed hosts file, mapped to the addresses the runner
// resolved before the start.
//
// The child runs as ChildUID, which should be an account of its own: another
// process of the same uid can read its environment (its /proc entry), so an
// account shared with other services shares the value with them. Core dumps
// are off for it (prlimit), so a crash writes no environment to disk.
//
// Destinations are IPv4 and TCP. An IPv6 destination is refused at start.
type Netns struct {
	// ChildUID and ChildGID are the account the child runs as; zero is
	// refused.
	ChildUID, ChildGID uint32

	// State of the Linux implementation (netns_linux.go); the type is the
	// same on every OS so the exported surface is.
	once          sync.Once //nolint:unused // used by netns_linux.go
	ip, nft, priv string    //nolint:unused // used by netns_linux.go
	ok            bool      //nolint:unused // used by netns_linux.go
	hasNft        bool      //nolint:unused // used by netns_linux.go
	lim           string    //nolint:unused // used by netns_linux.go

	mu   sync.Mutex   //nolint:unused // used by netns_linux.go
	used map[int]bool //nolint:unused // used by netns_linux.go
}
