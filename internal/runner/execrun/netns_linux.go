//go:build linux

package execrun

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/entire-vc/evc-keep/pkg/execpolicy"
)

// hostBinDirs is where the tools are looked for: not the PATH of whoever
// started the runner.
var hostBinDirs = []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin"}

func findTool(name string) string {
	for _, d := range hostBinDirs {
		p := filepath.Join(d, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
			return p
		}
	}
	return ""
}

func (n *Netns) probe() {
	n.once.Do(func() {
		n.ip, n.nft, n.priv, n.lim = findTool("ip"), findTool("nft"), findTool("setpriv"), findTool("prlimit")
		n.hasNft = n.nft != ""
		if n.ChildUID == 0 || n.ChildGID == 0 || n.ip == "" || n.priv == "" || n.lim == "" {
			return
		}
		// The kernel decides: make a namespace and remove it.
		name := "keep-probe-" + randID()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := n.cmd(ctx, nil, n.ip, "netns", "add", name); err != nil {
			return
		}
		_ = n.cmd(ctx, nil, n.ip, "netns", "del", name)
		if n.hasNft {
			// Allowlist needs a firewall the kernel really has.
			n.hasNft = n.cmd(ctx, nil, n.nft, "list", "tables") == nil
		}
		n.ok = true
	})
}

// Enforces reports whether this host can enforce mode right now.
func (n *Netns) Enforces(mode execpolicy.NetMode) bool {
	n.probe()
	switch mode {
	case execpolicy.NetNone:
		return n.ok
	case execpolicy.NetAllowlist:
		return n.ok && n.hasNft
	}
	return false
}

func (n *Netns) cmd(ctx context.Context, stdin []byte, bin string, args ...string) error {
	c := exec.CommandContext(ctx, bin, args...) //nolint:gosec // G204: bin is a tool found in fixed system directories, args are built here
	c.Env = []string{"PATH=" + strings.Join(hostBinDirs, ":")}
	if stdin != nil {
		c.Stdin = bytes.NewReader(stdin)
	}
	var out bytes.Buffer
	c.Stdout, c.Stderr = &out, &out
	if err := c.Run(); err != nil {
		return fmt.Errorf("%s %s: %w: %s", filepath.Base(bin), args[0], err, strings.TrimSpace(out.String()))
	}
	return nil
}

func randID() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("netns: no randomness")
	}
	return hex.EncodeToString(b[:])
}

// alloc picks a free /30 in 10.254.0.0/16 and returns its index.
func (n *Netns) alloc() (int, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.used == nil {
		n.used = map[int]bool{}
	}
	for i := 0; i < 1<<14; i++ {
		if !n.used[i] {
			n.used[i] = true
			return i, nil
		}
	}
	return 0, errors.New("no free address block")
}

func (n *Netns) free(i int) {
	n.mu.Lock()
	delete(n.used, i)
	n.mu.Unlock()
}

var hostNameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

// Prepare builds the namespace as described on Netns and returns the command
// prefix that runs a program inside it, under ip, setpriv and prlimit. It
// never sees the child's environment.
func (n *Netns) Prepare(mode execpolicy.NetMode, pins []Pin) ([]string, func(), error) {
	if !n.Enforces(mode) {
		return nil, nil, errors.New("netns: host cannot enforce this network mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	name := "keep-" + randID()
	var undo []func()
	cleanup := func() {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
	}
	bad := func(err error) ([]string, func(), error) {
		cleanup()
		return nil, nil, err
	}

	if err := n.cmd(ctx, nil, n.ip, "netns", "add", name); err != nil {
		return bad(err)
	}
	undo = append(undo, func() {
		c, cl := context.WithTimeout(context.Background(), 10*time.Second)
		defer cl()
		_ = n.cmd(c, nil, n.ip, "netns", "del", name)
	})

	etc := filepath.Join("/etc/netns", name)
	hosts := "127.0.0.1 localhost\n::1 localhost\n"
	if mode == execpolicy.NetAllowlist {
		for _, p := range pins {
			if p.Host != "" && hostNameRe.MatchString(p.Host) {
				hosts += p.Addr.Addr().String() + " " + p.Host + "\n"
			}
		}
	}
	if err := os.MkdirAll(etc, 0o755); err != nil { //nolint:gosec // G301: ip netns exec reads it as root; the child never sees the directory
		return bad(err)
	}
	undo = append(undo, func() { _ = os.RemoveAll(etc) })
	if err := os.WriteFile(filepath.Join(etc, "hosts"), []byte(hosts), 0o644); err != nil { //nolint:gosec // G306: bind-mounted over /etc/hosts, world-readable like the original
		return bad(err)
	}
	if err := os.WriteFile(filepath.Join(etc, "resolv.conf"), nil, 0o644); err != nil { //nolint:gosec // G306: empty on purpose, no resolver inside
		return bad(err)
	}

	if err := n.cmd(ctx, nil, n.ip, "-n", name, "link", "set", "lo", "up"); err != nil {
		return bad(err)
	}
	if mode == execpolicy.NetAllowlist {
		u, err := n.allowlist(ctx, name, pins)
		undo = append(undo, u...)
		if err != nil {
			return bad(err)
		}
	}

	wrap := []string{n.ip, "netns", "exec", name, n.priv,
		"--reuid", strconv.FormatUint(uint64(n.ChildUID), 10),
		"--regid", strconv.FormatUint(uint64(n.ChildGID), 10),
		"--clear-groups", "--no-new-privs", "--bounding-set", "-all", "--inh-caps", "-all",
		"--", n.lim, "--core=0:0", "--"}
	return wrap, cleanup, nil
}

// allowlist wires the veth pair and both firewalls; the returned functions
// undo what was done, even on error.
func (n *Netns) allowlist(ctx context.Context, name string, pins []Pin) ([]func(), error) {
	var undo []func()
	if len(pins) == 0 {
		return nil, errors.New("netns: allowlist without destinations")
	}
	for _, p := range pins {
		if !p.Addr.Addr().Is4() {
			return nil, errors.New("netns: only IPv4 destinations are supported")
		}
	}
	idx, err := n.alloc()
	if err != nil {
		return nil, err
	}
	undo = append(undo, func() { n.free(idx) })

	suffix := strconv.FormatInt(int64(idx), 36)
	vh, vp := "kh"+suffix, "kp"+suffix
	host := netip.AddrFrom4([4]byte{10, 254, byte((idx >> 6) & 0xff), byte((idx&63)*4 + 1)})
	peer := netip.AddrFrom4([4]byte{10, 254, byte((idx >> 6) & 0xff), byte((idx&63)*4 + 2)})
	prefix := func(a netip.Addr) string { return netip.PrefixFrom(a, 30).String() }

	if err := n.cmd(ctx, nil, n.ip, "link", "add", vh, "type", "veth", "peer", "name", vp, "netns", name); err != nil {
		return undo, err
	}
	undo = append(undo, func() {
		c, cl := context.WithTimeout(context.Background(), 10*time.Second)
		defer cl()
		_ = n.cmd(c, nil, n.ip, "link", "del", vh)
	})
	for _, step := range [][]string{
		{"addr", "add", prefix(host), "dev", vh},
		{"link", "set", vh, "up"},
		{"-n", name, "addr", "add", prefix(peer), "dev", vp},
		{"-n", name, "link", "set", vp, "up"},
		{"-n", name, "route", "add", "default", "via", host.String()},
	} {
		if err := n.cmd(ctx, nil, n.ip, step...); err != nil {
			return undo, err
		}
	}

	pairs := make([]string, 0, len(pins))
	for _, p := range pins {
		pairs = append(pairs, fmt.Sprintf("%s . %d", p.Addr.Addr(), p.Addr.Port()))
	}
	sort.Strings(pairs)
	set := strings.Join(pairs, ", ")

	// Inside: default drop in every hook; only the pinned pairs leave.
	inside := fmt.Sprintf(`table inet keep {
	chain output {
		type filter hook output priority 0; policy drop;
		oifname "lo" accept
		ct state established,related accept
		ip daddr . tcp dport { %s } accept
	}
	chain input {
		type filter hook input priority 0; policy drop;
		iifname "lo" accept
		ct state established,related accept
	}
	chain forward {
		type filter hook forward priority 0; policy drop;
	}
}
`, set)
	if err := n.cmd(ctx, []byte(inside), n.ip, "netns", "exec", name, n.nft, "-f", "-"); err != nil {
		return undo, err
	}

	// On the host: the same pairs again, from this veth only, then NAT.
	table := "keep_" + suffix
	outside := fmt.Sprintf(`table ip %[1]s {
	chain forward {
		type filter hook forward priority -10; policy accept;
		iifname "%[2]s" ip daddr . tcp dport { %[3]s } accept
		iifname "%[2]s" drop
		oifname "%[2]s" ct state established,related accept
		oifname "%[2]s" drop
	}
	chain input {
		type filter hook input priority -10; policy accept;
		iifname "%[2]s" counter drop
	}
	chain post {
		type nat hook postrouting priority 100; policy accept;
		ip saddr %[4]s oifname != "%[2]s" masquerade
	}
}
`, table, vh, set, peer)
	if err := n.cmd(ctx, []byte(outside), n.nft, "-f", "-"); err != nil {
		return undo, err
	}
	undo = append(undo, func() {
		c, cl := context.WithTimeout(context.Background(), 10*time.Second)
		defer cl()
		_ = n.cmd(c, nil, n.nft, "delete", "table", "ip", table)
	})
	if err := acquireForward(); err != nil {
		return undo, err
	}
	undo = append(undo, releaseForward)
	return undo, nil
}

// Sweep removes what a runner that died mid-run left behind: namespaces named
// keep-*, their /etc/netns directories and the host tables. Call it at start.
func (n *Netns) Sweep() {
	n.probe()
	if !n.ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ents, _ := os.ReadDir("/run/netns")
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "keep-") {
			_ = n.cmd(ctx, nil, n.ip, "netns", "del", e.Name())
			_ = os.RemoveAll(filepath.Join("/etc/netns", e.Name()))
		}
	}
	// A directory whose namespace is already gone.
	ents, _ = os.ReadDir("/etc/netns")
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "keep-") {
			_ = os.RemoveAll(filepath.Join("/etc/netns", e.Name()))
		}
	}
	if n.hasNft {
		out, err := exec.CommandContext(ctx, n.nft, "list", "tables").Output() //nolint:gosec // G204: fixed tool, fixed arguments
		if err == nil {
			for _, l := range strings.Split(string(out), "\n") {
				if f := strings.Fields(l); len(f) == 3 && f[1] == "ip" && strings.HasPrefix(f[2], "keep_") {
					_ = n.cmd(ctx, nil, n.nft, "delete", "table", "ip", f[2])
				}
			}
		}
	}
}

// ip_forward is host-wide: the first run in flight remembers the prior value
// and turns it on, the last one to finish puts the prior value back.
var fwd struct {
	mu    sync.Mutex
	users int
	prior []byte
}

const ipForwardPath = "/proc/sys/net/ipv4/ip_forward"

func acquireForward() error {
	fwd.mu.Lock()
	defer fwd.mu.Unlock()
	if fwd.users == 0 {
		prior, err := os.ReadFile(ipForwardPath)
		if err != nil {
			return fmt.Errorf("netns: ip_forward: %w", err)
		}
		if err := os.WriteFile(ipForwardPath, []byte("1\n"), 0o644); err != nil { //nolint:gosec // G306: a procfs knob
			return fmt.Errorf("netns: ip_forward: %w", err)
		}
		fwd.prior = prior
	}
	fwd.users++
	return nil
}

func releaseForward() {
	fwd.mu.Lock()
	defer fwd.mu.Unlock()
	if fwd.users == 0 {
		return
	}
	fwd.users--
	if fwd.users == 0 {
		_ = os.WriteFile(ipForwardPath, fwd.prior, 0o644) //nolint:gosec // G306: a procfs knob
	}
}
