//go:build linux

package execrun

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/pkg/execpolicy"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// These tests need root, CAP_NET_ADMIN, ip, nft and setpriv: the privileged
// CI job (and a privileged container locally). KEEP_NETNS_TESTS=1 says "this
// is that environment": then a missing capability FAILS the test instead of
// skipping it, so the job cannot go green without having isolated anything.
const netnsEnv = "KEEP_NETNS_TESTS"

const childID = 65534

// TestMain turns the test binary into the child the isolation tests run: the
// binary is copied where the unprivileged child can execute it, and started
// with a mode word as its first argument.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "__dial":
			c, err := net.DialTimeout("tcp", os.Args[2], 2*time.Second) //nolint:gosec // G704: test helper dials the address its parent test passes
			if err != nil {
				fmt.Println("dial-failed:", err)
				os.Exit(1)
			}
			_ = c.Close()
			fmt.Println("dial-ok")
			os.Exit(0)
		case "__enforces":
			n := &Netns{ChildUID: 1, ChildGID: 1}
			fmt.Printf("enforces=%v\n", n.Enforces(execpolicy.NetNone))
			os.Exit(0)
		case "__listen":
			for _, port := range os.Args[2:] {
				l, err := net.Listen("tcp", "0.0.0.0:"+port)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
				go func() {
					for {
						c, err := l.Accept()
						if err != nil {
							return
						}
						_ = c.Close()
					}
				}()
			}
			select {}
		case "__probe-none":
			if c, err := net.DialTimeout("tcp", "127.0.0.1:9", 2*time.Second); err == nil {
				_ = c.Close()
				os.Exit(0)
			}
			os.Exit(7)
		case "__status":
			b, _ := os.ReadFile("/proc/self/status")
			l, _ := os.ReadFile("/proc/self/limits")
			fmt.Printf("uid=%d\n%s\n%s", os.Getuid(), b, l)
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}

func netnsIso(t *testing.T) *Netns {
	t.Helper()
	if os.Getenv(netnsEnv) != "1" {
		t.Skipf("%s=1 not set: needs a privileged host", netnsEnv)
	}
	n := &Netns{ChildUID: childID, ChildGID: childID}
	if !n.Enforces(execpolicy.NetNone) || !n.Enforces(execpolicy.NetAllowlist) {
		t.Fatalf("%s=1 but this host cannot isolate (root? ip? nft? setpriv?)", netnsEnv)
	}
	n.Sweep()
	return n
}

// childExe copies the test binary where an unprivileged account can run it.
func childExe(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for d := dir; d != "/" && d != "/tmp"; d = filepath.Dir(d) {
		if err := os.Chmod(d, 0o755); err != nil { //nolint:gosec // G302: the child must traverse it
			t.Fatal(err)
		}
	}
	src, err := os.ReadFile(os.Args[0]) //nolint:gosec // G703: reads the test binary itself
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "child")
	if err := os.WriteFile(dst, src, 0o755); err != nil { //nolint:gosec // G306: a test executable
		t.Fatal(err)
	}
	if err := os.Chmod(dst, 0o755); err != nil { //nolint:gosec // G302: a test executable
		t.Fatal(err)
	}
	return dst
}

func hostIPv4(t *testing.T) netip.Addr {
	t.Helper()
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() && !p.Addr().IsLoopback() {
			return p.Addr()
		}
	}
	if os.Getenv("KEEP_NETNS_TESTS") == "1" {
		t.Fatal("no non-loopback IPv4 address on this host")
	}
	t.Skip("no non-loopback IPv4 address on this host")
	return netip.Addr{}
}

// listener counts connections it accepted.
func listener(t *testing.T, addr string) (net.Listener, *atomic.Int32) {
	t.Helper()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	var n atomic.Int32
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = l.Close() })
	return l, &n
}

func portOf(l net.Listener) uint16 { return uint16(l.Addr().(*net.TCPAddr).Port) } //nolint:gosec // G115: a port

// runChild starts exe with args under the isolator and returns its output
// and exit code.
func runChild(t *testing.T, iso *Netns, mode execpolicy.NetMode, pins []Pin, exe string, args ...string) (string, int) {
	t.Helper()
	wrap, cleanup, err := iso.Prepare(mode, pins)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer cleanup()
	argv := append(append(append([]string(nil), wrap...), exe), args...)
	cmd := exec.Command(argv[0], argv[1:]...) //nolint:gosec // G204: the test's own copy under the isolator
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err = cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	err = cmd.Wait()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("wait: %v", err)
	}
	return strings.TrimSpace(out.String()), code
}

// Network none: the child has a loopback with nothing behind it. A listener
// on the host's own loopback, and one on the host's real address, are both
// out of reach, and neither sees a connection.
func TestNetnsNoneIsolates(t *testing.T) {
	iso := netnsIso(t)
	exe := childExe(t)
	lo, loHits := listener(t, "127.0.0.1:0")
	hostIP := hostIPv4(t)
	ext, extHits := listener(t, hostIP.String()+":0")

	// Positive control: unisolated, the same child reaches the listeners.
	for _, target := range []string{lo.Addr().String(), net.JoinHostPort(hostIP.String(), fmt.Sprint(portOf(ext)))} {
		if out, code := func() (string, int) {
			b, err := exec.Command(exe, "__dial", target).CombinedOutput() //nolint:gosec // G204: the test's own copy
			if err != nil {
				return string(b), 1
			}
			return string(b), 0
		}(); code != 0 {
			t.Fatalf("control: unisolated dial of %s failed: %s", target, out)
		}
	}
	loHits.Store(0)
	extHits.Store(0)

	for _, target := range []string{lo.Addr().String(), net.JoinHostPort(hostIP.String(), fmt.Sprint(portOf(ext)))} {
		out, code := runChild(t, iso, execpolicy.NetNone, nil, exe, "__dial", target)
		if code == 0 {
			t.Errorf("none: child reached %s: %s", target, out)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if loHits.Load() != 0 || extHits.Load() != 0 {
		t.Fatalf("a listener saw the isolated child: lo=%d ext=%d", loHits.Load(), extHits.Load())
	}
}

// Network allowlist: the pinned address:port is reachable, by address and by
// the template's own name; a second listener on the same host, the same
// address with another port, and a name nobody pinned are not.
func TestNetnsAllowlistPinsDestinations(t *testing.T) {
	iso := netnsIso(t)
	exe := childExe(t)
	hostIP := hostIPv4(t)
	a, aHits := listener(t, hostIP.String()+":0")
	b, bHits := listener(t, hostIP.String()+":0")
	pa, pb := portOf(a), portOf(b)
	pins := []Pin{{Host: "a.test", Addr: netip.AddrPortFrom(hostIP, pa)}}
	at := func(host string, port uint16) string { return net.JoinHostPort(host, fmt.Sprint(port)) }

	for _, c := range []struct {
		name, target string
		reach        bool
	}{
		// A is a service of the runner host itself. A pin to a local address
		// must not open the host's input path: the positive control for the
		// pinned path is TestNetnsAllowlistReachesARemoteHost.
		{"A by address (a host-local service)", at(hostIP.String(), pa), false},
		{"A by its template name (a host-local service)", at("a.test", pa), false},
		{"B by address (same host, other port)", at(hostIP.String(), pb), false},
		{"B by the pinned name", at("a.test", pb), false},
		{"B by an unpinned name", at("b.test", pb), false},
		{"a public address", "93.184.216.34:443", false},
		{"DNS", "8.8.8.8:53", false},
	} {
		out, code := runChild(t, iso, execpolicy.NetAllowlist, pins, exe, "__dial", c.target)
		if (code == 0) != c.reach {
			t.Errorf("%s: reach=%v, want %v (%s)", c.name, code == 0, c.reach, out)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if aHits.Load() != 0 {
		t.Errorf("the host-local service A saw %d connection(s) from the pinned child", aHits.Load())
	}
	if bHits.Load() != 0 {
		t.Errorf("B saw %d connection(s) from the pinned child", bHits.Load())
	}
}

// The child is nobody: no capabilities, no way to gain any.
func TestNetnsChildIsUnprivileged(t *testing.T) {
	iso := netnsIso(t)
	exe := childExe(t)
	out, code := runChild(t, iso, execpolicy.NetNone, nil, exe, "__status")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	for _, want := range []string{fmt.Sprintf("uid=%d", childID), "CapEff:\t0000000000000000", "CapBnd:\t0000000000000000", "NoNewPrivs:\t1"} {
		if !strings.Contains(out, want) {
			t.Errorf("child status lacks %q:\n%s", want, out)
		}
	}
	if !regexp.MustCompile(`Max core file size\s+0\s+0`).MatchString(out) {
		t.Errorf("core dumps are not off:\n%s", out)
	}
}

// Nothing is left behind: not the namespace, not its files, not the host
// table. A refused start (an IPv6 destination) leaves nothing either.
// The firewall inside the namespace is a second line behind the host rules:
// the host rules alone already stop every probe, so its ruleset is checked
// itself. Default drop in every hook, the pinned pair and nothing else.
func TestNetnsInsideRulesetIsDefaultDropWithThePinnedPair(t *testing.T) {
	iso := netnsIso(t)
	hostIP := hostIPv4(t)
	pin := netip.AddrPortFrom(hostIP, 4455)
	wrap, cleanup, err := iso.Prepare(execpolicy.NetAllowlist, []Pin{{Addr: pin}})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer cleanup()
	name := ""
	for i, a := range wrap {
		if a == "exec" && i+1 < len(wrap) {
			name = wrap[i+1]
			break
		}
	}
	if !strings.HasPrefix(name, "keep-") {
		t.Fatalf("no namespace name in %v", wrap)
	}
	out, err := exec.Command(iso.ip, "netns", "exec", name, iso.nft, "list", "ruleset").CombinedOutput() //nolint:gosec // G204: a fixed tool and a name this test just made
	if err != nil {
		t.Fatalf("nft list ruleset: %v: %s", err, out)
	}
	rules := string(out)
	for _, want := range []string{
		"hook output priority filter; policy drop;",
		"hook input priority filter; policy drop;",
		"hook forward priority filter; policy drop;",
		hostIP.String() + " . 4455",
	} {
		if !strings.Contains(rules, want) {
			t.Errorf("inside ruleset lacks %q:\n%s", want, rules)
		}
	}
	if strings.Contains(rules, "policy accept") {
		t.Errorf("inside ruleset has an accepting default policy:\n%s", rules)
	}
}

func TestNetnsLeavesNothingBehind(t *testing.T) {
	iso := netnsIso(t)
	exe := childExe(t)
	hostIP := hostIPv4(t)
	l, _ := listener(t, hostIP.String()+":0")
	runChild(t, iso, execpolicy.NetAllowlist, []Pin{{Addr: netip.AddrPortFrom(hostIP, portOf(l))}}, exe, "__dial", net.JoinHostPort(hostIP.String(), fmt.Sprint(portOf(l))))

	if _, _, err := iso.Prepare(execpolicy.NetAllowlist, []Pin{{Addr: netip.MustParseAddrPort("[2001:db8::1]:443")}}); err == nil || !strings.Contains(err.Error(), "IPv4") {
		t.Fatalf("an IPv6 destination must be refused for being IPv6, got %v", err)
	}

	leftover := func() string {
		var left []string
		ents, _ := os.ReadDir("/run/netns")
		for _, e := range ents {
			left = append(left, "/run/netns/"+e.Name())
		}
		ents, _ = os.ReadDir("/etc/netns")
		for _, e := range ents {
			left = append(left, "/etc/netns/"+e.Name())
		}
		if out, err := exec.Command(iso.nft, "list", "tables").Output(); err == nil { //nolint:gosec // G204: a fixed tool
			for _, l := range strings.Split(string(out), "\n") {
				if strings.Contains(l, "keep_") {
					left = append(left, l)
				}
			}
		}
		return strings.Join(left, "\n")
	}
	if s := leftover(); s != "" {
		t.Fatalf("left behind:\n%s", s)
	}
}

// A runner that died mid-run leaves a namespace: Sweep removes it.
func TestNetnsSweepRemovesStrays(t *testing.T) {
	iso := netnsIso(t)
	if out, err := exec.Command(iso.ip, "netns", "add", "keep-stray01").CombinedOutput(); err != nil { //nolint:gosec // G204: a fixed tool
		t.Fatalf("%v: %s", err, out)
	}
	iso.Sweep()
	if _, err := os.Stat("/run/netns/keep-stray01"); err == nil {
		t.Fatal("stray namespace survived Sweep")
	}
}

// End to end through Run: the real isolator, a plan from Prepare, a child
// whose only job is to try the loopback.
func TestRunWithRealIsolatorNone(t *testing.T) {
	iso := netnsIso(t)
	w := newWorld(t)
	for d := w.bin; d != "/" && d != "/tmp"; d = filepath.Dir(d) {
		_ = os.Chmod(d, 0o755) //nolint:gosec // G302: the child must traverse it
	}
	exe := childExe(t)
	src, err := os.ReadFile(exe) //nolint:gosec // G304: path of the running test binary
	if err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(w.bin, "tool")
	if err := os.Remove(tool); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tool, src, 0o755); err != nil { //nolint:gosec // G306: a test executable
		t.Fatal(err)
	}
	if err := os.Chmod(tool, 0o755); err != nil { //nolint:gosec // G302: a test executable
		t.Fatal(err)
	}
	w.policy.ExecTemplates[0].Argv = []string{tool, "__probe-none"}
	w.policy.ExecTemplates[0].Params = nil
	pl := w.plan(map[string]string{})
	d, _ := w.deps(iso)
	_ = os.Chmod(d.HomeRoot, 0o755) //nolint:gosec // G302: the child enters its run directory through it
	d.Chown = nil                   // as root, the real thing
	out, class := Run(context.Background(), pl, secret.New([]byte("v")), w.policy, d)
	if class != "" {
		t.Fatalf("class = %q", class)
	}
	if out.ExitCode != 7 {
		t.Fatalf("exit %d, want 7 (loopback refused): %q %q", out.ExitCode, out.Stdout, out.Stderr)
	}
}

// The path to a host that is not this one: a second namespace plays the
// remote machine behind its own veth. The pinned child reaches it through
// the forward and masquerade rules; the unpinned port of the same machine is
// closed to it.
func TestNetnsAllowlistReachesARemoteHost(t *testing.T) {
	iso := netnsIso(t)
	exe := childExe(t)
	const ns = "keeptest-remote"
	sh := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(iso.ip, args...).CombinedOutput(); err != nil { //nolint:gosec // G204: a fixed tool
			t.Fatalf("ip %v: %v: %s", args, err, out)
		}
	}
	_ = exec.Command(iso.ip, "netns", "del", ns).Run() //nolint:gosec // G204: a fixed tool
	// Forwarding must be the runner's doing, not the host's luck: start from
	// off and put back what was there.
	const fwd = "/proc/sys/net/ipv4/ip_forward"
	was, err := os.ReadFile(fwd)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fwd, []byte("0\n"), 0o644); err != nil { //nolint:gosec // G306: a procfs knob
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.WriteFile(fwd, was, 0o644) }) //nolint:gosec // G306: a procfs knob
	sh("netns", "add", ns)
	t.Cleanup(func() {
		_ = exec.Command(iso.ip, "link", "del", "rh0").Run() //nolint:gosec // G204: a fixed tool
		_ = exec.Command(iso.ip, "netns", "del", ns).Run()   //nolint:gosec // G204: a fixed tool
	})
	sh("link", "add", "rh0", "type", "veth", "peer", "name", "rp0", "netns", ns)
	sh("addr", "add", "10.77.0.1/30", "dev", "rh0")
	sh("link", "set", "rh0", "up")
	sh("-n", ns, "addr", "add", "10.77.0.2/30", "dev", "rp0")
	sh("-n", ns, "link", "set", "rp0", "up")
	sh("-n", ns, "link", "set", "lo", "up")
	srv := exec.Command(iso.ip, "netns", "exec", ns, exe, "__listen", "7001", "7002") //nolint:gosec // G204: the test's own copy
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Process.Kill(); _, _ = srv.Process.Wait() })
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", "10.77.0.2:7001", 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the remote listener never came up: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	pins := []Pin{{Host: "remote.test", Addr: netip.MustParseAddrPort("10.77.0.2:7001")}}
	if out, code := runChild(t, iso, execpolicy.NetAllowlist, pins, exe, "__dial", "remote.test:7001"); code != 0 {
		t.Errorf("the pinned remote port is unreachable: %s", out)
	}
	if out, code := runChild(t, iso, execpolicy.NetAllowlist, pins, exe, "__dial", "10.77.0.2:7002"); code == 0 {
		t.Errorf("the unpinned port of the same remote host is reachable: %s", out)
	}
	// The knob was off before the runs; it must be off again after them.
	if now, err := os.ReadFile(fwd); err != nil || string(now) != "0\n" {
		t.Errorf("ip_forward after the runs = %q (%v), want it restored to \"0\\n\"", now, err)
	}
}

// A host where the runner is not root cannot make namespaces; a child account
// of 0 would be root inside the one it is put in. Both refuse.
func TestNetnsRefusesWithoutRootOrWithARootChild(t *testing.T) {
	iso := netnsIso(t)
	if (&Netns{ChildUID: 0, ChildGID: childID}).Enforces(execpolicy.NetNone) || (&Netns{ChildUID: childID, ChildGID: 0}).Enforces(execpolicy.NetNone) {
		t.Fatal("a root child account was accepted")
	}
	// Positive control: the same question asked by root is yes.
	if !(&Netns{ChildUID: childID, ChildGID: childID}).Enforces(execpolicy.NetNone) {
		t.Fatal("control: root with an ordinary child account is refused")
	}
	// Asked by an unprivileged process, the answer is no.
	out, code := runChild(t, iso, execpolicy.NetNone, nil, childExe(t), "__enforces")
	if code != 0 || out != "enforces=false" {
		t.Fatalf("an unprivileged process claims it can isolate: %d %q", code, out)
	}
}

// scriptWorld is a world whose tool is the given shell script, reachable by
// the child's account.
func scriptWorld(t *testing.T, body string) (*world, Plan) {
	t.Helper()
	w := newWorld(t)
	for d := w.bin; d != "/" && d != "/tmp"; d = filepath.Dir(d) {
		_ = os.Chmod(d, 0o755) //nolint:gosec // G302: the child must traverse it
	}
	setScript(t, w, body)
	w.policy.ExecTemplates[0].Argv = []string{filepath.Join(w.bin, "tool")}
	w.policy.ExecTemplates[0].Params = nil
	return w, w.plan(map[string]string{})
}

// A child that leaves its process group (setsid) and keeps running holds the
// value in its environment, and shares an account with the next child. After
// the run nothing of that account is alive and what it left in /tmp is gone.
func TestNetnsRunSweepsWhatLeftTheProcessGroup(t *testing.T) {
	iso := netnsIso(t)
	const marker = "/tmp/keep-w26-escaped"
	const kept = "/tmp/keep-w26-kept"
	_ = os.Remove(marker)
	_ = os.Remove(kept)
	t.Cleanup(func() { _ = os.Remove(marker); _ = os.Remove(kept) })
	for name, isoFor := range map[string]func() Isolator{
		"isolated":   func() Isolator { return iso },
		"unenforced": func() Isolator { return nil },
	} {
		t.Run(name, func(t *testing.T) {
			w, pl := scriptWorld(t, `setsid sh -c 'sleep 2; echo "$TOOL_KEY" > `+marker+`' </dev/null >/dev/null 2>&1 &
echo kept > `+kept+`
sleep 0.3
echo ran`)
			w.policy.ExecNetUnenforced = true
			dropAccount = dropToChild
			d, _ := w.deps(isoFor())
			_ = os.Chmod(d.HomeRoot, 0o755) //nolint:gosec // G302: the child enters its run directory through it
			d.Chown = nil                   // as root, the real thing
			out, class := Run(context.Background(), pl, secret.New([]byte("supersecretvalue1")), w.policy, d)
			// Positive control: the child did run and did what the test needs
			// it to do, so an empty /tmp afterwards is the sweep's doing.
			if class != "" || out.ExitCode != 0 {
				t.Fatalf("class = %q, exit %d: %q %q", class, out.ExitCode, out.Stdout, out.Stderr)
			}
			if got := strings.TrimSpace(out.Stdout); got != "ran" {
				t.Fatalf("the child did not run as expected: %q %q", out.Stdout, out.Stderr)
			}
			time.Sleep(3 * time.Second)
			if _, err := os.Stat(marker); err == nil {
				t.Fatal("a process that left the group outlived the run and wrote the value")
			}
			if _, err := os.Stat(kept); err == nil {
				t.Fatal("a file of the child's account survived in /tmp")
			}
		})
	}
}

// Without an isolator the runner itself gives the child its account: the
// child is not root, and a runner that cannot do it starts nothing.
func TestNetnsUnenforcedChildRunsAsItsOwnAccount(t *testing.T) {
	_ = netnsIso(t)
	w, pl := scriptWorld(t, `id -u; id -G`)
	dropAccount = dropToChild // newWorld restores the original afterwards
	w.policy.ExecNetUnenforced = true
	d, _ := w.deps(nil)
	_ = os.Chmod(d.HomeRoot, 0o755) //nolint:gosec // G302: the child enters its run directory through it
	d.Chown = nil                   // as root, the real thing
	out, class := Run(context.Background(), pl, secret.New([]byte("v")), w.policy, d)
	if class != "" {
		t.Fatalf("class = %q", class)
	}
	if got := strings.Fields(out.Stdout); len(got) != 2 || got[0] != fmt.Sprint(childID) || got[1] != fmt.Sprint(childID) {
		t.Fatalf("child ran as %q, want uid %d and no other group than %d", out.Stdout, childID, childID)
	}
}

// A process of the child's account that is already alive could read the
// child's environment: Run refuses before it starts anything.
func TestNetnsRunRefusesWhileTheAccountHasAProcess(t *testing.T) {
	_ = netnsIso(t)
	w, pl := scriptWorld(t, `echo ran`)
	dropAccount = dropToChild
	pre := exec.Command("/usr/bin/setpriv", "--reuid", fmt.Sprint(childID), "--regid", fmt.Sprint(childID), "--clear-groups", "sleep", "30") //nolint:gosec // G204: fixed test command
	if err := pre.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pre.Process.Kill(); _ = pre.Wait() })
	time.Sleep(300 * time.Millisecond)
	d, _ := w.deps(nil)
	_ = os.Chmod(d.HomeRoot, 0o755) //nolint:gosec // G302: the child enters its run directory through it
	d.Chown = nil                   // as root, the real thing
	w.policy.ExecNetUnenforced = true
	// Positive control: with the account free the same run goes through.
	_ = pre.Process.Kill()
	_ = pre.Wait()
	if out, class := Run(context.Background(), pl, secret.New([]byte("v")), w.policy, d); class != "" || strings.TrimSpace(out.Stdout) != "ran" {
		t.Fatalf("control: class=%q out=%q", class, out.Stdout)
	}
	pre = exec.Command("/usr/bin/setpriv", "--reuid", fmt.Sprint(childID), "--regid", fmt.Sprint(childID), "--clear-groups", "sleep", "30") //nolint:gosec // G204: fixed test command
	if err := pre.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	out, class := Run(context.Background(), pl, secret.New([]byte("v")), w.policy, d)
	if class != runnerproto.ErrClassInternal || out.Stdout != "" {
		t.Fatalf("class=%q out=%q: the child ran beside a live process of its account", class, out.Stdout)
	}
}

// A file the child leaves in a world-writable subdirectory of a shared
// directory is swept too.
func TestNetnsRunSweepsNestedSharedDirectories(t *testing.T) {
	_ = netnsIso(t)
	const dir = "/tmp/.keep-w26-shared"
	if err := os.MkdirAll(dir, 0o1777); err != nil { //nolint:gosec // G301: a world-writable directory on purpose
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o1777); err != nil { //nolint:gosec // G302: a world-writable directory on purpose
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	w, pl := scriptWorld(t, `echo "$TOOL_KEY" > `+dir+`/leak; chmod 644 `+dir+`/leak; echo ran`)
	w.policy.ExecNetUnenforced = true
	dropAccount = dropToChild
	d, _ := w.deps(nil)
	_ = os.Chmod(d.HomeRoot, 0o755) //nolint:gosec // G302: the child enters its run directory through it
	d.Chown = nil                   // as root, the real thing
	out, class := Run(context.Background(), pl, secret.New([]byte("supersecretvalue1")), w.policy, d)
	if class != "" || strings.TrimSpace(out.Stdout) != "ran" {
		t.Fatalf("class=%q out=%q: the child did not run as expected", class, out.Stdout)
	}
	if _, err := os.Stat(dir + "/leak"); err == nil {
		t.Fatal("a file of the child's account survived in a nested shared directory")
	}
}
