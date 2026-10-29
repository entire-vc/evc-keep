// Package execpolicy validates the argv templates that exec_with_secret may
// run. A template is written by a human and approved once; an agent can only
// pick an approved template and fill its typed placeholders.
//
// The check exists because an approved template can itself be the leak: the
// output scrubber sees what the command prints, not what it sends over the
// network. `curl -d "$KEY" https://…` prints nothing and leaks everything.
// So a template states its network intent, and the rules follow R-POL-3:
//
//   - Network none (the default): no interpreters, no shells, no known
//     network clients, no URL or user@host in any argument. The runner also
//     cuts the child off the network where the OS allows (ADR-001 §3.2); this
//     static check is the early, readable refusal, not the whole boundary.
//   - Network allowlist: every destination is a literal host and port named
//     in the template, every URL argument points at one of them, and the
//     template needs the same human approval as an external target, with the
//     destinations shown to the approver.
//
// Nothing in this package ever sees a secret value: templates carry only the
// names of the environment variables a secret is placed into.
package execpolicy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// NetMode is a template's declared network intent.
type NetMode int

const (
	// NetNone forbids network access. It is the zero value on purpose.
	NetNone NetMode = iota
	// NetAllowlist permits connections to the listed destinations only.
	NetAllowlist
)

// Destination is one host:port a networked template may reach.
type Destination struct {
	Host string
	Port int
}

func (d Destination) String() string { return net.JoinHostPort(d.Host, strconv.Itoa(d.Port)) }

// Network is the network section of a template.
type Network struct {
	Mode         NetMode
	Destinations []Destination
}

// Param types one placeholder. Pattern must be anchored (^…$) and must not
// admit a URL, user@host, an option (leading "-"), a path climb or shell
// syntax — Validate probes it with such strings.
type Param struct {
	Pattern string
}

// Template is an argv template. Argv[0] is an absolute path to the binary.
// An element of the form "{name}" is a placeholder filled at call time; a
// placeholder is always a whole element, never part of one, so it cannot
// be spliced into a URL or an option.
type Template struct {
	Argv      []string
	Params    map[string]Param
	SecretEnv []string
	Network   Network
}

// Decision is what a valid template requires before it may run.
type Decision struct {
	// RequiresApproval is true for every networked template: the approver
	// sees Destinations and approves exactly those.
	RequiresApproval bool
	Destinations     []Destination
}

// Reasons a template is refused. Errors wrap one of these.
var (
	ErrMalformed        = errors.New("malformed template")
	ErrInterpreter      = errors.New("interpreters, shells and command launchers are not allowed")
	ErrShellSyntax      = errors.New("shell syntax in an argument: nothing expands it, and it signals a shell-shaped intent")
	ErrNetworkBinary    = errors.New("network client in a template declared network none")
	ErrNetworkArg       = errors.New("network address in an argument of a template declared network none")
	ErrInvisibleChar    = errors.New("argument contains an invisible format character")
	ErrUndeclaredDest   = errors.New("argument names a destination the template does not declare")
	ErrBadDestination   = errors.New("destination must be a literal host and a port")
	ErrLoosePlaceholder = errors.New("placeholder pattern admits a value that could redirect the command")
	ErrReservedEnv      = errors.New("secret environment variable name is reserved")
	ErrArgValue         = errors.New("placeholder value rejected")
)

// launchers run another program or code given as an argument. Matched on the
// name BinaryName returns (python3.12 → python, cmd.exe → cmd).
var launchers = set(
	"sh", "bash", "zsh", "dash", "ksh", "mksh", "fish", "csh", "tcsh", "ash", "busybox", "toybox",
	"env", "xargs", "nohup", "nice", "ionice", "timeout", "stdbuf", "setsid", "chroot", "unshare",
	"nsenter", "sudo", "doas", "su", "runuser", "script", "expect", "watch", "parallel", "time",
	"python", "pypy", "perl", "ruby", "irb", "node", "nodejs", "deno", "bun", "php", "lua", "luajit",
	"tclsh", "wish", "osascript", "jxa", "swift", "java", "jshell", "groovy", "scala", "rscript", "r",
	"awk", "gawk", "mawk", "nawk", "sed", "gsed", "find", "make", "gdb", "lldb", "vim", "vi", "nvim",
	"emacs", "ed", "ex", "less", "more", "man", "open", "launchctl", "systemd-run", "at", "batch",
	"crontab", "pwsh", "powershell", "cmd", "wscript", "cscript", "mshta", "rundll32",
)

// netClients open connections to an address taken from their arguments or
// configuration. Not exhaustive and not meant to be: an unknown binary that
// talks to the network is stopped by the runner's isolation, not by this
// list. The list makes the obvious case a clear refusal at approval time.
var netClients = set(
	"curl", "wget", "wget2", "http", "https", "httpie", "xh", "aria2c", "lynx", "links", "w3m",
	"nc", "ncat", "netcat", "socat", "telnet", "ssh", "scp", "sftp", "rsync", "ftp", "lftp", "tftp",
	"openssl", "gnutls-cli", "dig", "nslookup", "host", "drill", "ping", "ping6", "traceroute", "nmap",
	"mail", "mailx", "sendmail", "mutt", "gh", "glab", "git", "aws", "gcloud", "gsutil", "az",
	"kubectl", "helm", "docker", "podman", "psql", "mysql", "mariadb", "redis-cli", "mongo", "mongosh",
	"sqlcmd", "mc", "rclone", "s3cmd", "terraform", "tofu", "ansible", "ansible-playbook", "npm",
	"pnpm", "yarn", "pip", "pip3", "cargo", "go", "brew", "apt", "apt-get", "yum", "dnf", "apk",
)

// winExecExt are the extensions Windows tries when it resolves a command
// (the default PATHEXT). curl.exe runs curl and git.cmd runs git, so the
// lists above must match them under the bare name.
var winExecExt = []string{".exe", ".com", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".msc"}

// reservedEnv names change how the child loads code or where it connects.
var reservedEnv = set(
	"PATH", "HOME", "SHELL", "ENV", "BASH_ENV", "IFS", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
	"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy",
	"no_proxy", "FTP_PROXY", "ftp_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE",
	"PYTHONPATH", "PYTHONSTARTUP", "NODE_OPTIONS", "PERL5OPT", "PERL5LIB", "RUBYOPT", "GIT_SSH",
	"GIT_SSH_COMMAND", "GIT_CONFIG_GLOBAL", "SSH_AUTH_SOCK", "TMPDIR",
)

// probes are values no placeholder pattern may accept.
var probes = []string{
	"https://attacker.example/x", "attacker.example:443", "user@attacker.example", "//attacker.example",
	"-o/tmp/x", "-v", "--output=/tmp/x", "--x", "../../etc/passwd", "$KEY", "${KEY}", "$(id)", "`id`", "a;id",
	"a|id", "a b", "a\nb", "",
}

// hostProbes are extra values no placeholder of a networked template may
// accept: in a template that can reach the network, a value shaped like a
// host name or a numeric IP could become a destination nobody approved.
var hostProbes = []string{"attacker.example", "203.0.113.9", "2130706433", "0x7f000001"}

var (
	placeholderRe = regexp.MustCompile(`^\{([a-z][a-z0-9_]*)\}$`)
	embeddedRe    = regexp.MustCompile(`\{[a-z][a-z0-9_]*\}`)
	envNameRe     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	shellRe       = regexp.MustCompile("\\$[A-Za-z_{(]|`|\\$\\(|&&|\\|\\||[;|<>]")
	hostRe        = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`)
	schemeRe      = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://`)
	// Two strengths of address detection. Offline templates use the dotted
	// forms: their boundary is OS isolation, and refusing 10:30 or pkg@1.2.3
	// there buys nothing. Networked templates use the wide forms, because
	// there the static check decides what the approver is shown.
	//
	// Host portions use \p{L}\p{N} (Unicode letter/number), not A-Za-z0-9: a
	// literal argument written with a Cyrillic (or other script) lookalike
	// letter — "api.example.com" with the first letter U+0430 CYRILLIC SMALL
	// LETTER A — is still address-shaped
	// and must not slip past these checks just because it is not ASCII.
	// \p{M} is there too: a combining mark that does not compose ("a" +
	// U+0336) is not a letter, yet a resolver still reads the label.
	// foldHostish (below) is applied before these run, so full stops, invisible
	// characters and decomposed forms are already folded away.
	userHostRe   = regexp.MustCompile(`^[^\s@/:]+@[\p{L}\p{M}\p{N}.-]+\.[\p{L}\p{M}]{2,}(:.*)?$`)
	hostPortRe   = regexp.MustCompile(`^([\p{L}\p{M}\p{N}.-]+\.[\p{L}\p{M}]{2,}|\d{1,3}(\.\d{1,3}){3}):\d{1,5}$`)
	userHostWide = regexp.MustCompile(`^[^\s@/:]+@[\p{L}\p{M}\p{N}][\p{L}\p{M}\p{N}.-]*(:.*)?$`)
	hostPortWide = regexp.MustCompile(`^\[?[\p{L}\p{M}\p{N}.:-]*[\p{L}\p{M}\p{N}]\]?:\d{1,5}$`)
	hostLikeRe   = regexp.MustCompile(`^([\p{L}\p{M}\p{N}-]+\.)+[\p{L}\p{M}\p{N}-]+$|^\d+$|^0[xX][0-9a-fA-F]+$`)
	// bareHostRe is a dotted host with no port and no scheme — "example.com"
	// on its own. It is only ever treated as address-shaped together with
	// disguisedBareHost (below): a plain literal like "backup.tar.gz",
	// "report.txt" or a non-Latin file name ending in ".pdf" must keep
	// working in an offline template, while "api.example.com" with a
	// Cyrillic first letter, or a host under a non-Latin zone, must not.
	bareHostRe = regexp.MustCompile(`^([\p{L}\p{M}\p{N}-]+\.)+[\p{L}\p{M}]{2,}$`)
	// numericTailRe matches a last host label that is a number in any radix
	// inet_aton and curl accept: decimal, octal (leading 0) or hex (0x…,
	// including a bare "0x"). A host ending in such a label is parsed as an
	// IPv4 address, not looked up as a name — "2130706433", "0x7f000001",
	// "0177.0.0.1", "0x7f.0.1" and "127.1" all reach 127.0.0.1. hostRe
	// alone accepts every one of them, and the human approver at §4.5 is
	// shown that string as-is, not its decoded meaning. See canonicalIPv4.
	numericTailRe = regexp.MustCompile(`(^|\.)(\d+|0[xX][0-9a-fA-F]*)$`)
	versionTailRe = regexp.MustCompile(`[0-9][0-9.]*$`)
	// rootDotRe finds the root label of an absolute name: one full stop after
	// a non-dot that ends the argument or sits before the port, path, query
	// or fragment. A lone "." and a run of dots do not match.
	rootDotRe = regexp.MustCompile(`([^.])\.([:/?#]|$)`)
)

// fileExts are the extensions a non-Latin file name may end in and still be
// read as a file, not a host. The list is closed on purpose: a non-Latin
// name followed by anything else (a Cyrillic "server.com" or "server.io",
// "παράδειγμα.gr")
// is treated as a domain. An unlisted extension is refused, not guessed — a
// template author can rename the file or pass it through a placeholder.
var fileExts = set("txt", "md", "csv", "tsv", "json", "yaml", "yml", "toml", "xml", "html", "htm",
	"log", "sql", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "rtf",
	"tar", "gz", "tgz", "bz2", "xz", "zst", "7z", "rar", "bak", "png", "jpg", "jpeg", "gif", "svg",
	"webp", "heic", "mp3", "wav", "mp4", "mkv", "env", "conf", "cfg", "ini")

// disguisedBareHost reports whether a bare dotted literal (bareHostRe) is a
// host name a human would not read as one: it has a letter outside Latin
// and does not end in a listed file extension. That one rule covers an IDN
// zone (a Cyrillic ".rf" host, "例子.中国"), a non-Latin name under an ASCII
// zone (a Cyrillic "server.com", "παράδειγμα.gr") and a homoglyph
// ("api.example.com" with a Cyrillic first letter), while a Cyrillic
// "report.pdf" and "見積書.xlsx" stay file names.
// A pure-Latin "example.com" or "backup.tar.gz" stays a literal (§4.5: in
// network:none the OS isolation, not this check, is the boundary; this
// check only refuses early and legibly).
//
// Accepted trade-off: an IDN host under a zone whose name is also a listed
// extension passes this check. Of fileExts only "md" (Moldova) is a
// delegated zone (IANA root list, checked 2026-09-24); keep it that way —
// ".zip", ".mov" and the like are real zones and stay off the list.
//
// A listed extension only excuses a plain file name: the part before it must
// not itself read as a host ("apple.com.txt" with a Cyrillic first letter,
// "例子.中国.pdf") and no word in it may mix Latin with another script
// ("example.pdf" with a Cyrillic "a").
func disguisedBareHost(a string) bool {
	if !hasNonLatinLetter(a) {
		return false
	}
	i := strings.LastIndex(a, ".")
	if !fileExts[strings.ToLower(a[i+1:])] {
		return true
	}
	stem := a[:i]
	return bareHostRe.MatchString(stem) || mixedScriptWord(stem)
}

// bareAddress reports whether a bare dotted literal (bareHostRe) names a host.
// In an allowlist template (wide) any such name whose last label is not a
// listed file extension is an address, so the approver at §4.5 is shown it;
// a listed extension still falls to disguisedBareHost. Offline, only
// disguisedBareHost applies. Accepted trade-off: an "md" host (Moldova) stays
// a file name here; the boundary there is the OS pin on IP:port.
func bareAddress(a string, wide bool) bool {
	if wide && !fileExts[strings.ToLower(a[strings.LastIndex(a, ".")+1:])] {
		return true
	}
	return disguisedBareHost(a)
}

// mixedScriptWord reports whether a run of letters holds both Latin and
// non-Latin ones.
func mixedScriptWord(s string) bool {
	var latin, other bool
	for _, r := range s + " " {
		if !unicode.IsLetter(r) {
			if latin && other {
				return true
			}
			latin, other = false, false
			continue
		}
		if unicode.Is(unicode.Latin, r) {
			latin = true
		} else {
			other = true
		}
	}
	return false
}

func hasNonLatinLetter(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) && !unicode.Is(unicode.Latin, r) {
			return true
		}
	}
	return false
}

// canonicalIPv4 reports whether h is an IPv4 address in its one canonical
// spelling: four dotted decimal octets, no leading zeros. That is the only
// numeric Destination.Host the approver can read at face value; every other
// numeric form (see numericTailRe) is refused rather than decoded.
func canonicalIPv4(h string) bool {
	ip, err := netip.ParseAddr(h)
	return err == nil && ip.Is4() && ip.String() == h
}

// Validate checks a template and reports what it needs before it may run.
func Validate(t Template) (Decision, error) {
	if len(t.Argv) == 0 {
		return Decision{}, fmt.Errorf("%w: empty argv", ErrMalformed)
	}
	bin := t.Argv[0]
	if placeholderRe.MatchString(bin) || !path.IsAbs(bin) || path.Clean(bin) != bin {
		return Decision{}, fmt.Errorf("%w: argv[0] must be a clean absolute path", ErrMalformed)
	}
	name := BinaryName(bin)
	if launchers[name] {
		return Decision{}, fmt.Errorf("%w: %s", ErrInterpreter, name)
	}
	if len(t.SecretEnv) == 0 {
		return Decision{}, fmt.Errorf("%w: no secret environment variable", ErrMalformed)
	}
	for _, e := range t.SecretEnv {
		if !envNameRe.MatchString(e) {
			return Decision{}, fmt.Errorf("%w: bad environment variable name %q", ErrMalformed, e)
		}
		if reservedEnv[e] || strings.HasPrefix(e, "DYLD_") || strings.HasPrefix(e, "LD_") {
			return Decision{}, fmt.Errorf("%w: %s", ErrReservedEnv, e)
		}
	}

	used := map[string]bool{}
	for i, a := range t.Argv[1:] {
		if m := placeholderRe.FindStringSubmatch(a); m != nil {
			p, ok := t.Params[m[1]]
			if !ok {
				return Decision{}, fmt.Errorf("%w: argv[%d] placeholder %q has no type", ErrMalformed, i+1, m[1])
			}
			if err := checkPattern(m[1], p.Pattern, t.Network.Mode == NetAllowlist); err != nil {
				return Decision{}, err
			}
			used[m[1]] = true
			continue
		}
		if embeddedRe.MatchString(a) {
			return Decision{}, fmt.Errorf("%w: argv[%d] placeholder must be the whole element", ErrMalformed, i+1)
		}
		if strings.IndexFunc(a, func(r rune) bool { return unicode.Is(unicode.Cf, r) }) >= 0 {
			return Decision{}, fmt.Errorf("%w: argv[%d]", ErrInvisibleChar, i+1)
		}
		if shellRe.MatchString(a) {
			return Decision{}, fmt.Errorf("%w: argv[%d]", ErrShellSyntax, i+1)
		}
	}
	for p := range t.Params {
		if !used[p] {
			return Decision{}, fmt.Errorf("%w: parameter %q is not used in argv", ErrMalformed, p)
		}
	}

	switch t.Network.Mode {
	case NetNone:
		if len(t.Network.Destinations) > 0 {
			return Decision{}, fmt.Errorf("%w: network none with destinations", ErrMalformed)
		}
		if netClients[name] {
			return Decision{}, fmt.Errorf("%w: %s", ErrNetworkBinary, name)
		}
		for i, a := range t.Argv[1:] {
			if looksLikeAddress(a, false) {
				return Decision{}, fmt.Errorf("%w: argv[%d]", ErrNetworkArg, i+1)
			}
		}
		return Decision{}, nil
	case NetAllowlist:
		if len(t.Network.Destinations) == 0 {
			return Decision{}, fmt.Errorf("%w: allowlist is empty", ErrBadDestination)
		}
		allowed := map[string]bool{}
		for _, d := range t.Network.Destinations {
			if !hostRe.MatchString(d.Host) || (numericTailRe.MatchString(d.Host) && !canonicalIPv4(d.Host)) ||
				strings.Contains(d.Host, "..") || d.Port < 1 || d.Port > 65535 {
				return Decision{}, fmt.Errorf("%w: %q", ErrBadDestination, d.String())
			}
			allowed[strings.ToLower(d.Host)] = true
		}
		for i, a := range t.Argv[1:] {
			for _, h := range addressHosts(a, true) {
				if !allowed[strings.ToLower(h)] {
					return Decision{}, fmt.Errorf("%w: argv[%d] host %q", ErrUndeclaredDest, i+1, h)
				}
			}
		}
		ds := append([]Destination(nil), t.Network.Destinations...)
		return Decision{RequiresApproval: true, Destinations: ds}, nil
	default:
		return Decision{}, fmt.Errorf("%w: unknown network mode", ErrMalformed)
	}
}

// Expand fills a validated template's placeholders with call-time values and
// returns the argv to execute. Each value must match its pattern and pass
// the same probes the pattern was checked against.
func Expand(t Template, values map[string]string) ([]string, error) {
	out := make([]string, len(t.Argv))
	for i, a := range t.Argv {
		m := placeholderRe.FindStringSubmatch(a)
		if i == 0 || m == nil {
			out[i] = a
			continue
		}
		v, ok := values[m[1]]
		if !ok {
			return nil, fmt.Errorf("%w: %q missing", ErrArgValue, m[1])
		}
		re, err := anchored(t.Params[m[1]].Pattern)
		networked := t.Network.Mode == NetAllowlist
		if err != nil || !re.MatchString(v) || unsafeValue(v, networked) ||
			(networked && hostLike(v)) {
			return nil, fmt.Errorf("%w: %q", ErrArgValue, m[1])
		}
		out[i] = v
	}
	return out, nil
}

// BinaryName is the lower-cased basename of a binary path with a Windows
// executable extension and a trailing version removed, so python3.12,
// Python3 and python3.12.exe all become python. Lower-casing matters: on a
// case-insensitive file system (macOS default) /usr/bin/CURL runs curl. The
// extension matters because Windows resolves curl.exe, curl.exe. (trailing
// dots and spaces are dropped) and curl through PATHEXT to one program.
// Stripping repeats until nothing changes, so the layers can come in any
// order; it never strips a name down to nothing. The extension list is the
// default PATHEXT: a runner host with a custom PATHEXT is outside this check
// and inside the runner's isolation.
func BinaryName(bin string) string {
	b := strings.ToLower(path.Base(bin))
	// A colon cannot be part of a Windows file name; it opens an NTFS data
	// stream, and curl.exe::$DATA runs curl.exe.
	if i := strings.Index(b, ":"); i > 0 {
		b = b[:i]
	}
	for {
		prev := b
		if t := strings.TrimRight(b, ". "); t != "" {
			b = t
		}
		for _, ext := range winExecExt {
			if t, ok := strings.CutSuffix(b, ext); ok && t != "" {
				b = t
				break
			}
		}
		if trimmed := versionTailRe.ReplaceAllString(b, ""); trimmed != "" {
			b = strings.TrimRight(trimmed, "-.")
		}
		if b == prev {
			return b
		}
	}
}

func checkPattern(name, pattern string, networked bool) error {
	re, err := anchored(pattern)
	if err != nil {
		return fmt.Errorf("%w: %q: %v", ErrLoosePlaceholder, name, err)
	}
	ps := probes
	if networked {
		ps = append(append([]string(nil), probes...), hostProbes...)
	}
	for _, p := range ps {
		if re.MatchString(p) {
			return fmt.Errorf("%w: %q accepts %q", ErrLoosePlaceholder, name, p)
		}
	}
	return nil
}

func anchored(pattern string) (*regexp.Regexp, error) {
	if !strings.HasPrefix(pattern, "^") || !strings.HasSuffix(pattern, "$") || strings.HasSuffix(pattern, `\$`) {
		return nil, errors.New("pattern must be anchored with ^ and $")
	}
	return regexp.Compile(pattern)
}

func unsafeValue(v string, networked bool) bool {
	return v == "" || strings.HasPrefix(v, "-") || strings.Contains(v, "..") ||
		looksLikeAddress(v, networked) || shellRe.MatchString(v) || strings.ContainsAny(v, " \t\r\n\x00")
}

func looksLikeAddress(a string, wide bool) bool {
	return len(addressHosts(a, wide)) > 0 || strings.Contains(a, "://")
}

// foldHostish maps a string to the form a resolver reads: invisible format
// characters (ZWSP, soft hyphen, ZWJ/ZWNJ, U+2060, variation selectors) are
// dropped, NFKC folds compatibility forms (U+FF0E, fullwidth @ : /) and
// decomposed marks, and the ideographic full stops U+3002 and U+FF61, which
// IDNA treats as label separators, become ".". The root label is then dropped:
// a resolver reads "host." as the absolute name of "host". Without it the
// address detector and the approver see a different host than the one that
// resolves.
func foldHostish(s string) string {
	drop := func(r rune) rune {
		if unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) ||
			unicode.Is(unicode.Variation_Selector, r) {
			return -1
		}
		return r
	}
	s = norm.NFKC.String(strings.Map(drop, s))
	s = strings.Map(func(r rune) rune {
		if r == '\u3002' || r == '\uff61' {
			return '.'
		}
		return r
	}, s)
	return rootDotRe.ReplaceAllString(s, "$1$2")
}

// hostLike reports whether v, raw or folded, has the shape of a host name or a
// numeric address.
func hostLike(v string) bool {
	return hostLikeRe.MatchString(v) || hostLikeRe.MatchString(foldHostish(v))
}

// addressHosts returns the hosts named by URLs, user@host, host:port or
// --opt=URL forms inside one argument, found in the raw text and in its folded
// form; the folded host is what an allowlist is compared with. wide also
// recognises hosts without a dotted name: integer and bracketed IPv6 hosts, and
// bare names.
func addressHosts(a string, wide bool) []string {
	hosts := scanHosts(a, wide)
	if f := foldHostish(a); f != a {
		hosts = append(hosts, scanHosts(f, wide)...)
	}
	for i, h := range hosts {
		if t := strings.TrimSuffix(h, "."); t != "" {
			hosts[i] = t
		}
	}
	return hosts
}

func scanHosts(a string, wide bool) []string {
	userHost, hostPort := userHostRe, hostPortRe
	if wide {
		userHost, hostPort = userHostWide, hostPortWide
	}
	var hosts []string
	if v, ok := strings.CutPrefix(a, "--"); ok {
		if _, rhs, ok := strings.Cut(v, "="); ok {
			a = rhs
		}
	}
	for _, loc := range schemeRe.FindAllStringIndex(a, -1) {
		rest := a[loc[0]:]
		if end := strings.IndexAny(rest, " \t,;"); end >= 0 {
			rest = rest[:end]
		}
		if u, err := url.Parse(rest); err == nil && u.Hostname() != "" {
			hosts = append(hosts, u.Hostname())
		} else {
			hosts = append(hosts, "?")
		}
	}
	if len(hosts) == 0 && userHost.MatchString(a) {
		h := a[strings.Index(a, "@")+1:]
		if c := strings.Index(h, ":"); c >= 0 {
			h = h[:c]
		}
		hosts = append(hosts, h)
	}
	if len(hosts) == 0 && hostPort.MatchString(a) {
		hosts = append(hosts, strings.Trim(a[:strings.LastIndex(a, ":")], "[]"))
	}
	if len(hosts) == 0 && bareHostRe.MatchString(a) && bareAddress(a, wide) {
		hosts = append(hosts, a)
	}
	return hosts
}

func set(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}
