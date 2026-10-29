package runnerproto

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

// HostPolicy is the host administrator's local limit on what a runner does,
// read from a file owned by the runner's user with mode 0600. It is checked
// by the runner independently of the server: a compromised server that signs
// a job does not make the job allowed here. Default is deny.
type HostPolicy struct {
	Version int          `json:"version"`
	Targets []TargetRule `json:"targets"`
	// AgentUIDs and AgentGIDs are the agents on this host. A target owned
	// by one of them, or readable by one of their groups, is refused: a
	// value written where an agent can read it has reached the agent.
	AgentUIDs []int64 `json:"agent_uids"`
	AgentGIDs []int64 `json:"agent_gids"`
	// UIDShared marks a host where agents and consumers share a uid. Such a
	// host cannot keep a value from an agent, so prod secrets are refused.
	UIDShared bool `json:"uid_shared"`
	// AllowExec admits exec_with_secret jobs at all.
	AllowExec bool `json:"allow_exec"`
	// ExecNetUnenforced records that the administrator accepts running
	// networked exec templates on a host where the OS cannot pin the
	// child's network (threat model 4.5). The exec runner reads
	// it; without it such templates fail closed.
	ExecNetUnenforced bool `json:"exec_net_unenforced"`
	// SystemdCredPlaintextFallback lets a systemd-credential target be
	// written as a plain 0600 file on a host without systemd-creds. Off by
	// default: without it the target writer must refuse such a target
	// rather than silently write it with less protection (threat model
	// 7.4). internal/targets takes it as the
	// WithSystemdCredPlaintextFallback write option; no runner code passes
	// that option yet, so the flag is not wired into a running host.
	SystemdCredPlaintextFallback bool `json:"systemd_cred_plaintext_fallback"`
	// MaxDeploysPerHour caps deploy and exec jobs; see Limiter.
	MaxDeploysPerHour int `json:"max_deploys_per_hour"`
	// ExecTemplates are the exec_with_secret templates this host runs. The
	// runner holds its own copy: a job names a template by id and digest,
	// and the host never runs a template it does not have, whatever the
	// server signs. Each is re-validated by execpolicy on load.
	ExecTemplates []ExecTemplate `json:"exec_templates,omitempty"`
	// ExecBinDirs are the directories argv[0] may resolve into, after
	// symlinks. Required once there is a template.
	ExecBinDirs []string `json:"exec_bin_dirs,omitempty"`
}

// TargetRule allows one target kind under the listed directories and, for
// a kind with a field, only the listed fields.
type TargetRule struct {
	Kind         TargetKind `json:"kind"`
	PathPrefixes []string   `json:"path_prefixes"`
	// Fields are the exact variable names or keys a job may write under
	// this rule. Required for a kind with a field, empty otherwise: the
	// field is the agent's choice, and a name the consumer reads as an
	// option of its interpreter echoes the value into its own output
	// (threat model 7.1).
	Fields []string `json:"fields,omitempty"`
	// AllowNonCredentialName admits field names that are not
	// credential-shaped (see credentialShaped). Off by default: the list
	// of names a consumer echoes can never be complete, the shape of a
	// credential name can. A rule that sets it is reported by Warnings;
	// the echo list still applies on top (threat model 7.1).
	AllowNonCredentialName bool `json:"allow_non_credential_name,omitempty"`
	// Units is the allowlist of consumer units (Target.Consumer) a deploy
	// job matching this rule may name for restart. Deny by default: an
	// empty or absent list permits no restart at all for this rule, even
	// though the deploy itself is allowed. A signed job cannot widen this —
	// the server saying yes does not make the host restart an unlisted
	// unit (threat model: a compromised server must not gain arbitrary
	// unit restart through a signed job).
	Units []string `json:"units,omitempty"`
	// UnitUIDs are the uids under which a launchd consumer in Units may be
	// restarted (user/<uid>/<label>). The uid comes from the signed job, so
	// the pair (unit, uid) must be listed. Deny by default: empty or absent
	// permits no launchd restart. Ignored for systemd consumers.
	UnitUIDs []int64 `json:"unit_uids,omitempty"`
	// Health is this rule's fixed definition of "healthy" after a restart.
	// The signed job never supplies these parameters: a
	// compromised server naming its own "loopback" URL and marker could
	// otherwise fake a trivially-passing check, and rotation is gated on
	// this result. Zero value means no check runs (Healthcheck.Status is
	// HealthSkipped).
	Health HealthCheck `json:"health,omitempty"`
}

// HealthCheck is a TargetRule's fixed definition of a healthcheck — see the
// Health field's doc on TargetRule for why the job never supplies this.
type HealthCheck struct {
	// Kind is empty (no check) or one of HealthKind's closed list.
	Kind HealthKind `json:"kind,omitempty"`
	// SettleSeconds: how long a unit-active check waits before deciding
	// the consumer is still up. Used only by HealthKindUnitActive.
	SettleSeconds int64 `json:"settle_seconds,omitempty"`
	// URL is the http check's target. Host must be exactly 127.0.0.1 or
	// ::1 — nothing else, not even "localhost" (its resolution depends on
	// host config, not a fixed loopback literal). Used only by
	// HealthKindHTTP.
	URL string `json:"url,omitempty"`
	// ExpectStatus is the required HTTP status code.
	ExpectStatus int64 `json:"expect_status,omitempty"`
	// BodyMarker is a substring the response body must contain. Required:
	// a bare status code proves nothing (fleet rule "HTTP 200 proves
	// nothing") — never logged or returned, only compared.
	BodyMarker string `json:"body_marker,omitempty"`
	// TimeoutSeconds bounds the http check's request.
	TimeoutSeconds int64 `json:"timeout_seconds,omitempty"`
}

const (
	maxHealthSettleSeconds  = 300
	maxHealthTimeoutSeconds = 30
	maxHealthMarkerLen      = 256
)

// loopbackHTTPHosts is the exact, closed set of hosts an http healthcheck
// may target — no DNS, no "localhost" (host-config-dependent), no allowlist
// to extend: literally 127.0.0.1 or ::1.
var loopbackHTTPHosts = map[string]bool{"127.0.0.1": true, "::1": true}

// validate checks h in isolation. It is what refuses a non-loopback http
// check: called from TargetRule.Validate via HostPolicy.Validate, so a
// policy naming one is refused when the policy is parsed — before any job,
// any restart, any network call.
func (h HealthCheck) validate() error {
	switch h.Kind {
	case "":
		if h != (HealthCheck{}) {
			return errors.New("health: kind is empty but other fields are set")
		}
	case HealthKindUnitActive:
		if h.SettleSeconds < 1 || h.SettleSeconds > maxHealthSettleSeconds {
			return errors.New("health: settle_seconds out of range")
		}
		if h.URL != "" || h.ExpectStatus != 0 || h.BodyMarker != "" || h.TimeoutSeconds != 0 {
			return errors.New("health: unit-active does not use url, expect_status, body_marker or timeout_seconds")
		}
	case HealthKindHTTP:
		u, err := url.Parse(h.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !loopbackHTTPHosts[u.Hostname()] {
			return errors.New("health: url must be an http(s) URL to 127.0.0.1 or ::1")
		}
		if h.ExpectStatus < 100 || h.ExpectStatus > 599 {
			return errors.New("health: expect_status must be a valid HTTP status")
		}
		if h.BodyMarker == "" || len(h.BodyMarker) > maxHealthMarkerLen {
			return errors.New("health: body_marker is required")
		}
		if h.TimeoutSeconds < 1 || h.TimeoutSeconds > maxHealthTimeoutSeconds {
			return errors.New("health: timeout_seconds out of range")
		}
		if h.SettleSeconds != 0 {
			return errors.New("health: http does not use settle_seconds")
		}
	default:
		return fmt.Errorf("health: unknown kind %q", h.Kind)
	}
	return nil
}

// ResolveHealth returns the healthcheck a matching TargetRule defines for
// t, or the zero HealthCheck (no check) if none does. Call only after Check
// has admitted the job — this does not repeat Check's own refusals, and it
// looks at the same rule (kind, path prefix, consumer in Units) that made
// the restart itself allowed.
func ResolveHealth(p HostPolicy, t Target) HealthCheck {
	for _, r := range p.Targets {
		if r.Kind != t.Kind {
			continue
		}
		for _, pre := range r.PathPrefixes {
			if under(t.Path, pre) && r.allowsConsumer(t) {
				return r.Health
			}
		}
	}
	return HealthCheck{}
}

// ProdScope is the secret scope refused on a UIDShared host.
const ProdScope = "prod"

// ErrPolicy wraps every refusal by the host policy.
var ErrPolicy = errors.New("runnerproto: refused by host policy")

func denied(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrPolicy, fmt.Sprintf(format, a...))
}

// ParseHostPolicy reads a policy strictly: unknown fields, trailing data,
// an unknown kind or a malformed prefix are errors, never ignored.
func ParseHostPolicy(b []byte) (HostPolicy, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var p HostPolicy
	if err := dec.Decode(&p); err != nil {
		return HostPolicy{}, fmt.Errorf("runnerproto: host policy: %w", err)
	}
	if !atEOF(dec) {
		return HostPolicy{}, errors.New("runnerproto: host policy: trailing data")
	}
	return p, p.Validate()
}

// Validate checks the policy itself.
func (p HostPolicy) Validate() error {
	if p.Version != 1 {
		return errors.New("runnerproto: host policy: version must be 1")
	}
	if p.MaxDeploysPerHour <= 0 {
		return errors.New("runnerproto: host policy: max_deploys_per_hour must be positive")
	}
	if err := p.validateExec(); err != nil {
		return err
	}
	for _, r := range p.Targets {
		if !knownKind(r.Kind) {
			return fmt.Errorf("runnerproto: host policy: unknown target kind %q", r.Kind)
		}
		for _, pre := range r.PathPrefixes {
			if err := ValidatePath(pre); err != nil {
				return fmt.Errorf("runnerproto: host policy: prefix: %w", err)
			}
		}
		if err := r.validateFields(); err != nil {
			return err
		}
		for _, u := range r.Units {
			if !consumerRe.MatchString(u) {
				return fmt.Errorf("runnerproto: host policy: unit %q", u)
			}
		}
		for _, uid := range r.UnitUIDs {
			if uid < 0 || uid > 1<<31-1 {
				return fmt.Errorf("runnerproto: host policy: unit_uids: uid %d out of range", uid)
			}
		}
		if err := r.Health.validate(); err != nil {
			return fmt.Errorf("runnerproto: host policy: %w", err)
		}
	}
	return nil
}

func (r TargetRule) validateFields() error {
	if !kindHasField(r.Kind) {
		if len(r.Fields) != 0 {
			return fmt.Errorf("runnerproto: host policy: %s has no field, fields must be empty", r.Kind)
		}
		return nil
	}
	if len(r.Fields) == 0 {
		return fmt.Errorf("runnerproto: host policy: a %s rule must list its fields", r.Kind)
	}
	for _, f := range r.Fields {
		if err := (Target{Kind: r.Kind, Field: f}).validateField(); err != nil {
			return fmt.Errorf("runnerproto: host policy: field %q is malformed", f)
		}
		if r.Kind == TargetMCPConfig && !mcpEnvKeyRe.MatchString(f) {
			return fmt.Errorf("runnerproto: host policy: mcp-config field %q must be mcpServers.<name>.env.<VAR>", f)
		}
		if !r.AllowNonCredentialName && !credentialShaped(f) {
			return fmt.Errorf("runnerproto: host policy: field %q is not a credential name (*_TOKEN, *_KEY, *_SECRET, *_PASSWORD, *_API_KEY, *_CREDENTIAL); set allow_non_credential_name on the rule to list it", f)
		}
		if echoField(f) {
			return fmt.Errorf("runnerproto: host policy: field %q matches a name that an interpreter or loader reads and is refused", f)
		}
	}
	return nil
}

// Warnings lists what a valid policy allows beyond the default: a field
// that is not credential-shaped, listed under allow_non_credential_name.
// It names rules and fields only, never a value.
func (p HostPolicy) Warnings() []string {
	var w []string
	for i, r := range p.Targets {
		if !r.AllowNonCredentialName {
			continue
		}
		for _, f := range r.Fields {
			if !credentialShaped(f) {
				w = append(w, fmt.Sprintf("runnerproto: host policy: rule %d (%s) lists %q, which is not a credential name (allow_non_credential_name)", i, r.Kind, f))
			}
		}
	}
	return w
}

// credentialShaped reports whether the last segment of a field, upper-cased,
// is a credential name: an underscore-separated name ending in TOKEN, KEY,
// SECRET, PASSWORD, API_KEY or CREDENTIAL, or one of the exact credential
// names accepted by precedent.
func credentialShaped(field string) bool {
	last := field[strings.LastIndex(field, ".")+1:]
	name := strings.ToUpper(last)
	return credentialNames[name] || credentialShapeRe.MatchString(name)
}

// Names a consumer reads as an option of its interpreter, its loader, its
// shell or its network stack. Written with a value, they run code or echo
// the value into the consumer's own output (PYTHONWARNINGS=<value> prints
// "Invalid -W option ignored: ... '<value>'"), which an agent may read.
// Threat model 7.1. Matched on the upper-cased last segment of the field.
// The list cannot be complete: the real guard is the administrator's exact
// list of fields, this only catches the known dangerous ones listed there.
var (
	// An mcp-config rule may only name a server's environment variable:
	// command, args, url or cwd would put the value where the client
	// prints it (a spawn error, a connection log).
	credentialShapeRe = regexp.MustCompile(`^[A-Z0-9_]*_(TOKEN|KEY|SECRET|PASSWORD|API_KEY|CREDENTIAL)$`)

	mcpEnvKeyRe = regexp.MustCompile(`^mcpServers\.[A-Za-z0-9_-]+\.env\.[A-Za-z_][A-Za-z0-9_]{0,127}$`)

	// PERL5 covers PERL5OPT and PERL5LIB; PERLLIB (no 5) is an exact name
	// below. BASH_FUNC_ is defence in depth: the exported-function form
	// carries "%%", which the field syntax already refuses.
	echoPrefixes = []string{
		"LD_", "DYLD_", "PYTHON", "PERL5", "_JAVA_", "JDK_JAVA_", "BASH_FUNC_",
		"CORECLR_", "NODE_", "GIT_", "NPM_CONFIG_", "LC_", "CGO_", "XDG_",
		"PHP_INI_", "R_PROFILE", "R_ENVIRON", "LUA_", "RUST", "CARGO_",
		// Build-tool and language-runtime option variables: their consumer
		// echoes the value into a compiler invocation, a package-manager
		// request line or a diagnostic (CFLAGS -> the printed cc command
		// line; PIP_CONFIG_FILE -> pip's own log of which file it read).
		"COMPLUS_", "DOTNET_", "PIP_", "UV_", "BUNDLE_", "GEM_", "ERL_",
		// clang reads CCC_OVERRIDE_OPTIONS and prints it on every call.
		"CCC_",
		// Found by review of the first release of this list (card
		// e1f0d8e5): docker compose, ruby's GC settings, clang's C++
		// include path, terraform's per-command arguments, cmake.
		"COMPOSE_", "RUBY_", "OBJCPLUS_", "TF_CLI_ARGS", "CMAKE_",
		// terraform prints input variables in plan output and validation
		// errors unless the variable is declared sensitive.
		"TF_VAR_",
	}
	// FLAGS/_OPTS: compiler and JVM/CLR-style option variables
	// (CFLAGS, LDFLAGS, CPPFLAGS, MAVEN_OPTS, GRADLE_OPTS, SBT_OPTS) are
	// spliced into a command line or a VM's own printed invocation.
	// _OPTIONS/_ARGS/_OPT: the same shape spelled out (NODE_OPTIONS,
	// TAR_OPTIONS, GREP_OPTIONS, XZ_OPT, DOCKER_BUILD_ARGS).
	echoSuffixes = []string{"_PROXY", "_CA_BUNDLE", "_CA_CERTS", "FLAGS", "_OPTS", "_OPTIONS", "_ARGS", "_OPT",
		// A client key is read as a path: a missing file is reported with
		// the path, which here is the value (VAULT_CLIENT_KEY).
		"_CLIENT_KEY", "_TLS_KEY", "_SSL_KEY"}
	echoNames = map[string]bool{
		"JAVA_TOOL_OPTIONS": true, "JAVA_OPTS": true, "RUBYOPT": true,
		"RUBYLIB": true, "PERLLIB": true, "DOTNET_STARTUP_HOOKS": true,
		"SSH_ASKPASS": true,
		"BASH_ENV":    true, "ENV": true, "PS4": true, "PROMPT_COMMAND": true,
		"SHELLOPTS": true, "BASHOPTS": true, "CDPATH": true, "IFS": true,
		"PATH": true, "HOME": true, "EDITOR": true, "VISUAL": true, "PAGER": true,
		// Files a consumer reads as its own configuration: zsh startup
		// files, the OpenSSL config (engine loading), curl and wget rc.
		"ZDOTDIR": true, "OPENSSL_CONF": true, "OPENSSL_ENGINES": true,
		"OPENSSL_MODULES": true, "CURL_HOME": true, "WGETRC": true,
		// Values a consumer quotes back in a warning (locale, terminal),
		// runs as a program, or loads as a library or
		// resolver configuration.
		"LANG": true, "LANGUAGE": true, "TERM": true,
		"SUDO_ASKPASS": true, "LESSOPEN": true, "LESSCLOSE": true,
		"MANPAGER": true, "BROWSER": true, "GCONV_PATH": true,
		"HOSTALIASES": true, "RES_OPTIONS": true, "LOCALDOMAIN": true,
		// Build tools and clients that run or load what these name.
		"PHPRC": true, "MAKEFLAGS": true, "CC": true, "CXX": true,
		"PS1": true, "PS2": true, "PS3": true, "TMPDIR": true, "SHELL": true,
		"KUBECONFIG": true, "DOCKER_HOST": true, "SSL_CERT_FILE": true,
		"SSL_CERT_DIR": true, "SSLKEYLOGFILE": true, "JAVA_HOME": true,
		// A consumer quotes these back verbatim: TZ in a zone-name warning,
		// CLASSPATH/GLIBC_TUNABLES/NLSPATH/LOCPATH/TERMINFO in a resolver or
		// loader diagnostic, HISTFILE/VIMINIT/EXINIT as a path a shell or
		// editor opens and may echo the read error for.
		"TZ": true, "CLASSPATH": true, "GLIBC_TUNABLES": true,
		"NLSPATH": true, "LOCPATH": true, "TERMINFO": true,
		"HISTFILE": true, "VIMINIT": true, "EXINIT": true,
		// make's implicit-rule variables: spliced into the recipe make
		// prints before running it (TARGET_ARCH=<value> make probe.o prints
		// "cc <value> -c -o probe.o probe.c"). MAKEFILES is read as a
		// makefile. Exact names: AR or LD inside a longer name is not one.
		"TARGET_ARCH": true, "LDLIBS": true, "LOADLIBES": true,
		"OUTPUT_OPTION": true, "MAKEFILES": true, "AR": true, "AS": true,
		"CPP": true, "LD": true, "FC": true, "PC": true, "LEX": true,
		"YACC": true, "M2C": true, "CO": true, "GET": true, "RM": true,
		"MAKEINFO": true, "TEX": true, "TEXI2DVI": true, "WEAVE": true,
		"CWEAVE": true, "TANGLE": true, "CTANGLE": true,
		// Toolchain search paths and console-tool defaults the tool quotes
		// back in its own diagnostic (clang's missing-SDK error, gzip's
		// option error, df's bad block size, gpg's home directory).
		"SDKROOT": true, "DEVELOPER_DIR": true, "LIBRARY_PATH": true,
		"CPATH": true, "C_INCLUDE_PATH": true, "CPLUS_INCLUDE_PATH": true,
		"OBJC_INCLUDE_PATH": true, "GZIP": true, "BZIP2": true,
		"BLOCKSIZE": true, "BLOCK_SIZE": true, "GNUPGHOME": true,
		"DOCKER_CONTEXT": true, "DOCKER_CONFIG": true, "LESS": true,
		"MORE": true,
		// Run or quoted back by their consumer: GNU make's own name and
		// its lint/command variables, the program rsync and cvs spawn,
		// docker's platform and cert path, perl's signal mode, pkg-config,
		// ccache, GNU coreutils' layout settings.
		"LINT": true, "MAKE": true, "MAKE_COMMAND": true, "RSYNC_RSH": true,
		"CVS_RSH": true, "DOCKER_DEFAULT_PLATFORM": true,
		"DOCKER_CERT_PATH": true, "PERL_SIGNALS": true, "PKG_CONFIG": true,
		"CCACHE_PREFIX": true, "COLUMNS": true, "TABSIZE": true,
		"QUOTING_STYLE": true, "TIME_STYLE": true, "ETCDCTL_KEY": true,
	}
	// The NODE_ and GIT_ families redirect the consumer (GIT_DIR, GIT_WORK_TREE
	// point git at another repository and its hooks; NODE_DEBUG, NODE_ICU_DATA
	// change what node loads or prints), so the whole family is refused. These
	// credentials are values, not options, and are the only exceptions: exact
	// names, compared upper-cased. A new exception is a threat model change.
	// CARGO_ is refused for the same reason (CARGO_BUILD_RUSTC_WRAPPER runs a
	// program); the registry token is its credential.
	credentialNames = map[string]bool{
		"NODE_AUTH_TOKEN": true, "GIT_TOKEN": true, "GIT_PASSWORD": true,
		"CARGO_REGISTRY_TOKEN": true,
	}
)

func echoField(field string) bool {
	name := strings.ToUpper(field[strings.LastIndex(field, ".")+1:])
	if echoNames[name] {
		return true
	}
	if credentialNames[name] {
		return false
	}
	// Go's own settings are GO followed by letters and digits only
	// (GOFLAGS, GOPROXY, GOTOOLCHAIN); an underscore marks some other
	// program's name, such as GOOGLE_API_KEY.
	if strings.HasPrefix(name, "GO") && !strings.Contains(name, "_") {
		return true
	}
	for _, p := range echoPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	for _, s := range echoSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// allowsField reports whether this rule lists the target's field. A kind
// without a field has nothing to list.
func (r TargetRule) allowsField(t Target) bool {
	if !kindHasField(t.Kind) {
		return true
	}
	for _, f := range r.Fields {
		if f == t.Field {
			return true
		}
	}
	return false
}

// ValidatePath checks a target path's syntax: absolute, already clean (no
// "..", ".", "//" or trailing slash), no control characters, not the root.
// That a path contains no symlink is checked by the writer, which opens
// every component with O_NOFOLLOW; syntax cannot tell.
func ValidatePath(p string) error {
	switch {
	case p == "" || len(p) > 1024:
		return denied("path is empty or too long")
	case !strings.HasPrefix(p, "/"):
		// This is also what refuses a URL: https://… is not absolute.
		return denied("path is not absolute")
	case p == "/":
		return denied("path is the root")
	case path.Clean(p) != p:
		return denied("path is not clean")
	}
	for _, c := range p {
		if c < 0x20 || c == 0x7f {
			return denied("path contains a control character")
		}
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == ".." || seg == "." {
			return denied("path has a relative component")
		}
	}
	return nil
}

func under(p, prefix string) bool {
	return strings.HasPrefix(p, prefix+"/")
}

func contains(xs []int64, x int64) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// allowsConsumer reports whether r lists t.Consumer in Units and, for a
// launchd consumer, t.UID in UnitUIDs: the restart domain user/<uid>/<label>
// is built from the job's uid, so the pair is what the host authorises.
func (r TargetRule) allowsConsumer(t Target) bool {
	if !slices.Contains(r.Units, t.Consumer) {
		return false
	}
	if strings.HasPrefix(t.Consumer, "launchd:") {
		return slices.Contains(r.UnitUIDs, t.UID)
	}
	return true
}

// consumerAllowed reports whether t.Consumer (and, for launchd, t.UID) is
// allowed by some rule whose kind and path prefix match t.
func consumerAllowed(p HostPolicy, t Target) bool {
	for _, r := range p.Targets {
		if r.Kind != t.Kind {
			continue
		}
		for _, pre := range r.PathPrefixes {
			if under(t.Path, pre) && r.allowsConsumer(t) {
				return true
			}
		}
	}
	return false
}

// Check decides whether this host runs j. j must already be verified
// (VerifyJob). The rate limit is separate (Limiter): it has state.
func Check(j Job, p HostPolicy) error {
	if err := p.Validate(); err != nil {
		return denied("policy is invalid")
	}
	if err := j.Validate(); err != nil {
		return err
	}
	if p.UIDShared && j.Secret.Scope == ProdScope && j.NeedsValue() {
		return denied("prod secrets are not deployed to a uid_shared host")
	}
	if j.Action == ActionExec {
		if !p.AllowExec {
			return denied("exec is not allowed on this host")
		}
		return nil
	}
	t := j.Target
	if err := ValidatePath(t.Path); err != nil {
		return err
	}
	allowed := false
	for _, r := range p.Targets {
		if r.Kind != t.Kind {
			continue
		}
		for _, pre := range r.PathPrefixes {
			if under(t.Path, pre) && r.allowsField(t) {
				allowed = true
			}
		}
	}
	if !allowed {
		return denied("target kind, path and field are not in the host policy")
	}
	// An agent-owned target is refused for verify too: an agent that can
	// write the file could use verify as an oracle for its guesses.
	if contains(p.AgentUIDs, t.UID) {
		return denied("target owner is an agent")
	}
	if j.Action == ActionVerify {
		return nil
	}
	// Deny by default: a job naming a consumer must have it in some
	// matching rule's allowlist, even though the deploy itself is allowed.
	if t.Consumer != "" && !consumerAllowed(p, t) {
		return denied("target consumer unit is not in the host policy")
	}
	switch {
	case t.Mode&0o007 != 0:
		return denied("target would be readable by others")
	case t.Mode&0o070 != 0 && contains(p.AgentGIDs, t.GID):
		return denied("target would be readable by an agent group")
	}
	return nil
}

// Limiter enforces MaxDeploysPerHour over a sliding hour. It counts jobs
// that need a value (deploy, exec).
type Limiter struct {
	mu    sync.Mutex
	max   int
	times []time.Time
}

// NewLimiter returns a limiter for p.
func NewLimiter(p HostPolicy) *Limiter { return &Limiter{max: p.MaxDeploysPerHour} }

// Allow records j at now and reports whether it is within the limit.
func (l *Limiter) Allow(j Job, now time.Time) error {
	if !j.NeedsValue() {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	keep := l.times[:0]
	for _, t := range l.times {
		if now.Sub(t) < time.Hour {
			keep = append(keep, t)
		}
	}
	l.times = keep
	if len(l.times) >= l.max {
		return denied("deploy rate limit")
	}
	l.times = append(l.times, now)
	return nil
}
