package execpolicy_test

import (
	"errors"
	"regexp"
	"testing"

	"github.com/entire-vc/evc-keep/pkg/execpolicy"
)

// Literal arguments whose host a resolver reads differently from the way the
// approver sees it: a full stop that is not "." , a character the resolver
// drops, a mark that composes. Each must be refused with the named error.
func TestFoldedHostFormsRefused(t *testing.T) {
	offline := []struct{ name, lit string }{
		{"ideographic_full_stop", "api\u3002example.com:443"},
		{"fullwidth_full_stop", "api\uff0eexample.com:443"},
		{"halfwidth_ideographic_stop", "api\uff61example.com:443"},
		{"zwsp", "api\u200b.example.com:443"},
		{"soft_hyphen", "ap\u00adi.example.com:443"},
		{"nfd_combining_acute", "exampl" + "e\u0301" + ".com:443"},
		{"user_at_nfd", "root@exampl" + "e\u0301" + ".com"},
		{"user_at_ideographic_stop", "root@attacker\u3002example"},
		{"fullwidth_at", "root\uff20attacker.example"},
		{"non_composing_mark", "a\u0336pi.example.com:443"},
		{"cyrillic_a_host_port", "\u0430pi.example.com:443"},
		{"cyrillic_a_user_host", "root@\u0430ttacker.example"},
		{"variation_selector_in_port", "api.example.com:44\ufe0f3"},
		{"default_ignorable_in_port", "api.example.com:4\u034f43"},
		{"idn_zone_host_port", "host.\u0440\u0444:443"},
		{"idn_zone_user_host", "root@host.\u0440\u0444"},
		{"idn_zone_bare", "host.\u0440\u0444"},
		{"mark_in_zone_host_port", "host.a\u0336b:443"},
		{"mark_in_zone_user_host", "root@host.a\u0336b"},
		{"mark_in_label_bare", "a\u0336b.\u0430\u0431"},
	}
	for _, c := range offline {
		_, err := execpolicy.Validate(tpl("/opt/keep/bin/report", "--target", c.lit))
		if err == nil {
			t.Errorf("network:none %s: literal %q accepted", c.name, c.lit)
		}
	}
	allow := []struct{ name, lit string }{
		{"ideographic_full_stop", "attacker\u3002example:443"},
		{"fullwidth_full_stop", "attacker\uff0eexample:443"},
		{"zwsp", "attack\u200ber.example:443"},
		{"soft_hyphen", "attack\u00ader.example:443"},
		{"user_at_ideographic_stop", "root@attacker\u3002example"},
		{"nfd_combining_acute", "attacker.exampl" + "e\u0301" + ":443"},
		{"cyrillic_a_host_port", "\u0430pi.example.com:443"},
		{"cyrillic_a_user_host", "root@\u0430ttacker.example"},
	}
	for _, c := range allow {
		_, err := execpolicy.Validate(withNet(tpl("/usr/bin/curl", "--target", c.lit), github))
		if err == nil {
			t.Errorf("allowlist %s: literal %q accepted", c.name, c.lit)
		}
	}
}

// A literal that folds to the declared destination is still refused: an
// invisible format character has no place in a template argument, so the
// reason is the character, not a host that failed to match.
func TestInvisibleFormatCharRefused(t *testing.T) {
	for _, lit := range []string{"api\u200b.github.com:443", "plain\u00adtext", "a\u2060b", "a\u200db"} {
		for _, tp := range []execpolicy.Template{
			tpl("/opt/keep/bin/report", lit),
			withNet(tpl("/usr/bin/curl", lit), github),
		} {
			_, err := execpolicy.Validate(tp)
			if !errors.Is(err, execpolicy.ErrInvisibleChar) {
				t.Errorf("literal %q: got %v, want ErrInvisibleChar", lit, err)
			}
			if err != nil && containsRune(err.Error(), lit) {
				t.Errorf("error quotes the argument: %v", err)
			}
			// %q escapes the invisible runes, so the rune check above is
			// blind to a quoted argument: pin the whole message shape.
			if err != nil && !invisibleMsgRe.MatchString(err.Error()) {
				t.Errorf("error is not index-only: %v", err)
			}
		}
	}
}

var invisibleMsgRe = regexp.MustCompile(`^` + regexp.QuoteMeta(execpolicy.ErrInvisibleChar.Error()) + `: argv\[\d+\]$`)

func containsRune(msg, lit string) bool {
	for _, r := range lit {
		if r > 0x7f && stringsContainsRune(msg, r) {
			return true
		}
	}
	return false
}

func stringsContainsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}

// Ordinary arguments must keep working: the fold must not turn the control
// cases into refusals.
func TestFoldLeavesOrdinaryArgumentsAlone(t *testing.T) {
	for _, lit := range []string{"backup.tar.gz", "caf\u00e9", "notes.md", "10:30", "--name=r\u00e9sum\u00e9"} {
		if _, err := execpolicy.Validate(tpl("/opt/keep/bin/report", lit)); err != nil {
			t.Errorf("network:none literal %q refused: %v", lit, err)
		}
	}
	if _, err := execpolicy.Validate(withNet(tpl("/usr/bin/curl", "https://api.github.com/x", "api.github.com:443"), github)); err != nil {
		t.Errorf("declared destination refused: %v", err)
	}
	if _, err := execpolicy.Validate(tpl("/opt/keep/bin/report", "api.example.com:443")); err == nil {
		t.Error("control: ASCII host:port accepted under network:none")
	}
}

// Expand folds too: a value that only looks like a host once folded, and a
// single-script host the shorter checks do not catch, are refused.
func TestExpandFoldedHostValuesRefused(t *testing.T) {
	loose := map[string]execpolicy.Param{"v": {Pattern: `^[^ ]+$`}}
	net := withNet(withParams(tpl("/usr/bin/curl", "https://api.github.com/x", "{v}"), loose), github)
	for _, v := range []string{"attacker\u3002example", "attacker\uff0eexample", "\u043f\u0440\u0438\u043c\u0435\u0440.\u0440\u0444", "e\u0301xample.com"} {
		if _, err := execpolicy.Expand(net, map[string]string{"v": v}); !errors.Is(err, execpolicy.ErrArgValue) {
			t.Errorf("networked value %q: got %v, want ErrArgValue", v, err)
		}
	}
	for _, v := range []string{"api.example.com\u200b:443", "api.example.com:44\ufe0f3", "api.example.com:4\u034f43"} {
		if _, err := execpolicy.Expand(net, map[string]string{"v": v}); !errors.Is(err, execpolicy.ErrArgValue) {
			t.Errorf("networked value %q: got %v, want ErrArgValue", v, err)
		}
		off := withParams(tpl("/opt/keep/bin/report", "{v}"), loose)
		if _, err := execpolicy.Expand(off, map[string]string{"v": v}); !errors.Is(err, execpolicy.ErrArgValue) {
			t.Errorf("offline value %q: got %v, want ErrArgValue", v, err)
		}
	}
	off := withParams(tpl("/opt/keep/bin/report", "{v}"), loose)
	for _, v := range []string{"attacker\u3002example:443", "root@attacker\u3002example"} {
		if _, err := execpolicy.Expand(off, map[string]string{"v": v}); !errors.Is(err, execpolicy.ErrArgValue) {
			t.Errorf("offline value %q: got %v, want ErrArgValue", v, err)
		}
	}
}
