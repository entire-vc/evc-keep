package execpolicy

import (
	"regexp"
	"testing"
)

func digestBase() Template {
	return Template{
		Argv:      []string{"/usr/local/bin/tool", "--id", "{id}"},
		Params:    map[string]Param{"id": {Pattern: `^[a-z0-9]{1,16}$`}},
		SecretEnv: []string{"TOOL_KEY"},
		Network:   Network{Mode: NetAllowlist, Destinations: []Destination{{Host: "api.example.com", Port: 443}}},
	}
}

func TestDigestIsLowercaseHexSHA256(t *testing.T) {
	d := Digest(digestBase())
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(d) {
		t.Fatalf("digest %q is not lowercase hex sha-256", d)
	}
	if d != Digest(digestBase()) {
		t.Fatal("digest is not deterministic")
	}
}

// Every field of the template is part of what a human approved, so each one
// moves the digest; two different argv splits that concatenate to the same
// text must differ too.
func TestDigestCoversEveryField(t *testing.T) {
	base := Digest(digestBase())
	mut := map[string]func(*Template){
		"argv0":        func(x *Template) { x.Argv[0] = "/usr/local/bin/other" },
		"argv-split":   func(x *Template) { x.Argv = []string{"/usr/local/bin/tool", "--i", "d{id}"} },
		"argv-extra":   func(x *Template) { x.Argv = append(x.Argv, "--x") },
		"param-name":   func(x *Template) { x.Params = map[string]Param{"id2": x.Params["id"]}; x.Argv[2] = "{id2}" },
		"param-regexp": func(x *Template) { x.Params = map[string]Param{"id": {Pattern: `^[a-z0-9]{1,17}$`}} },
		"secret-env":   func(x *Template) { x.SecretEnv = []string{"TOOL_KEY2"} },
		"secret-extra": func(x *Template) { x.SecretEnv = []string{"TOOL_KEY", "B"} },
		"net-mode":     func(x *Template) { x.Network = Network{Mode: NetNone} },
		"dest-host":    func(x *Template) { x.Network.Destinations[0].Host = "api.example.org" },
		"dest-port":    func(x *Template) { x.Network.Destinations[0].Port = 444 },
		"dest-extra": func(x *Template) {
			x.Network.Destinations = append(x.Network.Destinations, Destination{Host: "b.example.com", Port: 1})
		},
	}
	for name, f := range mut {
		tpl := digestBase()
		tpl.Argv = append([]string(nil), tpl.Argv...)
		tpl.Network.Destinations = append([]Destination(nil), tpl.Network.Destinations...)
		f(&tpl)
		if Digest(tpl) == base {
			t.Errorf("%s: digest did not change", name)
		}
	}
}

func TestDigestIgnoresMapOrder(t *testing.T) {
	a := digestBase()
	a.Argv = []string{"/usr/local/bin/tool", "{a}", "{b}"}
	a.Params = map[string]Param{"a": {Pattern: `^a$`}, "b": {Pattern: `^b$`}}
	first := Digest(a)
	for i := 0; i < 50; i++ {
		if Digest(a) != first {
			t.Fatal("digest depends on map iteration order")
		}
	}
}
