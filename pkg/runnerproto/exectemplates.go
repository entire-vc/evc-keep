package runnerproto

import (
	"errors"
	"fmt"

	"github.com/entire-vc/evc-keep/pkg/execpolicy"
)

// ExecTemplate is one exec_with_secret template in the host policy file. It
// mirrors execpolicy.Template with a JSON shape the administrator can write.
type ExecTemplate struct {
	ID        string               `json:"id"`
	Argv      []string             `json:"argv"`
	Params    map[string]ExecParam `json:"params,omitempty"`
	SecretEnv []string             `json:"secret_env"`
	Network   ExecNetwork          `json:"network"`
}

// ExecParam types one placeholder.
type ExecParam struct {
	Pattern string `json:"pattern"`
}

// ExecNetwork is the template's declared network intent: "none" or
// "allowlist".
type ExecNetwork struct {
	Mode         string            `json:"mode"`
	Destinations []ExecDestination `json:"destinations,omitempty"`
}

// ExecDestination is one literal host and port.
type ExecDestination struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// Template converts to the execpolicy form. A mode other than the two known
// ones is an error, never a default: an unknown word must not become "none".
func (t ExecTemplate) Template() (execpolicy.Template, error) {
	out := execpolicy.Template{
		Argv:      append([]string(nil), t.Argv...),
		SecretEnv: append([]string(nil), t.SecretEnv...),
	}
	if len(t.Params) > 0 {
		out.Params = make(map[string]execpolicy.Param, len(t.Params))
		for k, v := range t.Params {
			out.Params[k] = execpolicy.Param{Pattern: v.Pattern}
		}
	}
	switch t.Network.Mode {
	case "none":
		out.Network.Mode = execpolicy.NetNone
	case "allowlist":
		out.Network.Mode = execpolicy.NetAllowlist
	default:
		return execpolicy.Template{}, fmt.Errorf("unknown network mode %q", t.Network.Mode)
	}
	for _, d := range t.Network.Destinations {
		out.Network.Destinations = append(out.Network.Destinations, execpolicy.Destination{Host: d.Host, Port: d.Port})
	}
	return out, nil
}

// ExecTemplate finds a template of the host policy by id.
func (p HostPolicy) ExecTemplate(id string) (execpolicy.Template, bool) {
	for _, t := range p.ExecTemplates {
		if t.ID == id {
			tpl, err := t.Template()
			return tpl, err == nil
		}
	}
	return execpolicy.Template{}, false
}

func (p HostPolicy) validateExec() error {
	if len(p.ExecTemplates) == 0 {
		if len(p.ExecBinDirs) != 0 {
			return errors.New("runnerproto: host policy: exec_bin_dirs without exec_templates")
		}
		return nil
	}
	if !p.AllowExec {
		return errors.New("runnerproto: host policy: exec_templates without allow_exec")
	}
	if len(p.ExecBinDirs) == 0 {
		return errors.New("runnerproto: host policy: exec_templates need exec_bin_dirs")
	}
	for _, d := range p.ExecBinDirs {
		if err := ValidatePath(d); err != nil {
			return fmt.Errorf("runnerproto: host policy: exec_bin_dirs: %w", err)
		}
	}
	seen := map[string]bool{}
	for _, t := range p.ExecTemplates {
		if !idRe.MatchString(t.ID) || seen[t.ID] {
			return errors.New("runnerproto: host policy: exec template id is invalid or repeated")
		}
		seen[t.ID] = true
		tpl, err := t.Template()
		if err != nil {
			return fmt.Errorf("runnerproto: host policy: exec template %s: %w", t.ID, err)
		}
		if _, err := execpolicy.Validate(tpl); err != nil {
			return fmt.Errorf("runnerproto: host policy: exec template %s: %w", t.ID, err)
		}
	}
	return nil
}
