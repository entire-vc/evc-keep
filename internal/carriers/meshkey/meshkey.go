// Package meshkey describes the four places a Mesh agent key lives, as
// carrier metadata plus a read locator for "does this carrier hold exactly
// this key". It holds names, paths and field selectors only: no value, no
// file content, and it imports neither pkg/secret nor internal/targets.
//
// The read locators are consumed inside the plaintext zone: targets.VerifyCarrier
// takes a Carrier, accepts it only if Member says it is in this manifest, and
// checks a fingerprint against it.
package meshkey

import (
	"errors"
	"path"
	"regexp"
	"strings"

	"github.com/entire-vc/evc-keep/internal/carriers"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

// ErrAgent is returned for an agent description that cannot name a carrier.
var ErrAgent = errors.New("meshkey: agent description rejected")

// Agent is one lane. Dirs are absolute; Name is the agent's name as the
// Mesh registries spell it (a selector value, not a secret).
type Agent struct {
	Host    string
	Name    string // registry name, e.g. "Sage"
	LaneDir string // directory holding the lane's .mcp.json
	BinDir  string // directory holding mesh-agents.json
	CfgDir  string // fiddler config directory holding fiddler.json
	EnvDir  string // directory of per-agent env files
	EnvFile string // file name inside EnvDir, e.g. "sage.env"
	EnvVar  string // "" or MESH_AGENT_KEY: the only variable the manifest admits
}

// Kind names a carrier.
type Kind string

const (
	MCPJSON     Kind = "mcp-json"
	MeshAgents  Kind = "mesh-agents-json"
	FiddlerJSON Kind = "fiddler-json"
	AgentEnv    Kind = "agent-env"
)

// Format values of the read locator.
const (
	FormatJSON = "json"
	FormatEnv  = "env"
)

// Carrier is one destination of the key. Metadata is what the registry
// stores; Format, Path, Field locate the single field Verify may read.
type Carrier struct {
	Kind     Kind
	Metadata carriers.Metadata
	Format   string
	Path     string
	Field    string
}

var (
	nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
	fileRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
)

// DefaultEnvVar is the variable a per-agent env file keeps the key in.
const DefaultEnvVar = "MESH_AGENT_KEY"

// For returns the four carriers of an agent's key, in a fixed order.
// A name or path that could widen the selector (a dot, bracket or
// separator in Name, a relative or unclean directory) is refused, so a
// hostile registry entry cannot make the locator point at a neighbour.
func For(a Agent) ([]Carrier, error) {
	if a.Host == "" || !nameRe.MatchString(a.Name) || !fileRe.MatchString(a.EnvFile) {
		return nil, ErrAgent
	}
	ev := a.EnvVar
	if ev == "" {
		ev = DefaultEnvVar
	}
	if ev != DefaultEnvVar {
		return nil, ErrAgent // the manifest keeps one variable: no oracle over its neighbours
	}
	for _, d := range []string{a.LaneDir, a.BinDir, a.CfgDir, a.EnvDir} {
		if runnerproto.ValidatePath(d) != nil {
			return nil, ErrAgent
		}
	}
	mk := func(k Kind, kind runnerproto.TargetKind, format, p, field, consumer string) Carrier {
		return Carrier{
			Kind: k,
			Metadata: carriers.Metadata{
				Host: a.Host, TargetKind: kind, TargetPath: p, TargetField: field, Consumer: consumer,
			},
			Format: format, Path: p, Field: field,
		}
	}
	return []Carrier{
		mk(MCPJSON, runnerproto.TargetMCPConfig, FormatJSON, path.Join(a.LaneDir, ".mcp.json"),
			"mcpServers.evc-mesh.env.MESH_AGENT_KEY", ""),
		mk(MeshAgents, runnerproto.TargetMCPConfig, FormatJSON, path.Join(a.BinDir, "mesh-agents.json"),
			"agents[name="+a.Name+"].agent_key", ""),
		mk(FiddlerJSON, runnerproto.TargetMCPConfig, FormatJSON, path.Join(a.CfgDir, "fiddler.json"),
			"agents[name="+a.Name+"].mesh_agent_key", ""),
		mk(AgentEnv, runnerproto.TargetEnvFile, FormatEnv, path.Join(a.EnvDir, a.EnvFile), ev, ""),
	}, nil
}

// Member reports whether c is one of the four carriers For can produce for
// some agent: a known Kind with its own format, file name and field shape,
// a clean absolute path, and metadata that says the same as the locator.
// It is the closed manifest Verify checks a locator against; a path, field
// or kind outside it is not a Mesh agent key carrier.
func (c Carrier) Member() bool {
	if runnerproto.ValidatePath(c.Path) != nil ||
		c.Metadata.TargetPath != c.Path || c.Metadata.TargetField != c.Field {
		return false
	}
	base := path.Base(c.Path)
	switch c.Kind {
	case MCPJSON:
		return c.Format == FormatJSON && c.Metadata.TargetKind == runnerproto.TargetMCPConfig &&
			base == ".mcp.json" && c.Field == "mcpServers.evc-mesh.env."+DefaultEnvVar
	case MeshAgents:
		return c.Format == FormatJSON && c.Metadata.TargetKind == runnerproto.TargetMCPConfig &&
			base == "mesh-agents.json" && agentField(c.Field, "agent_key")
	case FiddlerJSON:
		return c.Format == FormatJSON && c.Metadata.TargetKind == runnerproto.TargetMCPConfig &&
			base == "fiddler.json" && agentField(c.Field, "mesh_agent_key")
	case AgentEnv:
		return c.Format == FormatEnv && c.Metadata.TargetKind == runnerproto.TargetEnvFile &&
			fileRe.MatchString(base) && strings.HasSuffix(base, ".env") && c.Field == DefaultEnvVar
	}
	return false
}

// agentField matches agents[name=<registry name>].<member> exactly.
func agentField(field, member string) bool {
	name, ok := strings.CutPrefix(field, "agents[name=")
	if !ok {
		return false
	}
	name, ok = strings.CutSuffix(name, "]."+member)
	return ok && nameRe.MatchString(name)
}
