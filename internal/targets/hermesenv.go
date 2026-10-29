//go:build unix

package targets

import (
	"bytes"

	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// hermesEnvHandler writes hermes-config: one NAME=value line in
// $HERMES_HOME/.env, the file Hermes loads and whose variables its config.yaml
// refers to as ${NAME}. The line is written and read back exactly as
// env-file's is; what differs is the reader. Hermes does not read the file
// with a shell, nor with bare python-dotenv: load_hermes_dotenv first rewrites
// the file (splitting a line that holds two known Hermes variable names), then
// loads it with python-dotenv, then strips non-ASCII characters from
// credential variables and prints them to stderr. Measured on Hermes 0.16.0,
// each of these would make the consumer see another value than the one Keep
// fingerprinted, or spill value characters into a log, or plant a neighbor:
//
//   - a single quote (the shell form closes the run, escapes it, reopens): the
//     line does not parse and the variable silently drops out;
//   - a backslash: decoded inside single quotes, and a trailing one swallows
//     the closing quote and the next line;
//   - ${ : interpolated on load;
//   - a double quote: the loader's second reader, hermes_cli.config.load_env
//     (run by /reload and by the docker sandbox setup), strips quote marks from
//     both ends of a value, so a value that starts or ends with one changes;
//     an interior one reads back unchanged, but any double quote is refused
//     rather than telling the two apart;
//   - a byte outside printable ASCII: stripped from credential variables
//     (and echoed to stderr), or read in another encoding when not UTF-8;
//   - a run of capitals, digits and underscores directly before an equals
//     sign: the file rewrite treats a known variable name there as the start
//     of a new line, so a value could plant other variables and cut its own.
//
// A value with any of these is refused with one message that names none of
// them, so the refusal reveals no more than that it happened.
type hermesEnvHandler struct{ envFileHandler }

// Named separately so the mutation script can switch each off on its own.
const (
	hermesForbiddenQuote     byte = '\''
	hermesForbiddenBackslash byte = '\\'
	hermesForbiddenDQuote    byte = '"'
	hermesPrintableLow       byte = 0x20
	hermesPrintableHigh      byte = 0x7e

	// hermesNameRun is how many name characters before an equals sign make it
	// look like a variable assignment. Every Hermes variable name is at least
	// 7 characters (checked by TestHermesConfigRefusesEveryKnownKeyInValue);
	// one less is kept as margin for a shorter name added later.
	hermesNameRun = 6

	hermesRefusal = "value has a form the Hermes .env loader would not read back unchanged"
)

// hermesInterpolation is the python-dotenv variable reference opener.
var hermesInterpolation = []byte("${")

func hermesNameByte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

// hermesMisreads reports whether val has a form the loader would change.
func hermesMisreads(val []byte) bool {
	for _, c := range val {
		if c < hermesPrintableLow || c > hermesPrintableHigh {
			return true
		}
	}
	if bytes.IndexByte(val, hermesForbiddenQuote) >= 0 {
		return true
	}
	if bytes.IndexByte(val, hermesForbiddenBackslash) >= 0 {
		return true
	}
	if bytes.IndexByte(val, hermesForbiddenDQuote) >= 0 {
		return true
	}
	if bytes.Contains(val, hermesInterpolation) {
		return true
	}
	run := 0
	for _, c := range val {
		switch {
		case hermesNameByte(c):
			run++
		case c == '=' && run >= hermesNameRun:
			return true
		default:
			run = 0
		}
	}
	return false
}

func (h hermesEnvHandler) build(existing []byte, exists bool, t runnerproto.Target, v secret.Value) ([]byte, error) {
	val := bytesOf(v)
	defer wipe(val)
	if hermesMisreads(val) {
		return nil, denied(hermesRefusal)
	}
	return envBuild(dialectDotenv, existing, exists, t, v)
}

func (hermesEnvHandler) readBack(content []byte, t runnerproto.Target) (secret.Value, error) {
	return envReadBack(dialectDotenv, content, t)
}
