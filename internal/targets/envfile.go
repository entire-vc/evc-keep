//go:build unix

package targets

import (
	"bytes"
	"strings"

	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// envFileHandler replaces one NAME=value line in place, byte for byte
// leaving every other line untouched, or appends the line if it is not
// already present. Stays in []byte throughout, never a Go string: a string
// is immutable and so cannot be wiped, and an env-file commonly holds
// several already-deployed secrets on neighboring lines — converting the
// whole existing content to a string, even transiently, would leave all of
// them lingering on the heap past this function's return (pkg/secret's own
// doc comment: "never be converted to string for transport, logging or
// comparison").
type envFileHandler struct{}

// Bytes a value must not contain: a line-oriented format has no way to
// represent them without inventing an escape convention that env-file
// consumers (shells, systemd's EnvironmentFile, docker --env-file) do not
// agree on, so this refuses rather than guesses. Named separately, not
// inlined as rune literals, so the mutation script can switch off exactly
// one of the three independently.
const (
	envForbiddenNUL byte = 0
	envForbiddenLF  byte = '\n'
	envForbiddenCR  byte = '\r'
)

// The dialect is POSIX-shell assignment syntax, the one a consumer that
// sources the file (`set -a; . file`, a wrapper script) reads. A value made of
// the characters below is written bare, which every env-file reader, this one
// included, takes the same way; any other value is single-quoted, with an
// embedded apostrophe written as close-quote, backslash, quote, open-quote —
// inside single quotes the shell interprets nothing, so a space, $, `, ;, #, a backslash or a double quote reach the
// consumer as themselves and nothing is executed. Readers that do not follow
// shell rules (docker --env-file takes the line raw, systemd's EnvironmentFile
// has its own handling of backslashes) are not covered: for those a quoted
// value would be wrong, not dangerous, and the target's owner picks the kind
// that fits the consumer.
const envBareChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+:,./-"

const (
	sq byte = '\'' // single quote
	bs byte = '\\' // backslash
)

// envEscQuote is how a single quote is written inside a single-quoted run:
// close the run, an escaped quote, open it again.
var envEscQuote = []byte{sq, bs, sq, sq}

func shellQuote(val []byte) []byte {
	bare := true
	for _, c := range val {
		if strings.IndexByte(envBareChars, c) < 0 {
			bare = false
			break
		}
	}
	if bare {
		return append([]byte{}, val...)
	}
	// Sized for the worst case (every byte an apostrophe, four bytes each): an
	// append that outgrew the buffer would leave a shorter copy of the value
	// on the heap, out of reach of wipe.
	out := make([]byte, 0, 4*len(val)+2)
	out = append(out, sq)
	for _, c := range val {
		if c == sq {
			out = append(out, envEscQuote...)
			continue
		}
		out = append(out, c)
	}
	return append(out, sq)
}

// shellUnquote is the inverse of shellQuote, and only of it: bare characters
// and single-quoted runs joined by \'. Anything else is a line this package
// did not write in that form, refused rather than guessed at.
func shellUnquote(raw []byte) ([]byte, error) {
	// Sized up front: an append that outgrows the buffer would leave the
	// earlier, shorter copy of the value on the heap, out of reach of wipe.
	out := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); {
		switch c := raw[i]; {
		case c == sq:
			j := bytes.IndexByte(raw[i+1:], sq)
			if j < 0 {
				wipe(out)
				return nil, writeFailed("written env-file line has an unterminated quote")
			}
			out = append(out, raw[i+1:i+1+j]...)
			i += j + 2
		case c == bs && i+1 < len(raw) && raw[i+1] == sq:
			out = append(out, sq)
			i += 2
		case strings.IndexByte(envBareChars, c) >= 0:
			out = append(out, c)
			i++
		default:
			wipe(out)
			return nil, writeFailed("written env-file line is not in the form this package writes")
		}
	}
	return out, nil
}

func (envFileHandler) foldsExisting() bool { return true }

func (envFileHandler) build(existing []byte, exists bool, t runnerproto.Target, v secret.Value) ([]byte, error) {
	return envBuild(dialectShell, existing, exists, t, v)
}

func (envFileHandler) readBack(content []byte, t runnerproto.Target) (secret.Value, error) {
	return envReadBack(dialectShell, content, t)
}

// envBuild is the shared body of env-file and hermes-config: d names the
// reader whose quoting decides which lines are entries.
func envBuild(d envDialect, existing []byte, exists bool, t runnerproto.Target, v secret.Value) ([]byte, error) {
	val := bytesOf(v)
	defer wipe(val)
	if bytes.IndexByte(val, envForbiddenNUL) >= 0 || bytes.IndexByte(val, envForbiddenLF) >= 0 || bytes.IndexByte(val, envForbiddenCR) >= 0 {
		return nil, denied("value contains a byte that cannot appear in an env-file line")
	}
	if d == dialectShell && shellSpecialName(t.Field) {
		return nil, denied("field name is special to a shell")
	}
	prefix := append([]byte(t.Field), '=')
	quoted := shellQuote(val)
	defer wipe(quoted)
	newLine := append(append([]byte{}, prefix...), quoted...)
	defer wipe(newLine)

	if !exists || len(existing) == 0 {
		return append(append(make([]byte, 0, len(newLine)+1), newLine...), '\n'), nil
	}

	if !existingIsSimple(existing, d) {
		return nil, writeFailed("existing env-file has an entry that spans lines or that the reader might take differently; refusing to write into it")
	}
	body := existing
	if body[len(body)-1] == '\n' {
		body = body[:len(body)-1]
	}
	lines := bytes.Split(body, []byte("\n"))
	foundAt := -1
	for i, l := range lines {
		if bytes.HasPrefix(l, prefix) {
			if foundAt >= 0 {
				return nil, writeFailed("existing env-file has more than one %s line; refusing to guess which is current", t.Field)
			}
			foundAt = i
		}
	}
	// The reader takes the last assignment. A later line that assigns the field
	// in another form (indented, with export, dotenv's spaced or key-only
	// forms) would win over the line written here.
	if foundAt >= 0 {
		for _, l := range lines[foundAt+1:] {
			if assignsField(l, t.Field, d) {
				return nil, writeFailed("%s is assigned again after its line in another form; refusing to write a value that would be overridden", t.Field)
			}
		}
	}
	if foundAt >= 0 {
		lines[foundAt] = newLine
	} else {
		lines = append(lines, newLine)
	}
	joined := bytes.Join(lines, []byte("\n"))
	defer wipe(joined)
	// Not append(joined, '\n'): Join returns a buffer with no spare capacity,
	// so the append would copy and leave the whole file, every neighbor's
	// secret included, in the old buffer.
	out := make([]byte, len(joined)+1)
	copy(out, joined)
	out[len(joined)] = '\n'
	return out, nil
}

func envReadBack(d envDialect, content []byte, t runnerproto.Target) (secret.Value, error) {
	prefix := append([]byte(t.Field), '=')
	if !existingIsSimple(content, d) {
		return secret.Value{}, writeFailed("written env-file has an entry that spans lines or that the reader might take differently")
	}
	lines := bytes.Split(content, []byte("\n"))
	for i, l := range lines {
		if bytes.HasPrefix(l, prefix) {
			for _, later := range lines[i+1:] {
				if assignsField(later, t.Field, d) {
					return secret.Value{}, writeFailed("%s is assigned again after its line in another form", t.Field)
				}
			}
			val, err := shellUnquote(l[len(prefix):])
			if err != nil {
				return secret.Value{}, err
			}
			defer wipe(val) // secret.New copies
			return secret.New(val), nil
		}
	}
	return secret.Value{}, writeFailed("field %q not found in written env-file", t.Field)
}
