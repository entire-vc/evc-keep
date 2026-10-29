//go:build unix

package targets

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

// nbSecret is a neighbour's value: it must survive every write untouched and
// never show up in an error text.
const nbSecret = "NEIGHBOUR-SECRET-5d1f0c93"

// envCase is one existing file, the kind that reads it, and what Write must
// produce: the exact new content, or a refusal that leaves the file as it was.
type envCase struct {
	name   string
	kind   runnerproto.TargetKind
	before string
	want   string // new content; empty means the write must be refused
}

func runEnvCases(t *testing.T, cases []envCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(realDir(t), "app.env")
			mustWriteFile(t, path, []byte(c.before), 0o600)
			uids, gids := noAgents()
			_, err := Write(target(c.kind, path, "NAME"), newValue("new-value"), uids, gids, testFPKey(t))
			got := string(mustReadFile(t, path))
			if c.want == "" {
				wantErr(t, err, ErrWrite, c.name)
				if got != c.before {
					t.Fatalf("file changed despite the refusal: %s", show([]byte(got)))
				}
				if strings.Contains(err.Error(), nbSecret) {
					t.Fatalf("refusal text carries a neighbour's value")
				}
				return
			}
			if err != nil {
				t.Fatalf("Write refused: %v", err)
			}
			if got != c.want {
				t.Fatalf("got  %s\nwant %s", show([]byte(got)), show([]byte(c.want)))
			}
			if c.kind == runnerproto.TargetEnvFile {
				shellReadsNewValue(t, path)
			}
		})
	}
}

// shells returns every POSIX-ish shell found on the machine; sh is required.
// Sourcing a file with a shell is the consumer check for env-file.
func shells(t *testing.T) []string {
	t.Helper()
	var found []string
	for _, name := range []string{"sh", "dash", "bash", "ksh", "zsh"} {
		if p, err := exec.LookPath(name); err == nil {
			found = append(found, p)
		} else if name == "sh" {
			t.Fatalf("no sh to read the file with: %v", err)
		}
	}
	names := make([]string, len(found))
	for i, p := range found {
		names[i] = filepath.Base(p)
	}
	t.Logf("shells that read the files here: %s", strings.Join(names, " "))
	return found
}

// sourceFile sources path with a shell and prints the given variables joined by
// a bar, returning stdout and stderr.
func sourceFile(t *testing.T, sh, path string, vars ...string) (string, string) {
	t.Helper()
	format := strings.TrimSuffix(strings.Repeat("%s|", len(vars)), "|")
	script := `set -a; . "$1"; printf "` + format + `"`
	for _, v := range vars {
		script += ` "$` + v + `"`
	}
	var out, errb bytes.Buffer
	cmd := exec.Command(sh, "-c", script, "sh", path) //nolint:gosec // G204: test-controlled arguments
	// Not the runner's environment: bash reads $BASH_ENV, zsh its zshenv.
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	cmd.Dir = filepath.Dir(path) // a command a value makes the shell run lands here, not in the source tree
	cmd.Stdout, cmd.Stderr = &out, &errb
	_ = cmd.Run()
	return out.String(), errb.String()
}

func shellReadsNewValue(t *testing.T, path string) {
	t.Helper()
	for _, sh := range shells(t) {
		out, errText := sourceFile(t, sh, path, "NAME")
		if errText != "" {
			t.Fatalf("%s complained (%d bytes on stderr) about the written file", filepath.Base(sh), len(errText))
		}
		if out != "new-value" {
			t.Fatalf("%s reads NAME as %d bytes, want the new value", filepath.Base(sh), len(out))
		}
	}
}

// Entries that are complete on their own line are read, replaced and appended
// to as before, quotes and comments included.
func TestEnvFileSimpleNeighbours(t *testing.T) {
	k := runnerproto.TargetEnvFile
	runEnvCases(t, []envCase{
		{"quoted neighbours on one line each", k,
			"A='x y'\nB=\"p q\"\nNAME=old\nZ=1\n",
			"A='x y'\nB=\"p q\"\nNAME=new-value\nZ=1\n"},
		{"apostrophe in a comment opens nothing", k,
			"# it's a comment\nNAME=old\n",
			"# it's a comment\nNAME=new-value\n"},
		{"trailing comment with an apostrophe", k,
			"A=1 # it's\nNAME=old\n",
			"A=1 # it's\nNAME=new-value\n"},
		{"metacharacters inside single quotes are inert", k,
			"A='a`b $(c) d;e|f<g'\nNAME=old\n",
			"A='a`b $(c) d;e|f<g'\nNAME=new-value\n"},
		{"escaped quote in an unquoted word", k,
			"A=a\\'b\nNAME=old\n",
			"A=a\\'b\nNAME=new-value\n"},
		{"a shell takes a carriage return as an ordinary byte", k,
			"A=1\r\nNAME=old\r\n",
			"A=1\r\nNAME=new-value\n"},
		{"export prefix, empty value, mixed word", k,
			"export A=1\nB=\nC=a'b c'd\"e f\"\nNAME=old\n",
			"export A=1\nB=\nC=a'b c'd\"e f\"\nNAME=new-value\n"},
		{"lowercase names, digits, empty quotes, a tab indent, a trailing blank, non-UTF-8 bytes", k,
			"http_proxy=x\nA1_b2=1\nA=\"\"\nB=''\n\tC=1\nD=1 \nE=\xff\nNAME=old\n",
			"http_proxy=x\nA1_b2=1\nA=\"\"\nB=''\n\tC=1\nD=1 \nE=\xff\nNAME=new-value\n"},
		{"a longer name after the line is not the field", k,
			"NAME=old\nNAMEX=1\nNAME_2=2\n",
			"NAME=new-value\nNAMEX=1\nNAME_2=2\n"},
		{"equals sign inside a word", k,
			"A=b=c\nNAME=old\n",
			"A=b=c\nNAME=new-value\n"},
		{"quoted tilde", k,
			"A='~x'\nNAME=old\n",
			"A='~x'\nNAME=new-value\n"},
		{"the field in another form before the written line wins over nothing", k,
			"export NAME=old\nA=1\n",
			"export NAME=old\nA=1\nNAME=new-value\n"},
		{"the field in another form before the line that is replaced", k,
			" NAME=older\nNAME=old\n",
			" NAME=older\nNAME=new-value\n"},
		{"appended when absent", k,
			"A=1\nOTHER='" + nbSecret + "'\n",
			"A=1\nOTHER='" + nbSecret + "'\nNAME=new-value\n"},
	})
}

// A file in which some entry spans lines, or might be read as if it did, is
// refused whole and left as it was: a line that starts with the field name
// could be text inside a neighbour's value or the tail of the field's own old
// value, and no rewrite of "the line" is right then.
func TestEnvFileEntriesThatSpanLinesAreRefused(t *testing.T) {
	k := runnerproto.TargetEnvFile
	runEnvCases(t, []envCase{
		{"single-quoted neighbour holding the field name", k,
			"A='" + nbSecret + "\nNAME=inside'\nOTHER=1\n", ""},
		{"double-quoted neighbour holding the field name", k,
			"NAME=old\nA=\"" + nbSecret + "\nNAME=inside\"\n", ""},
		{"the field's own entry spans lines (single)", k,
			"NAME='" + nbSecret + "\nb'\nOTHER=1\n", ""},
		{"the field's own entry spans lines (double)", k,
			"NAME=\"" + nbSecret + "\nb\"\nOTHER=1\n", ""},
		{"a backslash as the last byte inside double quotes", k,
			"A=\"x\\\"\nNAME=old\n", ""},
		{"a dollar sign as the last byte inside double quotes", k,
			"A=\"x$\"\nNAME=old\n", ""},
		{"a backtick as the last byte inside double quotes", k,
			"A=\"x`\"\nNAME=old\n", ""},
		{"a tab before a command", k,
			"A=1\tprintf\nNAME=old\n", ""},
		{"a space before a command", k,
			"A=1 printf\nNAME=old\n", ""},
		{"export with nothing after it", k,
			"export\nNAME=old\n", ""},
		{"a name starting with zero", k,
			"0A=x\nNAME=old\n", ""},
		{"a name starting with nine", k,
			"9A=x\nNAME=old\n", ""},
		{"unquoted backslash", k,
			"A=a\\.b\nNAME=old\n", ""},
		{"backslash in double quotes", k,
			"A=\"x\\y\"\nNAME=old\n", ""},
		{"variable expansion", k,
			"A=$B\nNAME=old\n", ""},
		{"expansion inside double quotes", k,
			"A=\"$B\"\nNAME=old\n", ""},
		{"backtick inside double quotes", k,
			"A=\"`x`\"\nNAME=old\n", ""},
		{"closed parameter expansion", k,
			"A=${B:-x}\nNAME=old\n", ""},
		{"nested parameter expansion", k,
			"A=${B:-${C}\nNAME=old\nC=z}\n", ""},
		{"escaped brace in a parameter expansion", k,
			"A=${B:-\\}\nNAME=old\nC=z}\n", ""},
		{"comment inside a parameter expansion", k,
			"A=${B #\"}\nNAME=old\nC=x\"}\"\n", ""},
		{"arithmetic expansion", k,
			"A=$[1\nNAME=old\nC=]\n", ""},
		{"compound command keyword", k,
			"for i\nNAME=old\n", ""},
		{"brace group", k,
			"{\nNAME=old\n", ""},
		{"conditional that decides whether the field is assigned", k,
			"if false\nthen :\nNAME=old\nfi\n", ""},
		{"readonly declaration", k,
			"readonly NAME\nNAME=old\n", ""},
		{"a second word on the field's line", k,
			"NAME=old B=neighbour\n", ""},
		{"a command", k,
			"NAME =spaced\n", ""},
		{"no equals sign", k,
			"export A\nNAME=old\n", ""},
		{"empty name", k,
			"=x\nNAME=old\n", ""},
		{"name starting with a digit", k,
			"1A=x\nNAME=old\n", ""},
		{"a command separator", k,
			"A=x;y\nNAME=old\n", ""},
		{"an ampersand", k,
			"A=x&y\nNAME=old\n", ""},
		{"a pipe", k,
			"A=x|y\nNAME=old\n", ""},
		{"an opening parenthesis", k,
			"A=x(y\nNAME=old\n", ""},
		{"a closing parenthesis", k,
			"A=xy)\nNAME=old\n", ""},
		{"a less-than sign", k,
			"A=x<y\nNAME=old\n", ""},
		{"a greater-than sign", k,
			"A=x>y\nNAME=old\n", ""},
		{"a backtick", k,
			"A=`x`\nNAME=old\n", ""},
		{"the field again later, exported", k,
			"NAME=v1\nexport NAME=" + nbSecret + "\n", ""},
		{"the field again later, indented", k,
			"NAME=v1\n NAME=" + nbSecret + "\n", ""},
		{"the field again later, after a tab", k,
			"NAME=v1\n\tNAME=" + nbSecret + "\n", ""},
		{"a tilde in a word", k,
			"A=~nosuchuser\nNAME=old\n", ""},
		{"a tilde after a colon", k,
			"A=x:~y\nNAME=old\n", ""},
		{"an equals sign at the start of a word", k,
			"A==x\nNAME=old\n", ""},
		{"an equals sign after a colon", k,
			"A=x:=y\nNAME=old\n", ""},
		{"a special variable", k,
			"UID=1\nNAME=old\n", ""},
		{"a special variable evaluated arithmetically", k,
			"SECONDS=1+\nNAME=old\n", ""},
		{"a locale variable", k,
			"LC_ALL=}\nNAME=old\n", ""},
		{"a zsh special variable", k,
			"status=1\nNAME=old\n", ""},
		{"backslash continuation", k,
			"NAME=" + nbSecret + "\\\nmore\nOTHER=1\n", ""},
		{"escaped quote next to a backslash", k,
			"A='" + nbSecret + "\\\\'\nNAME=inside\n'\n", ""},
		{"backslash-newline inside double quotes", k,
			"A=\"" + nbSecret + "\\\nNAME=inside\"\n", ""},
		{"quote left open at the end", k,
			"A='" + nbSecret + "\nB=1\n", ""},
		{"double quote left open", k,
			"A=\"" + nbSecret + "\nNAME=old\n", ""},
		{"apostrophe inside an unquoted word opens a shell quote", k,
			"A=it's\nNAME=old\n", ""},
		{"carriage return as a line end", k,
			"X=1\rA='" + nbSecret + "\nNAME=inside\n'\n", ""},
		{"vertical tab before a quote", k,
			"A=\v'" + nbSecret + "\nNAME=inside\n'\n", ""},
		{"form feed before a quote", k,
			"A=\f'" + nbSecret + "\nNAME=inside\n'\n", ""},
		{"no-break space before a quote", k,
			"A=\u00a0'" + nbSecret + "\nNAME=inside\n'\n", ""},
		{"quoted key", k,
			"'K Y'='" + nbSecret + "\nNAME=inside\n'\n", ""},
		{"ANSI-C quoting", k,
			"A=$'" + nbSecret + "\\'\nNAME=inside\n' #'\n", ""},
		{"here-document inside a command substitution", k,
			"A=$(cat <<'X'\nNAME=inside\nX\n)\n", ""},
		{"backtick command substitution", k,
			"A=`echo " + nbSecret + "\nNAME=inside`\n", ""},
		{"parameter expansion left open", k,
			"A=${B:-" + nbSecret + "\nNAME=inside}\n", ""},
		{"command separator", k,
			"A=1;\nNAME=old\n", ""},
		{"or-list that decides whether the next line runs", k,
			"A=1 ||\nNAME=old\n", ""},
		{"subshell", k,
			"A=(" + nbSecret + "\nNAME=inside)\n", ""},
		{"background job", k,
			"A=1 &\nNAME=old\n", ""},
		{"here-document", k,
			"cat <<'X'\nNAME=inside\nX\n", ""},
		{"redirection", k,
			"A=1 > /dev/null\nNAME=old\n", ""},
		{"command substitution opened inside double quotes", k,
			"A=\"$(echo \"\nNAME=inside\n\")\"\n", ""},
		{"backtick opened inside double quotes", k,
			"A=\"`echo \"\nNAME=inside\n\"`\"\n", ""},
		{"parameter expansion left open inside double quotes", k,
			"A=\"${B:-\"\nNAME=inside\n}\"\"\n", ""},
	})
}

// hermes-config is read by python-dotenv, whose quotes open only right after
// the equals sign: what a shell would take for an open quote (a lone
// apostrophe in a word, a here-document) is an ordinary line there, and what
// dotenv might read across lines is refused.
func TestHermesConfigSimpleNeighbours(t *testing.T) {
	k := runnerproto.TargetHermesConfig
	runEnvCases(t, []envCase{
		{"empty value, empty quotes, lowercase name, trailing blank, punctuation, short names", k,
			"A=\nB=''\nhttp_proxy=x\nD=1 \nE=!x\nAAAAA=x BBBBB=y\nNAME=old\n",
			"A=\nB=''\nhttp_proxy=x\nD=1 \nE=!x\nAAAAA=x BBBBB=y\nNAME=new-value\n"},
		{"a longer name after the line is not the field", k,
			"NAME=old\nNAMEX=1\nNAME_2 = 2\n",
			"NAME=new-value\nNAMEX=1\nNAME_2 = 2\n"},
		{"apostrophe inside an unquoted word is an ordinary line", k,
			"A=it's\nNAME=old\n",
			"A=it's\nNAME=new-value\n"},
		{"quoted neighbours, export and a trailing comment", k,
			"export A=\"p q\" # it's\nB='x'\nNAME=old\n",
			"export A=\"p q\" # it's\nB='x'\nNAME=new-value\n"},
		{"a comment with an apostrophe", k,
			"# it's a comment\nNAME=old\n",
			"# it's a comment\nNAME=new-value\n"},
		{"shell constructs are plain text to dotenv", k,
			"A=$(cat <<'X'\nNAME=old\nX\n)\n",
			"A=$(cat <<'X'\nNAME=new-value\nX\n)\n"},
		{"appended when absent", k,
			"A=1\nOTHER='" + nbSecret + "'\n",
			"A=1\nOTHER='" + nbSecret + "'\nNAME=new-value\n"},
	})
}

func TestHermesConfigEntriesThatSpanLinesAreRefused(t *testing.T) {
	k := runnerproto.TargetHermesConfig
	runEnvCases(t, []envCase{
		{"single-quoted neighbour holding the field name", k,
			"A='" + nbSecret + "\nNAME=inside'\nOTHER=1\n", ""},
		{"double-quoted neighbour holding the field name", k,
			"A=\"" + nbSecret + "\nNAME=inside\"\nNAME=old\n", ""},
		{"export prefix", k,
			"export A='" + nbSecret + "\nNAME=inside'\n", ""},
		{"the field's own entry spans lines", k,
			"NAME=\"" + nbSecret + "\nb\"\nOTHER=1\n", ""},
		{"quote left open at the end", k,
			"A='" + nbSecret + "\nB=1\n", ""},
		{"escaped closing quote", k,
			"A='" + nbSecret + "\\'\nNAME=1\nB=1'\n", ""},
		{"doubled backslash before the closing quote", k,
			"A=\"" + nbSecret + "\\\\\"\nNAME=old\nB=\"y\"\n", ""},
		{"text after the closing quote", k,
			"A='" + nbSecret + "' junk\nNAME=old\n", ""},
		{"carriage return as a line end", k,
			"X=1\rA='" + nbSecret + "\nNAME=inside\n'\n", ""},
		{"CRLF file", k,
			"A=1\r\nNAME=old\r\n", ""},
		{"vertical tab before a quote", k,
			"A=\v'" + nbSecret + "\nNAME=inside\n'\n", ""},
		{"no-break space before a quote", k,
			"A=\u00a0'" + nbSecret + "\nNAME=inside\n'\n", ""},
		{"quoted key", k,
			"'K Y'='" + nbSecret + "\nNAME=inside\n'\n", ""},
		{"two known variable names on one line", k,
			"OPENAI_API_KEY=x'ANTHROPIC_API_KEY='\nNAME=old\nC=y'\n", ""},
		{"a file that is not UTF-8", k,
			"A=\xff\nNAME=old\n", ""},
		{"double-quoted neighbour holding the field name, no other NAME line", k,
			"A=\"" + nbSecret + "\nNAME=inside\"\nOTHER=1\n", ""},
		{"a no-break space before a double quote", k,
			"A=\u00a0\"x\"\nNAME=old\n", ""},
		{"a file separator control as whitespace before an override", k,
			"NAME=old\n\x1cNAME=zzz\n", ""},
		{"a group separator control before an override", k,
			"NAME=old\n\x1dNAME=zzz\n", ""},
		{"a record separator control before an override", k,
			"NAME=old\n\x1eNAME=zzz\n", ""},
		{"a unit separator control before an exported override", k,
			"NAME=old\nA=1\n\x1fexport NAME=zzz\n", ""},
		{"a control byte before a quote", k,
			"A=\x1f'x'\nNAME=old\n", ""},
		{"two names of exactly six characters on one line", k,
			"AAAAAA=x'BBBBBB='\nNAME=old\n", ""},
		{"the field again later, indented", k,
			"NAME=v1\n NAME=" + nbSecret + "\n", ""},
		{"the field again later, with a space before the equals sign", k,
			"NAME=v1\nNAME =" + nbSecret + "\n", ""},
		{"the field again later, after a no-break space", k,
			"NAME=v1\n\u00a0NAME=" + nbSecret + "\n", ""},
		{"the field again later, exported", k,
			"NAME=v1\nexport NAME=" + nbSecret + "\n", ""},
		{"the field again later, without a value", k,
			"NAME=v1\nNAME\n", ""},
		{"the field again later, without a value but with a comment", k,
			"NAME=v1\nNAME #c\n", ""},
		{"a byte order mark", k,
			"\ufeffA=1\nNAME=old\n", ""},
		{"quote on a line without an equals sign", k,
			"it's\nNAME=old\n", ""},
		{"quote right at the end of the line", k,
			"A='\nNAME=inside'\n", ""},
		{"carriage return splits a line for dotenv", k,
			"A=1\rB=2\nNAME=old\n", ""},
		{"vertical tab", k,
			"A=\v1\nNAME=old\n", ""},
		{"form feed", k,
			"A=\f1\nNAME=old\n", ""},
		{"no-break space before a closed quote", k,
			"A=\u00a0'x'\nNAME=old\n", ""},
		{"quoted key", k,
			"'K Y'='x'\nNAME=old\n", ""},
	})
}

// The property the whole check exists for, against real shells: for every file
// the check accepts, appending a NAME= line makes each shell see exactly the
// new value for NAME, leaves every other variable as it was, and prints nothing
// on stderr (a shell that trips over the file quotes the offending line there,
// and the consumer's log would carry the value).
func TestEnvFileAcceptedFilesAreReadEntryPerLine(t *testing.T) {
	lines := []string{
		"", "# c", "# it's", "A=1", "A=", "A=x # c", "A=x#y", "A=\u00e9", "A=~", "A=*", "A=[x]", "A={x}", "A=!",
		"B='p q'", "B=\"p q\"", "C=a'b'c", "C=a\\'b", "  A=2", "export B=3", "C=1\r", "NAME=old", " NAME=old",
		"export NAME=old", "A=x y", "A=1 B=2", "A=$B", "A=${B:-x}", "A=`x`", "A='x", "A=\"x", "A=x\\", "for i", "{",
		"if x", "A=$[1", "readonly A", "A=x;B=2", "A=$(x", "A=<x", "A=x)", "A=~nosuchuser", "A=x:~y", "A==x", "A=x:=y",
		"A=b=c", "A='~x'", "UID=1", "SECONDS=1+", "OPTIND=/", "LC_ALL=}", "status=1", "path=x", "IFS=x", "PATH=/bin",
	}
	all := shells(t)
	probe := func(sh, content string) (string, string) {
		t.Helper()
		f := filepath.Join(t.TempDir(), "f.env")
		if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return sourceFile(t, sh, f, "A", "B", "C", "NAME")
	}
	// The harness must be able to see a shell complain, or "no stderr" proves
	// nothing.
	if _, errText := probe(all[0], "for i\nNAME=new-value\n"); errText == "" {
		t.Fatalf("a shell did not complain about a for loop with no body: the probe is blind")
	}
	accepted := 0
	for _, l1 := range lines {
		for _, l2 := range lines {
			before := l1 + "\n" + l2 + "\n"
			if !existingIsSimple([]byte(before), dialectShell) {
				continue
			}
			accepted++
			for _, sh := range all {
				name := filepath.Base(sh)
				wasOut, wasErr := probe(sh, before)
				if wasErr != "" {
					t.Fatalf("%s: accepted file %s made the shell complain (%d bytes on stderr)", name, show([]byte(before)), len(wasErr))
				}
				nowOut, nowErr := probe(sh, before+"NAME=new-value\n")
				if nowErr != "" {
					t.Fatalf("%s: accepted file %s plus a NAME line made the shell complain (%d bytes on stderr)", name, show([]byte(before)), len(nowErr))
				}
				wa := strings.Split(wasOut, "|")
				na := strings.Split(nowOut, "|")
				if len(wa) != 4 || len(na) != 4 || na[3] != "new-value" || strings.Join(na[:3], "|") != strings.Join(wa[:3], "|") {
					t.Fatalf("%s: accepted file %s: the shell reads %s before and %s after", name, show([]byte(before)), show([]byte(wasOut)), show([]byte(nowOut)))
				}
			}
		}
	}
	if accepted < 100 {
		t.Fatalf("only %d files accepted: the corpus no longer exercises the check", accepted)
	}
}

// What Write itself puts on the line is read back exactly by every shell,
// including values that a shell would expand, evaluate or split if they were
// not quoted.
func TestEnvFileWrittenValuesAreReadBackByShells(t *testing.T) {
	values := []string{
		"abc", "a b", "=x", "=", "a:=b", "nv:=:x", "a=b==", "~", "~root", "a~b", "$(echo hi)", "a$HOME", "`x`", "it's", "'", "a\\b",
		"a#b", " #x", "x;y", "x&y", "x|y", "(x)", "<x>", "*", "[x]", "{a,b}", "!x", "\u00e9", "\"q\"", "${x}", "x[$(echo hi)]", "-n", "%s",
	}
	for _, v := range values {
		t.Run(v, func(t *testing.T) {
			path := filepath.Join(realDir(t), "app.env")
			mustWriteFile(t, path, []byte("A=1\n"), 0o600)
			uids, gids := noAgents()
			if _, err := Write(target(runnerproto.TargetEnvFile, path, "NAME"), newValue(v), uids, gids, testFPKey(t)); err != nil {
				t.Fatalf("Write: %v", err)
			}
			for _, sh := range shells(t) {
				out, errText := sourceFile(t, sh, path, "A", "NAME")
				if errText != "" {
					t.Fatalf("%s complained (%d bytes on stderr) about the written file", filepath.Base(sh), len(errText))
				}
				if out != "1|"+v {
					t.Fatalf("%s reads a different value than was written (%d bytes back, %d written)", filepath.Base(sh), len(out)-2, len(v))
				}
			}
		})
	}
}

// A special variable is evaluated, restricted or reported on by a shell instead
// of just being assigned, so it is not a field a value may be written to.
func TestEnvFileSpecialFieldNamesAreRefused(t *testing.T) {
	for _, name := range []string{"OPTIND", "SECONDS", "RANDOM", "IFS", "PATH", "UID", "LANG", "LC_ALL", "BASH_ENV", "PS4", "status", "path", "ZSH_NAME",
		"SRANDOM", "JOBMAX", "ERRNO", "SAVEHIST", "LISTMAX", "KEYTIMEOUT", "TRY_BLOCK_ERROR", "TRY_BLOCK_INTERRUPT",
		"PS0", "RPROMPT", "RPS1", "PERIOD", "BAUD", "LOGCHECK", "POSTEDIT", "PROMPT_EOL_MARK", "DIRSTACKSIZE", "REPORTTIME",
		"ZLE_RPROMPT_INDENT", "YASH_PS1", "COMMAND_NOT_FOUND_HANDLER", "COMP_WORDS", "READLINE_LINE",
		"EDITOR", "HISTEDIT", "ZFTP_TMOUT", "ZCURSES_X", "ZLS_COLOURS"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(realDir(t), "app.env")
			mustWriteFile(t, path, []byte("A=1\n"), 0o600)
			uids, gids := noAgents()
			_, err := Write(target(runnerproto.TargetEnvFile, path, name), newValue("x[$(echo hi)]"), uids, gids, testFPKey(t))
			wantErr(t, err, ErrPolicy, name)
			if got := string(mustReadFile(t, path)); got != "A=1\n" {
				t.Fatalf("file changed despite the refusal: %s", show([]byte(got)))
			}
		})
	}
	// hermes-config is read by dotenv, not a shell: PATH is an ordinary name.
	path := filepath.Join(realDir(t), ".env")
	uids, gids := noAgents()
	if _, err := Write(target(runnerproto.TargetHermesConfig, path, "PATH"), newValue("x"), uids, gids, testFPKey(t)); err != nil {
		t.Fatalf("hermes-config refused a field a shell would treat as special: %v", err)
	}
}

// The read back is a second line of defence: it refuses content it could not
// read entry by entry, whatever produced it, and content in which a later line
// would override the one it reads.
func TestEnvReadBackRefusesEntriesThatSpanLines(t *testing.T) {
	tg := target(runnerproto.TargetEnvFile, "/unused", "NAME")
	for _, d := range []envDialect{dialectShell, dialectDotenv} {
		if _, err := envReadBack(d, []byte("A='x\nNAME=1\n'\n"), tg); err == nil {
			t.Errorf("dialect %d: a file with a multi-line entry was read back", d)
		}
		if _, err := envReadBack(d, []byte("A=1\nNAME=2\n"), tg); err != nil {
			t.Errorf("dialect %d: a plain file was refused: %v", d, err)
		}
		if _, err := envReadBack(d, []byte("NAME=2\nexport NAME=3\n"), tg); err == nil {
			t.Errorf("dialect %d: a later assignment in another form was ignored", d)
		}
	}
}

// validFieldName is what a target field may be for env-file (see runnerproto).
var validFieldName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// shellVarNames lists the variables a shell defines on its own, as the shell
// reports them: bash compgen -v, ksh93 typeset +, zsh ${(k)parameters}. Other
// shells (sh, dash, busybox ash) have no such listing and give nothing.
func shellVarNames(t *testing.T, sh string) []string {
	t.Helper()
	var script string
	switch filepath.Base(sh) {
	case "bash":
		script = "compgen -v"
	case "ksh":
		script = "typeset +"
	case "zsh":
		script = "print -l ${(k)parameters}"
	default:
		return nil
	}
	cmd := exec.Command(sh, "-c", script) //nolint:gosec // G204: test-controlled arguments
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s did not list its variables: %v", filepath.Base(sh), err)
	}
	var names []string
	for _, n := range strings.Fields(string(out)) {
		if validFieldName.MatchString(n) {
			names = append(names, n)
		}
	}
	return names
}

// Every variable the installed shells define themselves is either refused as
// an env-file field or read back by every installed shell as exactly the value
// written, with nothing on stderr and no command run. A shell evaluates the
// value of some of them as arithmetic (bash SRANDOM, ksh93 JOBMAX) and quotes
// its head in the message of others (zsh SAVEHIST, LISTMAX, KEYTIMEOUT); the
// value would reach the consumer's stderr, and its log, or run.
func TestEnvFileEveryShellOwnVariableIsRefusedOrReadCleanly(t *testing.T) {
	all := shells(t)
	seen := map[string]bool{}
	for _, sh := range all {
		for _, n := range shellVarNames(t, sh) {
			seen[n] = true
		}
	}
	if len(all) > 1 && len(seen) == 0 {
		t.Log("no installed shell lists its own variables here: this machine covers only the fixed names")
	}
	uids, gids := noAgents()
	for name := range seen {
		for _, val := range []string{"1 headOfTheValueXYZ", "a[$(touch PWNED)]"} {
			dir := realDir(t)
			path := filepath.Join(dir, "svc.env")
			_, err := Write(target(runnerproto.TargetEnvFile, path, name), newValue(val), uids, gids, testFPKey(t))
			if err != nil {
				continue // refused: nothing was written
			}
			for _, sh := range all {
				out, errText := sourceFile(t, sh, path, name)
				if errText != "" || out != val {
					t.Errorf("%s: field %s written and read by %s with stderr of %d bytes, value read as %s", filepath.Base(sh), name, filepath.Base(sh), len(errText), show([]byte(out)))
				}
			}
			if _, err := os.Stat(filepath.Join(dir, "PWNED")); err == nil {
				t.Errorf("field %s: a command ran while a shell sourced the file", name)
			}
		}
	}
}

// The fixed list has to cover what the installed shells define: a release that
// adds a variable turns this red instead of leaving the name writable.
func TestShellSpecialNamesCoverTheInstalledShells(t *testing.T) {
	for _, sh := range shells(t) {
		for _, n := range shellVarNames(t, sh) {
			if !shellSpecialName(n) {
				t.Errorf("%s defines %s itself, and the env-file writer does not treat it as special", filepath.Base(sh), n)
			}
		}
	}
}

// The list of special names is deliberate: this is the whole of it, so a name
// cannot be dropped, or added, by accident.
func TestShellSpecialNamesAreExactlyThese(t *testing.T) {
	want := strings.Fields(`
		ARGC ARGV0 BASH BASHOPTS BASHPID BAUD CDPATH CHILD_MAX COLUMNS COMMAND_NOT_FOUND_HANDLER
		COMPREPLY CORRECT_IGNORE CORRECT_IGNORE_FILE CPUTYPE DIRSTACK DIRSTACKSIZE EDITOR EGID ENV
		EPOCHREALTIME EPOCHSECONDS ERRNO EUID EXECIGNORE FCEDIT FIGNORE FPATH FUNCNAME FUNCNEST GID
		GLOBIGNORE GLOBSORT GROUPS HISTCHARS HISTCMD HISTCONTROL HISTEDIT HISTFILE HISTFILESIZE
		HISTIGNORE HISTORY_IGNORE HISTRMDUP HISTSIZE HISTTIMEFORMAT HOME HOST HOSTFILE HOSTNAME HOSTTYPE
		IFS IGNOREEOF INPUTRC JOBMAX KEYBOARD_HACK KEYTIMEOUT KSHEGID KSHGID KSHUID KSH_VERSION LANG
		LINENO LINES LISTMAX LISTPROMPT LOGCHECK LOGNAME MACHTYPE MAIL MAILCHECK MAILPATH MANPATH
		MAPFILE MATCH MBEGIN MEND MENUPROMPT MODULE_PATH NULLCMD OLDPWD OPTARG OPTERR OPTIND OSTYPE PATH
		PERIOD PGRP PIPESTATUS POSIX POSIXLY_CORRECT POSTEDIT POST_PROMPT_COMMAND PPID PROMPT PROMPT2
		PROMPT3 PROMPT4 PROMPT_COMMAND PROMPT_DIRTRIM PROMPT_EOL_MARK PS0 PS1 PS1R PS1S PS2 PS2R PS2S
		PS3 PS4 PSVAR PWD RANDOM READNULLCMD REPLY REPORTMEMORY REPORTTIME RPROMPT RPROMPT2 RPS1 RPS2
		SAVEHIST SECONDS SHELL SHELLOPTS SHLVL SPROMPT SRANDOM TERM TIMEFMT TIMEFORMAT TMOUT TMPPREFIX
		TMPSUFFIX TRY_BLOCK_ERROR TRY_BLOCK_INTERRUPT TTY TTYIDLE UID USER USERNAME USER_ID VENDOR
		VISUAL WATCH WATCHFMT WORDCHARS ZBEEP ZDOTDIR ZLS_COLORS ZLS_COLOURS _ aliases argv auto_resume
		builtins cdpath commands dirstack dis_aliases dis_builtins dis_functions dis_functions_source
		dis_galiases dis_patchars dis_reswords dis_saliases fignore fpath funcfiletrace funcsourcetrace
		funcstack functions functions_source functrace galiases histchars history historywords jobdirs
		jobstates jobtexts keymaps mailpath manpath match mbegin module_path modules nameddirs options
		parameters patchars path pipestatus prompt psvar reswords saliases signals status termcap
		terminfo userdirs usergroups watch widgets zle_bracketed_paste zle_highlight zsh_eval_context
		zsh_scheduled_events
	`)
	seen := map[string]bool{}
	for _, name := range want {
		seen[name] = true
		if !shellSpecialName(name) {
			t.Errorf("%s is not treated as special", name)
		}
	}
	for name := range shellSpecialNames {
		if !seen[name] {
			t.Errorf("%s is special in the code but not in this list", name)
		}
	}
	for _, name := range []string{"LC_ALL", "LC_CTYPE", "BASH_ENV", "BASH_ALIASES", "ZSH_VERSION", "ZLE_LINE", "YASH_X", "COMP_ANY", "READLINE_ANY", "TERMINFO_DIRS", "ZFTP_ANY", "ZCURSES_ANY"} {
		if !shellSpecialName(name) {
			t.Errorf("%s is not treated as special", name)
		}
	}
	for _, name := range []string{"NAME", "http_proxy", "LCX", "BASHFUL", "API_KEY"} {
		if shellSpecialName(name) {
			t.Errorf("%s is treated as special", name)
		}
	}
}
