//go:build unix

package targets

import (
	"bytes"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The writer treats every physical line of an env-file as one entry: it looks
// for the field's line by prefix and replaces that one line. That is only
// right if no entry spans lines. A quoted value that continues on the next
// line, a backslash continuation, a here-document or a command substitution all
// make a later line part of an earlier entry, and then a line that starts with
// the field name may be text inside a neighbour's value, or the rest of the
// field's own old value; replacing "the line" would cut the neighbour open,
// leave old secret text in the file as entries of their own, and, the read
// back being line based too, confirm a file the consumer reads differently.
//
// Rather than model every reader's multi-line grammar (POSIX shell, systemd,
// python-dotenv each differ, and an approximation is exactly where a value
// slips through), the writer refuses any existing file in which a line is not
// provably a complete entry on its own. The check is deliberately stricter than
// the readers: a file the check does not understand is refused, not guessed at.
//
// The rules are per line, and per reader: hermes-config's file is read by
// python-dotenv, env-file's by a POSIX shell.

type envDialect uint8

const (
	dialectShell envDialect = iota
	dialectDotenv
)

// existingIsSimple reports whether every line of content is a complete entry
// (or comment, or blank) on its own under the given reader's rules.
func existingIsSimple(content []byte, d envDialect) bool {
	// python-dotenv ends a line at a carriage return and counts a vertical tab
	// or form feed as whitespace, wherever they are; a shell does neither. A
	// file that uses them is not simple for dotenv.
	if d == dialectDotenv && bytes.ContainsAny(content, dotenvOddSpace) {
		return false
	}
	// Hermes reads the file as UTF-8 and falls back to Latin-1: appending to a
	// file that is not UTF-8 could change how the neighbours decode.
	if d == dialectDotenv && !utf8.Valid(content) {
		return false
	}
	// A byte order mark is stripped by Hermes only while it rewrites the file:
	// after a line is appended there is nothing to rewrite and the first key
	// carries the mark.
	if d == dialectDotenv && bytes.Contains(content, utf8BOM) {
		return false
	}
	for _, line := range bytes.Split(content, []byte("\n")) {
		if !lineIsSimple(line, d) {
			return false
		}
	}
	return true
}

func lineIsSimple(line []byte, d envDialect) bool {
	if d == dialectDotenv {
		return dotenvLineIsSimple(line)
	}
	return shellLineIsSimple(line)
}

const (
	// shellWordForbidden are the bytes that never appear in a plain assignment
	// word outside single quotes: a variable or command substitution, a command
	// separator, a redirection, a subshell.
	shellWordForbidden = "$`;&|()<>~"

	quoteChars = "'\""

	envBackslash byte = 0x5c
)

var utf8BOM = []byte{0xef, 0xbb, 0xbf}

// spaceTab are the blanks a line may be indented or separated with.
var spaceTab = string([]byte{0x20, 0x09})

// dotenvOddSpace are carriage return, vertical tab, form feed and the four
// separator controls U+001C..U+001F: python-dotenv (str.isspace) counts them as
// whitespace, Go's unicode.IsSpace does not.
var dotenvOddSpace = string([]byte{0x0d, 0x0b, 0x0c, 0x1c, 0x1d, 0x1e, 0x1f})

func isSpaceTab(c byte) bool { return strings.IndexByte(spaceTab, c) >= 0 }

func isNameByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// shellLineIsSimple accepts, for a POSIX shell, only a line of one of these
// shapes: blank, a comment, or an assignment  [export] NAME=word  optionally
// followed by a comment. A word is plain bytes, closed single-quoted runs,
// double-quoted runs without expansions, and \' for a literal apostrophe.
// Nothing else: a line that is a command, a compound-command keyword, an
// expansion or anything that reads on into the next line is refused, because
// what a shell does with those (and with what is appended after them) depends
// on the rest of the file.
func shellLineIsSimple(line []byte) bool {
	i := skipBlanks(line, 0)
	if i >= len(line) || line[i] == '#' {
		return true
	}
	if bytes.HasPrefix(line[i:], shellExport) && i+len(shellExport) < len(line) && isSpaceTab(line[i+len(shellExport)]) {
		i = skipBlanks(line, i+len(shellExport))
	}
	j := i
	for j < len(line) && isNameByte(line[j]) {
		j++
	}
	if j == i || line[i] >= '0' && line[i] <= '9' || j >= len(line) || line[j] != '=' {
		return false
	}
	// A special variable is not assigned but evaluated or refused by some
	// shell, and the message can quote the value.
	if shellSpecialName(string(line[i:j])) {
		return false
	}
	k, ok := shellWord(line, j+1)
	if !ok {
		return false
	}
	k = skipBlanks(line, k)
	return k == len(line) || line[k] == '#'
}

var shellExport = []byte("export")

// shellWord scans one word starting at k and returns where it ends.
func shellWord(line []byte, k int) (int, bool) {
	start := k
	for k < len(line) {
		c := line[k]
		switch {
		case isSpaceTab(c):
			return k, true
		case c == sq:
			end := bytes.IndexByte(line[k+1:], sq)
			if end < 0 {
				return 0, false
			}
			k += end + 2
		case c == '"':
			end := bytes.IndexByte(line[k+1:], '"')
			if end < 0 {
				return 0, false
			}
			if bytes.ContainsAny(line[k+1:k+1+end], shellInDouble) {
				return 0, false
			}
			k += end + 2
		case c == envBackslash:
			// Only as \' , a literal apostrophe.
			if k+1 >= len(line) || line[k+1] != sq {
				return 0, false
			}
			k += 2
		case strings.IndexByte(shellWordForbidden, c) >= 0:
			return 0, false
		case c == '=' && (k == start || line[k-1] == ':'):
			// zsh expands =command at the start of a word and after a colon.
			return 0, false
		default:
			k++
		}
	}
	return k, true
}

// shellSpecialNames are variables that a shell evaluates, restricts or reports
// on instead of just assigning: arithmetic ones (a value such as x[$(cmd)] is
// executed by bash and ksh), read-only ones, and ones whose message quotes the
// value (zsh prints the head of the value of SAVEHIST, LISTMAX, KEYTIMEOUT and
// friends when it is not a number; prompt and hook variables such as PS0,
// RPROMPT, POSTEDIT or yash's COMMAND_NOT_FOUND_HANDLER show or run it). It is
// the union of what bash, ksh93 and zsh list as their own variables (compgen -v,
// typeset +, ${(k)parameters}) and of the variables their manuals say the shell
// reads (including the editor that fc and hist run); the prefixes below cover
// the families. Variables that only a loaded zsh module defines are covered by
// prefix (ZFTP_, ZCURSES_) or not at all. It is a best effort, not a proof: a shell this list does not know can read more. TestShellSpecialNamesCoverTheInstalledShells
// re-reads the shells on the machine, so a release that adds a name turns that
// test red instead of leaving the name writable.
var shellSpecialNames = namesSet(`
	ARGC
	ARGV0
	BASH
	BASHOPTS
	BASHPID
	BAUD
	CDPATH
	CHILD_MAX
	COLUMNS
	COMMAND_NOT_FOUND_HANDLER
	COMPREPLY
	CORRECT_IGNORE
	CORRECT_IGNORE_FILE
	CPUTYPE
	DIRSTACK
	DIRSTACKSIZE
	EDITOR
	EGID
	ENV
	EPOCHREALTIME
	EPOCHSECONDS
	ERRNO
	EUID
	EXECIGNORE
	FCEDIT
	FIGNORE
	FPATH
	FUNCNAME
	FUNCNEST
	GID
	GLOBIGNORE
	GLOBSORT
	GROUPS
	HISTCHARS
	HISTCMD
	HISTCONTROL
	HISTEDIT
	HISTFILE
	HISTFILESIZE
	HISTIGNORE
	HISTORY_IGNORE
	HISTRMDUP
	HISTSIZE
	HISTTIMEFORMAT
	HOME
	HOST
	HOSTFILE
	HOSTNAME
	HOSTTYPE
	IFS
	IGNOREEOF
	INPUTRC
	JOBMAX
	KEYBOARD_HACK
	KEYTIMEOUT
	KSHEGID
	KSHGID
	KSHUID
	KSH_VERSION
	LANG
	LINENO
	LINES
	LISTMAX
	LISTPROMPT
	LOGCHECK
	LOGNAME
	MACHTYPE
	MAIL
	MAILCHECK
	MAILPATH
	MANPATH
	MAPFILE
	MATCH
	MBEGIN
	MEND
	MENUPROMPT
	MODULE_PATH
	NULLCMD
	OLDPWD
	OPTARG
	OPTERR
	OPTIND
	OSTYPE
	PATH
	PERIOD
	PGRP
	PIPESTATUS
	POSIX
	POSIXLY_CORRECT
	POSTEDIT
	POST_PROMPT_COMMAND
	PPID
	PROMPT
	PROMPT2
	PROMPT3
	PROMPT4
	PROMPT_COMMAND
	PROMPT_DIRTRIM
	PROMPT_EOL_MARK
	PS0
	PS1
	PS1R
	PS1S
	PS2
	PS2R
	PS2S
	PS3
	PS4
	PSVAR
	PWD
	RANDOM
	READNULLCMD
	REPLY
	REPORTMEMORY
	REPORTTIME
	RPROMPT
	RPROMPT2
	RPS1
	RPS2
	SAVEHIST
	SECONDS
	SHELL
	SHELLOPTS
	SHLVL
	SPROMPT
	SRANDOM
	TERM
	TIMEFMT
	TIMEFORMAT
	TMOUT
	TMPPREFIX
	TMPSUFFIX
	TRY_BLOCK_ERROR
	TRY_BLOCK_INTERRUPT
	TTY
	TTYIDLE
	UID
	USER
	USERNAME
	USER_ID
	VENDOR
	VISUAL
	WATCH
	WATCHFMT
	WORDCHARS
	ZBEEP
	ZDOTDIR
	ZLS_COLORS
	ZLS_COLOURS
	_
	aliases
	argv
	auto_resume
	builtins
	cdpath
	commands
	dirstack
	dis_aliases
	dis_builtins
	dis_functions
	dis_functions_source
	dis_galiases
	dis_patchars
	dis_reswords
	dis_saliases
	fignore
	fpath
	funcfiletrace
	funcsourcetrace
	funcstack
	functions
	functions_source
	functrace
	galiases
	histchars
	history
	historywords
	jobdirs
	jobstates
	jobtexts
	keymaps
	mailpath
	manpath
	match
	mbegin
	module_path
	modules
	nameddirs
	options
	parameters
	patchars
	path
	pipestatus
	prompt
	psvar
	reswords
	saliases
	signals
	status
	termcap
	terminfo
	userdirs
	usergroups
	watch
	widgets
	zle_bracketed_paste
	zle_highlight
	zsh_eval_context
	zsh_scheduled_events
`)

func namesSet(list string) map[string]bool {
	set := map[string]bool{}
	for _, n := range strings.Fields(list) {
		set[n] = true
	}
	return set
}

var shellSpecialPrefixes = []string{"LC_", "BASH_", "ZSH_", "ZLE_", "YASH_", "COMP_", "READLINE_", "TERMINFO", "ZFTP_", "ZCURSES_"}

func shellSpecialName(name string) bool {
	if shellSpecialNames[name] {
		return true
	}
	for _, p := range shellSpecialPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// assignsField reports whether line assigns field in any form the reader
// accepts: indented, with export, and for dotenv also with blanks around the
// equals sign or with no value at all.
func assignsField(line []byte, field string, d envDialect) bool {
	l := line
	if d == dialectDotenv {
		l = bytes.TrimLeftFunc(l, unicode.IsSpace)
	} else {
		l = bytes.TrimLeft(l, spaceTab)
	}
	if bytes.HasPrefix(l, shellExport) && len(l) > len(shellExport) && isSpaceTab(l[len(shellExport)]) {
		l = bytes.TrimLeft(l[len(shellExport):], spaceTab)
	}
	if !bytes.HasPrefix(l, []byte(field)) {
		return false
	}
	rest := l[len(field):]
	if d == dialectDotenv {
		rest = bytes.TrimLeftFunc(rest, unicode.IsSpace)
		return len(rest) == 0 || rest[0] == '=' || rest[0] == '#'
	}
	return len(rest) > 0 && rest[0] == '='
}

// shellInDouble are the bytes that are not literal inside double quotes: a
// dollar sign, a backtick and a backslash.
var shellInDouble = string([]byte{0x24, 0x60, 0x5c})

// dotenvLineIsSimple follows python-dotenv's line grammar closely enough to
// tell that a line is complete on its own: a quoted value opens only right
// after the equals sign and must close on the same line, followed by nothing
// but a comment. Anything it cannot place with certainty (a quote in a key, a
// quote after a character that dotenv might count as whitespace, a backslash
// next to a quote) is not simple.
func dotenvLineIsSimple(line []byte) bool {
	// How dotenv pairs escapes with quotes depends on what follows in the file.
	if bytes.IndexByte(line, envBackslash) >= 0 && bytes.ContainsAny(line, quoteChars) {
		return false
	}
	// Hermes rewrites its .env before loading it, cutting a line at every
	// known variable name followed by an equals sign: a line with two of them
	// becomes two entries.
	if countAssignmentNames(line) > 1 {
		return false
	}
	i := skipBlanks(line, 0)
	if i >= len(line) || line[i] == '#' {
		return true
	}
	eq := bytes.IndexByte(line, '=')
	if eq < 0 {
		return !bytes.ContainsAny(line, quoteChars)
	}
	if bytes.ContainsAny(line[:eq], quoteChars) {
		return false
	}
	v := skipBlanks(line, eq+1)
	if v >= len(line) {
		return true
	}
	if q := line[v]; q == '\'' || q == '"' {
		end := bytes.IndexByte(line[v+1:], q)
		if end < 0 {
			return false
		}
		rest := bytes.TrimLeft(line[v+1+end+1:], spaceTab)
		return len(rest) == 0 || rest[0] == '#'
	}
	// An unquoted value. dotenv skips any Unicode whitespace before a quote, so
	// a value that starts with something other than a plain printable ASCII
	// byte and holds a quote later might be a quoted one to the reader.
	if line[v] > 0x20 && line[v] < 0x7f {
		return true
	}
	return !bytes.ContainsAny(line[v:], quoteChars)
}

// countAssignmentNames counts the runs of at least hermesNameRun capitals,
// digits and underscores that are directly followed by an equals sign.
func countAssignmentNames(line []byte) int {
	n, run := 0, 0
	for _, c := range line {
		switch {
		case hermesNameByte(c):
			run++
		case c == '=' && run >= hermesNameRun:
			n++
			run = 0
		default:
			run = 0
		}
	}
	return n
}

func skipBlanks(line []byte, i int) int {
	for i < len(line) && isSpaceTab(line[i]) {
		i++
	}
	return i
}
