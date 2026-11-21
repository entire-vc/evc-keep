"""Literal anchor edit shared by every mutation suite.

A mutant names the property it switches off; the anchor is how it finds the
code. An anchor that occurs more than once is ambiguous: replacing "the first
one" silently may switch off a different property, and a mutant without a
designated witness then goes red on someone else's guard while the property
it claims stays unchecked. So an anchor must occur exactly once, or the
mutant must name which occurrence it means (1-based, counted left to right,
non-overlapping, over the whole text, newlines included).

Shell suites call this through `mutation_edit` in scripts/mutation-helpers.sh;
Python suites import `edit` (or `edit_file`) from here. The refusal text is
the same either way.

Apply-only mode can check a whole suite in one process: `--batch BASE QUEUE
COUNT` (shell side: `mutation_batch` and `mutation_batch_run`) reads the
mutants a suite queued and applies each one to its own copy of the files under
BASE, in memory. BASE is never written, and no mutant sees another's edit.
"""

import os
import sys


class AnchorError(Exception):
    """The anchor is absent, ambiguous or the named occurrence is missing."""


def occurrences(text, old):
    """Start offsets of the non-overlapping literal occurrences of old."""
    if not old:
        raise AnchorError('empty anchor')
    found = []
    at = text.find(old)
    while at >= 0:
        found.append(at)
        at = text.find(old, at + len(old))
    return found


def parse_occurrence(value):
    """None for "not named"; otherwise a positive int, or AnchorError."""
    if value is None or value == '':
        return None
    if isinstance(value, bool):
        raise AnchorError('occurrence must be a positive number, not %r' % (value,))
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and value.isascii() and value.isdigit() and not value.startswith('0'):
        number = int(value)
    else:
        raise AnchorError('occurrence must be a positive number, not %r' % (value,))
    if number < 1:
        raise AnchorError('occurrence must be a positive number, not %r' % (value,))
    return number


def edit(text, old, new, occurrence=None, src='source'):
    """Replace the named (or the only) literal occurrence of old in text."""
    number = parse_occurrence(occurrence)
    found = occurrences(text, old)
    if not found:
        raise AnchorError('anchor not found in %s' % src)
    if number is None:
        if len(found) > 1:
            raise AnchorError('anchor occurs %d times in %s, name the occurrence' % (len(found), src))
        number = 1
    if number > len(found):
        raise AnchorError('occurrence %d named, but the anchor occurs %d times in %s' % (number, len(found), src))
    at = found[number - 1]
    return text[:at] + new + text[at + len(old):]


def named_edit(name, text, old, new, occurrence=None, src='source'):
    """Use the shell diagnostic format for an embedded Python suite."""
    try:
        return edit(text, old, new, occurrence, src)
    except AnchorError as err:
        raise SystemExit('FAIL %s: %s' % (name, err)) from None


def edit_file(path, old, new, occurrence=None, src=None):
    """Edit path in place; src names it in a refusal (default: path)."""
    with open(path, encoding='utf-8', newline='') as handle:
        text = handle.read()
    text = edit(text, old, new, occurrence, src if src is not None else str(path))
    with open(path, 'w', encoding='utf-8', newline='') as handle:
        handle.write(text)


def read_text(path):
    with open(path, encoding='utf-8', newline='') as handle:
        return handle.read()


def parse_batch(data):
    """Mutants from a queue: NUL-terminated fields, per mutant NAME, the edit
    count N (1 or 2), then N times SRC FROM TO OCCURRENCE. ValueError if the
    queue is not exactly that."""
    if not data.endswith(b'\0'):
        raise ValueError('queue does not end with a field terminator')
    fields = [f.decode('utf-8', 'surrogateescape') for f in data[:-1].split(b'\0')]
    mutants = []
    at = 0
    while at < len(fields):
        if at + 2 > len(fields):
            raise ValueError('queue ends inside a mutant header')
        name, count = fields[at], fields[at + 1]
        if not name or count not in ('1', '2'):
            raise ValueError('bad mutant header at field %d' % at)
        at += 2
        edits = []
        for _ in range(int(count)):
            if at + 4 > len(fields):
                raise ValueError('queue ends inside mutant %s' % name)
            edits.append(tuple(fields[at:at + 4]))
            at += 4
        mutants.append((name, edits))
    return mutants


def run_batch(base, queue, count):
    """Apply every queued mutant to BASE in memory; one verdict line each."""
    try:
        with open(queue, 'rb') as handle:
            mutants = parse_batch(handle.read())
    except (OSError, ValueError) as err:
        print('FAIL apply-only batch: unreadable queue (%s)' % err)
        return 2
    if str(len(mutants)) != count:
        print('FAIL apply-only batch: %d mutants in the queue, the suite queued %s' % (len(mutants), count))
        return 2
    base_texts = {}
    failed = False
    for name, edits in mutants:
        # Each mutant starts from the base files: edits of the mutants before
        # it live only in their own `texts` and are dropped with it.
        texts = {}
        try:
            for src, old, new, occurrence in edits:
                if src not in texts:
                    if src not in base_texts:
                        try:
                            base_texts[src] = read_text(os.path.join(base, src))
                        except (OSError, UnicodeDecodeError):
                            raise AnchorError('cannot read %s' % src) from None
                    texts[src] = base_texts[src]
                texts[src] = edit(texts[src], old, new, occurrence, src)
        except AnchorError as err:
            print('FAIL %s: mutation did not apply (%s), the source changed, update this script' % (name, err))
            failed = True
            continue
        print('ok   %s: applies' % name)
    return 1 if failed else 0


def main(argv):
    if len(argv) == 5 and argv[1] == '--batch':
        return run_batch(argv[2], argv[3], argv[4])
    # mutation_edit.py NAME SRC FROM TO [OCCURRENCE]: the edited SRC on stdout.
    if len(argv) not in (5, 6):
        sys.stderr.write('FAIL mutation_edit: usage NAME SRC FROM TO [OCCURRENCE]\n')
        return 2
    name, src, old, new = argv[1:5]
    occurrence = argv[5] if len(argv) == 6 else None
    try:
        with open(src, encoding='utf-8', newline='') as handle:
            text = handle.read()
        out = edit(text, old, new, occurrence, src)
    except (AnchorError, OSError, UnicodeDecodeError) as err:
        message = str(err) if isinstance(err, AnchorError) else 'cannot read %s' % src
        # stdout carries the edited source, so the refusal goes to stderr.
        sys.stderr.write('FAIL %s: %s\n' % (name, message))
        return 1
    sys.stdout.write(out)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
