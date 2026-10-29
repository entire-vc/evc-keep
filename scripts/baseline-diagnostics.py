#!/usr/bin/env python3
"""Names the tests that went red or skipped in a `go test -json` log (stdin).

The log is untrusted: an assertion can carry a value and can contain a
newline followed by a forged `--- FAIL:` or `file.go:N:` line. A verdict is
therefore read only from the structured `Action` of an event, never from
the text of an `output` event, where the forgery lives. Beyond that nothing
from the log is printed except what the source tree vouches for: a failing
test is named only if it is a top-level `func TestXxx(` declared in a
*_test.go file under the root, and its location is that declaration's
file:line, not a location taken from the log. Anything else is counted, not
printed. Subtest names (which may be values) are cut to their parent.
"""
import json
import os
import re
import sys

root = os.path.abspath(sys.argv[1])
decl = {}
for d, dirs, files in os.walk(root):
    dirs[:] = [x for x in dirs if x not in {".git", "node_modules", "vendor"}]
    for f in files:
        if not f.endswith("_test.go"):
            continue
        p = os.path.join(d, f)
        try:
            with open(p, encoding="utf-8", errors="replace") as fh:
                for n, line in enumerate(fh, 1):
                    m = re.match(r"func (Test[A-Za-z0-9_]*)\(", line)
                    if m:
                        decl.setdefault(m.group(1), f"{os.path.relpath(p, root)}:{n}")
        except OSError:
            pass

seen, unknown, panics, failed_pkgs, unparsed = set(), 0, 0, 0, 0
out = []
for raw in sys.stdin.read().splitlines():
    try:
        ev = json.loads(raw)
        action = ev["Action"]
    except (ValueError, KeyError, TypeError):
        unparsed += 1
        continue
    if not isinstance(ev, dict):
        unparsed += 1
        continue
    test = ev.get("Test")
    if action in ("fail", "skip") and isinstance(test, str):
        name = test.split("/")[0]
        verdict = action.upper()
        if name in decl:
            if (verdict, name) not in seen:
                seen.add((verdict, name))
                out.append(f"--- {verdict}: {name} at {decl[name]}")
        else:
            unknown += 1
    elif action == "fail" and test is None:
        failed_pkgs += 1
    elif action == "output" and isinstance(ev.get("Output"), str) and ev["Output"].startswith("panic:"):
        panics += 1
for line in out[:40]:
    print(line)
print(f"failing/skipped lines not matching a declared test: {unknown}; panics: {panics}; failed packages: {failed_pkgs}; unparsed lines: {unparsed}")
