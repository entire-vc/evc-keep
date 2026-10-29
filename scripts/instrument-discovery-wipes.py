#!/usr/bin/env python3
"""Instrument a disposable test tree, never production or host files.

Retain byte backing arrays at allocation/growth, not at wipe: deleting a wipe
must not delete its observer. Test assertions never print buffer contents.
"""
import pathlib
import re
import sys

package = pathlib.Path(sys.argv[1]) / "internal/runner/discover"
for name in ("scan.go", "parse.go", "json.go", "bplist.go", "read_unix.go"):
    path = package / name
    source = path.read_text()
    source = re.sub(r"bytes.Clone\(([^()]*)\)", r"observeBytes(bytes.Clone(\1))", source)
    source = source.replace("var encoded [utf8.UTFMax]byte", "var encoded [utf8.UTFMax]byte; observeBytes(encoded[:])")
    source = source.replace("secret.New(raw)", "observeSecret(secret.New(raw))")
    source = source.replace("make([]byte, limit+1)", "observeBytes(make([]byte, limit+1))")
    source = source.replace("make([]byte, len(dst), size)", "observeBytes(make([]byte, len(dst), size))")
    # Capture the old array even if appendWiped is later mutated into append.
    source = re.sub(r"(?m)^(\s*)(out|parent.text) = (appendWiped\(.*)\n",
                    r"\1\2 = observeAppend(\2, \3)\n", source)
    path.write_text(source)
