#!/bin/sh
# Usage: baseline-diagnostics.sh ROOT < go-test-log
# Which tests went red or skipped, named only from declarations in the tree
# at ROOT; see baseline-diagnostics.py for why the log text is not echoed.
exec python3 -I "$(dirname "$0")/baseline-diagnostics.py" "$@"
