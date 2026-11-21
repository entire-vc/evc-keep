#!/bin/sh
# Usage: test-result-names.sh [--resolve-callers] ROOT < log
# What a plain-text go test log says about results, named only from the tree
# at ROOT; see test-result-names.py for why the log text is not echoed.
exec python3 -I "$(dirname "$0")/test-result-names.py" "$@"
