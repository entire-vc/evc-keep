#!/bin/sh
# Print the CHANGELOG section of one release, without its heading.
#
#   scripts/changelog-section.sh <version> [changelog]
#
# <version> is a release tag such as 0.7.0 (a leading "v" is ignored). The
# section starts at the exact line "## [<version>]" and ends before the next
# "## " heading. The `release` job of
# .gitlab-ci.yml uses the output as the description of the GitLab release.
#
# Exit 0 with the section on stdout. Exit 1, printing nothing on stdout, when
# the version is malformed, the file is missing, the section is absent, appears
# more than once, or holds no text: a release must never go out with an empty
# or guessed description. POSIX sh and awk only, so it runs on busybox (the
# release job's alpine image), GNU and BSD alike.
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: changelog-section.sh <version> [changelog]" >&2
  exit 1
fi
version=${1#v}
file=${2:-CHANGELOG.md}

case $version in
  ''|*[!0-9.]*|.*|*.|*..*)
    echo "changelog-section: version must be digits and dots, like 0.7.0" >&2
    exit 1 ;;
esac
if [ ! -f "$file" ]; then
  echo "changelog-section: no changelog file" >&2
  exit 1
fi

# Fixed-string comparison of the heading: the version is never used as a regex.
section=$(awk -v want="## [$version]" '
  function heading(line) { return substr(line, 1, 3) == "## " }
  {
    sub(/\r$/, "")
    if (heading($0)) {
      if (inside) { inside = 0 }
      if ($0 == want) {
        found++; inside = 1; next
      }
    }
    if (inside) { print }
  }
  END { if (found != 1) exit 3 }
' "$file") || {
  echo "changelog-section: no single section for $version" >&2
  exit 1
}

# Trim blank lines around the section; refuse one with no text at all.
section=$(printf '%s\n' "$section" | awk '
  NF { for (; pending > 0; pending--) print ""; print; started = 1; next }
  started { pending++ }
')
if [ -z "$section" ]; then
  echo "changelog-section: section for $version is empty" >&2
  exit 1
fi
printf '%s\n' "$section"
