#!/bin/sh
# Print the CHANGELOG.md section of a release, for its GitHub release notes.
#
#   scripts/release-notes.sh v0.19.0
#
# Fails when CHANGELOG.md has no section for that version, or an empty one,
# so a tag cannot be published without notes.
set -eu
tag="${1:?usage: release-notes.sh vX.Y.Z}"
version="${tag#v}"
cd "$(dirname "$0")/.."
if ! notes=$(awk -v v="$version" '
  index($0, "## [" v "]") == 1 { found = 1; next }
  found && (/^## \[/ || /^\[[^]]+\]: /) { exit }
  found { print }
  END { if (!found) exit 3 }
' CHANGELOG.md); then
  echo "CHANGELOG.md has no section for $version: rename [Unreleased] to [$version] - $(date +%Y-%m-%d) first" >&2
  exit 1
fi
# $(...) already dropped trailing blank lines; drop leading ones too.
notes=$(printf '%s\n' "$notes" | sed -e '/./,$!d')
if [ -z "$notes" ]; then
  echo "CHANGELOG.md's section for $version is empty" >&2
  exit 1
fi
# Relative links (docs/...) point into the repository at this tag.
repo=$(awk 'index($0, "[Unreleased]: ") == 1 { sub(/\/compare\/.*/, "", $2); print $2; exit }' CHANGELOG.md)
if [ -n "$repo" ]; then
  notes=$(printf '%s\n' "$notes" | sed -E "s#\]\(([^):#]+)\)#]($repo/blob/$tag/\1)#g")
fi
printf '%s\n' "$notes"
link=$(awk -v v="$version" 'index($0, "[" v "]: ") == 1 { print $2; exit }' CHANGELOG.md)
if [ -n "$link" ]; then
  printf '\n**Full Changelog**: %s\n' "$link"
fi
