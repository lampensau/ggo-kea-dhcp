#!/bin/sh
# Assert a commit is MOVE-ONLY: it may relocate code between files but must not
# add, delete, or alter a line of logic. Git renders a 1-file -> 5-file split as
# a delete plus four adds, which is unreviewable by eye, so this proves the union
# of the touched .go files is byte-identical before and after the commit - modulo
# `package`/`import` lines, which every split-out file needs its own copy of.
# Reusable for the internal/web disentangle series: PR 1's split, and the
# move-only commits the later receiver-rename stages are required to isolate.
#
# Usage: scripts/assert-move-only.sh [commit]   (default HEAD)
# Exit 0 = move-only; non-zero + a diff = logic changed.
set -e

commit="${1:-HEAD}"

# Drop package + import lines, blank lines, then sort so relocation between files
# is invisible and only added/removed/edited code shows as a diff.
strip() {
    awk '
        /^import \(/ { imp = 1; next }
        imp && /^\)/ { imp = 0; next }
        imp          { next }
        /^package /  { next }
        /^import "/  { next }
        NF           { print }
    ' | sort
}

files=$(git diff-tree --no-commit-id --name-only -r "$commit" -- '*.go')
[ -n "$files" ] || { echo "no .go files touched by $commit"; exit 0; }

before=$(mktemp)
after=$(mktemp)
trap 'rm -f "$before" "$after"' EXIT

# Missing pre-image (added file) or post-image (deleted file) is expected in a
# split; `|| true` lets the concatenation continue so the union still balances.
for f in $files; do git show "$commit^:$f" 2>/dev/null || true; done | strip > "$before"
for f in $files; do git show "$commit:$f"  2>/dev/null || true; done | strip > "$after"

if diff -u "$before" "$after"; then
    echo "OK: $commit is move-only ($(echo "$files" | wc -w) files, $(wc -l < "$after") code lines unchanged)"
else
    echo "FAIL: $commit changed logic, not just file location" >&2
    exit 1
fi
