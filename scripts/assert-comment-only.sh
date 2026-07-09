#!/bin/sh
# Assert a commit is COMMENT-ONLY: it may reword, condense, move or delete comments
# but must not touch a byte of code. Reviewing a comment sweep by eye means reading
# every hunk twice, once for the prose and once to be sure no logic rode along; this
# proves the second half so review can spend itself on the first.
#
# Two checks, because "comment" means two different things:
#   1. Code equality. Parse the before- and after-image with go/parser WITHOUT
#      parser.ParseComments (so comments never enter the AST), print both, compare.
#      A line-based awk filter is NOT safe here: `//` occurs inside string literals
#      (URLs) and after code (trailing comments).
#   2. Directive equality. `//go:embed`, `//go:build`, `//nolint` are comments to the
#      parser but CODE to the toolchain - check 1 passes happily when one is deleted,
#      and internal/db/sqlite.go's `//go:embed migrations/*.sql` failing silently
#      would empty the migrations FS. Compare the sorted directive lines verbatim.
#
# Usage: scripts/assert-comment-only.sh [commit]   (default HEAD)
#        ALLOW_NONGO=1 scripts/assert-comment-only.sh   (a sweep that also edits docs)
# Exit 0 = comment-only; non-zero + a diff = code or a directive changed.
set -e

commit="${1:-HEAD}"
root=$(git rev-parse --show-toplevel)

# `git show $commit^:f` silently means the FIRST parent on a merge, so the whole
# comparison would be against the wrong side. Refuse rather than mislead.
[ -z "$(git rev-list --no-walk --merges "$commit")" ] || { echo "FAIL: $commit is a merge commit; assert the side branch's commits instead" >&2; exit 1; }

# A comment-only commit edits files in place. An added/deleted/renamed .go file has
# no counterpart image to compare, so treat it as out of scope rather than skip it.
churn=$(git diff-tree --no-commit-id -r --diff-filter=ADR --name-only "$commit" -- '*.go')
[ -z "$churn" ] || { echo "FAIL: $commit adds/deletes/renames .go files:" >&2; echo "$churn" >&2; exit 1; }

# Only .go files are proven below. A stray .sh/.templ/.yml edit would sail through
# unchecked, so surface it; ALLOW_NONGO=1 for a sweep that also reflows a doc.
nongo=$(git diff-tree --no-commit-id --name-only -r "$commit" | grep -v '\.go$' || true)
if [ -n "$nongo" ] && [ "${ALLOW_NONGO:-0}" != "1" ]; then
    echo "FAIL: $commit touches non-Go files (unproven by this script); re-run with ALLOW_NONGO=1 if intended:" >&2
    echo "$nongo" >&2
    exit 1
fi

files=$(git diff-tree --no-commit-id --name-only -r "$commit" -- '*.go')
[ -n "$files" ] || { echo "no .go files touched by $commit"; exit 0; }

# Canonical code, comments stripped. go/printer is fed a fresh FileSet so it cannot
# reproduce the original line structure - the output is position-independent, which
# is what makes a deleted comment invisible here. awk 'NF' drops the residual blanks.
strip() { go run "$root/scripts/stripcomments.go" | awk 'NF'; }

# ponytail: greps the raw source, so a `//go:` inside a string literal or block
# comment would be counted as a directive. Harmless (it is compared to itself on both
# sides) and no such string exists here; switch to an ast.CommentGroup scan if one appears.
directives() { grep -E '^[[:space:]]*//(go:|nolint)' || true; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
rc=0

for f in $files; do
    git show "$commit^:$f" > "$tmp/before.go"
    git show "$commit:$f"  > "$tmp/after.go"

    strip < "$tmp/before.go" > "$tmp/before.code"
    strip < "$tmp/after.go"  > "$tmp/after.code"
    if ! diff -u --label "$f (before)" --label "$f (after)" "$tmp/before.code" "$tmp/after.code"; then
        echo "FAIL: $f changed CODE, not just comments" >&2
        rc=1
    fi

    directives < "$tmp/before.go" | sort > "$tmp/before.dir"
    directives < "$tmp/after.go"  | sort > "$tmp/after.dir"
    if ! diff -u --label "$f directives (before)" --label "$f directives (after)" "$tmp/before.dir" "$tmp/after.dir"; then
        echo "FAIL: $f changed a toolchain directive (//go: or //nolint)" >&2
        rc=1
    fi
done

[ "$rc" -eq 0 ] || exit "$rc"
echo "OK: $commit is comment-only ($(echo "$files" | wc -w) files, code + directives byte-identical)"
