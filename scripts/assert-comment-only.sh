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
#      would empty the migrations FS.
#
# Check 2 compares each directive BOUND TO the declaration it governs, in file order.
# A set comparison is not enough: moving a lone `//go:embed` onto the neighbouring var
# leaves both the AST and the directive set identical while silently emptying the
# original var, and two `//nolint`s trading places would likewise pass. Binding catches
# the re-bind, order catches the swap. Neither sort nor a bare presence check would.
#
# Usage: scripts/assert-comment-only.sh [commit]   (default HEAD)
#        scripts/assert-comment-only.sh --selftest (prove the checks still catch)
#        ALLOW_NONGO=1 scripts/assert-comment-only.sh   (a sweep that also edits docs)
# Exit 0 = comment-only; non-zero + a diff = code or a directive changed.
set -e

root=$(git rev-parse --show-toplevel)

# Canonical code, comments stripped. Deliberately NOT a pipeline: a pipeline's status
# is its last command, so a failing `go run` (broken toolchain, unparseable source)
# would be masked by a trailing filter and the script would compare two empty files
# and declare them equal. stripcomments.go drops blank lines itself for this reason.
strip() { go run "$root/scripts/stripcomments.go"; }

# Emit `<directive> => <declaration it governs>` per directive, in file order. Blank
# lines and ordinary comments between a directive and its declaration are skipped, so
# rewording a doc comment above a var never disturbs the binding. A directive trailing
# a code line is emitted with that whole line.
#
# ponytail: only `//` comments are skipped when looking for the declaration, so a `/* */`
# block comment between a directive and its declaration binds in the declaration's place,
# as does a `//go:` or `//nolint` inside prose or a raw string. Each compares to itself on
# both sides, so the cost is at worst a false FAIL (loud, never silent) when a sweep rewords
# that exact line. The repo has no block comments and no such string; add a block-comment
# skip here if one appears.
directives() {
    awk '
        function isdir(s) { return s ~ /\/\/(go:|nolint)/ }
        /^[ \t]*\/\// { if (isdir($0)) pend[++n] = $0; next }
        /^[ \t]*$/    { next }
        {
            for (i = 1; i <= n; i++) print pend[i] " => " $0
            n = 0
            if (isdir($0)) print "trailing => " $0
        }
        END { for (i = 1; i <= n; i++) print pend[i] " => <EOF>" }
    '
}

selftest() {
    t=$(mktemp -d)
    trap 'rm -rf "$t"' EXIT
    mkdir -p "$t/scripts" "$t/migrations"
    cp "$root/scripts/assert-comment-only.sh" "$root/scripts/stripcomments.go" "$t/scripts/"
    touch "$t/migrations/001.sql"
    cd "$t"
    printf 'module t\n\ngo 1.24\n' > go.mod
    git init -q . && git config user.email s@s && git config user.name s

    fails=0
    # want: "ok" = script must exit 0, "fail" = script must exit non-zero. Run through `sh`,
    # not the exec bit: a copy that lost its +x would make every "want fail" case pass for
    # the wrong reason, and a selftest whose failure mode is "everything passes" is the very
    # thing this file exists to prevent.
    case_run() {
        want=$1; label=$2
        if sh scripts/assert-comment-only.sh >/dev/null 2>&1; then got=ok; else got=fail; fi
        if [ "$got" = "$want" ]; then
            echo "  PASS  $label (want $want)"
        else
            echo "  BROKEN  $label: want $want, got $got" >&2
            fails=$((fails + 1))
        fi
    }

    printf 'package p\n\n// doc\nfunc F() int { return 1 }\n' > a.go
    git add -A && git commit -qm base
    printf 'package p\n\n// reworded doc\nfunc F() int { return 1 }\n' > a.go
    git commit -aqm x && case_run ok "comment reword"

    printf 'package p\n\n// reworded doc\nfunc F() int { return 2 }\n' > a.go
    git commit -aqm x && case_run fail "code change (1 -> 2)"

    # A broken toolchain must FAIL even on a commit that IS comment-only: the checks never
    # ran, so the script must not claim they passed. Asserting this on a code change would
    # prove nothing, since that fails either way. GOCACHE below /dev/null cannot be created
    # even by root, so this holds in a root CI container too.
    printf 'package p\n\n// reworded twice\nfunc F() int { return 2 }\n' > a.go
    git commit -aqm x
    if GOCACHE=/dev/null/cache sh scripts/assert-comment-only.sh >/dev/null 2>&1; then
        echo "  BROKEN  broken toolchain reported OK; the checks never ran" >&2
        fails=$((fails + 1))
    else
        echo "  PASS  broken toolchain on a comment-only commit (want fail)"
    fi

    printf 'package p\n\nimport "embed"\n\n//go:embed migrations\nvar mig embed.FS\n\nvar other embed.FS\n' > e.go
    git add -A && git commit -qm base-embed
    printf 'package p\n\nimport "embed"\n\nvar mig embed.FS\n\n//go:embed migrations\nvar other embed.FS\n' > e.go
    git commit -aqm x && case_run fail "//go:embed re-bound to another var"

    printf 'package p\n\n//nolint:gosec\nfunc A() {}\n\n//nolint:errcheck\nfunc B() {}\n' > n.go
    git add -A && git commit -qm base-nolint
    printf 'package p\n\n//nolint:errcheck\nfunc A() {}\n\n//nolint:gosec\nfunc B() {}\n' > n.go
    git commit -aqm x && case_run fail "two //nolint swapped between funcs"

    printf 'package p\n\n//go:embed migrations\nvar mig2 embed.FS\n' > z.go
    git add -A && git commit -qm x && case_run fail "adds a .go file"

    [ "$fails" -eq 0 ] || { echo "SELFTEST FAILED ($fails)" >&2; exit 1; }
    echo "OK: selftest passed - every check still catches what it is for"
}

[ "${1:-}" != "--selftest" ] || { selftest; exit 0; }

commit="${1:-HEAD}"

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

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
rc=0

for f in $files; do
    git show "$commit^:$f" > "$tmp/before.go"
    git show "$commit:$f"  > "$tmp/after.go"

    if ! strip < "$tmp/before.go" > "$tmp/before.code" || ! strip < "$tmp/after.go" > "$tmp/after.code"; then
        echo "FAIL: $f could not be normalized (toolchain broken, or source does not parse)" >&2
        rc=1
        continue
    fi
    if ! diff -u --label "$f (before)" --label "$f (after)" "$tmp/before.code" "$tmp/after.code"; then
        echo "FAIL: $f changed CODE, not just comments" >&2
        rc=1
    fi

    directives < "$tmp/before.go" > "$tmp/before.dir"
    directives < "$tmp/after.go"  > "$tmp/after.dir"
    if ! diff -u --label "$f directives (before)" --label "$f directives (after)" "$tmp/before.dir" "$tmp/after.dir"; then
        echo "FAIL: $f changed a toolchain directive (//go: or //nolint) or what it binds to" >&2
        rc=1
    fi
done

[ "$rc" -eq 0 ] || exit "$rc"
echo "OK: $commit is comment-only ($(echo "$files" | wc -w) files, code + bound directives byte-identical)"
