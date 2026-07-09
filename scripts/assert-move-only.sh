#!/bin/sh
# Assert a commit is MOVE-ONLY: it may relocate code between files but must not
# add, delete, alter, or REORDER a line of logic. Git renders a 1-file -> 5-file
# split as a delete plus four adds, which is unreviewable by eye, so this proves
# the union of the touched .go files is byte-identical before and after the commit
# - modulo `package`/`import` lines, which every split-out file needs its own copy
# of, and which are checked separately as a set.
# Reusable for the internal/web disentangle series: PR 1's split, and the
# move-only commits the later receiver-rename stages are required to isolate.
#
# Three properties are checked, because the first alone is not enough:
#   1. Conservation - the sorted multiset of code lines is unchanged (nothing
#      added, removed, or edited).
#   2. Order - each destination file decomposes into CONTIGUOUS runs of the
#      pre-image whose start positions ASCEND through it. Conservation is blind to
#      reordering: a swapped pair of statements, or a moved mu.Unlock(), conserves
#      the multiset exactly. In a lifecycle refactor, ordering IS the behavior. A
#      split carves the source into ordered chunks, so a destination file reads its
#      chunks front-to-back; a swap makes one run start behind its predecessor.
#   3. Imports - the import set (paths and aliases) is unchanged in both
#      directions. The stripper discards import lines, so without this a changed
#      alias or an added blank import (`_ "net/http/pprof"`, a side effect) rides
#      through silently.
#
# Usage: scripts/assert-move-only.sh [commit]   (default HEAD)
#   ALLOW_NONGO=1     permit non-.go files in the same commit (they are NOT checked)
# Exit 0 = move-only; non-zero + a diff = logic changed.
set -e

commit="${1:-HEAD}"

# A merge commit has two parents, and `git diff-tree` without -m prints nothing for
# one - the script would report "no .go files touched" and exit 0, a pass that means
# nothing. Refuse instead: move-only is a property of a single-parent commit.
if [ "$(git rev-list --parents -n 1 "$commit" | wc -w)" -gt 2 ]; then
    echo "FAIL: $commit is a merge commit; assert move-only on its side commits" >&2
    exit 1
fi

# Non-.go files are outside what this proves. Fail loudly rather than pass a commit
# whose Makefile or embedded asset changed alongside a "pure" move.
nongo=$(git diff-tree --no-commit-id --name-only -r "$commit" | grep -v '\.go$' || true)
if [ -n "$nongo" ] && [ "${ALLOW_NONGO:-0}" != "1" ]; then
    echo "FAIL: $commit also touches files this script does not check:" >&2
    echo "$nongo" | sed 's/^/  /' >&2
    echo "  (re-run with ALLOW_NONGO=1 if they are genuinely unrelated)" >&2
    exit 1
fi

# Drop package + import lines and blank lines. Sorting happens in the caller, so the
# same stripper serves the ordered (per-file) and unordered (union) checks.
strip() {
    awk '
        /^import \(/ { imp = 1; next }
        imp && /^\)/ { imp = 0; next }
        imp          { next }
        /^package /  { next }
        /^import "/  { next }
        NF           { print }
    '
}

# Import paths with their aliases, one per line, for the set comparison.
imports() {
    awk '
        /^import \(/ { imp = 1; next }
        imp && /^\)/ { imp = 0; next }
        imp && NF    { gsub(/^[ \t]+|[ \t]+$/, ""); print; next }
        /^import "/  { sub(/^import /, ""); print }
    '
}

files=$(git diff-tree --no-commit-id --name-only -r "$commit" -- '*.go')
[ -n "$files" ] || { echo "no .go files touched by $commit"; exit 0; }

before=$(mktemp); after=$(mktemp)
impbefore=$(mktemp); impafter=$(mktemp)
src=$(mktemp); dst=$(mktemp)
trap 'rm -f "$before" "$after" "$impbefore" "$impafter" "$src" "$dst"' EXIT

# Missing pre-image (added file) or post-image (deleted file) is expected in a
# split; `|| true` lets the concatenation continue so the union still balances.
for f in $files; do git show "$commit^:$f" 2>/dev/null || true; done > "$src"
for f in $files; do git show "$commit:$f"  2>/dev/null || true; done > "$dst"

strip < "$src" | sort > "$before"
strip < "$dst" | sort > "$after"

# --- 1. conservation --------------------------------------------------------
if ! diff -u "$before" "$after"; then
    echo "FAIL: $commit changed logic, not just file location" >&2
    exit 1
fi

# --- 3. imports (cheap, do it before the expensive run check) ---------------
imports < "$src" | sort -u > "$impbefore"
imports < "$dst" | sort -u > "$impafter"
if ! diff -u "$impbefore" "$impafter"; then
    echo "FAIL: $commit changed the import set (alias, or an added side-effect import)" >&2
    exit 1
fi

# --- 2. order ---------------------------------------------------------------
# Each destination file must be a concatenation of contiguous slices of the
# pre-image union, taken front-to-back. Runs are matched greedily from the
# occurrence that extends furthest (so duplicate lines like "}" do not fragment
# them), preferring a candidate that keeps the starts ascending. A start that
# lands behind its predecessor means the code was reordered, not relocated.
runs_total=0
for f in $files; do
    git show "$commit:$f" >/dev/null 2>&1 || continue   # deleted by the split
    result=$(git show "$commit:$f" | strip | awk -v src="$src" '
        BEGIN {
            while ((getline line < src) > 0) {
                if (line ~ /^import \(/) { imp = 1; continue }
                if (imp && line ~ /^\)/) { imp = 0; continue }
                if (imp || line ~ /^package / || line ~ /^import "/) continue
                if (line ~ /^[ \t]*$/) continue
                S[++m] = line
            }
        }
        { D[++n] = $0 }
        # runLen: how far the pre-image at p keeps matching the destination at i.
        function runLen(p, i,   len) {
            len = 0
            while (p + len <= m && i + len <= n && S[p + len] == D[i + len]) len++
            return len
        }
        END {
            pos = 0; runs = 0; lastStart = 0
            for (i = 1; i <= n; i++) {
                if (pos > 0 && pos < m && S[pos + 1] == D[i]) { pos++; continue }
                # Prefer the longest run starting at or after the previous run, so a
                # duplicate line does not fake a backwards jump; fall back to the
                # longest run anywhere, which is then reported as the violation.
                best = 0; bestlen = -1
                for (p = lastStart + 1; p <= m; p++) {
                    if (S[p] != D[i]) continue
                    len = runLen(p, i)
                    if (len > bestlen) { bestlen = len; best = p }
                }
                if (best == 0) {
                    for (p = 1; p <= m; p++) {
                        if (S[p] != D[i]) continue
                        len = runLen(p, i)
                        if (len > bestlen) { bestlen = len; best = p }
                    }
                    if (best == 0) { print "MISSING\t" D[i]; exit }
                    print "REORDER\t" D[i]; exit
                }
                pos = best; lastStart = best; runs++
            }
            print "OK\t" runs
        }
    ')
    verdict=${result%%	*}; detail=${result#*	}
    case "$verdict" in
        MISSING)
            echo "FAIL: $f has a line absent from the pre-image: $detail" >&2; exit 1 ;;
        REORDER)
            echo "FAIL: $f reorders the pre-image; this line moved ahead of code that preceded it:" >&2
            echo "  $detail" >&2
            echo "  Conservation of lines is not enough - ordering is behavior." >&2
            exit 1 ;;
    esac
    echo "  $f: $detail run(s)"
    runs_total=$((runs_total + detail))
done

echo "OK: $commit is move-only ($(echo "$files" | wc -w) files, $(wc -l < "$after") code lines, $runs_total ordered runs, imports unchanged)"
