#!/bin/sh
# Per-package coverage floors over the coverage.txt `make test` produces. The
# aggregate 50% gate (Makefile cover-gate) lets a big package mask a collapsing
# small one - a package dropping 82% -> 40% was invisible. These are REGRESSION
# floors, set a few points below each package's current coverage: raise a floor
# when you raise a package's coverage, never lower one to make CI pass.
#
# The main package (ggo-kea-dhcp) is exempt: it is boot glue (flag parsing +
# wiring) verified on the appliance, and holds no logic to unit-test.
# A package with coverage data but no floor fails - new packages get a floor.
set -e

awk '
BEGIN {
    floor["ggo-kea-dhcp/internal/arpscan"]   = 70
    floor["ggo-kea-dhcp/internal/config"]    = 75
    floor["ggo-kea-dhcp/internal/db"]        = 40
    floor["ggo-kea-dhcp/internal/dns"]       = 75
    floor["ggo-kea-dhcp/internal/ggoscan"]   = 30
    floor["ggo-kea-dhcp/internal/kea"]       = 75
    floor["ggo-kea-dhcp/internal/netmon"]    = 75
    floor["ggo-kea-dhcp/internal/network"]   = 50
    floor["ggo-kea-dhcp/internal/preflight"] = 90
    floor["ggo-kea-dhcp/internal/web"]       = 50
    floor["ggo-kea-dhcp/internal/web/views"] = 50
}
/^mode:/ { next }
{
    # Profile line: <pkg>/<file>.go:<start>,<end> <numStmts> <hitCount>
    split($1, loc, ":"); pkg = loc[1]; sub(/\/[^\/]+\.go$/, "", pkg)
    total[pkg] += $2
    if ($3 > 0) covered[pkg] += $2
}
END {
    fail = 0
    for (p in floor) {
        if (total[p] == 0) {
            printf "FAIL %-40s no coverage data (package gone? update scripts/cover_floors.sh)\n", p
            fail = 1
            continue
        }
        pct = covered[p] * 100 / total[p]
        if (pct < floor[p]) {
            printf "FAIL %-40s %.1f%% is below its floor (%d%%)\n", p, pct, floor[p]
            fail = 1
        } else {
            printf "ok   %-40s %.1f%% (floor %d%%)\n", p, pct, floor[p]
        }
    }
    for (p in total) {
        if (!(p in floor) && p != "ggo-kea-dhcp") {
            printf "FAIL %-40s has coverage data but no floor - add one to scripts/cover_floors.sh\n", p
            fail = 1
        }
    }
    exit fail
}' coverage.txt
