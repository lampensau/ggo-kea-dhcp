#!/bin/sh
# updater.sh - root oneshot that installs the staged appliance package.
#
# Runs as ggo-kea-dhcp-update.service, triggered by the control plane (via its
# sudoers-scoped `systemctl start --no-block`) after it downloaded and verified
# the .deb into /var/lib/ggo-kea-dhcp/update/. The outcome is written to
# result.json in that directory; the control plane (app-scope failures) or its
# next boot (a successful in-place restart) folds it into the audit log.
#
# Trust model: authenticity comes from the TLS download from GitHub verified
# against the release's API-published digest, done by the control plane at
# staging time - the same anchor install.sh uses. The sha256 re-verify below is
# integrity defense in depth against a corrupted or swapped staging file, not a
# second authenticity check.
#
# There is deliberately NO rollback for a half-applied system-scope update:
# apt/dpkg cannot transactionally undo a partial dependency upgrade. The
# `dpkg --configure -a` at the start of every run is the only recovery after a
# mid-install power loss; beyond that, re-run the update or the installer.
# App-scope updates replace a single package and inherit dpkg's own atomicity.
set -eu

STAGE=/var/lib/ggo-kea-dhcp/update
RESULT="$STAGE/result.json"
MANIFEST="$STAGE/manifest.json"
APT_LOG="$STAGE/apt.log"

VERSION=unknown
STATUS=failed
DETAIL="updater aborted unexpectedly"

# Every exit path reports through result.json (values are fixed strings from
# this script, safe to interpolate into JSON). Owned by the service user so the
# control plane can reconcile and clean it up.
# shellcheck disable=SC2329  # invoked via the EXIT trap
write_result() {
	printf '{"version":"%s","status":"%s","detail":"%s"}\n' "$VERSION" "$STATUS" "$DETAIL" > "$RESULT.tmp"
	mv "$RESULT.tmp" "$RESULT"
	chown ggo-kea-dhcp:ggo-kea-dhcp "$RESULT" 2>/dev/null || true
}
trap write_result EXIT

fail() {
	STATUS=failed
	DETAIL="$1"
	echo "updater: $DETAIL" >&2
	exit 1
}

[ -f "$MANIFEST" ] || fail "no staged manifest"

# Dependency-free manifest parse: the control plane writes compact JSON with
# known string keys, so one sed per field suffices (no jq on the appliance).
field() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" "$MANIFEST"; }
VERSION="$(field version)"
SCOPE="$(field scope)"
SHA="$(field sha256)"
DEB="$(field deb)"
if [ -z "$VERSION" ] || [ -z "$SHA" ] || [ -z "$DEB" ]; then
	fail "staged manifest is incomplete"
fi
case "$DEB" in
	"$STAGE"/*) ;;
	*) fail "staged package path escapes the staging directory" ;;
esac
[ -f "$DEB" ] || fail "staged package is missing"

# Recover a previous mid-dpkg power loss before touching anything (see the
# header comment - this is the only rollback story there is).
dpkg --configure -a || true

echo "$SHA  $DEB" | sha256sum -c - >/dev/null 2>&1 || fail "staged package failed its sha256 re-verification"

PKG="$(dpkg-deb -f "$DEB" Package 2>/dev/null || true)"
[ "$PKG" = "ggo-kea-dhcp" ] || fail "staged file is not the ggo-kea-dhcp package (got '$PKG')"

export DEBIAN_FRONTEND=noninteractive

if [ "$SCOPE" = "system" ]; then
	# System scope: the release changed dependency requirements. Refresh the
	# package lists and let apt upgrade what the .deb's versioned Depends demand
	# (the apt pin keeps Kea on its supported series).
	apt-get update >"$APT_LOG" 2>&1 || fail "apt-get update failed"
	if ! apt-get install -y "$DEB" >>"$APT_LOG" 2>&1; then
		tail -n 40 "$APT_LOG" >&2 || true
		fail "system-scope install failed"
	fi
else
	# App scope (the default): install ONLY the staged package with the
	# dependency set frozen - no apt-get update, so nothing else moves. If apt
	# refuses because this release needs dependency versions the box doesn't
	# have, report needs_system and keep the staged .deb: the Settings card then
	# offers the broader path as a second explicit click. Classification is
	# apt's standard unmet-dependencies phrasing in its error output - pinned
	# here as the decision rule.
	if ! apt-get install -y "$DEB" >"$APT_LOG" 2>&1; then
		if grep -qi "unmet dependencies" "$APT_LOG"; then
			STATUS=needs_system
			DETAIL="dependencies changed - a system-scope update is required"
			echo "updater: $DETAIL" >&2
			exit 0
		fi
		tail -n 40 "$APT_LOG" >&2 || true
		fail "install failed"
	fi
fi

# Success. The package's own postinstall already restarted the control plane in
# place (it did so mid-apt, before this line runs). Keep the staged .deb: the
# new control plane confirms the running version at boot and cleans the staging
# directory itself.
STATUS=ok
DETAIL=""
echo "updater: installed ggo-kea-dhcp v$VERSION (scope: ${SCOPE:-app})"
exit 0
