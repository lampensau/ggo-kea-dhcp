#!/bin/sh
# updater.sh - root oneshot that installs the staged appliance package.
#
# Runs as ggo-kea-dhcp-update.service, triggered by the control plane (via its
# sudoers-scoped `systemctl start --no-block`) after it downloaded and verified
# the .deb into /var/lib/ggo-kea-dhcp/update/. The outcome is written to
# result.json in that directory; the control plane (app-scope failures) or its
# next boot (a successful in-place restart) folds it into the audit log.
#
# Trust model: this root updater anchors authenticity in the digest GitHub
# publishes for the release, fetched HERE (as root) from the releases API using
# only the version string from the manifest. The app user (ggo-kea-dhcp) writes
# both the staged .deb AND manifest.json, so a compromised app user could make
# the app-written sha256 agree with a hostile package - that sha is therefore an
# integrity check only (a corrupted or swapped staging file), never the
# authenticity gate. Verifying against GitHub's published digest constrains the
# root install to a genuinely published release even if the app user is
# compromised. Fail closed: if the authoritative digest cannot be fetched, no
# install happens. The outbound API call needs no sudoers (this runs as root)
# and the update unit applies none of the main unit's network sandboxing.
#
# There is deliberately NO rollback for a half-applied system-scope update:
# apt/dpkg cannot transactionally undo a partial dependency upgrade. The
# `dpkg --configure -a` at the start of every run is the only recovery after a
# mid-install power loss; beyond that, re-run the update or the installer.
# App-scope updates replace a single package and inherit dpkg's own atomicity.
set -eu

# Parse apt's classification output and the GitHub API JSON in a fixed locale so
# a localized Pi can't defeat the string matching below (the needs_system grep
# and the digest check).
export LC_ALL=C LANG=C

STAGE=/var/lib/ggo-kea-dhcp/update
RESULT="$STAGE/result.json"
MANIFEST="$STAGE/manifest.json"
APT_LOG="$STAGE/apt.log"

REPO=lampensau/ggo-kea-dhcp
ASSET=ggo-kea-dhcp_arm64.deb
GH_API=https://api.github.com

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

# Compact-manifest parse: the control plane writes compact JSON with known
# string keys, so one sed per field suffices (jq is reserved for the richer
# releases API response below).
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

# VERSION anchors the authoritative API lookup below, so it must be plain
# semver: a compromised app user must not be able to smuggle '/' or '..' into
# the API URL and redirect it at an attacker-controlled repo (curl normalizes
# '..' path segments). Digits and dots only kills that.
case "$VERSION" in
	*[!0-9.]*) fail "manifest version is not a plain semver" ;;
esac

# Recover a previous mid-dpkg power loss before touching anything (see the
# header comment - this is the only rollback story there is).
dpkg --configure -a || true

# Copy the staged .deb into a root-only tempdir and verify+install THAT copy, not
# the app-writable original. The digest gate below and apt-get install are two
# separate opens of the file; a compromised app user could pass the digest then
# swap in a hostile .deb before apt reads it (TOCTOU). A swap mid-copy yields a
# Frankenstein file that fails the digest (fail-closed); anything passing it is
# byte-identical to what apt installs.
WORK="$(mktemp -d)" || fail "cannot create a private staging directory"
trap 'rm -rf "$WORK"; write_result' EXIT
cp "$DEB" "$WORK/pkg.deb" || fail "cannot stage a private copy of the package"
DEB="$WORK/pkg.deb"

# Integrity check against the app-written sha first: cheap defense in depth
# against a corrupted or swapped staging file. This is NOT an authenticity
# check - the app user wrote both the .deb and this sha, so a compromised app
# user can make them agree.
echo "$SHA  $DEB" | sha256sum -c - >/dev/null 2>&1 || fail "staged package failed its sha256 re-verification"

# Authoritative authenticity gate: fetch the digest GitHub published for this
# release's asset (keyed only on the manifest's version string) and verify the
# staged .deb against THAT. A compromised app user cannot forge a
# GitHub-published digest, so this pins the install to a genuinely published
# release. Fail closed - never fall back to the app-written sha - if the digest
# is unreachable or absent.
api="$(curl -fsSL --max-time 30 -H 'Accept: application/vnd.github+json' \
	"$GH_API/repos/$REPO/releases/tags/v$VERSION" 2>/dev/null || true)"
[ -n "$api" ] || fail "cannot reach GitHub to verify the release digest (failing closed)"
want="$(printf '%s' "$api" | jq -r --arg n "$ASSET" \
	'.assets[] | select(.name == $n) | .digest' 2>/dev/null || true)"
case "$want" in
	sha256:*) ;;
	*) fail "GitHub published no verifiable digest for v$VERSION (failing closed)" ;;
esac
got="sha256:$(sha256sum "$DEB" | awk '{print $1}')"
[ "$got" = "$want" ] || fail "staged package does not match GitHub's published digest for v$VERSION"

# Monotonic downgrade guard (root-side, cannot be bypassed by a compromised app
# user). The web handler already refuses a non-newer stage before it writes the
# manifest, but a compromised app process skips the web layer entirely and drives
# this service directly - so re-enforce "strictly newer" HERE against the version
# dpkg currently has installed. An authentic-but-older published release still
# passes the digest gate above, yet reinstalling it re-opens whatever
# vulnerabilities later releases fixed. Compare the SAME $VERSION that anchored
# the digest fetch, so the guard can't be desynchronized from what installs.
# Equal versions are not an upgrade -> refuse (blocks reinstall-as-downgrade).
# Not-installed (empty) is not a downgrade -> allow.
INSTALLED="$(dpkg-query -W -f='${Version}' ggo-kea-dhcp 2>/dev/null || true)"
if [ -n "$INSTALLED" ] && ! dpkg --compare-versions "$VERSION" gt "$INSTALLED"; then
	fail "refusing to install v$VERSION over installed v$INSTALLED - not an upgrade"
fi

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
