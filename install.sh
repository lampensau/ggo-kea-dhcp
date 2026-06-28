#!/usr/bin/env bash
#
# Green-GO Kea DHCP appliance - one-command installer for Raspberry Pi
# (Debian Trixie, arm64). Idempotent; re-run it to upgrade.
#
# Default (public repo) - one-liner that downloads the latest released .deb and
# verifies it against the SHA-256 the GitHub release publishes:
#   curl -fsSL https://raw.githubusercontent.com/lampensau/ggo-kea-dhcp/main/install.sh | sudo bash
#
# Local .deb (air-gapped, or while the repo is still private - no remote checksum
# to verify against, so the file is trusted as supplied):
#   scp install.sh ggo-kea-dhcp_arm64.deb pi@<ip>:~/
#   ssh pi@<ip> 'sudo GGO_DEB_FILE=~/ggo-kea-dhcp_arm64.deb ./install.sh'
#
# Override the source/package via env vars if needed:
#   GGO_DEB_FILE=/path/to/ggo-kea-dhcp_arm64.deb   (install a specific local .deb)
#   GGO_REPO=owner/repo  GGO_DEB_URL=https://.../ggo-kea-dhcp_arm64.deb
set -euo pipefail

GGO_REPO="${GGO_REPO:-lampensau/ggo-kea-dhcp}"
GGO_DEB_URL="${GGO_DEB_URL:-https://github.com/${GGO_REPO}/releases/latest/download/ggo-kea-dhcp_arm64.deb}"

log() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run as root (e.g. pipe into 'sudo bash')."
[ "$(dpkg --print-architecture)" = "arm64" ] || die "This installer targets arm64 (Raspberry Pi 64-bit)."
command -v apt-get >/dev/null || die "This installer requires Debian/apt (Raspberry Pi OS / Debian Trixie)."

export DEBIAN_FRONTEND=noninteractive

log "Installing base tooling..."
apt-get update -qq
apt-get install -y -qq curl ca-certificates gnupg debian-keyring debian-archive-keyring apt-transport-https jq

log "Adding the ISC Kea 3.0 package repository..."
if ls /etc/apt/sources.list.d/*kea*.list >/dev/null 2>&1; then
	log "  (already configured; skipping)"
else
	curl -1sLf 'https://dl.cloudsmith.io/public/isc/kea-3-0/setup.deb.sh' | bash
fi

log "Adding the Caddy package repository..."
# Guarded + --batch --yes so a re-run never blocks on gpg's "overwrite? (y/N)"
# prompt - the installer must stay non-interactive and idempotent.
if [ ! -s /usr/share/keyrings/caddy-stable-archive-keyring.gpg ]; then
	curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
		| gpg --batch --yes --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
fi
if [ ! -s /etc/apt/sources.list.d/caddy-stable.list ]; then
	curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
		> /etc/apt/sources.list.d/caddy-stable.list
fi

apt-get update -qq

log "Installing and starting MariaDB..."
apt-get install -y -qq mariadb-server
systemctl enable --now mariadb
# The Kea database + user (with a randomly generated password) are provisioned by
# the package's postinstall, which writes the DSN to /etc/ggo-kea-dhcp/mariadb.env
# - no credential is hardcoded here.

# Resolve + verify the package. Default: download the LATEST released .deb and
# check it against the SHA-256 the GitHub release publishes for that asset (the
# REST API exposes it as the asset's `digest`, e.g. "sha256:..."), so a corrupted
# or tampered download is refused. This needs the repo to be public (the API and
# the download are both unauthenticated). To install a local .deb instead - air-
# gapped, or while the repo is still private - set GGO_DEB_FILE; a local file has
# no published digest to check against, so it is trusted as supplied.
deb=""; cleanup=""
if [ -n "${GGO_DEB_FILE:-}" ]; then
	[ -f "$GGO_DEB_FILE" ] || die "GGO_DEB_FILE=$GGO_DEB_FILE does not exist."
	deb="$(readlink -f "$GGO_DEB_FILE")"
	log "Installing the local package (checksum not verified): $deb"
else
	log "Reading the published SHA-256 for the latest release..."
	want="$(curl -fsSL "https://api.github.com/repos/${GGO_REPO}/releases/latest" \
		| jq -r '.assets[] | select(.name == "ggo-kea-dhcp_arm64.deb") | .digest')"
	case "${want:-}" in
		sha256:*) ;;
		*) die "Could not read the published SHA-256 for ggo-kea-dhcp_arm64.deb from the latest release (is ${GGO_REPO} public yet? set GGO_DEB_FILE to install a local .deb)." ;;
	esac
	log "Downloading the latest .deb..."
	deb="$(mktemp --suffix=.deb)"; cleanup="$deb"
	curl -fsSL "$GGO_DEB_URL" -o "$deb" || die "Failed to download $GGO_DEB_URL"
	got="sha256:$(sha256sum "$deb" | awk '{print $1}')"
	[ "$got" = "$want" ] || die "Checksum mismatch for ggo-kea-dhcp_arm64.deb: got $got, expected $want - refusing to install."
	log "Checksum verified ($want)"
fi

# Stage the package in a world-readable temp file. apt's unprivileged sandbox user
# (_apt) cannot read a .deb left in a 0700 home dir - it warns and falls back to
# unsandboxed root; a 0644 copy under /tmp avoids that.
staged="$(mktemp --suffix=.deb)"; cleanup="$cleanup $staged"
# shellcheck disable=SC2064  # expand $cleanup now (mktemp paths are space-free).
trap "rm -f $cleanup" EXIT
cp "$deb" "$staged"
chmod 0644 "$staged"

log "Installing ggo-kea-dhcp (pulls in Kea, hooks, Caddy)..."
# Note whether the package is already installed: this run is then an UPGRADE/REINSTALL,
# and the closing message + the postinstall restart behaviour differ from a fresh box.
prev_ver="$(dpkg-query -W -f='${Version}' ggo-kea-dhcp 2>/dev/null || true)"
# apt resolves the package's declared dependencies from the repos added above.
# GGO_REINSTALL=1 forces re-applying the SAME version (apt otherwise skips an already-
# current .deb), which re-runs the postinstall - handy for re-testing the update path
# or repairing an install without bumping the version.
apt_opts=(-y)
if [ -n "${GGO_REINSTALL:-}" ] && [ -n "$prev_ver" ]; then
	apt_opts+=(--reinstall)
fi
apt-get install "${apt_opts[@]}" "$staged"
new_ver="$(dpkg-query -W -f='${Version}' ggo-kea-dhcp 2>/dev/null || true)"

if [ -n "$prev_ver" ]; then
	if [ "$prev_ver" = "$new_ver" ]; then
		change="reinstalled (v$new_ver)"
	else
		change="updated: $prev_ver -> $new_ver"
	fi
	# UPGRADE/REINSTALL: the box keeps its address. If the control plane was running,
	# the postinstall already restarted it onto the new binary - no reboot, no reconnect.
	cat <<EOF

$(printf '\033[1;32m')================================================================
 UPDATE COMPLETE
================================================================$(printf '\033[0m')

ggo-kea-dhcp $change

If the control plane was already running it has been restarted onto the new
version in place (no reboot, no IP change, your connection stays up). If the box
has not been activated yet, it still activates on the next reboot.
EOF
else
	# FRESH install: the box is not active yet and will seize eth0 on first boot.
	# Default onboarding SSID (the app stores any custom value in SQLite, but a fresh
	# install always uses this default).
	ssid="GGO-DHCP-Onboarding"
	cat <<EOF

$(printf '\033[1;33m')================================================================
 INSTALL COMPLETE - ACTION REQUIRED, READ BEFORE YOU DISCONNECT
================================================================$(printf '\033[0m')

The appliance is installed but NOT yet active. It activates on REBOOT, and on
its first start it SEIZES eth0 (becomes 10.0.0.1) and raises a WiFi onboarding
access point. If you are connected over eth0 right now, that connection WILL
DROP on reboot - this is expected. Do NOT reconnect to the old IP afterwards.

  1. Reboot to activate:        sudo reboot

  2. After it reboots, reconnect by EITHER:
       - joining the WiFi AP "$ssid", OR
       - plugging a laptop into eth0 (you'll get a 10.0.0.x lease via DHCP).

  3. Then open the dashboard. Easiest (works on both):
         https://ggo-kea-dhcp.local/      (mDNS - no IP to remember)
     IP fallback if .local doesn't resolve on your client:
         https://172.31.255.1/   (over the WiFi AP)
         https://10.0.0.1/       (over eth0)

  4. First visit: accept the self-signed certificate (or import Caddy's local CA).

If something goes wrong and the app does NOT take over eth0, it will stay a
normal DHCP client so you can SSH back in over your LAN to investigate.
EOF
fi
