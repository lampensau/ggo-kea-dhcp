#!/bin/sh
# postinstall for ggo-kea-dhcp. Idempotent: safe to re-run on upgrade/reconfigure.
set -e

KEA_DB_USER="kea_user"
KEA_DB_NAME="kea"
ENV_FILE="/etc/ggo-kea-dhcp/mariadb.env"
HOOKS_DIR="/usr/lib/aarch64-linux-gnu/kea/hooks"

echo "ggo-kea-dhcp: configuring..."

# 1. Service user + group (system account, no login, home is the state dir).
if ! getent group ggo-kea-dhcp >/dev/null; then
	addgroup --system ggo-kea-dhcp
fi
if ! getent passwd ggo-kea-dhcp >/dev/null; then
	adduser --system --no-create-home --home /var/lib/ggo-kea-dhcp --ingroup ggo-kea-dhcp \
		--disabled-password --shell /usr/sbin/nologin ggo-kea-dhcp
fi
# Let the service user read group-readable Kea files (gui-secret, conf).
if getent group _kea >/dev/null; then
	adduser ggo-kea-dhcp _kea >/dev/null 2>&1 || true
fi

# 2. State directory (systemd StateDirectory also does this, but create it now so
#    the DB/snapshots exist before first start).
install -d -o ggo-kea-dhcp -g ggo-kea-dhcp -m 0750 /var/lib/ggo-kea-dhcp /var/lib/ggo-kea-dhcp/snapshots

# 3. Kea API secret: generate once so the app never falls back to a local path.
if [ ! -s /etc/kea/gui-secret ]; then
	install -d -m 0750 /etc/kea
	umask 077
	od -An -tx1 -N16 /dev/urandom | tr -d ' \n' > /etc/kea/gui-secret
fi
chown ggo-kea-dhcp:_kea /etc/kea/gui-secret 2>/dev/null || chown ggo-kea-dhcp:ggo-kea-dhcp /etc/kea/gui-secret
chmod 0640 /etc/kea/gui-secret

# 4. Bootstrap kea-dhcp4.conf and make it app-owned so the control plane can rewrite
#    it in place (the app never creates files in /etc/kea, which must keep its
#    systemd-mandated 0750 mode - it only truncates this existing file).
#    CRITICAL: the stock isc-kea-dhcp4-server package (configured BEFORE us in the
#    same apt run) ships a default /etc/kea/kea-dhcp4.conf with only a UNIX control
#    socket. The control plane drives Kea exclusively over the HTTP socket on :8004,
#    so we must install our config whenever :8004 is absent - not only when the file
#    is missing - or Kea boots unix-only, the app can never reach it, and no DHCP is
#    ever served. An already-onboarded config (which has :8004) is left untouched.
if [ ! -s /etc/kea/kea-dhcp4.conf ] || ! grep -q 8004 /etc/kea/kea-dhcp4.conf; then
	cat > /etc/kea/kea-dhcp4.conf <<'EOF'
{
  "Dhcp4": {
    "interfaces-config": { "interfaces": [], "re-detect": false },
    "control-sockets": [
      { "socket-type": "unix", "socket-name": "/var/run/kea/kea-dhcp4-ctrl.sock" },
      {
        "socket-type": "http",
        "socket-address": "127.0.0.1",
        "socket-port": 8004,
        "authentication": {
          "type": "basic",
          "realm": "kea-api",
          "clients": [ { "user": "gui", "password-file": "/etc/kea/gui-secret" } ]
        }
      }
    ],
    "lease-database": { "type": "memfile" },
    "subnet4": []
  }
}
EOF
fi
chown ggo-kea-dhcp:_kea /etc/kea/kea-dhcp4.conf 2>/dev/null || chown ggo-kea-dhcp:ggo-kea-dhcp /etc/kea/kea-dhcp4.conf
chmod 0660 /etc/kea/kea-dhcp4.conf

# 5. Validate the sudoers drop-in; remove it rather than leave a broken file that
#    would block ALL sudo on the box.
if [ -f /etc/sudoers.d/ggo-kea-dhcp ]; then
	if ! visudo -cf /etc/sudoers.d/ggo-kea-dhcp >/dev/null 2>&1; then
		echo "ggo-kea-dhcp: WARNING - /etc/sudoers.d/ggo-kea-dhcp failed validation; removing it." >&2
		rm -f /etc/sudoers.d/ggo-kea-dhcp
	fi
fi

# 6. MariaDB credentials: generate a random password once, store the app's DSN in
#    an EnvironmentFile the systemd unit reads, and converge the DB user to it. The
#    password is never hardcoded - this file is the single source of truth (the app
#    renders it into kea-dhcp4.conf, and kea-admin/db-init below use it).
install -d -m 0750 -o root -g ggo-kea-dhcp /etc/ggo-kea-dhcp
if [ ! -s "$ENV_FILE" ]; then
	NEW_PASS="$(od -An -tx1 -N18 /dev/urandom | tr -d ' \n')"
	umask 027
	printf 'GGO_MARIADB_DSN=%s:%s@tcp(localhost:3306)/%s\n' "$KEA_DB_USER" "$NEW_PASS" "$KEA_DB_NAME" > "$ENV_FILE"
	chown root:ggo-kea-dhcp "$ENV_FILE"
	chmod 0640 "$ENV_FILE"
fi
# Extract the password from the stored DSN (kea_user:<pass>@tcp(...)/kea).
KEA_DB_PASS="$(sed -n 's/^GGO_MARIADB_DSN=[^:]*:\(.*\)@tcp.*/\1/p' "$ENV_FILE")"

# Converge the database + user to this password. On a fresh appliance MariaDB root
# uses unix_socket auth, so this works without a password; if root was hardened the
# operator provisions the user manually with the DSN above (best effort, never fatal).
if command -v mariadb >/dev/null 2>&1 && [ -n "$KEA_DB_PASS" ]; then
	# The user must exist for BOTH 'localhost' (matched by Kea's libmysqlclient,
	# which treats host=localhost as the unix socket) AND '127.0.0.1' (matched by
	# the Go app, whose DSN tcp(localhost:3306) is a real TCP connection that, under
	# skip-name-resolve, only matches the literal IP - granting only @'localhost'
	# yields "Access denied for 'kea_user'@'localhost' (using password: YES)").
	mariadb 2>/dev/null <<SQL || echo "ggo-kea-dhcp: WARNING - could not provision the MariaDB user automatically; create it from the DSN in $ENV_FILE." >&2
CREATE DATABASE IF NOT EXISTS $KEA_DB_NAME;
CREATE USER IF NOT EXISTS '$KEA_DB_USER'@'localhost' IDENTIFIED BY '$KEA_DB_PASS';
CREATE USER IF NOT EXISTS '$KEA_DB_USER'@'127.0.0.1' IDENTIFIED BY '$KEA_DB_PASS';
ALTER USER '$KEA_DB_USER'@'localhost' IDENTIFIED BY '$KEA_DB_PASS';
ALTER USER '$KEA_DB_USER'@'127.0.0.1' IDENTIFIED BY '$KEA_DB_PASS';
GRANT ALL PRIVILEGES ON $KEA_DB_NAME.* TO '$KEA_DB_USER'@'localhost';
GRANT ALL PRIVILEGES ON $KEA_DB_NAME.* TO '$KEA_DB_USER'@'127.0.0.1';
FLUSH PRIVILEGES;
SQL
fi

# 7. Initialize the Kea hosts schema if the DB is reachable and not yet set up.
if command -v kea-admin >/dev/null 2>&1 && [ -n "$KEA_DB_PASS" ]; then
	if ! mariadb -u "$KEA_DB_USER" -p"$KEA_DB_PASS" "$KEA_DB_NAME" -e "SELECT 1 FROM hosts LIMIT 1" >/dev/null 2>&1; then
		echo "ggo-kea-dhcp: initializing Kea MariaDB schema..."
		kea-admin db-init mysql -u "$KEA_DB_USER" -p "$KEA_DB_PASS" -n "$KEA_DB_NAME" >/dev/null 2>&1 \
			|| echo "ggo-kea-dhcp: WARNING - kea-admin db-init failed; run it manually." >&2
	fi
fi

# 8. Enable + start services. The supporting services never touch the operator's
#    network, so start them now. The control-plane app is the exception (see below).
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl enable isc-kea-dhcp4-server >/dev/null 2>&1 || true
# RESTART (not just enable --now): the stock isc-kea package, configured earlier in
# this same apt run, may already be running with its unix-only default config. In
# that case `enable --now` is a no-op and Kea never opens the :8004 HTTP control
# socket our config (written above) adds - the control plane would be permanently
# locked out (config-reload needs :8004 and cannot bootstrap it). A restart makes
# Kea re-read the file we just wrote. Safe mid-transaction: Kea only serves DHCP on
# the (currently empty) configured interfaces, it never touches the operator network.
systemctl restart isc-kea-dhcp4-server >/dev/null 2>&1 || true
if [ -d "$HOOKS_DIR" ]; then :; fi
# Caddy: load our reverse-proxy config.
systemctl enable --now caddy >/dev/null 2>&1 || true
systemctl reload caddy >/dev/null 2>&1 || systemctl restart caddy >/dev/null 2>&1 || true

# 8b. mDNS: publish ggo-kea-dhcp.local so operators reach the box by name instead of
#     memorizing an IP (the PRD's zero-IP-memory reconnect path). Setting the system
#     hostname makes avahi-daemon advertise <hostname>.local as A-records on every
#     active interface (eth0 10.0.0.1 AND wlan0 172.31.255.1), so the name resolves on
#     both onboarding subnets with no per-interface config. Caddy's :443 on-demand
#     internal issuer then serves a cert for that SNI (no Caddyfile change needed).
if [ "$(hostname)" != "ggo-kea-dhcp" ]; then
	hostnamectl set-hostname ggo-kea-dhcp >/dev/null 2>&1 || hostname ggo-kea-dhcp >/dev/null 2>&1 || true
fi
# Keep /etc/hosts in sync (hostnamectl does NOT) so every `sudo` the app runs doesn't
# stall on an unresolvable hostname reverse-lookup.
if ! grep -qE "127\.0\.1\.1[[:space:]]+ggo-kea-dhcp" /etc/hosts 2>/dev/null; then
	printf '127.0.1.1\tggo-kea-dhcp\n' >> /etc/hosts
fi
systemctl enable --now avahi-daemon >/dev/null 2>&1 || true

# Control-plane activation.
# FRESH install (or one never activated): only ENABLE it. Its first start seizes
# eth0 -> 10.0.0.1 and raises the wlan0 SoftAP, which would instantly drop an SSH
# session over eth0 and can race systemd mid-apt - so we defer the takeover to the
# operator's deliberate reboot (the closing banner explains how to reconnect).
# UPGRADE/REINSTALL of an already-RUNNING box: restart it onto the new binary now.
# That is the same idempotent boot reconcile the box has already done, on the same
# IP, so nothing re-seizes eth0 and no session drops. The is-active guard is the key
# safety: a not-yet-activated box is never started here (that would seize eth0 mid-
# apt), and keying on "running" (not a version delta) means a same-version reinstall
# exercises the restart path too.
systemctl enable ggo-kea-dhcp >/dev/null 2>&1 || true
ggo_restarted=false
if systemctl is-active --quiet ggo-kea-dhcp 2>/dev/null; then
	systemctl restart ggo-kea-dhcp >/dev/null 2>&1 || true
	ggo_restarted=true
fi

# 9. Report prerequisite status (informational - never fails the install). Pass the
#    REAL runtime config so the probes match what the systemd service uses. Without
#    --mariadb-dsn, --check falls back to the built-in *dev default* DSN and reports a
#    bogus "Access denied" against the generated password. The DSN is read out of the
#    env file (not sourced - its tcp(...) parens are not shell-safe to `.`-source).
if command -v ggo-kea-dhcp >/dev/null 2>&1; then
	# Let the just-(re)started Kea/app bind their sockets before probing them.
	sleep 3
	dsn="$(sed -n 's/^GGO_MARIADB_DSN=//p' "$ENV_FILE" 2>/dev/null)"
	ggo-kea-dhcp --check \
		--mariadb-dsn "$dsn" \
		--kea-secret /etc/kea/gui-secret \
		--kea-conf-dir /etc/kea \
		|| echo "ggo-kea-dhcp: some prerequisites need attention (see above and the Diagnostics page)." >&2
fi

if [ "$ggo_restarted" = true ]; then
	echo "ggo-kea-dhcp: updated - the control plane was restarted onto the new version."
else
	echo "ggo-kea-dhcp: package configured. The control plane is ENABLED but NOT yet"
	echo "ggo-kea-dhcp: running - it activates on reboot, when it takes over eth0."
fi
exit 0
