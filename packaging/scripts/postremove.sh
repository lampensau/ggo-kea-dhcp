#!/bin/sh
# postremove for ggo-kea-dhcp.
# On purge: remove the service user and the appliance state. The Kea/MariaDB data
# (the kea database, /etc/kea) is left intact - it belongs to those packages.
set -e

systemctl daemon-reload >/dev/null 2>&1 || true

if [ "$1" = "purge" ]; then
	rm -rf /var/lib/ggo-kea-dhcp
	rm -rf /etc/ggo-kea-dhcp
	# The kea database + kea_user are left to MariaDB (another package's data).
	if getent passwd ggo-kea-dhcp >/dev/null; then
		deluser --system ggo-kea-dhcp >/dev/null 2>&1 || true
	fi
	if getent group ggo-kea-dhcp >/dev/null; then
		delgroup --system ggo-kea-dhcp >/dev/null 2>&1 || true
	fi
fi
exit 0
