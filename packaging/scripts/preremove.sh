#!/bin/sh
# preremove (deb prerm) for ggo-kea-dhcp.
#
# Stop and disable the service ONLY on a genuine removal. dpkg runs this script from
# the OLD package during an UPGRADE too (with $1=upgrade); stopping there is exactly
# the bug that left the box down until a reboot - the postinstall's restart guard
# then saw an inactive service and deferred. On an upgrade we do nothing and let the
# new package's postinstall restart the control plane in place.
set -e
case "$1" in
	remove | deconfigure)
		systemctl stop ggo-kea-dhcp >/dev/null 2>&1 || true
		systemctl disable ggo-kea-dhcp >/dev/null 2>&1 || true
		;;
esac
exit 0
