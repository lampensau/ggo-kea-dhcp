#!/bin/sh
# preremove for ggo-kea-dhcp: stop and disable the service before files are removed.
set -e
systemctl stop ggo-kea-dhcp >/dev/null 2>&1 || true
systemctl disable ggo-kea-dhcp >/dev/null 2>&1 || true
exit 0
