# Installation

This page takes you from an empty SD card to an installed appliance, ready for its first boot. It is one of only two pages in this guide where you need a terminal (the other is [Troubleshooting](troubleshooting.md)); everything after installation happens in the web UI.

You need a Raspberry Pi capable of running a 64-bit OS, with wired ethernet, an SD card, and internet access on the Pi for the installation only.

## Flash the SD card

Use the official [Raspberry Pi Imager](https://www.raspberrypi.com/software/) (Windows, macOS, Linux):

1. Choose your Pi model, then as the operating system pick **Raspberry Pi OS Lite (64-bit)**, found under "Raspberry Pi OS (other)". The appliance has no use for a desktop.
2. Choose your SD card.
3. When the imager offers OS customisation, take it: set a hostname, a username and password, and enable SSH on the Services tab. These credentials are how you will log in for the install step.
4. Write the card, put it in the Pi, connect ethernet to your normal network, and power it up.

After a minute the Pi appears on your network under the hostname you set (or find its address in your router's client list).

## Install

SSH into the Pi with the credentials from the imager and run:

```sh
curl -fsSL https://raw.githubusercontent.com/lampensau/ggo-kea-dhcp/main/install.sh | sudo bash
```

> [!NOTE]
> The command is idempotent: running it again later upgrades the appliance to the latest release.

The installer checks its own prerequisites and refuses to run on an unsupported system (32-bit OS, non-apt distribution). What it does, in plain terms:

1. Adds the package sources for [ISC Kea](https://www.isc.org/kea/) (pinned to the supported release series) and the [Caddy](https://caddyserver.com/) web server.
2. Installs and starts [MariaDB](https://mariadb.org/). The Kea database and its user are created automatically with a random password; no credential is hardcoded anywhere.
3. Downloads the latest released appliance package and verifies it against the SHA-256 checksum published with the release. A corrupted or tampered download is refused.
4. Installs the package, which pulls in Kea, its hook libraries and Caddy, and sets up the system service.

If any step fails, the script stops and prints the reason. Nothing on the Pi is changed beyond package installation until the first reboot.

## Offline or air-gapped install

If the Pi has no internet access, download the `.deb` from the [releases page](https://github.com/lampensau/ggo-kea-dhcp/releases) on another machine, copy it and the installer over, and point the installer at the local file:

```sh
scp install.sh ggo-kea-dhcp_arm64.deb pi@<ip>:~/
ssh pi@<ip> 'sudo GGO_DEB_FILE=~/ggo-kea-dhcp_arm64.deb bash install.sh'
```

A local file has no published checksum to verify against, so it is trusted as supplied. The package sources for Kea, Caddy and MariaDB still need to be reachable; a fully disconnected install requires a local mirror.

> [!NOTE]
> If this page and the script ever disagree, the comment header of [`install.sh`](../install.sh) itself is authoritative.

## Before you reboot

The appliance is installed but not yet active. It activates on reboot, and on its first start it takes over eth0 and becomes `10.0.0.1`, while raising a WiFi onboarding access point.

> [!WARNING]
> If you are connected over eth0 right now, that SSH session will drop on reboot. This is expected. Do not try to reconnect to the Pi's old address afterwards; use one of the paths described in [First boot](first-boot.md).

```sh
sudo reboot
```

If something goes wrong and the appliance does not take over eth0, the Pi stays a normal DHCP client on your LAN so you can SSH back in and investigate. See [Troubleshooting](troubleshooting.md).

## Upgrading

Re-run the same install command. On a box that is already active, the control plane is restarted in place onto the new version: no reboot, no address change, your browser session stays up. Your configuration is untouched.

The appliance version currently running is shown on the Settings page.

## Uninstalling

```sh
sudo apt remove ggo-kea-dhcp    # stops the appliance, keeps its configuration
sudo apt purge ggo-kea-dhcp     # also deletes the appliance state and service user
```

Kea, Caddy and MariaDB remain installed as regular packages, as does the Kea reservation database; remove them separately if you no longer want them.

## Next

Continue with [First boot](first-boot.md) to reconnect after the reboot and create the administrator account.
