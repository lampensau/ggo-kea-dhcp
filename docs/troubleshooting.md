# Troubleshooting

Symptom-first, most common first. Alongside [installation](install.md), this is the only page where a terminal appears; everything else is handled in the web UI.

> [!TIP]
> Whatever the symptom, the Diagnostics page is the first stop: it re-runs the appliance's prerequisite checks on every load and shows the recent system events, so it usually names the failing part for you.

## I can't reach the web UI

Work through the [access table](first-boot.md) for the state the box is in:

- On an active appliance, the address is the gateway of your first scope, and `https://ggo-kea-dhcp.local/` always points at it. If `.local` does not resolve, your laptop's mDNS is the usual culprit (some VPN clients and corporate images disable it); use the IP.
- The onboarding WiFi access point only exists before setup is complete. If you expect it and it is gone, the box may already be active, or it never activated (see below).
- A certificate warning is not an error; the appliance signs its own certificate. Proceed past it.
- No answer at all on any path: give the box the benefit of one full boot (about a minute), then check the link LEDs and, as a last resort, the section below.

## Devices aren't getting addresses

In order of likelihood:

1. **The banner says the DHCP server is down.** The banner clears itself the moment the server answers again. If it stays up, check Diagnostics for the failing prerequisite; a reboot from Settings re-applies the whole configuration and restarts the DHCP server with it.
2. **A pool is full.** The DHCP Pools page shows per-pool utilization; a pool at 100% refuses newcomers of that device family. Raise its device count and save.
3. **The devices are on the wrong VLAN.** The network health card warns when tagged traffic arrives that no scope serves, and the wizard's link badge shows which VLAN IDs are actually on the wire. Compare against your scope list.
4. **Another DHCP server is answering first.** The alert strip and audit log will name a rogue server if the monitor sees one; track down the cable that connects it.

## The install finished but the box never took over eth0

By design, a failed activation leaves the Pi as a normal DHCP client on your LAN so you can reach it over SSH. Find its address on your router, log in, and look at the service:

```sh
systemctl status ggo-kea-dhcp
journalctl -u ggo-kea-dhcp -b
```

The journal states plainly what the appliance could not do. Fix the cause (most often: no cable on eth0 at boot), then reboot.

## The banner warns the reservation database is down

Dynamic leases keep serving, so the show is not in danger. Reservations and port pinning are read-only until the database returns; the appliance reconnects automatically and audits both the outage and the recovery. If it stays down across a reboot, Diagnostics will show the failing check.

## The network health card says monitoring is idle, or warns constantly

The card never goes blank while a profile is active: every served interface shows its full column of detectors, green when confirmed good, gray for traffic it simply has not seen yet. A quiet card full of green "No ..." rows is the healthy baseline, not an absence of monitoring.

"Monitoring idle" across the whole card means no profile is applied yet; monitoring starts with DHCP. When a single interface carries a note instead, the note is the honest reason: "no capture socket" means the monitor lacks its capture permission (Diagnostics names the failing check), and "reduced monitoring - high load" means it is deliberately shedding work to protect DHCP and lifts itself when traffic calms down. Address serving is unaffected in either case. The one deliberate gap is sACN detail, which only appears on scopes with Multicast inspect enabled.

If the card warns constantly on a busy or messy network (venues with legacy gear), some warnings are simply true. The [detector reference](network-health.md) says what each one means and when it is acceptable to live with it.

## The box greeted me with the factory screen out of nowhere

The appliance checks its configuration database on every boot. If the database is damaged beyond repair (SD cards fail, power cuts happen), it moves the damaged file aside and starts fresh at the factory screen instead of refusing to boot, and Diagnostics notes the recovery. Restore your latest backup directly from the factory screen and you are back; see [Backup, restore and reset](backup-restore.md).

This event is the reason to keep a current backup off the box.

## Time looks wrong after the box was powered off for a while

The Pi has no battery-backed clock. The appliance restores the last-known time at boot, which keeps leases sane across normal reboots, but after weeks in a case the clock will be behind until the box reaches a time source. Expect the first minutes after such a boot to show odd lease ages; it settles once the clock syncs (an internet uplink helps but is not required for DHCP to serve correctly).

## Reporting an issue

Open an issue on [GitHub](https://github.com/lampensau/ggo-kea-dhcp/issues) and include the appliance version (Settings page), what Diagnostics shows, and the relevant lines from the audit log. For anything security-related, use the [security policy](../.github/SECURITY.md) instead of a public issue.
