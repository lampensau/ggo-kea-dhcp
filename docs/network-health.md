# Network health

While serving DHCP, the appliance passively listens to the traffic on each network it serves and reports what it sees on the dashboard's network health card, one sub-card per interface. This page is the reference for what each detector means and what to do when it warns.

![Network health](images/nethealth.png)

## What it is, and is not

The monitor observes; it does not manage. Almost everything it knows comes from passively captured traffic, complemented by two light read-only queries: presence checks (so lease rows can show whether a device actually answers) and a Green-GO device scan that reads names and firmware versions. It never changes the DHCP configuration, never reconfigures a device, and never acts on the network on its own. A finding is information for you, not an automatic intervention - the one place it hands you a control is the rogue-server warning, which offers a one-click stand-down you choose to use (see below). Warnings and errors also appear in the dashboard's alert strip and are recorded in the audit log with timestamps.

It runs only while the appliance is active, and only on the wired networks it serves. Under heavy traffic it deliberately sheds its own work to stay out of DHCP's way, and says so on the card instead of silently going blind.

## Detector reference

Rows are ordered by severity, then by how directly a problem breaks DHCP.

**Rogue DHCP server.** Another DHCP server answered on a network this appliance serves; the detail names the server address and MAC. This is the highest-priority finding: devices are leasing from the wrong server, and which server wins any given request is a race. Because it is that disruptive, a rogue detection is also promoted to the loud alert banner at the top of every page, carrying a **Stand Down DHCP** control: one click stops this appliance serving DHCP on every scope so it stops competing with the other server, and the banner switches to a **Resume DHCP** control that restores serving once the intruder is gone. Standing down is never automatic and never required - the appliance only warns; whether to stop and when to resume is your call, and the stand-down survives a reboot so the box will not quietly start serving again on its own. Either way, find the cable that connects the offending device (most often a router someone plugged in for "just a minute") and remove or deactivate it.

**Duplicate IP.** Two devices claim the same address; the detail shows the address and how many times devices have declined it. Typical cause: a statically configured device sitting on an address the pool also hands out. Reserve the address for that device or move the static into the reserved range.

**Static device in a pool.** A device with a manually configured address is squatting inside a dynamic pool; the detail shows its IP, MAC and the pool. It has not collided with anything yet, which is exactly the time to fix it: give it a reservation or move it to the reserve block.

**Green-GO devices.** A census of the Green-GO hardware the monitor hears, with a per-device roster (family, IP, MAC). It warns when devices sit on link-local addresses (they asked for DHCP and got nothing - wrong VLAN or an exhausted pool) or run without a lease. Hearing Green-GO devices tagged onto a VLAN no scope serves outranks everything else, since the appliance can never lease them; the detail names the offending VLAN IDs. A healthy row doubles as a live inventory of the rig.

**Firmware mix.** A Green-GO rig normally runs a single firmware release across every device type. When the monitor hears devices on two or more releases, the Green-GO scope's card gets one warning row naming each release and how many devices run it, with the per-device breakdown behind its info icon; legacy models frozen on their final release are exempt. Mixed firmware is a classic source of "works on this pack, not on that one"; align versions before the show, not during it.

**Green-GO config.** Shows which Green-GO configuration is announced on the segment. Multiple configurations active at once is a rig split in two: devices in different configs do not talk to each other. That state usually means a device from another show or a freshly reset unit is on the wire; align it with the production's config.

**VLAN reality.** Tagged traffic is arriving for VLANs that no scope serves; the detail lists the VLAN IDs. Either the switch trunk carries more than it should, or a scope is missing from the profile. Compare the [wizard's](setup-wizard.md) link badge and your scope list against the switch configuration. When the network hardware hides VLAN tags from the monitor, the row says "VLAN inspection limited" instead of pretending all is clear.

**IGMP querier.** Reports the active multicast querier and its version. Multicast-heavy networks (Dante, sACN) need exactly one working querier, usually the switch; a querier address of `0.0.0.0` is a valid snooping querier, not an error.

**PTP grandmaster.** Tracks the precision-time grandmaster per PTP domain, with its clock class. A stable grandmaster is what Dante and AES67 clocking depend on; grandmaster changes, failovers or flapping during a show mean audio devices are re-syncing. The current grandmaster state is also promoted to a dashboard stat tile.

**sACN.** Reports lighting control traffic (sACN/E1.31) seen on the scope, so you can confirm the lighting network is where you think it is, and warns when two sources fight over a universe at the same priority or a source identity appears twice. Requires Multicast inspect (below).

**Uplink (LLDP/CDP).** The switch and port the appliance is plugged into, as announced by the switch; the native VLAN sits behind the row's info icon. This is the dashboard's "you are here" chip; if the appliance ends up on the wrong patch, this row says so immediately. Switch announcements are untagged, so the neighbor appears on the physical interface's card; VLAN scopes show "No LLDP/CDP neighbor seen", which is normal.

**Broadcast storm / STP.** Warns on broadcast storms (with the observed packet rate) and on spanning-tree topology churn. Both usually mean a loop: a cable plugged into two access ports, or a misbehaving switch. Find the loop before it takes the network down.

**Link activity.** Notes when a monitored network has gone completely silent for an extended time - a dead port or an unplugged trunk looks exactly like this.

## Multicast inspect

Most detectors work from traffic the appliance receives anyway. Full multicast inspection (needed for sACN detail, and for richer multicast health generally) is a per-scope switch, off by default, set in the [wizard](setup-wizard.md): it adds a low-rate sample of all multicast traffic on that scope. It is also the first thing the monitor sheds under load. PTP grandmaster tracking works without it.

## Reading the card's state

The card never goes blank on a running appliance: every detector reports a row per interface, green when it has confirmed the situation is good, gray when it simply has not observed that kind of traffic yet. A column of green "No ..." rows is the healthy baseline, not an absence of monitoring.

Two special states replace that baseline. Before a profile is applied, the card shows "Monitoring idle" - monitoring starts with DHCP. And when an interface carries a note instead of a clean rollup, the note is the honest reason. Load shedding announces itself in stages ("multicast inspection paused - high load", then "reduced monitoring - high load", finally "monitoring paused - high load"), all of which lift themselves when traffic calms down. "Monitoring idle - no capture socket" means the monitor lacks its capture permission and cannot observe that interface at all (DHCP is unaffected either way). See [Troubleshooting](troubleshooting.md).
