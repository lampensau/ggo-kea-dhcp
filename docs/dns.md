# Local DNS

The appliance knows the friendly name of every device it serves; local DNS makes those names resolvable on the network. When enabled for a scope, clients get the appliance as their DNS server and `ping bpx-19` just works - in sniffers, browser bookmarks, third-party tools, anywhere an IP used to be the only handle.

Every known device is published under two subdomains of greengo.digital, a domain reserved for exactly this purpose: `<name>.inv.greengo.digital` and `<name>.dhcp.greengo.digital` both resolve to the device, forward and reverse. The appliance itself answers as `dhcp.greengo.digital`, always with the address reachable from the asking client's own scope. Names come from what the appliance already knows - device scans, client-announced hostnames, and your reservations, in rising order of authority - sanitized to DNS-safe labels exactly as they appear on the [Leases page](operating.md#leases-and-reservations). The zone follows the live network: a device that moves gets its new address within a minute.

For everything outside those two subdomains the appliance is a plain forwarder: when a WiFi uplink is connected, general lookups pass through to the venue's resolver, so clients pointed at the appliance keep normal internet resolution. On an isolated network those lookups fail cleanly and device names keep resolving - the whole system works identically offline.

## One-time public setup on greengo.digital

This is done once, on the public greengo.digital zone, and covers every appliance ever deployed - no appliance address appears in it. Skip this section if it has already been done for your organization.

Create an insecure delegation for both subdomains: an NS record for `inv.greengo.digital` and one for `dhcp.greengo.digital`, each pointing at a dummy nameserver name (for example `blackhole.greengo.digital`), and **no DS records** for either. The delegation exists only to create an unsigned zone cut. Without it, DNSSEC-validating resolvers would treat the appliance's answers for these names as bogus, because the parent zone's signatures say the names should not exist; with a DS-less delegation the subdomains are provably insecure, and split-horizon answers from the appliance validate as "insecure" rather than "bogus" - which every resolver accepts. The dummy NS target never has to answer: on the show network the appliance is authoritative, and public queries for these names simply go nowhere.

Optionally, a public wildcard A record under each subdomain can point at a help page ("these names resolve only inside a Green-GO network") for people who try them from outside.

## Enabling the handout

Local DNS is enabled per scope, in the DHCP Options section of a scope card - in the [setup wizard](setup-wizard.md) when building a profile, or on the [DHCP Pools page](pools.md) on a running appliance. Flip the Local DNS switch and apply or save; clients receive the appliance as `domain-name-servers` plus a `domain-search` covering both subdomains on their next lease renewal. An explicit DNS override in the same section wins over the toggle, same as the gateway override.

The handout is opt-in because it makes a control-plane restart a brief resolution blip for clients. DHCP keeps serving throughout, the service restarts automatically and clients cache answers, so the blip is acceptable - but it is yours to choose. The name service itself runs on every served scope regardless of the toggle, so a venue's own resolver can conditionally forward the two subdomains at the appliance even where the handout stays off.

> [!NOTE]
> Devices only pick up the new DNS settings when they renew their lease. After enabling, wait out one renewal interval (half the lease time) or bounce a device to see it immediately.

## Verifying it works

From a client that received the appliance as its DNS server (substitute your box's address and a device name from the Leases page):

```
# The appliance's own name answers with its address on YOUR scope
dig @10.0.0.1 dhcp.greengo.digital

# A device resolves under both suffixes to the same address
dig bpx-19.dhcp.greengo.digital
dig bpx-19.inv.greengo.digital

# Reverse lookup gives the canonical name
dig -x 10.0.0.42

# The search domain makes bare names work
ping bpx-19

# Firefox's DoH probe gets NXDOMAIN, keeping the browser on local DNS
dig @10.0.0.1 use-application-dns.net

# General resolution forwards when an uplink exists...
dig @10.0.0.1 example.com

# ...and fails cleanly (SERVFAIL) when the appliance is isolated
```

Then pull the uplink and repeat the device-name lookups: they must all still answer. That is the venue-independence guarantee - resolution inside the scope needs nothing from the surrounding network.

If port 53 is blocked or taken, the [Diagnostics page](operating.md#diagnostics-and-the-audit-log) has a dedicated check: "UDP port 53 (local DNS)" warns when another service holds the port, and the CAP_NET_BIND_SERVICE check covers the permission to bind it.
