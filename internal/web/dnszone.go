package web

import (
	"context"
	"sort"
	"strings"

	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/dns"
	"ggo-kea-dhcp/internal/ggoscan"
	"ggo-kea-dhcp/internal/kea"
)

// collectDNSHostsWith gathers the zone builder's three inputs (with the reservation
// map supplied by the caller) and delegates to the pure buildDNSHosts, so a single
// publishDashboardWithLeases fetch feeds both the zone rebuild and the dashboard
// fragments instead of querying MariaDB twice per broadcast.
func (s *Server) collectDNSHostsWith(leases []kea.ActiveLease, res map[string]db.HostReservation) map[string]string {
	var devs []ggoscan.Device
	if s.ggoscan != nil {
		devs = s.ggoscan.Snapshot().Devices
	}
	return buildDNSHosts(devs, leases, res)
}

// buildDNSHosts assembles the local-DNS zone input: every device the appliance
// can corroborate, as sanitized short label -> IPv4 address. Sources, weakest to
// strongest (later overwrites earlier):
//
//   - Green-GO scan inventory: scan-derived name + scan-observed address. This is
//     what publishes online-but-unleased hosts, and for Green-GO gear (which
//     announces no DHCP hostname) the scan name is the only name that exists.
//   - Active leases: the lease address is authoritative for its MAC, and a
//     client-announced hostname beats the scan name.
//   - Reservations: the operator's hostname beats everything; the reserved
//     address only fills in when the device holds no lease.
//
// Every name goes through the HostnameSlugs funnel (sanitize + MAC-tag dedupe),
// so the returned labels are DNS-safe and unique. Rows without a usable MAC
// never enter the funnel, and a device whose name sanitizes away entirely (an
// empty slug) is skipped - an anonymous device gets no zone entry.
func buildDNSHosts(devs []ggoscan.Device, leases []kea.ActiveLease, reservations map[string]db.HostReservation) map[string]string {
	names := map[string]string{} // normalized MAC -> raw name
	ips := map[string]string{}   // normalized MAC -> address

	// Deterministic overwrite order: the snapshot is inventory-map derived.
	devs = append([]ggoscan.Device(nil), devs...)
	sort.Slice(devs, func(i, j int) bool { return devs[i].MAC < devs[j].MAC })
	for _, d := range devs {
		mac := normalizeMAC(d.MAC)
		if mac == "" {
			continue
		}
		if d.Name != "" {
			names[mac] = d.Name
		}
		if d.IP != "" {
			ips[mac] = d.IP
		}
	}

	// Sort so a device holding several leases (one per trunk VLAN) publishes a
	// deterministic address instead of whichever lease iterated last.
	active := activeLeases(leases)
	sort.Slice(active, func(i, j int) bool { return active[i].IPAddress < active[j].IPAddress })
	for _, l := range active {
		mac := normalizeMAC(l.HWAddress)
		if mac == "" {
			continue
		}
		ips[mac] = l.IPAddress
		if l.Hostname != "" {
			names[mac] = l.Hostname
		}
	}

	for mac, rsv := range reservations {
		if mac == "" {
			continue
		}
		if rsv.Hostname != "" {
			names[mac] = rsv.Hostname
		}
		if _, leased := ips[mac]; !leased && rsv.IPv4Address != 0 {
			ips[mac] = kea.Uint32ToIP(rsv.IPv4Address).String()
		}
	}

	slugs := HostnameSlugs(names)
	hosts := make(map[string]string, len(slugs))
	for mac, slug := range slugs {
		if slug == "" || ips[mac] == "" {
			continue
		}
		hosts[slug] = ips[mac]
	}
	return hosts
}

// rebuildDNSZone builds and atomically swaps the local-DNS zone. Called from
// publishDashboardWithLeases (the dashboard cadence: the ticker's leasesChanged
// branch plus every post-mutation publishDashboard) and, signature-gated, from
// the always-on metrics sampler so a headless box stays fresh too.
// It reports whether this generation actually installed the zone (see
// rebuildDNSZoneWith); callers that track a dedup signature record it only on true.
func (s *Server) rebuildDNSZone(ctx context.Context, leases []kea.ActiveLease, gen uint64) bool {
	if s.dns == nil {
		return false
	}
	return s.rebuildDNSZoneWith(leases, s.fetchHWReservationMap(ctx), gen)
}

// rebuildDNSZoneWith is rebuildDNSZone with a caller-supplied reservation map, so
// the dashboard broadcast reuses the map it already fetched for the fragments
// rather than issuing a second identical MariaDB query. It returns whether this
// generation installed the zone: false means a later-dispatched rebuild already
// won, so a caller tracking a dedup signature must not record this one as installed.
func (s *Server) rebuildDNSZoneWith(leases []kea.ActiveLease, res map[string]db.HostReservation, gen uint64) bool {
	if s.dns == nil {
		return false
	}
	// Build the zone outside the lock (pure CPU; res is already fetched), then apply
	// under dnsZoneMu as last-writer-by-generation: a rebuild that dispatched later
	// wins, so a slow detached primeDNSZone cannot clobber a fresher zone the sampler
	// or an event-driven publish already installed. gen 0 (unversioned callers/tests)
	// always applies. A panic while building the zone (before the lock) propagates,
	// so the caller's signature commit is skipped exactly as an unapplied rebuild.
	z := dns.NewZone(s.collectDNSHostsWith(leases, res))
	s.dnsZoneMu.Lock()
	defer s.dnsZoneMu.Unlock()
	if gen != 0 && gen < s.dnsZoneAppliedGen {
		return false
	}
	s.dnsZoneAppliedGen = gen
	s.dns.SetZone(z)
	return true
}

// maybeRebuildDNSZone is the sampler's gate: rebuild only when the lease set or
// the scanned name inventory changed, so an idle box does not re-query the
// reservation database every 12 seconds. Reservation-only changes are covered
// by the event-driven publishDashboard rebuild.
func (s *Server) maybeRebuildDNSZone(ctx context.Context, leases []kea.ActiveLease) {
	if s.dns == nil {
		return
	}
	sig := leasesSignature(leases) ^ ggoNamesSignature(s.ggoScanIdentityByMAC())
	if s.dnsZoneSig.Load() == sig {
		return
	}
	// Latch this sig only when the rebuild actually installed the zone. A rebuild that
	// panicked (propagates, caught by the sampler's recover) or lost the generation
	// race never returns true, so the sig stays put and the next tick retries instead
	// of stranding a stale zone behind a "current" sig. The sampler is this gate's only
	// caller, so a plain Load/Store needs no CAS.
	if s.rebuildDNSZone(ctx, leases, s.dnsZoneSeq.Add(1)) {
		s.dnsZoneSig.Store(sig)
	}
}

// ggoScanIdentityByMAC keys each scanned Green-GO device's zone identity - its name
// AND its observed address - by normalized MAC, for the sampler's change gate. Both
// fields matter: a device that re-IPs without any name or lease change still moves its
// A/PTR record, so the scan address has to be in the signature or the zone goes stale.
// Scan addresses are the device's real lease/static IP (stable per device), so folding
// them in triggers a rebuild only on a genuine re-IP, not on churn.
func (s *Server) ggoScanIdentityByMAC() map[string]string {
	if s.ggoscan == nil {
		return nil
	}
	return scanIdentityByMAC(s.ggoscan.Snapshot().Devices)
}

// scanIdentityByMAC is the pure body of ggoScanIdentityByMAC: name+address per
// normalized MAC, skipping rows with no MAC or neither field.
func scanIdentityByMAC(devs []ggoscan.Device) map[string]string {
	m := make(map[string]string, len(devs))
	for _, d := range devs {
		mac := normalizeMAC(d.MAC)
		if mac == "" || (d.Name == "" && d.IP == "") {
			continue
		}
		m[mac] = d.Name + "\x00" + d.IP
	}
	return m
}

// ggoNamesSignature hashes a per-MAC identity inventory (order-independent input,
// order-fixed hash) for the sampler's change gate.
func ggoNamesSignature(names map[string]string) uint64 {
	if len(names) == 0 {
		return 0
	}
	keys := make([]string, 0, len(names))
	for k := range names {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(names[k])
		b.WriteByte('\n')
	}
	return fnv64(b.String())
}

// healDNSBinds re-attempts any served-interface DNS listener whose bind failed at
// apply time (the address not yet present after a re-IP, EADDRNOTAVAIL retry
// exhausted) but whose address has since appeared, so a scope's local DNS comes up
// within the sampler cadence instead of waiting for the next full reconcile. A
// recovered bind is audited (symmetric with the DNS_BIND_FAILED logged at apply
// time) so the self-heal shows on Diagnostics; the original failure row is what
// surfaces a persistent one. Inert outside ACTIVE (the server is stopped, so
// RebindMissing has no desired set).
func (s *Server) healDNSBinds() {
	if s.dns == nil {
		return
	}
	for _, ip := range s.dns.RebindMissing() {
		_ = s.sqlite.LogAudit("SYSTEM", "DNS_BIND_RECOVERED", ip, "", "port 53 bind succeeded on retry", "OK")
	}
}

// primeDNSZone fills the zone right after the ACTIVE listeners come up, so
// device names resolve within seconds of an apply instead of waiting out the
// first sampler tick. Best-effort.
func (s *Server) primeDNSZone() {
	ctx, cancel := opCtx()
	defer cancel()
	// Force a fresh poll (not the 3s-cached read) so prime's zone reflects its own
	// generation: as a slow detached goroutine it must not install leases older than
	// the generation it claims, or the last-writer-by-generation guard would let it
	// win with stale data.
	leases, err := s.getLeases(ctx, 0)
	if err != nil {
		return
	}
	s.rebuildDNSZone(ctx, leases, s.dnsZoneSeq.Add(1))
}
