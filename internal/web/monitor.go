package web

import "ggo-kea-dhcp/internal/netmon"

// monitorSet owns the appliance's background network observers. The reconciler
// holds one and drives their lifecycle across the lifecycle transitions; every
// field is nil-safe so a dev sandbox (no CAP_NET_RAW) or a bare test Server can
// start/stop without special-casing. The stop discipline lives here so a
// lifecycle fix cannot land in one exit path and strand the others.
//
// Fields are written once (NewServer) and only read after, which is what lets
// Server hold this by value: the zero value is a usable empty set. The stop
// methods additionally tolerate a nil receiver, for the hand-built reconcilers in
// tests that never populate one.
type monitorSet struct {
	// netmon is the passive network-health monitor. It runs only while ACTIVE, is
	// a read-only observer that never touches Kea, and feeds the dashboard's
	// Network Health card + edge-triggered audit rows.
	netmon *netmon.MonitorManager
	// arp is the active device-presence prober: it ARPs each active lease IP and
	// reports which answered recently - the single source for the online/offline
	// dot on the leases/dashboard views. Runs ACTIVE-only, beside netmon.
	arp presenceProber
	// ggoscan is the active Green-GO device scanner (6464 device-scan): a
	// firmware/model inventory for the firmware-mismatch warning and friendly
	// hostnames. Runs ACTIVE-only and only under a Green-GO preset.
	ggoscan deviceScanner
	// trunkProbe passively sniffs eth0 during onboarding to tell the setup wizard
	// whether the switch port is trunking tagged VLANs (the full monitor runs
	// only in ACTIVE).
	trunkProbe *netmon.TrunkProbe
	// rogueProbe passively watches eth0 during onboarding for a foreign DHCP
	// server already answering, feeding the wizard's shield badge. Same lifecycle
	// as trunkProbe.
	rogueProbe rogueProber
}

// stopActive tears down the ACTIVE-only observers (passive monitor, ARP prober,
// Green-GO scanner). Idempotent and nil-safe. The port-53 DNS listeners are NOT
// stopped here - the reconciler owns dns and stops it alongside this call (see
// reconciler.stopActiveMonitors), so a nil monitorSet still lets DNS drop.
func (m *monitorSet) stopActive() {
	if m == nil {
		return
	}
	if m.netmon != nil {
		m.netmon.Stop()
	}
	if m.arp != nil {
		m.arp.Stop()
	}
	if m.ggoscan != nil {
		m.ggoscan.Stop()
	}
}

// stopOnboarding tears down the onboarding-only probes (trunk + rogue-DHCP).
// Idempotent and nil-safe; called when leaving onboarding for ACTIVE.
func (m *monitorSet) stopOnboarding() {
	if m == nil {
		return
	}
	if m.trunkProbe != nil {
		m.trunkProbe.Stop()
	}
	if m.rogueProbe != nil {
		m.rogueProbe.Stop()
	}
}
