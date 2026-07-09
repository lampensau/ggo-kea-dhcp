package appliance

import (
	"ggo-kea-dhcp/internal/arpscan"
	"ggo-kea-dhcp/internal/ggoscan"
	"ggo-kea-dhcp/internal/netmon"
)

// MonitorSet owns the appliance's background network observers. The Reconciler
// holds one and drives their lifecycle across the lifecycle transitions; every
// field is nil-safe so a dev sandbox (no CAP_NET_RAW) or a bare zero value can
// start/stop without special-casing. The stop discipline lives here so a
// lifecycle fix cannot land in one exit path and strand the others.
//
// Fields are written once by the constructing caller and only read after, which is
// what lets that caller hold this by value: the zero value is a usable empty set, and
// the Reconciler points at the caller's copy, so no nil *MonitorSet ever exists.
type MonitorSet struct {
	// Netmon is the passive network-health monitor. It runs only while ACTIVE, is
	// a read-only observer that never touches Kea, and feeds the dashboard's
	// Network Health card + edge-triggered audit rows.
	Netmon *netmon.MonitorManager
	// Arp is the active device-presence prober: it ARPs each active lease IP and
	// reports which answered recently - the single source for the online/offline
	// dot on the leases/dashboard views. Runs ACTIVE-only, beside netmon.
	Arp PresenceProber
	// Ggoscan is the active Green-GO device scanner (UDP 6464): a firmware/model
	// inventory for the firmware-mismatch warning and friendly hostnames. Runs
	// ACTIVE-only and only under a Green-GO preset.
	Ggoscan DeviceScanner
	// TrunkProbe passively sniffs eth0 during onboarding to tell the setup wizard
	// whether the switch port is trunking tagged VLANs (the full monitor runs
	// only in ACTIVE).
	TrunkProbe *netmon.TrunkProbe
	// RogueProbe passively watches eth0 during onboarding for a foreign DHCP
	// server already answering, feeding the wizard's shield badge. Same lifecycle
	// as TrunkProbe.
	RogueProbe RogueProber
}

// StopActive tears down the ACTIVE-only observers (passive monitor, ARP prober,
// Green-GO scanner). Idempotent; each field is nil-checked, since a dev sandbox or a
// zero-value set leaves them unset. The port-53 DNS listeners are NOT stopped here -
// the Reconciler owns dns and stops it alongside this call (see
// Reconciler.StopActiveMonitors).
func (m *MonitorSet) StopActive() {
	if m.Netmon != nil {
		m.Netmon.Stop()
	}
	if m.Arp != nil {
		m.Arp.Stop()
	}
	if m.Ggoscan != nil {
		m.Ggoscan.Stop()
	}
}

// StopOnboarding tears down the onboarding-only probes (trunk + rogue-DHCP).
// Idempotent; each field is nil-checked. Called when leaving onboarding for ACTIVE.
func (m *MonitorSet) StopOnboarding() {
	if m.TrunkProbe != nil {
		m.TrunkProbe.Stop()
	}
	if m.RogueProbe != nil {
		m.RogueProbe.Stop()
	}
}

// DeviceScanner is the subset of *ggoscan.Scanner the reconciler drives. Declaring the
// field as an interface lets a test inject a fake inventory and capture the reboot send
// without opening a real socket. *ggoscan.Scanner satisfies it.
type DeviceScanner interface {
	Start([]ggoscan.Spec)
	Stop()
	Snapshot() ggoscan.Snapshot
	SendReboot(ip string) error
}

// PresenceProber is the subset of *arpscan.Prober the reconciler drives, seamed for the
// same reason: a test can report presence and the live MAC at an IP. *arpscan.Prober
// satisfies it.
type PresenceProber interface {
	Start([]arpscan.Spec)
	Stop()
	Snapshot() arpscan.Snapshot
	ProbeHost(ip string) (mac string, alive bool)
}

// RogueProber is the onboarding rogue-DHCP probe surface (*netmon.RogueProbe in
// production; faked in wizard tests).
type RogueProber interface {
	Start(iface string)
	Stop()
	// Watching is false when the probe is stopped or blind (no CAP_NET_RAW), so
	// the shield can report "unverified" instead of a false all-clear.
	Watching() bool
	Server() (ip, mac string, ok bool)
}
