package views

import (
	"strings"
)

// --- Network Health (passive monitoring card) ---

// NetHealthView is the dashboard's Network Health card model: one block per
// monitored interface, each with the per-detector signal rows. The backend emits
// structured signals (severity/kind/subject/text) - this view maps them to
// presentation; it bakes in no HTML of its own.
type NetHealthView struct {
	Interfaces []NetHealthIface
}

// NetHealthIface is one monitored interface's health: its detector rows plus the
// honest governor/availability state (so the card can say "multicast inspection
// paused - high load" or "monitoring unavailable").
type NetHealthIface struct {
	Iface     string
	ScopeName string // friendly scope name for the card title ("" -> show Iface alone)
	Available bool
	Note      string // honest state when not fully available / shedding
	Level     string // governor level ("full", "no-promiscuous", "counters-only", "paused")
	Degraded  bool   // governor is shedding (Level != full) or unavailable
	LinkMode  string // "flat"/"trunk"/"" - shown in the rollup header
	OKCount   int    // rollup of Rows by severity
	WarnCount int
	ErrCount  int
	Rows      []NetHealthRow
}

// NetHealthRow is one detector's signal. Severity is "ok"|"info"|"warn"|"error";
// Detail is an optional secondary line (subject/MAC/port) the card shows muted.
type NetHealthRow struct {
	Kind     string
	Severity string
	Title    string
	Detail   string
	// DetailRows, when set, renders the tooltip as one line per entry (e.g. a device
	// roster: "BPX 10.0.0.24 (00:1f:80:…)" per row) instead of one wrapping blob.
	DetailRows []string
}

// LLDPChip is the config-card "you are here" chip derived from the LLDP neighbor.
type LLDPChip struct {
	Present    bool
	Switch     string
	Port       string
	NativeVLAN string
}

// AlertRow is a backend-health signal (Kea down, MariaDB down, Wi-Fi uplink down)
// rendered in the always-on #backend-alert strip above the page h1: Severity
// ("err"/"warn") picks the .alert variant (alertClass) and Title+Detail are the
// strip's lines. (Netmon signals go to the header pill instead - see StatusPillView.)
type AlertRow struct {
	Severity string
	Title    string
	Detail   string
}

// alertClass maps an AlertRow severity ("err"/"warn") to its .alert variant class.
func alertClass(sev string) string {
	if sev == "err" {
		return "alert-err"
	}
	return "alert-warn"
}

// toastRole is "alert" (assertive) for an error toast so a screen reader
// interrupts to announce it, and "status" (polite) for success/info.
func toastRole(typ string) string {
	if typ == "error" {
		return "alert"
	}
	return "status"
}

// PTPRow is one PTP-domain clock signal for the PTP panel.
type PTPRow struct {
	Severity   string
	Domain     string // "domain N"
	Text       string
	ClockClass int // grandmaster's advertised clockClass (-1 if unknown/absent)
}

// PTPQuality maps a PTP grandmaster clockClass (IEEE 1588-2008 Table 5) to an
// operator-facing lock state and a status-dot severity. clockClass is the GM's
// advertised sync quality: 6 = locked to a primary reference (GPS/atomic), 7 =
// holdover (reference lost, still within spec), the degraded buckets are out of
// spec, and 248 is a free-running default master - normal in a self-contained
// Green-GO network, so it is neutral rather than alarming. The useful signal is a
// *change* (e.g. 6 -> 7 -> 248 = a GM that lost its GPS lock).
func PTPQuality(clockClass int) (label, dot string) {
	switch clockClass {
	case 6:
		return "GPS", "ok" // locked to a primary reference (commonly GPS)
	case 13:
		return "Locked", "ok" // locked to an arbitrary (ARB) timescale
	case 7, 14:
		return "Holdover", "warn"
	case 52, 58, 187, 193:
		return "Degraded", "warn"
	case 248:
		return "Local", "" // free-running default master - normal/neutral in a closed net
	case 255:
		return "Slave", "warn" // a slave-only clock acting as GM is odd
	default:
		if clockClass < 0 {
			return "Present", "ok" // a GM is present but did not advertise a class we read
		}
		return "Class " + itoa(clockClass), ""
	}
}

// presenceDot maps a lease's passive online/offline signal to a status-dot variant:
// online is a green ok dot, offline a neutral (muted) dot - meaning is reinforced by
// the cell's title tooltip, never color alone.
func presenceDot(presence string) string {
	if presence == "online" {
		return "ok"
	}
	return "" // offline → neutral/muted dot
}

// leaseDot is the row-aware presence-dot variant: a no-lease row (awaiting renewal /
// static in pool) gets the amber warn dot so it never reads as a plain healthy
// lease; normal rows keep the presence-driven color.
func leaseDot(l LeaseRow) string {
	if l.NoLeaseState != "" {
		return "warn"
	}
	return presenceDot(l.Presence)
}

// leaseDotTitle is the row-aware hover/aria text for the presence dot.
func leaseDotTitle(l LeaseRow) string {
	switch l.NoLeaseState {
	case "awaiting":
		return "Online but holds no DHCP lease - awaiting renewal"
	case "static":
		return "Online but holds no DHCP lease - static address in pool"
	}
	return presenceTitle(l.Presence)
}

// presenceTitle is the hover/aria text for the lease availability dot - "online"/
// "offline" alone is terse, so spell out what the passive monitor means by it.
func presenceTitle(presence string) string {
	switch presence {
	case "online":
		return "Online - answered a recent ARP probe"
	case "offline":
		return "Offline - no reply to the ARP probe"
	default:
		return ""
	}
}

// netHealthDot maps a detector severity to the status-dot variant (ok/warn/err;
// info is a neutral muted dot - informational signals must not read as alarms).
// netRowShowTip reports whether a detector row gets an info bubble: only when it
// carries machine detail distinct from the row text. Echoing the title (the old
// long-title fallback) just repeated the whole row in the tooltip, which operators
// read as noise - the detail must ADD something (a MAC, a port, the full census).
func netRowShowTip(r NetHealthRow) bool {
	return len(r.DetailRows) > 0 || (r.Detail != "" && r.Detail != r.Title)
}

// netRowTip is the bubble's text: the machine detail (only shown when distinct from
// the title, per netRowShowTip).
func netRowTip(r NetHealthRow) string {
	return r.Detail
}

func netHealthDot(severity string) string {
	switch severity {
	case "ok":
		return "ok"
	case "warn":
		return "warn"
	case "error":
		return "err"
	default: // info / unknown → neutral
		return ""
	}
}

// netRollupClass picks the per-interface rollup pill variant from the worst
// detector severity (only called when the interface is available): any error →
// err, any warning → warn, otherwise ok.
func netRollupClass(ifc NetHealthIface) string {
	switch {
	case ifc.ErrCount > 0:
		return "is-err"
	case ifc.WarnCount > 0:
		return "is-warn"
	default:
		return "is-ok"
	}
}

// netRollupDot maps an interface's worst severity to the header status-dot variant
// (err/warn/ok); an unavailable interface is neutral (no color) rather than a
// misleading green.
func netRollupDot(ifc NetHealthIface) string {
	switch {
	case !ifc.Available:
		return ""
	case ifc.ErrCount > 0:
		return "err"
	case ifc.WarnCount > 0:
		return "warn"
	default:
		return "ok"
	}
}

// netSubcardClass gives the interface sub-card its severity accent (a colored left
// border via sev-warn/sev-err); ok and unavailable carry no accent.
func netSubcardClass(ifc NetHealthIface) string {
	if !ifc.Available {
		return ""
	}
	switch {
	case ifc.ErrCount > 0:
		return "sev-err"
	case ifc.WarnCount > 0:
		return "sev-warn"
	default:
		return ""
	}
}

// netRollupText summarizes an interface's detector counts for the rollup pill:
// the worst nonzero count leads (those counts are meaningful problem totals),
// falling back to "Healthy" when every detector is OK, then "monitoring" when
// nothing has been observed yet. The all-OK count itself ("6 ok") was dropped -
// it counted passive detectors, not anything an operator can act on, and read as
// a mystery number next to the per-detector dots already listed below.
func netRollupText(ifc NetHealthIface) string {
	switch {
	case ifc.ErrCount > 0:
		return itoa(ifc.ErrCount) + " " + pluralize(ifc.ErrCount, "alert", "alerts")
	case ifc.WarnCount > 0:
		return itoa(ifc.WarnCount) + " " + pluralize(ifc.WarnCount, "warning", "warnings")
	case ifc.OKCount > 0:
		return "Healthy"
	default:
		return "monitoring"
	}
}

// netOverall sums detector counts across every interface plus how many are
// available, feeding the collapsed network-health header's combined rollup.
func netOverall(v NetHealthView) (ok, warn, err, avail int) {
	for _, ifc := range v.Interfaces {
		if ifc.Available {
			avail++
		}
		ok += ifc.OKCount
		warn += ifc.WarnCount
		err += ifc.ErrCount
	}
	return
}

// netOverallClass picks the combined rollup pill variant from the worst severity
// seen on any interface; with nothing monitored yet it stays neutral (no tint).
func netOverallClass(v NetHealthView) string {
	ok, warn, err, avail := netOverall(v)
	switch {
	case err > 0:
		return "is-err"
	case warn > 0:
		return "is-warn"
	case avail == 0:
		return ""
	case ok > 0:
		return "is-ok"
	default:
		return ""
	}
}

// netOverallText summarizes combined health for the collapsed header: the worst
// nonzero count leads, then "All clear" once interfaces report, then the idle
// placeholder before any monitoring has happened.
func netOverallText(v NetHealthView) string {
	ok, warn, err, avail := netOverall(v)
	switch {
	case err > 0:
		return itoa(err) + " " + pluralize(err, "alert", "alerts")
	case warn > 0:
		return itoa(warn) + " " + pluralize(warn, "warning", "warnings")
	case avail == 0:
		return "Monitoring idle"
	case ok > 0:
		return "All clear"
	default:
		return "Monitoring"
	}
}

// netHealthRollupDetail is the hover tooltip on the collapsed network-health pill:
// the active warnings/alerts across every interface (capped so the tooltip stays
// readable), or a reassuring "no issues" line - context without expanding the card.
func netHealthRollupDetail(v NetHealthView) string {
	_, _, _, avail := netOverall(v)
	if avail == 0 {
		return "Passive monitoring starts once a profile is active."
	}
	var issues []string
	for _, ifc := range v.Interfaces {
		for _, r := range ifc.Rows {
			if r.Severity == "warn" || r.Severity == "error" {
				issues = append(issues, ifc.Iface+": "+r.Title)
			}
		}
	}
	if len(issues) == 0 {
		return itoa(avail) + " " + pluralize(avail, "interface", "interfaces") + " monitored · no issues detected"
	}
	if len(issues) > 4 {
		more := len(issues) - 4
		return strings.Join(issues[:4], " · ") + " · +" + itoa(more) + " more"
	}
	return strings.Join(issues, " · ")
}

// pinningsRollupDetail is the hover tooltip on the collapsed port-pinnings pill:
// the first few pinned ports and their fixed IPs, so the operator sees what is
// pinned without expanding the card.
func pinningsRollupDetail(rows []PortRow) string {
	if len(rows) == 0 {
		return "No switch ports pinned. Pin a port to give its device a fixed IP."
	}
	var parts []string
	for i, p := range rows {
		if i >= 3 {
			break
		}
		parts = append(parts, portLabel(p)+" → "+p.IPAddress)
	}
	out := strings.Join(parts, " · ")
	if len(rows) > 3 {
		out += " · +" + itoa(len(rows)-3) + " more"
	}
	return out
}

// lldpChipText assembles the LLDP "you are here" chip label from the neighbor's
// switch, port, and (when advertised) native VLAN, joining only the parts that
// are present so a missing port/VLAN leaves no dangling separator.
func lldpChipText(c LLDPChip) string {
	head := c.Switch
	if c.Port != "" {
		head += " (" + c.Port + ")"
	}
	parts := []string{head}
	if c.NativeVLAN != "" {
		parts = append(parts, "VLAN "+c.NativeVLAN)
	}
	return strings.Join(parts, " · ")
}

// netHealthIcon maps a detector kind to its card glyph (all Lucide names that
// exist under views/icons/).
func netHealthIcon(kind string) string {
	switch kind {
	case "igmp":
		return "network"
	case "lldp":
		return "ethernet-port"
	case "rogue_dhcp":
		return "shield"
	case "duplicate_ip":
		return "copy" // two devices claiming one address - duplication, not a generic alert
	case "ptp":
		return "clock"
	case "storm":
		return "activity"
	case "idle":
		return "cable" // link carrying no traffic
	case "sacn":
		return "cpu"
	case "vlan":
		return "layers"
	case "static_in_pool":
		return "pin" // a fixed/static address sitting inside a dynamic pool
	case "greengo":
		return "headset" // Green-GO intercom device census
	case "greengo_config":
		return "sliders-horizontal" // the active Green-GO intercom configuration
	case "firmware":
		return "cpu" // mixed firmware within a Green-GO device family
	default:
		return "circle"
	}
}
