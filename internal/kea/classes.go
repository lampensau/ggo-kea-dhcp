package kea

import (
	"fmt"
	"strings"
)

// DeviceClass is a single Green-GO device-type band, and the SINGLE source of truth
// for the Kea client-class `test` expressions, lease/dashboard classification, and
// pool sizing (PRD §16 / D7: maintained here, never re-implemented per call site).
//
// Prefixes match at offset 6 of the MAC hexstring (classPrefixExpr builds the exact
// Kea expression) - the device-type digits following the `001f80` OUI. BPX takes 2
// digits ("20") because its serial blocks span 0x200xxx-0x202xxx; every other type
// takes 3.
type DeviceClass struct {
	Name     string   // Kea class name, e.g. "GGO-BPX"
	CountKey string   // wizard/pool_spec key, e.g. "count_bpx"
	Prefixes []string // hexstring offset-6 prefixes (length 2 or 3)
	Label    string   // operator-facing name, e.g. "Beltpacks"
	Icon     string   // display icon key, e.g. "bpx"
	Codes    string   // hardware codes, e.g. "BPX / BP2"
}

// DeviceClasses lists the mapped Green-GO bands. This order is the canonical display
// order everywhere (Add-pool menu, wizard device grid, dashboard breakdown): beltpacks
// first, then the rack/panel gear, then the RF/antenna family, then interfaces and
// bridges, switches last. The catch-alls are intentionally absent - ClientClasses and
// ClassifyMAC handle them.
//
// Each 3-hex prefix is exactly one allocated MAC block base. Carry ONLY allocated
// blocks: a speculative prefix maps to no real device and only widens a class's match.
var DeviceClasses = []DeviceClass{
	{Name: "GGO-BPX", CountKey: "count_bpx", Prefixes: []string{"20"}, Label: "Beltpacks", Icon: "bpx", Codes: "BPX / BP2"},
	{Name: "GGO-MCX-D", CountKey: "count_mcx", Prefixes: []string{"220", "225"}, Label: "Multi-Channel", Icon: "mcx", Codes: "MCX / MCXD"},
	{Name: "GGO-MCD-MCR", CountKey: "count_mcd", Prefixes: []string{"210"}, Label: "Desktop / Rack", Icon: "mcd", Codes: "MCD / MCR"},
	{Name: "GGO-WP-X", CountKey: "count_wpx", Prefixes: []string{"213"}, Label: "Wall Panels", Icon: "wpx", Codes: "WPX / WP"},
	{Name: "GGO-STRIDE", CountKey: "count_stride", Prefixes: []string{"230"}, Label: "STRIDE Antennas", Icon: "radio-tower", Codes: "STRIDE"},
	{Name: "GGO-WAA", CountKey: "count_waa", Prefixes: []string{"216", "223"}, Label: "Active Antennas", Icon: "radio-tower", Codes: "WAA"},
	{Name: "GGO-RDX-SI-BEACON", CountKey: "count_beacon", Prefixes: []string{"217", "224", "226"}, Label: "Radio, SI & Beacon", Icon: "beacon", Codes: "RDX / SI2WR / SI4WR / Beacon"},
	{Name: "GGO-INTERFACE-Q4WR", CountKey: "count_interface", Prefixes: []string{"211"}, Label: "Interfaces", Icon: "interface", Codes: "INTERFACEX / Q4WR"},
	{Name: "GGO-BRIDGE-DANTEX", CountKey: "count_bridge", Prefixes: []string{"214"}, Label: "Bridges / Dante", Icon: "bridge", Codes: "BRIDGEX / DANTEX"},
	{Name: "GGO-SWITCH", CountKey: "count_switch", Prefixes: []string{"212", "221", "240"}, Label: "Switches", Icon: "network", Codes: "SW5 / SW6 / SW18GBX"},
}

const (
	// greenGOOUI is registered to Lucas Holding BV - the parent of both Green-GO
	// and ELC - so this OUI is shared by Green-GO intercom and (some) ELC gear.
	greenGOOUI = "001f80"
	// ClassNameGGOOthers is the single Green-GO catch-all: any Green-GO/ELC device with
	// no model pool of its own in the scope (see GGOOthersTest).
	ClassNameGGOOthers = "GGO-OTHERS"
	// ClassNameOthers is the non-Green-GO pool; its test excludes the Green-GO OUI
	// (see ClientClasses for why that exclusivity matters).
	ClassNameOthers = "OTHERS"
	CountKeyOthers  = "count_others"
)

// IsCatchAll reports whether class is one of the two unmatched-device safety nets.
// Their pools are non-removable in the editor, so no device is ever left without a
// pool, and thus without a lease.
func IsCatchAll(class string) bool {
	return class == ClassNameGGOOthers || class == ClassNameOthers
}

// ClassMetadata returns the display label, icon, and hardware codes for a Kea class.
func ClassMetadata(class string) (label, icon, codes string) {
	for _, dc := range DeviceClasses {
		if dc.Name == class {
			return dc.Label, dc.Icon, dc.Codes
		}
	}
	switch class {
	case ClassNameGGOOthers:
		return "Green-GO Other", "circle-help", ""
	case ClassNameOthers:
		return "Non Green-GO", "cpu", ""
	case "DANTE":
		return "Dante / AES67 Audio", "bridge", ""
	case "SACN":
		return "sACN / Art-Net Lighting", "cpu", ""
	default:
		return class, "cpu", ""
	}
}

// ouiMatch is the Kea expression fragment testing the Green-GO OUI.
const ouiMatch = "substring(hexstring(pkt4.mac, ''), 0, 6) == '" + greenGOOUI + "'"

// classPrefixExpr builds the device-type prefix fragment for one mapped class: the
// offset-6 substring test, OR-ed across the class's prefixes and parenthesized when
// there is more than one. It carries no OUI check - callers AND it with ouiMatch.
func classPrefixExpr(dc DeviceClass) string {
	var terms []string
	for _, p := range dc.Prefixes {
		terms = append(terms, fmt.Sprintf("substring(hexstring(pkt4.mac, ''), 6, %d) == '%s'", len(p), p))
	}
	if len(terms) == 1 {
		return terms[0]
	}
	return "(" + strings.Join(terms, " or ") + ")"
}

// classTest builds the Kea `test` expression for one mapped device class.
func classTest(dc DeviceClass) string {
	return ouiMatch + " and " + classPrefixExpr(dc)
}

// deviceClassByName returns the mapped DeviceClass for a Kea class name.
func deviceClassByName(name string) (DeviceClass, bool) {
	for _, dc := range DeviceClasses {
		if dc.Name == name {
			return dc, true
		}
	}
	return DeviceClass{}, false
}

// GGOOthersTest builds the SCOPE-RELATIVE GGO-OTHERS test: any Green-GO/ELC device
// whose model has no pool of its own in this scope. Excluding the pooled classes is
// what stops a classified device (a beltpack in a scope that has a GGO-BPX pool) from
// being a member of - and so sticking in - the catch-all while its own pool has room.
// A recognized type with NO pool here (an MCXD where only BPX is pooled) is not
// excluded and still lands in GGO-OTHERS. With no specific GGO pools the test degrades
// to the bare OUI match: every Green-GO device is a catch-all member.
func GGOOthersTest(pooled []DeviceClass) string {
	if len(pooled) == 0 {
		return ouiMatch
	}
	terms := make([]string, 0, len(pooled))
	for _, dc := range pooled {
		terms = append(terms, classPrefixExpr(dc))
	}
	return ouiMatch + " and not (" + strings.Join(terms, " or ") + ")"
}

// ClientClasses renders the GLOBAL ordered set of Kea client-classes: every mapped
// device band, then OTHERS (the non-Green-GO pool). The Green-GO catch-all GGO-OTHERS
// is NOT global - RenderProfile generates it PER SCOPE (GGO-OTHERS-<idx>) with a
// scope-relative test; see GGOOthersTest for why.
func ClientClasses() []ClientClassConfig {
	classes := make([]ClientClassConfig, 0, len(DeviceClasses)+1)
	for _, dc := range DeviceClasses {
		classes = append(classes, ClientClassConfig{Name: dc.Name, Test: classTest(dc)})
	}

	// OTHERS: the non-Green-GO pool, its test excluding the Green-GO/ELC OUI. A Green-GO
	// device is therefore NEVER a member, which is the whole point - one that ends up
	// here (an old lease whose address a range repack shifted into this pool) is NAKed
	// off and re-DISCOVERs into its own pool instead of clinging to the address forever
	// (proven on the box: while OTHERS was member('ALL') the device re-requested and was
	// re-granted its stale address). The tradeoff, chosen knowingly: a POOLED Green-GO
	// type whose own pool is FULL no longer overflows here, it is NAKed - a clear "grow
	// that pool" signal. Unpooled Green-GO types still never-NAK via the elastic
	// GGO-OTHERS pool. Ordered last (profile.go precedence).
	classes = append(classes, ClientClassConfig{
		Name: ClassNameOthers,
		Test: "not (" + ouiMatch + ")",
	})

	return classes
}

// ClassifyMAC maps a MAC string to its class name using the same table that
// drives the Kea client-classes, so leases/dashboard labels never disagree with
// what Kea actually matched.
func ClassifyMAC(mac string) string {
	mac = strings.ReplaceAll(strings.ToLower(mac), ":", "")
	if !strings.HasPrefix(mac, greenGOOUI) || len(mac) < 8 {
		return ClassNameOthers
	}
	low := mac[6:]
	for _, dc := range DeviceClasses {
		for _, p := range dc.Prefixes {
			if strings.HasPrefix(low, p) {
				return dc.Name
			}
		}
	}
	return ClassNameGGOOthers
}
