package kea

import (
	"fmt"
	"strings"
)

// DeviceClass is a single Green-GO device-type band. It is the SINGLE source of
// truth for (a) the Kea client-class `test` expressions, (b) lease/dashboard
// classification, and (c) elastic pool sizing. PRD §16 / D7: this table must be
// maintainable in one place rather than re-implemented per call site.
//
// Prefixes are matched at offset 6 of hexstring(pkt4.mac,”) - i.e. the low-24
// device-type nibble that follows the `001f80` OUI. BPX is matched on 2 hex
// digits ("20") because its serial blocks span 0x200xxx–0x202xxx; every other
// type is matched on 3 digits.
type DeviceClass struct {
	Name     string   // Kea class name, e.g. "GGO-BPX"
	CountKey string   // wizard/pool_spec key, e.g. "count_bpx"
	Prefixes []string // hexstring offset-6 prefixes (length 2 or 3)
	Label    string   // operator-facing name, e.g. "Beltpacks"
	Icon     string   // display icon key, e.g. "bpx"
	Codes    string   // hardware codes, e.g. "BPX / BP2"
}

// DeviceClasses lists the mapped Green-GO bands in canonical order.
// GGO-OTHERS (any Green-GO device without its own pool) and OTHERS (non-Green-GO /
// universal backstop) are catch-alls handled by ClientClasses/ClassifyMAC and are
// intentionally not in this slice. (Pool sizing is WYSIWYG via SizeForClass - the old
// per-class "headroom" multiplier is gone from the live path; see layout.go.)
// Order here is the canonical display order everywhere (Add-pool menu, wizard
// device grid, dashboard breakdown): beltpacks first, then the rack/panel gear,
// then the RF/antenna family, then interfaces and bridges, switches last.
//
// Prefixes are the manufacturer's 0x1000 MAC blocks per the vendor's allocation
// table - each 3-hex prefix is exactly one allocated block base. We carry ONLY
// allocated blocks; speculative
// "high" guesses (22d/21d/23d/21e/222) were removed as they map to no real device.
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
	// ClassNameGGOOthers: the single Green-GO catch-all - ANY Green-GO/ELC device not
	// served by a specific model pool, whether genuinely unclassified (unmapped
	// prefix) or a recognized type with no pool of its own (e.g. a STRIDE when no
	// STRIDE pool is configured).
	ClassNameGGOOthers = "GGO-OTHERS"
	// ClassNameOthers: the NON-Green-GO pool. Its test excludes the Green-GO OUI, so a
	// Green-GO device is never a member - that exclusivity is what lets a mis-placed
	// Green-GO device migrate out instead of clinging to an OTHERS-pool address.
	ClassNameOthers = "OTHERS"
	CountKeyOthers  = "count_others"
)

// IsCatchAll reports whether a class is one of the unmatched-device safety nets:
// GGO-OTHERS (any Green-GO device without its own pool) or OTHERS (non-Green-GO /
// universal backstop). Their pools are non-removable in the editor so no device is
// ever left without a pool (and thus a lease).
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

// classPrefixExpr builds the device-type prefix fragment for one mapped class
// (the offset-6 substring test, OR-ed across the class's prefixes and parenthesized
// when there is more than one). It carries no OUI check - callers AND it with
// ouiMatch. Reused by both classTest and the scope-relative GGO-OTHERS test.
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
// whose model is NOT one of the device classes that already has its own pool in this
// scope. Excluding the pooled classes is what stops a classified device (e.g. a
// beltpack in a scope that has a GGO-BPX pool) from being a member of - and therefore
// sticking in - the catch-all pool when its own pool has room. A recognized type with
// NO pool here (e.g. an MCXD when only a BPX pool is configured) is NOT excluded, so it
// still falls into GGO-OTHERS as intended. With no specific GGO pools the test degrades
// to the bare OUI match (every Green-GO device is a catch-all member).
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
// is NOT global - it is generated PER SCOPE in RenderProfile (GGO-OTHERS-<idx>) with a
// scope-relative test (see GGOOthersTest) so a classified device is not a member of the
// catch-all pool in a scope that already pools its type. This replaces the literals
// previously inlined in the wizard and server render paths.
func ClientClasses() []ClientClassConfig {
	classes := make([]ClientClassConfig, 0, len(DeviceClasses)+1)
	for _, dc := range DeviceClasses {
		classes = append(classes, ClientClassConfig{Name: dc.Name, Test: classTest(dc)})
	}

	// OTHERS: the NON-Green-GO pool (test excludes the Green-GO/ELC OUI). A Green-GO
	// device is therefore NEVER a member of OTHERS - which is the whole point: a
	// Green-GO device that ends up here (e.g. an old lease whose address a range repack
	// shifted into this pool) is NAKed off it and re-DISCOVERs into its own pool,
	// instead of clinging to the address forever (proven on the box: while OTHERS was
	// member('ALL') the device re-requested and was re-granted its stale address). The
	// tradeoff, chosen knowingly: a POOLED Green-GO type whose own pool is FULL no
	// longer overflows here - it is NAKed (a clear "grow that pool" signal). Unpooled
	// Green-GO types still never-NAK via the elastic GGO-OTHERS pool; non-Green-GO
	// devices are OTHERS' occupants. Ordered last (profile.go precedence).
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
