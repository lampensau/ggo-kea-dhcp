package web

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	"ggo-kea-dhcp/internal/kea"
	"ggo-kea-dhcp/internal/web/views"
)

// staticReserveSize is the default carved-out static-host reserve (.2–.19) that
// seeds a plan, matching the legacy firstDynamic=.20 start.
const staticReserveSize = 18

// flatPlan is the "Flat" size: no device-class pools, just a static reserve and
// one elastic catch-all that fills the subnet to the brink.
func flatPlan() PoolPlan {
	return PoolPlan{
		{Kind: PoolKindReserve, Name: "Static reserve", Count: staticReserveSize},
		{Kind: PoolKindElastic, Name: "All devices", Icon: "cpu", Weight: 1},
	}
}

// seedPlan derives a PoolPlan from a legacy scope (preset + counts) - the bridge
// that lets the active config and the wizard adopt the new per-pool model. A
// greengo scope seeds a static reserve, then the device classes in the
// operator-facing order (user stations, antennas, interfaces) as Fixed pools sized
// from their forecast counts, then the two catch-alls - the Green-GO Fixed pool
// and the single non-Green-GO Elastic backstop that takes the remainder (see
// TestSeedPlanGreengo). A single-pool preset seeds a static reserve plus one
// Elastic catch-all.
func seedPlan(sc ScopeConfig) PoolPlan {
	if sc.Preset != "greengo" {
		// Single-pool / flat / custom presets seed one elastic catch-all. (Custom's
		// user-defined vendor-classified islands are added via the editor; the
		// vendor classification engine lands in Phase 4.)
		label, icon := "Devices", "cpu"
		switch sc.Preset {
		case "dante":
			label, icon = "Dante / AES67", "speaker"
		case "sacn":
			label, icon = "sACN / Art-Net", "cpu"
		case "flat":
			label, icon = "Green-GO (flat)", "cpu"
		case "custom":
			label, icon = "General", "cpu"
		}
		return PoolPlan{
			{Kind: PoolKindReserve, Name: "Static reserve", Count: staticReserveSize},
			{Kind: PoolKindElastic, Name: label, Icon: icon, Weight: 1},
		}
	}
	counts := sc.Counts.Map()
	countFor := func(class string) int {
		for _, dc := range kea.DeviceClasses {
			if dc.Name == class {
				return counts[dc.CountKey]
			}
		}
		return 0
	}
	plan := PoolPlan{{Kind: PoolKindReserve, Name: "Static reserve", Count: staticReserveSize}}
	elastic := func(class string) {
		m := views.ClassDisplay(class)
		plan = append(plan, PoolPlanEntry{Kind: PoolKindElastic, Class: class, Name: m.Label, Icon: m.Icon, Weight: 1})
	}
	// fixed seeds a device-class pool only when it has a forecast count; empty (0)
	// types are omitted - the operator adds them deliberately via "+ Add pool". No
	// device strands: every unmatched device lands in a catch-all below.
	fixed := func(class string) {
		if countFor(class) <= 0 {
			return
		}
		m := views.ClassDisplay(class)
		plan = append(plan, PoolPlanEntry{Kind: PoolKindFixed, Class: class, Name: m.Label, Icon: m.Icon, Sizing: "auto", Count: countFor(class)})
	}
	// Operator-facing default order: user stations, then antennas, then interfaces,
	// then the catch-alls. This is the display + address-layout order and is
	// deliberately independent of kea.DeviceClasses (the MAC-prefix match list), so
	// the two can be tuned apart. Every device class (Beltpacks included) is a Fixed
	// pool sized from its forecast count; only the non-Green-GO backstop is Elastic.
	fixed("GGO-BPX")            // user stations: Beltpacks
	fixed("GGO-MCX-D")          //   Multi-channel
	fixed("GGO-MCD-MCR")        //   Desktop / rack
	fixed("GGO-WP-X")           //   Wall panels
	fixed("GGO-WAA")            // antennas: Active antennas
	fixed("GGO-STRIDE")         //   STRIDE antennas
	fixed("GGO-RDX-SI-BEACON")  //   Radio / SI / beacon
	fixed("GGO-INTERFACE-Q4WR") // interfaces: Interfaces
	fixed("GGO-BRIDGE-DANTEX")  //   Bridges / Dante
	fixed("GGO-SWITCH")         //   Managed switches (SW5/SW6/SW18GBX)
	// Two catch-alls, always present and non-removable (the unmatched-device safety
	// nets): GGO-OTHERS (Green-GO devices whose model has no pool in this scope) and
	// OTHERS (non-Green-GO backstop). BOTH are Elastic so they grow into the subnet
	// remainder; GGO-OTHERS is weighted heavier because in a Green-GO network the spare
	// capacity should favour unconfigured Green-GO gear - e.g. MCXDs plugged in later,
	// when only a BPX pool was set up, land here and need room to grow. (Was: a small
	// Fixed pool sized from the "Others" count, which capped that growth.)
	unk := views.ClassDisplay(kea.ClassNameGGOOthers)
	plan = append(plan, PoolPlanEntry{Kind: PoolKindElastic, Class: kea.ClassNameGGOOthers, Name: unk.Label, Icon: unk.Icon, Weight: 2})
	elastic(kea.ClassNameOthers)
	return plan
}

// ScopeConfig is the single canonical representation of one served subnet. It is
// what the setup wizard parses form data into, what is persisted to/loaded from
// the scopes table (its Counts marshal to pool_spec, its Uplink to uplink_json),
// and the source of the renderer input (ToRenderInput). It replaces the three
// near-parallel shapes (setupScope / scopeRow / dashboardScope) and the hand-built
// fmt.Sprintf JSON they round-tripped through.
type ScopeConfig struct {
	// Name is an optional operator-facing label (e.g. "Stage Left Intercom"). Empty
	// falls back to the derived "preset · VLAN" title. Persisted to scopes.name.
	Name   string       `json:"name,omitempty"`
	Preset string       `json:"preset"`
	VlanID int          `json:"vlan_id"`
	CIDR   string       `json:"cidr"`
	Counts DeviceCounts `json:"counts"`
	Uplink UplinkConfig `json:"uplink"`
	// Plan is the per-pool model (ordered Fixed/Elastic/Reserve) and the authoritative
	// source for rendering (ToRenderInput emits it as kea.PoolSpec). Persisted to
	// scopes.pool_plan; loadScopeConfigs seeds one for any legacy row that lacks it.
	Plan PoolPlan `json:"pool_plan,omitempty"`
	// MulticastSniff opts this scope into the passive monitor's promiscuous
	// duty-cycle (PTP/sACN/Green-GO multicast inspection). Default off - the
	// governor sheds it first under load. Persisted to scopes.multicast_sniff.
	MulticastSniff bool `json:"multicast_sniff"`
	// Services are the per-scope DHCP network services (explicit gateway/DNS, extra
	// options, lease-lifetime override). Persisted to scopes.services_json. All-zero
	// when unset, so a scope with no services renders exactly as before.
	Services ScopeServices `json:"services,omitzero"`
}

// ScopeServices is the per-scope DHCP network-services config, persisted as
// scopes.services_json. Gateway/DNS override the uplink-derived defaults; Options
// are free-form extra DHCP options (NTP, domain-name, ...) gated only by kea -t;
// LeaseLifetime overrides the global lease lifetime for this scope (0 = inherit).
type ScopeServices struct {
	Gateway       string        `json:"gateway,omitempty"`
	DNS           string        `json:"dns,omitempty"`
	LeaseLifetime int           `json:"lease_lifetime,omitempty"`
	Options       []ScopeOption `json:"options,omitempty"`
}

// ScopeOption is one extra DHCP option (Kea option name + data). Maps 1:1 to
// kea.OptionKV / the rendered option-data entry.
type ScopeOption struct {
	Name string `json:"name"`
	Data string `json:"data"`
}

// GlobalDHCPOptions are the site-wide DHCP option DEFAULTS (app_state
// global_dhcp_options) every served scope inherits unless it overrides them per-scope
// on /pools. Gateway is deliberately absent (it is per-subnet / isolation-critical),
// and lease lifetime has its own global setting; this carries the shareable bits -
// DNS plus a free-form option list (ntp-servers, domain-name, ...).
type GlobalDHCPOptions struct {
	DNS     string        `json:"dns,omitempty"`
	Options []ScopeOption `json:"options,omitempty"`
}

// keaOptions maps the global option rows to the renderer's OptionKV list.
func (g GlobalDHCPOptions) keaOptions() []kea.OptionKV {
	out := make([]kea.OptionKV, 0, len(g.Options))
	for _, o := range g.Options {
		out = append(out, kea.OptionKV{Name: o.Name, Data: o.Data})
	}
	return out
}

// parseScopeServices builds and validates a ScopeServices from raw form strings.
// It is the SINGLE parse path shared by the setup wizard and the /pools editor so
// the two surfaces can't drift. gateway/DNS are the only IP-validated fields; each
// option row is free-form (kea -t is the gate) and blank rows are dropped. optNames
// and optData are positional - row i pairs optNames[i] with optData[i].
func parseScopeServices(gateway, dns, lease string, optNames, optData []string) (ScopeServices, error) {
	var svc ScopeServices
	// IPv4-only (To4) is intentional: this is a DHCPv4 server (routers / domain-name-
	// servers are v4 options), so an IPv6 literal is correctly rejected, not a gap.
	if gateway = strings.TrimSpace(gateway); gateway != "" {
		if ip := net.ParseIP(gateway); ip == nil || ip.To4() == nil {
			return svc, fmt.Errorf("gateway %q is not a valid IPv4 address", gateway)
		}
		svc.Gateway = gateway
	}
	if dns = strings.TrimSpace(dns); dns != "" {
		parts := strings.Split(dns, ",")
		clean := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if ip := net.ParseIP(p); ip == nil || ip.To4() == nil {
				return svc, fmt.Errorf("DNS server %q is not a valid IPv4 address", p)
			}
			clean = append(clean, p)
		}
		svc.DNS = strings.Join(clean, ", ")
	}
	if lease = strings.TrimSpace(lease); lease != "" {
		n, err := strconv.Atoi(lease)
		if err != nil || n < 30 || n > 86400 {
			return svc, fmt.Errorf("lease lifetime must be a whole number of seconds between 30 and 86400")
		}
		svc.LeaseLifetime = n
	}
	for i, name := range optNames {
		name = strings.TrimSpace(name)
		var data string
		if i < len(optData) {
			data = strings.TrimSpace(optData[i])
		}
		if name == "" || data == "" {
			continue // drop blank/half-filled rows
		}
		svc.Options = append(svc.Options, ScopeOption{Name: name, Data: data})
	}
	return svc, nil
}

// PoolPlan is the persisted, ordered pool plan for a scope - the authoritative
// source for rendering under the per-pool model. Each entry is a Fixed pool (a set
// size, or auto-sized via SizeForClass when Sizing is "auto"), an Elastic pool
// (weighted remainder), or a Reserve (carved-out space, no DHCP pool). Order is
// significant: pools pack in list order. Persisted as JSON in scopes.pool_plan.
type PoolPlan []PoolPlanEntry

// Pool kinds (string-valued so the persisted JSON is self-describing).
const (
	PoolKindFixed   = "fixed"
	PoolKindElastic = "elastic"
	PoolKindReserve = "reserve"
)

// PoolPlanEntry is one pool in the plan. Class is the Kea client-class for a DHCP
// pool ("" for the catch-all or a Reserve). Sizing is "auto" (Fixed size derived from
// Count via SizeForClass = max(count, floor) - the Simple-mode default that tracks the
// device count) or "explicit" (Count/Range are exact - Advanced or an override).
// Vendors are MAC-OUI prefixes that classify devices into this pool (custom /
// non-Green-GO); Icon is the display glyph. Range, Vendors and Icon are carried
// here but consumed later (range overlay in the render rewire; vendors in Phase 4).
type PoolPlanEntry struct {
	Kind    string   `json:"kind"`
	Name    string   `json:"name,omitempty"`
	Class   string   `json:"class,omitempty"`
	Sizing  string   `json:"sizing,omitempty"` // "auto" | "explicit"
	Count   int      `json:"count,omitempty"`
	Range   string   `json:"range,omitempty"`
	Weight  int      `json:"weight,omitempty"`
	Vendors []string `json:"vendors,omitempty"`
	Icon    string   `json:"icon,omitempty"`
}

// ToSpecs maps the persisted plan to the renderer's allocator input. Fixed pools
// resolve their size (explicit Count, or kea.SizeForClass = max(count, floor) for
// "auto"); Elastic carries its weight; Reserve carries its Count as carved space.
// The result feeds kea.LayoutPools, which assigns ranges in order.
func (p PoolPlan) ToSpecs() []kea.PoolSpec {
	specs := make([]kea.PoolSpec, 0, len(p))
	for _, e := range p {
		switch e.Kind {
		case PoolKindElastic:
			specs = append(specs, kea.PoolSpec{Class: e.Class, Kind: kea.PoolElastic, Weight: max(e.Weight, 1), Range: e.Range, Vendors: e.Vendors})
		case PoolKindReserve:
			specs = append(specs, kea.PoolSpec{Kind: kea.PoolReserve, Size: e.Count, Range: e.Range})
		default: // fixed: auto = SizeForClass(count), explicit = exact size; Range pins it
			size := e.Count
			switch {
			case e.Sizing != "explicit":
				// Auto: max(count, floor) - WYSIWYG, no headroom multiplier.
				size = kea.SizeForClass(e.Class, e.Count)
			case kea.IsCatchAll(e.Class):
				// Explicit catch-all: honor the operator's size (so GGO-OTHERS can grow
				// past its floor), but never below the safety-net floor. Auto catch-alls
				// are pinned to the floor by SizeForClass; only an explicit size grows.
				size = max(e.Count, kea.FloorForClass(e.Class))
			}
			specs = append(specs, kea.PoolSpec{Class: e.Class, Kind: kea.PoolFixed, Size: size, Range: e.Range, Vendors: e.Vendors})
		}
	}
	return specs
}

// DeviceCounts is the per-device-class forecast persisted as scopes.pool_spec.
// The json tags are the wizard form field names and the on-disk keys, so the
// form, the DB, and kea pool sizing all agree.
type DeviceCounts struct {
	BPX       int `json:"count_bpx"`
	MCX       int `json:"count_mcx"`
	MCD       int `json:"count_mcd"`
	Interface int `json:"count_interface"`
	WPX       int `json:"count_wpx"`
	Bridge    int `json:"count_bridge"`
	WAA       int `json:"count_waa"`
	Beacon    int `json:"count_beacon"`
	Stride    int `json:"count_stride"`
	Switch    int `json:"count_switch"`
	Others    int `json:"count_others"`
	// Nodes is storage-only (a total-node estimate); it is NOT a device class
	// and is deliberately excluded from Map().
	Nodes int `json:"count_nodes"`
}

// Map returns the count map the renderer consumes. count_nodes is excluded
// because it is not a device-class key.
func (d DeviceCounts) Map() map[string]int {
	return map[string]int{
		"count_bpx": d.BPX, "count_mcx": d.MCX, "count_mcd": d.MCD,
		"count_interface": d.Interface, "count_wpx": d.WPX, "count_bridge": d.Bridge,
		"count_waa": d.WAA, "count_beacon": d.Beacon, "count_stride": d.Stride,
		"count_switch": d.Switch, "count_others": d.Others,
	}
}

// UplinkConfig is the per-scope uplink, persisted as scopes.uplink_json.
type UplinkConfig struct {
	Enabled  bool   `json:"enabled"`
	SSID     string `json:"ssid"`
	Password string `json:"password"`
}

// ToRenderInput maps a ScopeConfig to the DB-agnostic renderer input. The Plan is
// the authoritative kea.PoolSpec list; loadScopeConfigs and the wizard always seed
// one, so the renderer is purely plan-driven.
func (sc ScopeConfig) ToRenderInput() kea.ScopeInput {
	opts := make([]kea.OptionKV, 0, len(sc.Services.Options))
	for _, o := range sc.Services.Options {
		opts = append(opts, kea.OptionKV{Name: o.Name, Data: o.Data})
	}
	return kea.ScopeInput{
		VlanID:        sc.VlanID,
		CIDR:          sc.CIDR,
		PoolPlan:      sc.Plan.ToSpecs(),
		Uplink:        sc.Uplink.Enabled,
		Gateway:       sc.Services.Gateway,
		DNS:           sc.Services.DNS,
		LeaseLifetime: sc.Services.LeaseLifetime,
		Options:       opts,
	}
}

// planJSON marshals the pool plan for the scopes.pool_plan column. An empty plan
// renders as "" (NULL semantics → the legacy preset/counts path renders the scope).
func (sc ScopeConfig) planJSON() (string, error) {
	if len(sc.Plan) == 0 {
		return "", nil
	}
	b, err := json.Marshal(sc.Plan)
	if err != nil {
		return "", fmt.Errorf("marshal pool_plan: %w", err)
	}
	return string(b), nil
}

// poolSpecJSON / uplinkJSON marshal the two JSON columns. Errors are surfaced so
// a persist failure is never silent (the old fmt.Sprintf path could not fail but
// also could not escape).
func (sc ScopeConfig) poolSpecJSON() (string, error) {
	b, err := json.Marshal(sc.Counts)
	if err != nil {
		return "", fmt.Errorf("marshal pool_spec: %w", err)
	}
	return string(b), nil
}

func (sc ScopeConfig) uplinkJSON() (string, error) {
	b, err := json.Marshal(sc.Uplink)
	if err != nil {
		return "", fmt.Errorf("marshal uplink_json: %w", err)
	}
	return string(b), nil
}

// servicesJSON marshals the per-scope network services for scopes.services_json.
// An all-zero ScopeServices renders as "" (NULL) so untouched scopes stay clean.
func (sc ScopeConfig) servicesJSON() (string, error) {
	if sc.Services.Gateway == "" && sc.Services.DNS == "" &&
		sc.Services.LeaseLifetime == 0 && len(sc.Services.Options) == 0 {
		return "", nil
	}
	b, err := json.Marshal(sc.Services)
	if err != nil {
		return "", fmt.Errorf("marshal services_json: %w", err)
	}
	return string(b), nil
}

// loadScopeConfigs returns the scopes for profileID (or the active profile when
// 0), decoding pool_spec and uplink_json into typed fields with checked errors.
// It is the single scope loader shared by the reconciler and the dashboard.
func (s *Server) loadScopeConfigs(profileID int) ([]ScopeConfig, error) {
	if profileID == 0 {
		err := s.sqlite.QueryRow("SELECT id FROM profiles WHERE active = 1 LIMIT 1").Scan(&profileID)
		if err == sql.ErrNoRows {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
	}

	rows, err := s.sqlite.Query("SELECT preset, vlan_id, cidr, pool_spec, uplink_json, pool_plan, multicast_sniff, services_json, name FROM scopes WHERE profile_id = ? ORDER BY id", profileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ScopeConfig
	for rows.Next() {
		var sc ScopeConfig
		var vlan sql.NullInt64
		var poolSpec, uplinkJSON, poolPlan, servicesJSON, name sql.NullString
		var multicastSniff sql.NullInt64
		if e := rows.Scan(&sc.Preset, &vlan, &sc.CIDR, &poolSpec, &uplinkJSON, &poolPlan, &multicastSniff, &servicesJSON, &name); e != nil {
			return nil, e
		}
		sc.Name = name.String
		sc.MulticastSniff = multicastSniff.Valid && multicastSniff.Int64 != 0
		if vlan.Valid {
			sc.VlanID = int(vlan.Int64)
		}
		if poolPlan.Valid && poolPlan.String != "" {
			if e := json.Unmarshal([]byte(poolPlan.String), &sc.Plan); e != nil {
				log.Printf("[scopes] malformed pool_plan for scope %q - reseeding from counts: %v", sc.CIDR, e)
				sc.Plan = nil
			}
		}
		// Malformed JSON in a single scope degrades that one field (logged loudly)
		// rather than failing the whole load - one corrupt row must not take a
		// reconcile or the dashboard down for the profile's other valid scopes.
		if poolSpec.Valid && poolSpec.String != "" {
			if e := json.Unmarshal([]byte(poolSpec.String), &sc.Counts); e != nil {
				log.Printf("[scopes] malformed pool_spec for scope %q - using empty counts: %v", sc.CIDR, e)
				sc.Counts = DeviceCounts{}
			}
		}
		if uplinkJSON.Valid && uplinkJSON.String != "" {
			if e := json.Unmarshal([]byte(uplinkJSON.String), &sc.Uplink); e != nil {
				log.Printf("[scopes] malformed uplink_json for scope %q - uplink disabled: %v", sc.CIDR, e)
				sc.Uplink = UplinkConfig{}
			}
		}
		if servicesJSON.Valid && servicesJSON.String != "" {
			if e := json.Unmarshal([]byte(servicesJSON.String), &sc.Services); e != nil {
				log.Printf("[scopes] malformed services_json for scope %q - no extra services: %v", sc.CIDR, e)
				sc.Services = ScopeServices{}
			}
		}
		// Every scope must carry a Plan (the single render path). A legacy row with
		// no pool_plan is seeded from its stored counts here, so the dashboard and
		// reconciler are uniformly plan-driven and never hit a legacy branch.
		if len(sc.Plan) == 0 {
			sc.Plan = seedDefaultPlan(sc)
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// PresetLabel returns the unified human-readable label for a preset.
func PresetLabel(preset string) string {
	switch preset {
	case "greengo":
		return "Green-GO Intercom"
	case "flat":
		return "Green-GO Flat"
	case "dante":
		return "Dante / AES67 Audio"
	case "sacn":
		return "sACN / Art-Net Lighting"
	case "custom":
		return "Custom"
	default:
		return "Generic / Management"
	}
}
