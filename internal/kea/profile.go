package kea

import (
	"fmt"
	"net"
	"sort"
	"strings"

	localdns "ggo-kea-dhcp/internal/dns"
)

// ScopeInput is the DB-agnostic description of one served subnet. The web layer
// builds these from SQLite scope rows (or wizard form data) so this package
// never needs to know about the database.
type ScopeInput struct {
	VlanID int    // 0 = untagged on eth0; otherwise eth0.<vid>
	CIDR   string // e.g. "10.0.0.0/23"
	// PoolPlan is the authoritative ordered pool plan, rendered via LayoutPools.
	// Required: RenderProfile rejects a scope without one.
	PoolPlan []PoolSpec
	Uplink   bool // hand out the DERIVED gateway + DNS fallback when true
	// Gateway/DNS are explicit per-scope overrides (routers / domain-name-servers) and
	// win regardless of Uplink, so a wired-uplink or local-resolver scope can hand them
	// out without the WiFi uplink. Empty falls back to the Uplink-driven defaults.
	Gateway string
	DNS     string
	// LocalDNS opts the scope into the appliance's own name service: the box's per-scope
	// address as domain-name-servers (an explicit DNS override still wins) plus a
	// domain-search over both device suffixes, so a bare `ping <name>` resolves via either.
	LocalDNS bool
	// LeaseLifetime overrides the profile-global lease lifetime for this scope (0 =
	// inherit). Options are extra DHCP options (NTP, domain-name, ...) for this scope.
	LeaseLifetime int
	Options       []OptionKV
}

// defaultLeaseLifetime is the active-profile lease lifetime (seconds) when none is
// configured. ~30 min keeps the T1 change-latency (see leaseTimers) reasonable while still
// letting devices ride through a Kea restart and staying gentle on the SD card; override
// via --lease-lifetime. Onboarding uses onboardingLeaseLifetime instead.
const defaultLeaseLifetime = 1800

// onboardingLeaseLifetime is the SHORT lease (seconds) the transient onboarding config hands
// out. After a setup-apply re-IPs the box, the operator's device drops its old lease - and
// the now-stale default gateway it carried - at T1 (~45s) and re-DHCPs into the new subnet,
// so the reconnect interstitial lands quickly rather than waiting out Kea's 2h default (the
// cause of the lingering-gateway / slow-reconnect behaviour).
const onboardingLeaseLifetime = 90

// leaseTimers derives (valid, renew, rebind) from a lease lifetime in seconds using the
// conventional T1 = 1/2 and T2 = 7/8 of the lifetime. A non-positive lifetime falls back
// to the default.
//
// T1, not the lifetime, is the latency of every change that only lands on renewal, because a
// device re-DHCPs then: adopting a freshly-created host reservation, or migrating into its
// correct device-class pool after a class/pool change (its old, now-disallowed lease is NAKed).
func leaseTimers(lifetime int) (valid, renew, rebind int) {
	if lifetime <= 0 {
		lifetime = defaultLeaseLifetime
	}
	return lifetime, lifetime / 2, lifetime * 7 / 8
}

// ProfileRenderInput is the full input to RenderProfile.
type ProfileRenderInput struct {
	Scopes        []ScopeInput
	MariaDBHost   string
	MariaDBUser   string
	MariaDBPass   string
	MariaDBName   string
	KeaSecretPath string
	// GlobalDNS and GlobalOptions are the site-wide DHCP option DEFAULTS (from
	// /settings) every scope inherits unless it sets its own. They apply to ALL scopes
	// (DNS/NTP/etc. are harmless on an isolated scope - the PRD-D5/D8 isolation rule is
	// about not advertising a dead GATEWAY, and gateway has no global default).
	GlobalDNS     string
	GlobalOptions []OptionKV
	// LeaseLifetime is the active-profile lease lifetime in seconds; 0 uses the default.
	// renew/rebind are derived (leaseTimers).
	LeaseLifetime int
	Debug         bool
	// IfaceWildcard renders interfaces-config as ["*"] instead of the per-scope
	// eth0/eth0.<vid> list, for the pre-commit kea-dhcp4 -t validation in beginApply: a
	// VLAN scope's eth0.<vid> does not exist until finishApply's reconcile creates it, so
	// validating the real list first would fail "interface doesn't exist". "*" checks the
	// subnets/pools/options without them; writeAndReloadKea does the authoritative
	// per-interface validation once they are up.
	IfaceWildcard bool
}

// mergeOptions overlays a scope's options onto the global defaults: a scope option
// with the same name REPLACES the matching global one (per-scope wins); the rest of
// the globals are kept and scope-only options are appended. Name match is
// case-insensitive. Returns the globals untouched when the scope adds nothing.
func mergeOptions(global, scope []OptionKV) []OptionKV {
	if len(global) == 0 {
		return scope
	}
	out := make([]OptionKV, 0, len(global)+len(scope))
	used := map[string]bool{}
	for _, g := range global {
		pick := g
		for _, s := range scope {
			if strings.EqualFold(s.Name, g.Name) {
				pick = s
				used[strings.ToLower(s.Name)] = true
				break
			}
		}
		out = append(out, pick)
	}
	for _, s := range scope {
		if !used[strings.ToLower(s.Name)] {
			out = append(out, s)
		}
	}
	return out
}

// hasOption reports whether the merged option list already carries name.
func hasOption(opts []OptionKV, name string) bool {
	for _, o := range opts {
		if strings.EqualFold(o.Name, name) {
			return true
		}
	}
	return false
}

// rankScopePools orders one scope's placements into Kea pools by client-class match
// precedence and returns the generated client classes the caller must register (vendor
// pools and the per-scope GGO-OTHERS get generated names). Kea picks the first pool
// whose client-class a device belongs to, so a non-Green-GO device (which also matches
// the broad OTHERS catch-all) must hit its vendor pool first, and where prefixes overlap
// the longer (more specific) prefix wins. Precedence keys off the PLAN class (p.Class),
// not the rendered name, so the generated renames don't break ordering. Ranges are
// per-pool, so this reorder is precedence-only and never changes which addresses a pool
// serves. idx is the scope index (for the generated class names); pooledGGO is the set
// of Green-GO classes that have their own pool in this scope (the GGO-OTHERS exclusion).
func rankScopePools(placements []PoolPlacement, plan []PoolSpec, idx int, pooledGGO []DeviceClass) (pools []PoolConfig, classes []ClientClassConfig) {
	type ranked struct {
		pc   PoolConfig
		prec int
	}
	var rps []ranked
	for i, p := range placements {
		if p.Kind == PoolReserve || p.Range == "" {
			continue
		}
		renderedClass := p.Class
		prec := 100 // specific, non-conflicting (Green-GO device classes, etc.)
		switch {
		case i < len(plan) && VendorClassTest(plan[i].Vendors) != "":
			renderedClass = fmt.Sprintf("VENDOR-%d-%d", idx, i)
			classes = append(classes, ClientClassConfig{Name: renderedClass, Test: VendorClassTest(plan[i].Vendors)})
			prec = 10 + maxOUILen(plan[i].Vendors) // longer prefix → earlier
		case p.Class == ClassNameOthers:
			prec = 0 // non-Green-GO pool (not 001f80) → strictly last
		case p.Class == ClassNameGGOOthers:
			// Per-scope Green-GO catch-all: Green-GO devices whose model has no pool in
			// this scope. Generated here (not global) so the exclusion set is the scope's
			// own pooled classes.
			renderedClass = fmt.Sprintf("%s-%d", ClassNameGGOOthers, idx)
			classes = append(classes, ClientClassConfig{Name: renderedClass, Test: GGOOthersTest(pooledGGO)})
			prec = 1 // after model pools, before OTHERS
		}
		rps = append(rps, ranked{PoolConfig{ClientClass: renderedClass, Range: p.Range}, prec})
	}
	sort.SliceStable(rps, func(a, b int) bool { return rps[a].prec > rps[b].prec })
	for _, r := range rps {
		pools = append(pools, r.pc)
	}
	return pools, classes
}

// RenderProfile is the SINGLE render path for an active profile, used by both the
// wizard apply and the boot/converge reconciler. DNS and extra options come from a
// per-scope override or the site-wide global defaults; the GATEWAY is the isolation-
// critical one - per-scope override or the uplink-derived .1, never global - so an
// isolated scope still advertises no default route (PRD D5/D8).
func RenderProfile(in ProfileRenderInput) (configStr string, ifaces []string, err error) {
	var subnets []SubnetConfig
	// Per-pool vendor classes generated from custom pools' OUIs, appended to the built-in
	// Green-GO classes. One pool with OUIs yields one client-class OR-matching them, and
	// guards that pool. Devices match by OUI, so a vendor pool must be ordered BEFORE the
	// OTHERS catch-all for its devices to prefer it.
	var vendorClasses []ClientClassConfig

	for idx, sc := range in.Scopes {
		iface := "eth0"
		if sc.VlanID != 0 {
			iface = fmt.Sprintf("eth0.%d", sc.VlanID)
		}
		ifaces = append(ifaces, iface)

		_, ipnet, perr := net.ParseCIDR(sc.CIDR)
		if perr != nil {
			return "", nil, fmt.Errorf("scope %d: invalid CIDR %q: %w", idx, sc.CIDR, perr)
		}
		gatewayIP := IncIP(ipnet.IP, 1)

		if len(sc.PoolPlan) == 0 {
			return "", nil, fmt.Errorf("scope %d (%s): no pool plan (every scope must carry a seeded plan)", idx, sc.CIDR)
		}
		// The persisted pool plan is authoritative. LayoutPools honors pinned ranges
		// and packs the rest; Reserve entries occupy space but emit no DHCP pool.
		placements, lerr := LayoutPools(sc.CIDR, sc.PoolPlan)
		if lerr != nil {
			return "", nil, fmt.Errorf("scope %d (%s): %w", idx, sc.CIDR, lerr)
		}
		// The Green-GO device classes with their OWN pool in THIS scope: exactly the set
		// the scope's catch-all excludes (see GGOOthersTest).
		var pooledGGO []DeviceClass
		for _, p := range placements {
			if p.Kind == PoolReserve || p.Range == "" {
				continue
			}
			if dc, ok := deviceClassByName(p.Class); ok {
				pooledGGO = append(pooledGGO, dc)
			}
		}

		// A per-scope gateway override must not fall inside a DHCP pool: Kea would
		// advertise it as the router AND remain free to lease it to a client - an
		// on-wire conflict with the real gateway. (The box's own gateway is
		// network+1, which is never in a pool: pools start at network+2.)
		if sc.Gateway != "" {
			if gw := net.ParseIP(sc.Gateway).To4(); gw != nil {
				gwU := IPToUint32(gw)
				for _, p := range placements {
					if p.Kind == PoolReserve || p.Range == "" {
						continue
					}
					if lo, hi, ok := ParsePoolRange(p.Range); ok && gwU >= lo && gwU <= hi {
						return "", nil, fmt.Errorf("scope %d (%s): gateway %s falls inside DHCP pool %s - move it out of the pool (e.g. into the static reserve)", idx, sc.CIDR, sc.Gateway, p.Range)
					}
				}
			}
		}

		pools, scopeClasses := rankScopePools(placements, sc.PoolPlan, idx, pooledGGO)
		vendorClasses = append(vendorClasses, scopeClasses...)

		// DNS + extra options: a per-scope explicit value wins, then the local-DNS
		// self-reference (the box's own per-scope address, mirroring the uplink gateway's
		// derived .1), then the site-wide global default. Gateway has no global default -
		// per-scope override, else the uplink-derived .1, else nothing (the PRD-D5/D8
		// isolation rule: never advertise a dead default route).
		dns := sc.DNS
		switch {
		case dns != "":
		case sc.LocalDNS:
			dns = gatewayIP.String()
		default:
			dns = in.GlobalDNS
		}
		opts := mergeOptions(in.GlobalOptions, sc.Options)
		// The local-DNS handout also carries a domain-search over both device
		// suffixes; an explicit per-scope or global domain-search wins untouched.
		if sc.LocalDNS && !hasOption(opts, "domain-search") {
			opts = append(opts, OptionKV{Name: "domain-search", Data: localdns.SuffixInv + ", " + localdns.SuffixDHCP})
		}
		sub := SubnetConfig{
			// Emit the canonical masked form (ipnet.String()), not the raw operator
			// CIDR: a "10.0.0.1/23" with host bits set would otherwise make the
			// subnet4 declaration disagree with the masked base the pools are computed
			// against. Matches onboardingSubnet.
			ID: idx + 1, Subnet: ipnet.String(), Pools: pools,
			LeaseLifetime: sc.LeaseLifetime,
			DNS:           dns,
			Options:       opts,
		}
		switch {
		case sc.Gateway != "":
			sub.Gateway = sc.Gateway
		case sc.Uplink:
			sub.Gateway = gatewayIP.String()
		}
		subnets = append(subnets, sub)
	}

	valid, renew, rebind := leaseTimers(in.LeaseLifetime)
	// Only the rendered list becomes "*" (see IfaceWildcard); the returned ifaces stay
	// the real per-scope list, which the caller still uses to set the interfaces up.
	renderIfaces := ifaces
	if in.IfaceWildcard {
		renderIfaces = []string{"*"}
	}
	data := TemplateData{
		Interfaces:    renderIfaces,
		MariaDBHost:   in.MariaDBHost,
		MariaDBUser:   in.MariaDBUser,
		MariaDBPass:   in.MariaDBPass,
		MariaDBName:   in.MariaDBName,
		PortPinning:   true,
		KeaSecretPath: in.KeaSecretPath,
		ClientClasses: append(ClientClasses(), vendorClasses...),
		Subnets:       subnets,
		ValidLifetime: valid,
		RenewTimer:    renew,
		RebindTimer:   rebind,
		Debug:         in.Debug,
	}

	configStr, err = RenderConfig(data)
	if err != nil {
		return "", nil, err
	}
	return configStr, ifaces, nil
}

// OnboardingInput describes the ungrouped dynamic onboarding scopes.
type OnboardingInput struct {
	EthCIDR       string // management IP/CIDR for eth0, e.g. "10.0.0.1/24"; "" skips eth0
	WlanIP        string // SoftAP IP for wlan0, e.g. "172.31.255.1"; "" skips wlan0 (/24 assumed)
	KeaSecretPath string
	Debug         bool
}

// RenderOnboarding renders the tiny dynamic onboarding configuration. Each served
// interface hands out a dynamic lease only - no default gateway or DNS (onboardingSubnet)
// - so connected clients keep their own internet and the OS captive-portal assistant is
// not triggered. The operator reaches the box on its own same-subnet address.
func RenderOnboarding(in OnboardingInput) (configStr string, ifaces []string, err error) {
	var subnets []SubnetConfig

	if in.EthCIDR != "" {
		sub, serr := onboardingSubnet(len(subnets)+1, in.EthCIDR)
		if serr != nil {
			return "", nil, serr
		}
		ifaces = append(ifaces, "eth0")
		subnets = append(subnets, sub)
	}
	if in.WlanIP != "" {
		sub, serr := onboardingSubnet(len(subnets)+1, in.WlanIP+"/24")
		if serr != nil {
			return "", nil, serr
		}
		ifaces = append(ifaces, "wlan0")
		subnets = append(subnets, sub)
	}
	if len(ifaces) == 0 {
		// Fallback so the daemon still has a valid config (e.g. minimal container).
		sub, _ := onboardingSubnet(1, "10.0.0.1/24")
		ifaces = []string{"eth0"}
		subnets = []SubnetConfig{sub}
	}

	// Onboarding is intentionally memfile-only: with no MariaDB fields, RenderConfig omits
	// the hosts-database and MySQL hooks. eth0 DHCP must come up for the operator to reach
	// the box, and cannot depend on MariaDB being ready (only dynamic leases are served).
	valid, renew, rebind := leaseTimers(onboardingLeaseLifetime)
	data := TemplateData{
		Interfaces:    ifaces,
		PortPinning:   false,
		KeaSecretPath: in.KeaSecretPath,
		Subnets:       subnets,
		ValidLifetime: valid,
		RenewTimer:    renew,
		RebindTimer:   rebind,
		Debug:         in.Debug,
	}

	configStr, err = RenderConfig(data)
	if err != nil {
		return "", nil, err
	}
	return configStr, ifaces, nil
}

// HoldoffInput renders the DHCP stand-down (holdoff) config: Kea keeps running
// with its control socket up but serves NO subnet, so it stops answering DHCP
// entirely. Used when the operator stands DHCP down after a rogue server is
// detected - keeping the daemon reachable means health stays green (no false
// "Kea down") and resume is a plain config reload, not a service restart.
type HoldoffInput struct {
	Interfaces    []string // the served interfaces to bind (informational; no subnet is served)
	KeaSecretPath string
	Debug         bool
}

// RenderHoldoff renders the holdoff config: a valid kea-dhcp4 config with an
// empty subnet4 list, so the daemon runs and answers its control socket but
// serves no address on any interface.
func RenderHoldoff(in HoldoffInput) (string, error) {
	ifaces := in.Interfaces
	if len(ifaces) == 0 {
		ifaces = []string{"eth0"}
	}
	// No MariaDB fields and no subnets: RenderConfig omits the hosts-database and
	// the host hooks, and buildSubnets yields an empty (never null) subnet4 array.
	return RenderConfig(TemplateData{
		Interfaces:    ifaces,
		KeaSecretPath: in.KeaSecretPath,
		Debug:         in.Debug,
	})
}

// onboardingSubnet derives a dynamic onboarding subnet from a host CIDR
// (e.g. "10.0.0.1/24") with a .100-.250 pool clamped to the subnet size. It hands out NO
// default gateway or DNS: clients only need the box's own same-subnet address, and
// advertising the box as gateway/DNS made connected PCs route their internet through an
// uplink-less box and tripped the OS captive-portal assistant (which then looped on the
// self-signed cert). See reconcileOnboarding.
func onboardingSubnet(id int, hostCIDR string) (SubnetConfig, error) {
	ip, ipnet, err := net.ParseCIDR(hostCIDR)
	if err != nil {
		return SubnetConfig{}, fmt.Errorf("invalid onboarding CIDR %q: %w", hostCIDR, err)
	}
	hostIP := ip.To4()
	if hostIP == nil {
		return SubnetConfig{}, fmt.Errorf("onboarding CIDR %q is not IPv4", hostCIDR)
	}
	maskSize, _ := ipnet.Mask.Size()
	totalIPs := 1 << (32 - maskSize)
	// A /31 or /32 has no room for a usable pool (network + broadcast leave nothing),
	// and the offset math below would invert to first>last (an invalid Kea range).
	if totalIPs < 4 {
		return SubnetConfig{}, fmt.Errorf("onboarding CIDR %q is too small for a DHCP pool (need /30 or larger)", hostCIDR)
	}

	firstOff, lastOff := 100, 250
	if lastOff > totalIPs-2 {
		lastOff = totalIPs - 2
	}
	if firstOff >= lastOff {
		firstOff = totalIPs / 2
		if firstOff < 2 {
			firstOff = 2
		}
	}

	first := IncIP(ipnet.IP, firstOff).String()
	last := IncIP(ipnet.IP, lastOff).String()

	return SubnetConfig{
		ID:     id,
		Subnet: ipnet.String(),
		// No Gateway/DNS on purpose - see the doc comment. The renderer omits the
		// routers/domain-name-servers options when these are empty.
		Pools: []PoolConfig{{Range: fmt.Sprintf("%s - %s", first, last)}},
	}, nil
}
