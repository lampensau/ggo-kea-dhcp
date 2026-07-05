package kea

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	localdns "ggo-kea-dhcp/internal/dns"
)

// harness_kea_profile_test.go: verification tests for onboardingSubnet (the new
// too-small guard + pool-range arithmetic) and RenderProfile JSON-validity under
// adversarial string inputs (quotes/backslashes) and host-bits-set CIDRs.

// assertPoolRangeValid checks a "start - end" pool range is non-inverted (first<=last)
// and lies entirely within the usable host span of subnetCIDR.
func assertPoolRangeValid(t *testing.T, subnetCIDR, poolRange string) {
	t.Helper()
	lo, hi, ok := ParsePoolRange(poolRange)
	if !ok {
		t.Fatalf("pool range %q does not parse", poolRange)
	}
	if lo > hi {
		t.Fatalf("pool range %q is inverted (first > last)", poolRange)
	}
	_, ipnet, err := net.ParseCIDR(subnetCIDR)
	if err != nil {
		t.Fatalf("bad subnet %q: %v", subnetCIDR, err)
	}
	ulo, uhi, ok := subnetUsableBounds(ipnet)
	if !ok {
		t.Fatalf("subnet %q has no usable bounds", subnetCIDR)
	}
	if lo < ulo || hi > uhi {
		t.Fatalf("pool range %q (%#x-%#x) escapes usable subnet bounds %#x-%#x", poolRange, lo, hi, ulo, uhi)
	}
}

// TestOnboardingSubnetNormal covers the common /24: a .100-.250 pool inside a
// canonicalized subnet base.
func TestOnboardingSubnetNormal(t *testing.T) {
	sub, err := onboardingSubnet(1, "10.0.0.1/24")
	if err != nil {
		t.Fatalf("onboardingSubnet /24: %v", err)
	}
	if sub.Subnet != "10.0.0.0/24" {
		t.Errorf("subnet base = %q, want canonical 10.0.0.0/24", sub.Subnet)
	}
	if len(sub.Pools) != 1 || sub.Pools[0].Range != "10.0.0.100 - 10.0.0.250" {
		t.Fatalf("pool = %+v, want [10.0.0.100 - 10.0.0.250]", sub.Pools)
	}
	assertPoolRangeValid(t, sub.Subnet, sub.Pools[0].Range)
	// Onboarding subnets advertise no gateway/DNS (captive-portal avoidance).
	if sub.Gateway != "" || sub.DNS != "" {
		t.Errorf("onboarding subnet must not set gateway/DNS, got gw=%q dns=%q", sub.Gateway, sub.DNS)
	}
}

// TestOnboardingSubnetClampsToSmallSubnet covers a /30 - the smallest subnet
// the guard still allows. The .100-.250 offsets are clamped down to a single-address
// pool at network+2, and that range must be valid (first<=last, in-subnet).
func TestOnboardingSubnetClampsToSmallSubnet(t *testing.T) {
	sub, err := onboardingSubnet(1, "10.0.0.1/30")
	if err != nil {
		t.Fatalf("onboardingSubnet /30: %v", err)
	}
	if sub.Subnet != "10.0.0.0/30" {
		t.Errorf("subnet base = %q, want 10.0.0.0/30", sub.Subnet)
	}
	if len(sub.Pools) != 1 || sub.Pools[0].Range != "10.0.0.2 - 10.0.0.2" {
		t.Fatalf("/30 clamped pool = %+v, want single-addr [10.0.0.2 - 10.0.0.2]", sub.Pools)
	}
	assertPoolRangeValid(t, sub.Subnet, sub.Pools[0].Range)

	// /29 also clamps but to a wider window; just assert validity (no inverted range).
	sub29, err := onboardingSubnet(1, "10.0.0.1/29")
	if err != nil {
		t.Fatalf("onboardingSubnet /29: %v", err)
	}
	assertPoolRangeValid(t, sub29.Subnet, sub29.Pools[0].Range)
}

// TestOnboardingSubnetTooSmallRejected pins the new guard: a /31 and /32 have
// no room for a usable pool (the offset math would invert to first>last), so they
// must return an error instead of an invalid Kea range.
func TestOnboardingSubnetTooSmallRejected(t *testing.T) {
	for _, cidr := range []string{"10.0.0.1/31", "10.0.0.1/32"} {
		if _, err := onboardingSubnet(1, cidr); err == nil {
			t.Errorf("onboardingSubnet(%q) = nil error, want too-small rejection", cidr)
		}
	}
}

// TestOnboardingSubnetBadInput covers the parse/non-IPv4 error arms.
func TestOnboardingSubnetBadInput(t *testing.T) {
	if _, err := onboardingSubnet(1, "not-a-cidr"); err == nil {
		t.Error("expected an error for an unparseable CIDR")
	}
	if _, err := onboardingSubnet(1, "fe80::1/64"); err == nil {
		t.Error("expected an error for a non-IPv4 CIDR")
	}
}

// TestRenderOnboardingTooSmallPropagates proves RenderOnboarding surfaces the
// onboardingSubnet too-small error rather than swallowing it (the eth path).
func TestRenderOnboardingTooSmallPropagates(t *testing.T) {
	if _, _, err := RenderOnboarding(OnboardingInput{EthCIDR: "10.0.0.1/31", KeaSecretPath: "/etc/kea/gui-secret"}); err == nil {
		t.Error("RenderOnboarding with a /31 eth CIDR should error")
	}
}

// TestRenderProfileEscapesAdversarialStrings is the JSON-injection guard: a
// MariaDB password, a DNS string, and a DHCP option value all containing quotes and
// backslashes must produce VALID JSON that round-trips to the exact bytes - proving
// the struct-marshal render path (not string templating) escapes them correctly.
func TestRenderProfileEscapesAdversarialStrings(t *testing.T) {
	const nastyPass = `p"a\s's"\\w0rd` + "\t\n"
	const nastyOpt = `dom"ain\with"slash`
	in := ProfileRenderInput{
		KeaSecretPath: `/etc/kea/gui"secret\path`,
		MariaDBHost:   "127.0.0.1",
		MariaDBUser:   "kea",
		MariaDBPass:   nastyPass,
		MariaDBName:   "kea",
		LeaseLifetime: 1800,
		Scopes: []ScopeInput{{
			CIDR:     "10.0.0.0/24",
			PoolPlan: []PoolSpec{{Kind: PoolElastic, Weight: 1}},
			Options:  []OptionKV{{Name: "domain-name", Data: nastyOpt}},
		}},
	}
	cfg, _, err := RenderProfile(in)
	if err != nil {
		t.Fatalf("RenderProfile: %v", err)
	}
	var js map[string]any
	if err := json.Unmarshal([]byte(cfg), &js); err != nil {
		t.Fatalf("rendered config is not valid JSON with quote/backslash inputs: %v\n%s", err, cfg)
	}
	dhcp4 := js["Dhcp4"].(map[string]any)
	hdb, ok := dhcp4["hosts-database"].(map[string]any)
	if !ok {
		t.Fatal("hosts-database missing despite MariaDB host set")
	}
	if hdb["password"] != nastyPass {
		t.Errorf("password did not round-trip: got %q want %q", hdb["password"], nastyPass)
	}
	// The option value must also survive escaping somewhere in the subnet's options.
	if !strings.Contains(cfg, "domain-name") {
		t.Error("domain-name option missing from rendered config")
	}
}

// TestRenderProfileMasksHostBitsInSubnet pins the canonicalization fix: an
// operator CIDR with host bits set (10.0.0.1/23) must emit the MASKED base
// (10.0.0.0/23) in subnet4 so the declaration agrees with the pool base, while the
// pool itself stays inside the subnet.
func TestRenderProfileMasksHostBitsInSubnet(t *testing.T) {
	cfg, _, err := RenderProfile(ProfileRenderInput{
		KeaSecretPath: "/etc/kea/gui-secret",
		LeaseLifetime: 1800,
		Scopes: []ScopeInput{{
			CIDR:     "10.0.0.1/23", // host bits set
			PoolPlan: []PoolSpec{{Kind: PoolElastic, Weight: 1}},
		}},
	})
	if err != nil {
		t.Fatalf("RenderProfile: %v", err)
	}
	var js map[string]any
	if err := json.Unmarshal([]byte(cfg), &js); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	sub := js["Dhcp4"].(map[string]any)["subnet4"].([]any)[0].(map[string]any)
	if sub["subnet"] != "10.0.0.0/23" {
		t.Errorf("subnet = %q, want masked 10.0.0.0/23", sub["subnet"])
	}
	pools := sub["pools"].([]any)
	if len(pools) == 0 {
		t.Fatal("no pools emitted")
	}
	rng := pools[0].(map[string]any)["pool"].(string)
	assertPoolRangeValid(t, "10.0.0.0/23", rng)
}

// TestRenderProfileNoPoolPlanRejected pins the "every scope must carry a
// seeded plan" contract.
func TestRenderProfileNoPoolPlanRejected(t *testing.T) {
	if _, _, err := RenderProfile(ProfileRenderInput{
		KeaSecretPath: "/etc/kea/gui-secret",
		Scopes:        []ScopeInput{{CIDR: "10.0.0.0/24"}},
	}); err == nil {
		t.Error("expected an error for a scope with no pool plan")
	}
}

// TestRenderProfileInvalidCIDRRejected pins the per-scope CIDR parse arm.
func TestRenderProfileInvalidCIDRRejected(t *testing.T) {
	if _, _, err := RenderProfile(ProfileRenderInput{
		KeaSecretPath: "/etc/kea/gui-secret",
		Scopes:        []ScopeInput{{CIDR: "garbage", PoolPlan: []PoolSpec{{Kind: PoolElastic, Weight: 1}}}},
	}); err == nil {
		t.Error("expected an error for an unparseable scope CIDR")
	}
}

// TestRenderProfileGatewayInPoolBoundary complements the diff's added test by
// checking the pool BOUNDARY: the gateway at exactly the pool's first/last address is
// rejected, and an address one below the pool start is accepted.
func TestRenderProfileGatewayInPoolBoundary(t *testing.T) {
	// A reserve carves .2..19; the elastic pool then runs .20..254. Gateway at .20
	// (the pool's first address) must be rejected.
	base := ProfileRenderInput{
		KeaSecretPath: "/etc/kea/gui-secret",
		LeaseLifetime: 1800,
		Scopes: []ScopeInput{{
			CIDR: "10.0.0.0/24",
			PoolPlan: []PoolSpec{
				{Kind: PoolReserve, Size: 18},
				{Class: "GGO-BPX", Kind: PoolElastic, Weight: 1},
			},
		}},
	}
	base.Scopes[0].Gateway = "10.0.0.20" // pool's first address
	if _, _, err := RenderProfile(base); err == nil {
		t.Error("gateway at the pool's first address must be rejected")
	}
	base.Scopes[0].Gateway = "10.0.0.254" // pool's last address
	if _, _, err := RenderProfile(base); err == nil {
		t.Error("gateway at the pool's last address must be rejected")
	}
	// A gateway inside the static reserve (.2..19, not a DHCP pool) is fine.
	base.Scopes[0].Gateway = "10.0.0.5"
	if _, _, err := RenderProfile(base); err != nil {
		t.Errorf("gateway inside the static reserve must be accepted, got: %v", err)
	}
}

// TestRenderProfileLocalDNSHandout pins the per-scope local-DNS opt-in: the scope
// hands out the box's own per-scope address as domain-name-servers (the same
// derived .1 as the uplink gateway self-reference) plus a domain-search listing
// both device suffixes; an explicit DNS override or an operator domain-search
// still wins.
func TestRenderProfileLocalDNSHandout(t *testing.T) {
	render := func(sc ScopeInput) map[string]string {
		t.Helper()
		cfg, _, err := RenderProfile(ProfileRenderInput{
			KeaSecretPath: "/etc/kea/gui-secret",
			LeaseLifetime: 1800,
			GlobalDNS:     "9.9.9.9",
			Scopes:        []ScopeInput{sc},
		})
		if err != nil {
			t.Fatalf("RenderProfile: %v", err)
		}
		var js struct {
			Dhcp4 struct {
				Subnet4 []struct {
					OptionData []struct{ Name, Data string } `json:"option-data"`
				} `json:"subnet4"`
			}
		}
		if err := json.Unmarshal([]byte(cfg), &js); err != nil {
			t.Fatalf("rendered config not JSON: %v", err)
		}
		opts := map[string]string{}
		for _, o := range js.Dhcp4.Subnet4[0].OptionData {
			opts[o.Name] = o.Data
		}
		return opts
	}
	plan := []PoolSpec{{Kind: PoolElastic, Weight: 1}}

	opts := render(ScopeInput{CIDR: "10.20.0.0/24", VlanID: 20, PoolPlan: plan, LocalDNS: true})
	if opts["domain-name-servers"] != "10.20.0.1" {
		t.Errorf("local-DNS scope hands out %q, want the box's own 10.20.0.1", opts["domain-name-servers"])
	}
	if want := localdns.SuffixInv + ", " + localdns.SuffixDHCP; opts["domain-search"] != want {
		t.Errorf("domain-search = %q, want %q", opts["domain-search"], want)
	}

	// An explicit per-scope DNS override wins over the self-reference (the same
	// precedence as the gateway); the domain-search still rides the opt-in.
	opts = render(ScopeInput{CIDR: "10.20.0.0/24", PoolPlan: plan, LocalDNS: true, DNS: "1.1.1.1"})
	if opts["domain-name-servers"] != "1.1.1.1" {
		t.Errorf("explicit DNS override lost to the self-reference: %q", opts["domain-name-servers"])
	}

	// An operator-set domain-search is left untouched.
	opts = render(ScopeInput{CIDR: "10.20.0.0/24", PoolPlan: plan, LocalDNS: true,
		Options: []OptionKV{{Name: "domain-search", Data: "venue.example"}}})
	if opts["domain-search"] != "venue.example" {
		t.Errorf("operator domain-search overwritten: %q", opts["domain-search"])
	}

	// Opt-out: the global DNS default flows through and no domain-search appears.
	opts = render(ScopeInput{CIDR: "10.20.0.0/24", PoolPlan: plan})
	if opts["domain-name-servers"] != "9.9.9.9" {
		t.Errorf("opt-out scope hands out %q, want the global 9.9.9.9", opts["domain-name-servers"])
	}
	if _, has := opts["domain-search"]; has {
		t.Error("opt-out scope must not hand out a domain-search")
	}
}
