package kea

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRenderConfig(t *testing.T) {
	data := TemplateData{
		Interfaces:    []string{"eth0", "eth0.10"},
		MariaDBHost:   "localhost",
		MariaDBUser:   "kea_user",
		MariaDBPass:   "vertas",
		MariaDBName:   "kea",
		HooksDir:      "/usr/lib/kea/hooks/",
		PortPinning:   true,
		KeaSecretPath: "/etc/kea/gui/gui-secret",
		ClientClasses: []ClientClassConfig{
			{Name: "GGO-BPX", Test: "substring(mac) == '001f80'"},
			{Name: "OTHERS", Test: "not member('GGO-BPX')"},
		},
		Subnets: []SubnetConfig{
			{
				ID:      1,
				Subnet:  "10.0.0.0/24",
				Gateway: "10.0.0.1",
				DNS:     "1.1.1.1, 8.8.8.8",
				Pools: []PoolConfig{
					{Range: "10.0.0.10 - 10.0.0.250", ClientClass: "GGO-BPX"},
				},
			},
		},
	}

	configStr, err := RenderConfig(data)
	if err != nil {
		t.Fatalf("RenderConfig failed: %v", err)
	}

	// Verify the result is valid JSON
	var js map[string]any
	if err := json.Unmarshal([]byte(configStr), &js); err != nil {
		t.Fatalf("Rendered config is not valid JSON: %v\nConfig content:\n%s", err, configStr)
	}

	// Verify some fields
	dhcp4, ok := js["Dhcp4"].(map[string]any)
	if !ok {
		t.Fatal("Missing Dhcp4 block in config")
	}

	ifaces, ok := dhcp4["interfaces-config"].(map[string]any)["interfaces"].([]any)
	if !ok || len(ifaces) != 2 || ifaces[0] != "eth0" {
		t.Errorf("Interfaces block rendered incorrectly: %+v", dhcp4["interfaces-config"])
	}

	classes, ok := dhcp4["client-classes"].([]any)
	if !ok || len(classes) != 2 {
		t.Errorf("Client classes block rendered incorrectly: %+v", dhcp4["client-classes"])
	}

	subnets, ok := dhcp4["subnet4"].([]any)
	if !ok || len(subnets) != 1 {
		t.Fatalf("Subnets block rendered incorrectly: %+v", dhcp4["subnet4"])
	}

	sub := subnets[0].(map[string]any)
	if sub["subnet"] != "10.0.0.0/24" {
		t.Errorf("Subnet CIDR rendered incorrectly: %s", sub["subnet"])
	}
}

// TestBuildHooksFlexIDExpression locks in the port-pinning flex-id expression: it
// must join the Option-82 remote-id (relay4[2]) and circuit-id (relay4[1]) with a
// 0x1f delimiter so the UI can split them, and guard with ifelse so a direct client
// gets no phantom flex-id. When port pinning is off, flex_id must not be loaded.
func TestBuildHooksFlexIDExpression(t *testing.T) {
	hooks := buildHooks("/usr/lib/kea/hooks/", true, true)
	var flex *hookLibrary
	for i := range hooks {
		if strings.HasSuffix(hooks[i].Library, "libdhcp_flex_id.so") {
			flex = &hooks[i]
			break
		}
	}
	if flex == nil {
		t.Fatal("flex_id hook not present when port pinning is enabled")
	}
	expr, _ := flex.Parameters["identifier-expression"].(string)
	want := "ifelse(relay4[1].exists or relay4[2].exists, relay4[2].hex + 0x1f + relay4[1].hex, '')"
	if expr != want {
		t.Errorf("flex-id expression = %q, want %q", expr, want)
	}
	if flex.Parameters["replace-client-id"] != true {
		t.Errorf("replace-client-id = %v, want true", flex.Parameters["replace-client-id"])
	}

	for _, h := range buildHooks("/usr/lib/kea/hooks/", false, true) {
		if strings.HasSuffix(h.Library, "libdhcp_flex_id.so") {
			t.Error("flex_id hook must not be loaded when port pinning is disabled")
		}
	}
}

// TestBuildHooksDBGating locks in that the MySQL host backend hooks load only when a
// DB is configured (hasDB), while the memfile lease/stat hooks always load. This is
// what lets the onboarding config run without MariaDB present.
func TestBuildHooksDBGating(t *testing.T) {
	has := func(hooks []hookLibrary, lib string) bool {
		for _, h := range hooks {
			if strings.HasSuffix(h.Library, lib) {
				return true
			}
		}
		return false
	}

	withDB := buildHooks("/usr/lib/kea/hooks/", false, true)
	if !has(withDB, "libdhcp_mysql.so") || !has(withDB, "libdhcp_host_cmds.so") {
		t.Error("DB hooks (mysql + host_cmds) must load when hasDB=true")
	}

	noDB := buildHooks("/usr/lib/kea/hooks/", false, false)
	if has(noDB, "libdhcp_mysql.so") || has(noDB, "libdhcp_host_cmds.so") {
		t.Error("DB hooks must NOT load when hasDB=false (onboarding path)")
	}
	if !has(noDB, "libdhcp_lease_cmds.so") || !has(noDB, "libdhcp_stat_cmds.so") {
		t.Error("lease/stat hooks must always load regardless of hasDB")
	}
}

// TestRenderConfig_EscapesSpecialChars verifies the marshalled-struct renderer
// produces valid JSON even when a value contains characters that would have
// broken the old hand-built text/template (a double-quote and a backslash in the
// MariaDB password), and that the value round-trips intact.
func TestRenderConfig_EscapesSpecialChars(t *testing.T) {
	const nasty = `p"a\ss`
	data := TemplateData{
		Interfaces:    []string{"eth0"},
		MariaDBHost:   "localhost", // a host must be set for the backend to be emitted
		MariaDBPass:   nasty,
		MariaDBName:   "kea",
		KeaSecretPath: "/etc/kea/gui-secret",
		HooksDir:      "/usr/lib/kea/hooks/",
	}

	configStr, err := RenderConfig(data)
	if err != nil {
		t.Fatalf("RenderConfig failed: %v", err)
	}

	var cfg struct {
		Dhcp4 struct {
			HostsDatabase struct {
				Password       string `json:"password"`
				RetryOnStartup bool   `json:"retry-on-startup"`
				OnFail         string `json:"on-fail"`
			} `json:"hosts-database"`
		} `json:"Dhcp4"`
	}
	if err := json.Unmarshal([]byte(configStr), &cfg); err != nil {
		t.Fatalf("rendered config not valid JSON with special chars: %v\n%s", err, configStr)
	}
	if cfg.Dhcp4.HostsDatabase.Password != nasty {
		t.Errorf("password did not round-trip: got %q want %q", cfg.Dhcp4.HostsDatabase.Password, nasty)
	}
	// The backend must carry the resilience knobs so a down/slow MariaDB degrades
	// (Kea serves dynamic leases + retries) instead of the default fatal exit.
	if !cfg.Dhcp4.HostsDatabase.RetryOnStartup || cfg.Dhcp4.HostsDatabase.OnFail != "serve-retry-continue" {
		t.Errorf("hosts-database missing resilience knobs: retry-on-startup=%v on-fail=%q",
			cfg.Dhcp4.HostsDatabase.RetryOnStartup, cfg.Dhcp4.HostsDatabase.OnFail)
	}
}

// TestRenderProfile_GlobalDNSGatewayIsolation verifies the merged model: the global
// DNS default reaches EVERY scope (DNS is harmless when isolated), while the gateway
// is the isolation-critical option - only an uplink scope advertises the derived .1,
// so an isolated scope still gets no default route (PRD D5/D8).
func TestRenderProfile_GlobalDNSGatewayIsolation(t *testing.T) {
	in := ProfileRenderInput{
		KeaSecretPath: "/etc/kea/gui-secret",
		GlobalDNS:     "1.1.1.1",
		Scopes: []ScopeInput{
			{VlanID: 0, CIDR: "10.0.0.0/24", Uplink: false, PoolPlan: []PoolSpec{{Kind: PoolElastic, Weight: 1}}},
			{VlanID: 20, CIDR: "10.20.0.0/24", Uplink: true, PoolPlan: []PoolSpec{{Kind: PoolElastic, Weight: 1}}},
		},
	}
	configStr, ifaces, err := RenderProfile(in)
	if err != nil {
		t.Fatalf("RenderProfile failed: %v", err)
	}
	if len(ifaces) != 2 || ifaces[0] != "eth0" || ifaces[1] != "eth0.20" {
		t.Errorf("unexpected ifaces: %v", ifaces)
	}

	var js map[string]any
	if err := json.Unmarshal([]byte(configStr), &js); err != nil {
		t.Fatalf("rendered config not valid JSON: %v\n%s", err, configStr)
	}
	subnets := js["Dhcp4"].(map[string]any)["subnet4"].([]any)

	optNames := func(sub any) []string {
		var names []string
		for _, o := range sub.(map[string]any)["option-data"].([]any) {
			names = append(names, o.(map[string]any)["name"].(string))
		}
		return names
	}
	// Isolated: DNS (global) but NO routers.
	if got := optNames(subnets[0]); len(got) != 1 || got[0] != "domain-name-servers" {
		t.Errorf("isolated scope: want only domain-name-servers, got %v", got)
	}
	// Uplink: routers (derived) + DNS (global).
	if got := optNames(subnets[1]); len(got) != 2 || got[0] != "routers" || got[1] != "domain-name-servers" {
		t.Errorf("uplink scope: want routers + domain-name-servers, got %v", got)
	}
}

// TestMergeOptions checks per-scope options overlay onto the global defaults: a same
// name replaces, others append, and an empty global returns the scope list as-is.
func TestMergeOptions(t *testing.T) {
	global := []OptionKV{{Name: "ntp-servers", Data: "10.0.0.1"}, {Name: "domain-name", Data: "site.local"}}
	scope := []OptionKV{{Name: "NTP-Servers", Data: "10.9.9.9"}, {Name: "tftp-server-name", Data: "10.0.0.2"}}
	got := mergeOptions(global, scope)
	want := []OptionKV{
		{Name: "NTP-Servers", Data: "10.9.9.9"}, // scope overrides global (case-insensitive)
		{Name: "domain-name", Data: "site.local"},
		{Name: "tftp-server-name", Data: "10.0.0.2"}, // scope-only appended
	}
	if len(got) != len(want) {
		t.Fatalf("want %d merged options, got %d: %v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("merged[%d]: want %v, got %v", i, want[i], got[i])
		}
	}
	if got := mergeOptions(nil, scope); len(got) != 2 {
		t.Errorf("empty global should return scope as-is, got %v", got)
	}
}

// TestRenderProfile_ScopeServices verifies the per-scope network services: an
// explicit gateway/DNS renders even with the uplink OFF, extra options (ntp-servers,
// domain-search) are appended after routers/DNS, and a lease-lifetime override emits
// subnet-level timers while a scope without one inherits the global (no subnet timers).
func TestRenderProfile_ScopeServices(t *testing.T) {
	in := ProfileRenderInput{
		KeaSecretPath: "/etc/kea/gui-secret",
		LeaseLifetime: 1800,
		Scopes: []ScopeInput{
			{ // explicit gateway/DNS + options + lease override, uplink OFF.
				// Gateway .1 sits outside the elastic pool (network+2 .. broadcast-1);
				// an in-pool gateway is now correctly rejected by RenderProfile.
				VlanID: 0, CIDR: "10.0.0.0/24", Uplink: false,
				Gateway: "10.0.0.1", DNS: "10.0.0.53, 10.0.0.54",
				LeaseLifetime: 600,
				Options:       []OptionKV{{Name: "ntp-servers", Data: "10.0.0.1"}, {Name: "domain-search", Data: "intercom.local"}},
				PoolPlan:      []PoolSpec{{Kind: PoolElastic, Weight: 1}},
			},
			{ // no services at all - inherits global timers, no options
				VlanID: 20, CIDR: "10.20.0.0/24", Uplink: false,
				PoolPlan: []PoolSpec{{Kind: PoolElastic, Weight: 1}},
			},
		},
	}
	configStr, _, err := RenderProfile(in)
	if err != nil {
		t.Fatalf("RenderProfile failed: %v", err)
	}
	var js map[string]any
	if err := json.Unmarshal([]byte(configStr), &js); err != nil {
		t.Fatalf("rendered config not valid JSON: %v\n%s", err, configStr)
	}
	subnets := js["Dhcp4"].(map[string]any)["subnet4"].([]any)

	s0 := subnets[0].(map[string]any)
	opts := s0["option-data"].([]any)
	// routers, domain-name-servers, ntp-servers, domain-search - in that order.
	want := []struct{ name, data string }{
		{"routers", "10.0.0.1"},
		{"domain-name-servers", "10.0.0.53, 10.0.0.54"},
		{"ntp-servers", "10.0.0.1"},
		{"domain-search", "intercom.local"},
	}
	if len(opts) != len(want) {
		t.Fatalf("scope 0: want %d options, got %d: %v", len(want), len(opts), opts)
	}
	for i, w := range want {
		o := opts[i].(map[string]any)
		if o["name"] != w.name || o["data"] != w.data {
			t.Errorf("scope 0 option %d: want %s=%q, got %v", i, w.name, w.data, o)
		}
	}
	if v := s0["valid-lifetime"]; v != float64(600) {
		t.Errorf("scope 0: want subnet valid-lifetime 600, got %v", v)
	}
	if v := s0["renew-timer"]; v != float64(300) {
		t.Errorf("scope 0: want subnet renew-timer 300, got %v", v)
	}

	s1 := subnets[1].(map[string]any)
	if len(s1["option-data"].([]any)) != 0 {
		t.Errorf("scope 1: want no options, got %v", s1["option-data"])
	}
	if _, ok := s1["valid-lifetime"]; ok {
		t.Errorf("scope 1: must inherit global timers (no subnet valid-lifetime), got %v", s1["valid-lifetime"])
	}
}

// TestRenderProfile_VendorPoolClass verifies a custom pool carrying vendor OUIs
// renders a generated client-class (OUI-OR test) that the pool is guarded by, so
// only those devices land in it.
func TestRenderProfile_VendorPoolClass(t *testing.T) {
	in := ProfileRenderInput{
		KeaSecretPath: "/etc/kea/gui-secret",
		Scopes: []ScopeInput{{
			VlanID: 0, CIDR: "10.0.0.0/24",
			PoolPlan: []PoolSpec{
				{Kind: PoolFixed, Size: 30, Vendors: []string{"00:1d:c1", "e44f29"}}, // Dante + MA
				{Kind: PoolElastic, Weight: 1, Class: "OTHERS"},
			},
		}},
	}
	configStr, _, err := RenderProfile(in)
	if err != nil {
		t.Fatalf("RenderProfile: %v", err)
	}
	var js map[string]any
	if err := json.Unmarshal([]byte(configStr), &js); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	dhcp := js["Dhcp4"].(map[string]any)
	// The generated vendor class exists with the OUI-OR test.
	var found map[string]any
	for _, c := range dhcp["client-classes"].([]any) {
		cc := c.(map[string]any)
		if cc["name"] == "VENDOR-0-0" {
			found = cc
		}
	}
	if found == nil {
		t.Fatalf("generated vendor class VENDOR-0-0 missing: %v", dhcp["client-classes"])
	}
	test, _ := found["test"].(string)
	if !strings.Contains(test, "001dc1") || !strings.Contains(test, "e44f29") || !strings.Contains(test, " or ") {
		t.Errorf("vendor class test should OR-match both OUIs, got: %q", test)
	}
	// The pool is guarded by the generated class, OR the built-in KNOWN class so a
	// host-reserved client can take its reserved address from any pool regardless of
	// device class (reservations override the per-class guards).
	pools := dhcp["subnet4"].([]any)[0].(map[string]any)["pools"].([]any)
	cc := pools[0].(map[string]any)["client-classes"].([]any)
	if cc[0] != "VENDOR-0-0" {
		t.Errorf("vendor pool not guarded by its class, got: %v", pools[0])
	}
	if len(cc) != 2 || cc[1] != "KNOWN" {
		t.Errorf("guarded pool should also allow KNOWN (reservation override), got client-classes: %v", cc)
	}
}

// TestRenderProfile_VendorPrecedence verifies the rendered pools are ordered most-
// specific-first: a longer OUI prefix beats a shorter overlapping one, and both
// vendor pools beat the broad OTHERS catch-all - regardless of plan order. Kea
// picks the first matching pool, so this is what makes the specific match win.
func TestRenderProfile_VendorPrecedence(t *testing.T) {
	in := ProfileRenderInput{
		KeaSecretPath: "/etc/kea/gui-secret",
		Scopes: []ScopeInput{{
			VlanID: 0, CIDR: "10.0.0.0/24",
			// Deliberately WORST plan order: catch-all first, then short prefix, then
			// the long (most specific) one - the render must invert this.
			PoolPlan: []PoolSpec{
				{Kind: PoolElastic, Weight: 1, Class: "OTHERS"},
				{Kind: PoolFixed, Size: 20, Vendors: []string{"0050c2"}},    // 6-hex parent
				{Kind: PoolFixed, Size: 20, Vendors: []string{"0050c2145"}}, // 9-hex child (ELC)
			},
		}},
	}
	configStr, _, err := RenderProfile(in)
	if err != nil {
		t.Fatalf("RenderProfile: %v", err)
	}
	var js map[string]any
	_ = json.Unmarshal([]byte(configStr), &js)
	pools := js["Dhcp4"].(map[string]any)["subnet4"].([]any)[0].(map[string]any)["pools"].([]any)
	order := make([]string, len(pools))
	for i, p := range pools {
		if cc, ok := p.(map[string]any)["client-classes"].([]any); ok && len(cc) > 0 {
			order[i] = cc[0].(string)
		}
	}
	// VENDOR-0-2 is the 9-hex pool (plan index 2); VENDOR-0-1 the 6-hex; OTHERS last.
	want := []string{"VENDOR-0-2", "VENDOR-0-1", "OTHERS"}
	for i, w := range want {
		if i >= len(order) || order[i] != w {
			t.Fatalf("pool order = %v, want most-specific-first %v", order, want)
		}
	}
}

// TestRenderProfile_GGOOthersScopeRelative verifies the catch-all is generated per
// scope and EXCLUDES the device classes that have their own pool there: a beltpack
// (prefix 20, with a GGO-BPX pool) must NOT be a member of the scope's GGO-OTHERS
// class (so it can't stick in the catch-all pool), while the class still matches any
// other Green-GO device. The bare global "GGO-OTHERS" class must no longer be emitted.
func TestRenderProfile_GGOOthersScopeRelative(t *testing.T) {
	in := ProfileRenderInput{
		KeaSecretPath: "/etc/kea/gui-secret",
		Scopes: []ScopeInput{{
			VlanID: 0, CIDR: "10.0.0.0/24",
			PoolPlan: []PoolSpec{
				{Kind: PoolFixed, Size: 30, Class: "GGO-BPX"},
				{Kind: PoolElastic, Weight: 1, Class: ClassNameGGOOthers},
				{Kind: PoolElastic, Weight: 1, Class: ClassNameOthers},
			},
		}},
	}
	configStr, _, err := RenderProfile(in)
	if err != nil {
		t.Fatalf("RenderProfile: %v", err)
	}
	var js map[string]any
	if err := json.Unmarshal([]byte(configStr), &js); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	dhcp := js["Dhcp4"].(map[string]any)

	var ggoOthersTest string
	for _, c := range dhcp["client-classes"].([]any) {
		cc := c.(map[string]any)
		name := cc["name"].(string)
		if name == ClassNameGGOOthers {
			t.Errorf("bare global %q class should no longer be emitted (now per-scope)", ClassNameGGOOthers)
		}
		if name == "GGO-OTHERS-0" {
			ggoOthersTest = cc["test"].(string)
		}
	}
	if ggoOthersTest == "" {
		t.Fatalf("per-scope GGO-OTHERS-0 class missing: %v", dhcp["client-classes"])
	}
	// OTHERS must be non-Green-GO (excludes the OUI), NOT member('ALL'), so a Green-GO
	// device is never a member and can migrate out of the OTHERS pool.
	for _, c := range dhcp["client-classes"].([]any) {
		cc := c.(map[string]any)
		if cc["name"] == ClassNameOthers {
			test := cc["test"].(string)
			if test != "not (substring(hexstring(pkt4.mac, ''), 0, 6) == '001f80')" {
				t.Errorf("OTHERS test should be non-Green-GO, got: %q", test)
			}
		}
	}
	// Must be the OUI match AND-NOT the beltpack prefix, so a beltpack is excluded.
	if !strings.Contains(ggoOthersTest, "001f80") ||
		!strings.Contains(ggoOthersTest, "and not (") ||
		!strings.Contains(ggoOthersTest, "== '20'") {
		t.Errorf("GGO-OTHERS-0 test should exclude the pooled BPX prefix, got: %q", ggoOthersTest)
	}

	// The catch-all pool is guarded by the per-scope class (plus KNOWN), not the bare name.
	pools := dhcp["subnet4"].([]any)[0].(map[string]any)["pools"].([]any)
	var found bool
	for _, p := range pools {
		cc, _ := p.(map[string]any)["client-classes"].([]any)
		if len(cc) > 0 && cc[0] == "GGO-OTHERS-0" {
			found = true
			if len(cc) != 2 || cc[1] != "KNOWN" {
				t.Errorf("catch-all pool should allow KNOWN, got: %v", cc)
			}
		}
	}
	if !found {
		t.Errorf("no pool guarded by GGO-OTHERS-0; pools=%v", pools)
	}
}

// TestRenderProfile_LeaseTimers verifies the active profile emits lease timers derived
// from LeaseLifetime (default when unset, renew=1/2, rebind=7/8) while the transient
// onboarding config leaves them unset (Kea defaults).
func TestRenderProfile_LeaseTimers(t *testing.T) {
	check := func(in int, wantValid, wantRenew, wantRebind int) {
		active, _, err := RenderProfile(ProfileRenderInput{
			KeaSecretPath: "/etc/kea/gui-secret",
			LeaseLifetime: in,
			Scopes:        []ScopeInput{{CIDR: "10.0.0.0/24", PoolPlan: []PoolSpec{{Kind: PoolElastic, Weight: 1}}}},
		})
		if err != nil {
			t.Fatalf("RenderProfile: %v", err)
		}
		var aj map[string]any
		if err := json.Unmarshal([]byte(active), &aj); err != nil {
			t.Fatalf("active not valid JSON: %v", err)
		}
		d := aj["Dhcp4"].(map[string]any)
		if d["valid-lifetime"] != float64(wantValid) || d["renew-timer"] != float64(wantRenew) || d["rebind-timer"] != float64(wantRebind) {
			t.Errorf("LeaseLifetime=%d: timers valid=%v renew=%v rebind=%v, want %d/%d/%d",
				in, d["valid-lifetime"], d["renew-timer"], d["rebind-timer"], wantValid, wantRenew, wantRebind)
		}
	}
	check(0, defaultLeaseLifetime, defaultLeaseLifetime/2, defaultLeaseLifetime*7/8) // unset → default 1800/900/1575
	check(30, 30, 15, 26)                                                            // testing value

	onb, _, err := RenderOnboarding(OnboardingInput{EthCIDR: "10.0.0.1/24", KeaSecretPath: "/etc/kea/gui-secret"})
	if err != nil {
		t.Fatalf("RenderOnboarding: %v", err)
	}
	var oj map[string]any
	_ = json.Unmarshal([]byte(onb), &oj)
	od := oj["Dhcp4"].(map[string]any)
	// Onboarding hands out a SHORT lease so the operator's device renews quickly into the
	// new subnet after a setup-apply re-IP (dropping the stale gateway) rather than clinging
	// to Kea's 2h default - see onboardingLeaseLifetime.
	if od["valid-lifetime"] != float64(onboardingLeaseLifetime) {
		t.Errorf("onboarding valid-lifetime = %v, want short %d", od["valid-lifetime"], onboardingLeaseLifetime)
	}
	// Onboarding must be memfile-only: no MariaDB backend, so eth0 DHCP comes up
	// regardless of MariaDB state (otherwise a down/uninitialized DB bricks onboarding).
	if _, ok := od["hosts-database"]; ok {
		t.Error("onboarding config must NOT contain a hosts-database (would couple eth0 DHCP to MariaDB)")
	}
	if strings.Contains(onb, "libdhcp_mysql.so") || strings.Contains(onb, "libdhcp_host_cmds.so") {
		t.Error("onboarding config must NOT load the MySQL/host_cmds hooks")
	}
}
