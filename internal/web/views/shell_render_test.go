package views

// harness_views_test.go - verification harness for the views package, focused on
// the components/helpers touched by the uncommitted diff: the CONFIGURING reload
// script in Base, the live StatusPill, sparkline/stat-tile rendering, and the pure
// presentation helpers. Reuses render() (pages_test.go) and renderBase()
// (shell_test.go). New unique names only; no production code is modified.

import (
	"strings"
	"testing"
)

// --- PRIORITY 1: the CONFIGURING reload script is emitted in exactly one state ---

// TestConfiguringReloadScriptGating is the core diff guard: the
// configuringReloadScript() poller (fetch /api/state -> location.reload) must be
// emitted ONLY for an authenticated page whose lifecycle State is "CONFIGURING".
// In every other state the page must rely on the live SSE channel alone, so the
// poller must be absent (it exists precisely to survive the eth0 bounce an apply
// performs, and would be wasted work otherwise).
func TestConfiguringReloadScriptGating(t *testing.T) {
	const probe = "/api/state"
	const reload = "location.reload"

	// Authenticated CONFIGURING: the poller MUST be present.
	cfg := renderBase(t, PageData{State: "CONFIGURING", Authenticated: true, CSRFToken: "tok"})
	for _, want := range []string{probe, reload, "CONFIGURING"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("authenticated CONFIGURING shell missing reload-poll marker %q", want)
		}
	}

	// Authenticated non-CONFIGURING states: the poller MUST be absent.
	for _, st := range []string{"ACTIVE", "ONBOARDING", "FACTORY"} {
		html := renderBase(t, PageData{State: st, Authenticated: true, CSRFToken: "tok"})
		if strings.Contains(html, probe) {
			t.Errorf("authenticated %s shell wrongly emitted the /api/state reload poller", st)
		}
	}

	// Unauthenticated CONFIGURING: the whole post-auth script block (incl. the
	// poller) is gated behind d.Authenticated, so it must NOT appear pre-auth.
	unauth := renderBase(t, PageData{State: "CONFIGURING", Authenticated: false})
	if strings.Contains(unauth, probe) {
		t.Error("unauthenticated CONFIGURING shell must not emit the /api/state reload poller")
	}
}

// TestConfiguringPillIsInfo confirms the header pill the CONFIGURING shell
// renders reads "Configuring" and carries the accent (is-info) class - the two
// surfaces (script + pill) agree on the state.
func TestConfiguringShellPill(t *testing.T) {
	html := renderBase(t, PageData{State: "CONFIGURING", Authenticated: true, CSRFToken: "tok"})
	if !strings.Contains(html, "Configuring") {
		t.Error("CONFIGURING shell pill should read 'Configuring'")
	}
	if !strings.Contains(html, "is-info") {
		t.Error("CONFIGURING shell pill should carry the is-info accent class")
	}
	// CONFIGURING shares the ACTIVE nav set, so the live channel still opens.
	if !strings.Contains(html, "/sse/live") {
		t.Error("authenticated CONFIGURING shell should still open the live SSE channel")
	}
}

// --- StatusPill: state -> label + class, with live alert recoloring ---

func TestStatusPillStates(t *testing.T) {
	cases := []struct {
		name       string
		v          StatusPillView
		wantText   string
		wantClass  string
		wantAbsent string
	}{
		{"active clean", StatusPillView{State: "ACTIVE"}, "Active", "is-ok", "·"},
		{"configuring clean", StatusPillView{State: "CONFIGURING"}, "Configuring", "is-info", "·"},
		{"onboarding clean", StatusPillView{State: "ONBOARDING"}, "Onboarding", "is-warn", "·"},
		// A warning recolors the pill (is-warn) and appends a singular counter even
		// while ACTIVE - live alert severity wins over the lifecycle color.
		{"active with one warning", StatusPillView{State: "ACTIVE", WarnCount: 1}, "Active · 1 warning", "is-warn", "errors"},
		// Errors take precedence over warnings and pluralize.
		{"active with errors", StatusPillView{State: "ACTIVE", WarnCount: 1, ErrCount: 2}, "Active · 2 errors", "is-err", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			html := render(t, StatusPill(c.v))
			if !strings.Contains(html, c.wantText) {
				t.Errorf("pill missing label %q", c.wantText)
			}
			if !strings.Contains(html, c.wantClass) {
				t.Errorf("pill missing class %q", c.wantClass)
			}
			if c.wantAbsent != "" && strings.Contains(html, c.wantAbsent) {
				t.Errorf("clean pill should not contain %q", c.wantAbsent)
			}
			// The pill links to Diagnostics; with a live alert it deep-links to the
			// latest alert entry (#latest-alert), otherwise the page top.
			wantHref := `href="/diagnostics"`
			if c.v.WarnCount > 0 || c.v.ErrCount > 0 {
				wantHref = `href="/diagnostics#latest-alert"`
			}
			if !strings.Contains(html, wantHref) {
				t.Errorf("status pill should link with %s", wantHref)
			}
		})
	}
}

// TestStatusPillTooltipLists asserts the live alert titles end up in the
// pill's hover title attribute (the tooltip the operator reads without clicking).
func TestStatusPillTooltipLists(t *testing.T) {
	html := render(t, StatusPill(StatusPillView{State: "ACTIVE", ErrCount: 1, Details: []string{"Rogue DHCP server detected"}}))
	if !strings.Contains(html, "Rogue DHCP server detected") {
		t.Error("pill tooltip should list the live alert title")
	}
}

// --- Sparkline / StatTile rendering ---

// TestSparklineExtraEdges extends the existing SparklinePoints cases with
// a longer monotone run and the area-polygon closure on a flat series.
func TestSparklineExtraEdges(t *testing.T) {
	// Flat area polygon: a centered line plus the two baseline corners.
	if got := SparklineArea([]int{4, 4}); got != "0,16 100,16 100,32 0,32" {
		t.Errorf("flat area = %q, want centered line closed to baseline", got)
	}
	// Single-point area: the centered flat line closed to the baseline.
	if got := SparklineArea([]int{9}); got != "0,16 100,16 100,32 0,32" {
		t.Errorf("single-point area = %q", got)
	}
}

// TestSparklinePointsExact pins the integer-rounded interior coordinates of
// a rising series so a refactor of the normalization math can't silently drift.
func TestSparklinePointsExact(t *testing.T) {
	// series 0..3, lo=0 hi=3, pad=2, h=32: y = (32-2) - v*(32-4)/3 = 30 - v*28/3.
	// v=0 ->30, v=1 ->30-9=21, v=2 ->30-18=12, v=3 ->30-28=2. x: 0,33,66,100.
	if got := SparklinePoints([]int{0, 1, 2, 3}); got != "0,30 33,21 66,12 100,2" {
		t.Errorf("rising 4-pt = %q, want %q", got, "0,30 33,21 66,12 100,2")
	}
}

// TestStatTileSparklinePresence verifies the Sparkline templ emits an SVG
// only when Points are present, and that the severity class flows onto both the
// polyline and the polygon so the chart auto-themes.
func TestStatTileSparklinePresence(t *testing.T) {
	withSpark := render(t, StatTile(StatTileView{
		Icon: "gauge", Label: "Pool utilization", Value: "96", Unit: "%", Dot: "err",
		Points: "0,30 100,2", Area: "0,30 100,2 100,32 0,32",
	}))
	for _, want := range []string{
		`<svg class="sparkline"`,
		`class="sparkline-line err"`,
		`class="sparkline-area err"`,
		`points="0,30 100,2"`,
		`<span class="status-dot err">`, // meaning via the dot, not color alone
		`Pool utilization`,
	} {
		if !strings.Contains(withSpark, want) {
			t.Errorf("stat tile with sparkline missing %q", want)
		}
	}

	// An offline/no-history tile (empty Points) renders the value but no sparkline.
	// (The tile still contains the label's @Icon SVG, so assert on the sparkline
	// class specifically, not a bare <svg>.)
	noSpark := render(t, StatTile(StatTileView{Icon: "globe", Label: "Uplink", Value: "Offline", Dot: ""}))
	if strings.Contains(noSpark, `class="sparkline"`) {
		t.Error("a tile with no Points must not render a sparkline SVG")
	}
	if !strings.Contains(noSpark, "Offline") {
		t.Error("a sparkline-less tile should still render its value")
	}
}

// TestStatTilesGridPinsColumns checks the strip pins its column count to the
// number of tiles via the inline --tiles custom property (keeps 5 tiles on one row).
func TestStatTilesGridPinsColumns(t *testing.T) {
	v := DashboardView{Stats: []StatTileView{
		{Label: "A", Value: "1"}, {Label: "B", Value: "2"}, {Label: "C", Value: "3"},
	}}
	html := render(t, StatTiles(v))
	if !strings.Contains(html, "--tiles:3") {
		t.Error("StatTiles should pin --tiles to the tile count")
	}
	if !strings.Contains(html, `id="dash-tiles"`) {
		t.Error("StatTiles should carry the #dash-tiles live region id")
	}
}

// --- Pure presentation helpers (table-driven, directly callable) ---

func TestPluralize(t *testing.T) {
	cases := []struct {
		n    int
		want string
	}{{0, "errors"}, {1, "error"}, {2, "errors"}, {-1, "errors"}}
	for _, c := range cases {
		if got := pluralize(c.n, "error", "errors"); got != c.want {
			t.Errorf("pluralize(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}

func TestStateLabelAndClass(t *testing.T) {
	labels := map[string]string{
		"ACTIVE": "Active", "CONFIGURING": "Configuring", "ONBOARDING": "Onboarding",
		"FACTORY": "Factory", "WEIRD": "WEIRD", // unknown passes through verbatim
	}
	for in, want := range labels {
		if got := statusLabel(in); got != want {
			t.Errorf("statusLabel(%q) = %q, want %q", in, got, want)
		}
	}
	classes := map[string]string{
		"ACTIVE": "is-ok", "CONFIGURING": "is-info", "ONBOARDING": "is-warn",
		"FACTORY": "is-warn", "": "", "NOPE": "",
	}
	for in, want := range classes {
		if got := statusPillClass(in); got != want {
			t.Errorf("statusPillClass(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestPillHealthClassPrecedence: errors beat warnings beat the lifecycle color.
func TestPillHealthClassPrecedence(t *testing.T) {
	cases := []struct {
		v    StatusPillView
		want string
	}{
		{StatusPillView{State: "ACTIVE"}, "is-ok"},
		{StatusPillView{State: "ACTIVE", WarnCount: 3}, "is-warn"},
		{StatusPillView{State: "ACTIVE", WarnCount: 3, ErrCount: 1}, "is-err"},
		{StatusPillView{State: "ONBOARDING"}, "is-warn"},
	}
	for _, c := range cases {
		if got := pillHealthClass(c.v); got != c.want {
			t.Errorf("pillHealthClass(%+v) = %q, want %q", c.v, got, c.want)
		}
	}
}

func TestPTPQuality(t *testing.T) {
	cases := []struct {
		cc        int
		wantLabel string
		wantDot   string
	}{
		{6, "GPS", "ok"},
		{13, "Locked", "ok"},
		{7, "Holdover", "warn"},
		{52, "Degraded", "warn"},
		{248, "Local", ""}, // free-running default master - neutral in a closed net
		{255, "Slave", "warn"},
		{-1, "Present", "ok"}, // GM present, class unread
		{99, "Class 99", ""},  // unknown positive class
	}
	for _, c := range cases {
		l, d := PTPQuality(c.cc)
		if l != c.wantLabel || d != c.wantDot {
			t.Errorf("PTPQuality(%d) = (%q,%q), want (%q,%q)", c.cc, l, d, c.wantLabel, c.wantDot)
		}
	}
}

// TestHasOtherProfiles reports true only when a non-active profile exists,
// so the dashboard only shows the switcher when there is somewhere to switch to.
func TestHasOtherProfiles(t *testing.T) {
	if hasOtherProfiles(nil) {
		t.Error("no profiles -> false")
	}
	if hasOtherProfiles([]ProfileOption{{Name: "A", Active: true}}) {
		t.Error("only the active profile -> false")
	}
	if !hasOtherProfiles([]ProfileOption{{Name: "A", Active: true}, {Name: "B", Active: false}}) {
		t.Error("an inactive profile present -> true")
	}
	if !hasOtherProfiles([]ProfileOption{{Name: "B", Active: false}}) {
		t.Error("a single inactive profile -> true")
	}
}

func TestLLDPChipText(t *testing.T) {
	cases := []struct {
		c    LLDPChip
		want string
	}{
		{LLDPChip{Switch: "core-sw1", Port: "Gi1/0/12", NativeVLAN: "1"}, "core-sw1 (Gi1/0/12) · VLAN 1"},
		{LLDPChip{Switch: "core-sw1", Port: "Gi1/0/12"}, "core-sw1 (Gi1/0/12)"},
		{LLDPChip{Switch: "core-sw1"}, "core-sw1"},
		{LLDPChip{Switch: "sw", NativeVLAN: "20"}, "sw · VLAN 20"}, // no port: no dangling parens
	}
	for _, c := range cases {
		if got := lldpChipText(c.c); got != c.want {
			t.Errorf("lldpChipText(%+v) = %q, want %q", c.c, got, c.want)
		}
	}
}

func TestPortLabelAndOnline(t *testing.T) {
	labelCases := []struct {
		p    PortRow
		want string
	}{
		{PortRow{RemoteID: "sw1", CircuitID: "Gi1"}, "sw1 / Gi1"},
		{PortRow{RemoteID: "sw1"}, "sw1"},
		{PortRow{CircuitID: "Gi1"}, "Gi1"},
		{PortRow{PortIdentity: "0xdeadbeef"}, "0xdeadbeef"}, // neither decoded -> opaque key
	}
	for _, c := range labelCases {
		if got := portLabel(c.p); got != c.want {
			t.Errorf("portLabel(%+v) = %q, want %q", c.p, got, c.want)
		}
	}
	// portOnline: the merge marks an offline pinned port with HWAddress "-".
	if portOnline(PortRow{HWAddress: "-"}) {
		t.Error("portOnline should be false for the '-' offline sentinel")
	}
	if portOnline(PortRow{HWAddress: ""}) {
		t.Error("portOnline should be false for an empty HWAddress")
	}
	if !portOnline(PortRow{HWAddress: "00:1f:80:aa:bb:cc"}) {
		t.Error("portOnline should be true for a real HWAddress")
	}
}

func TestAuditResultLabel(t *testing.T) {
	cases := map[string]string{
		"SUCCESS": "Success", "OK": "OK", "WARN": "Warning", "WARNING": "Warning",
		"INFO": "Info", "ERROR": "Error", "FAIL": "Failed", "FAILED": "Failed",
		"custom-token": "custom-token", // unknown falls through verbatim
	}
	for in, want := range cases {
		if got := auditResultLabel(in); got != want {
			t.Errorf("auditResultLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNetRollupText(t *testing.T) {
	cases := []struct {
		ifc  NetHealthIface
		want string
	}{
		{NetHealthIface{ErrCount: 2}, "2 alerts"},
		{NetHealthIface{ErrCount: 1}, "1 alert"},
		{NetHealthIface{WarnCount: 1}, "1 warning"},
		{NetHealthIface{WarnCount: 3}, "3 warnings"},
		{NetHealthIface{OKCount: 5}, "Healthy"},
		{NetHealthIface{}, "monitoring"}, // nothing observed yet
	}
	for _, c := range cases {
		if got := netRollupText(c.ifc); got != c.want {
			t.Errorf("netRollupText(%+v) = %q, want %q", c.ifc, got, c.want)
		}
	}
}

func TestNetRollupClassAndDot(t *testing.T) {
	if got := netRollupClass(NetHealthIface{ErrCount: 1}); got != "is-err" {
		t.Errorf("netRollupClass err = %q", got)
	}
	if got := netRollupClass(NetHealthIface{WarnCount: 1}); got != "is-warn" {
		t.Errorf("netRollupClass warn = %q", got)
	}
	if got := netRollupClass(NetHealthIface{OKCount: 1}); got != "is-ok" {
		t.Errorf("netRollupClass ok = %q", got)
	}
	// An unavailable interface is neutral, never a misleading green.
	if got := netRollupDot(NetHealthIface{Available: false, OKCount: 9}); got != "" {
		t.Errorf("netRollupDot for unavailable iface = %q, want neutral", got)
	}
	if got := netRollupDot(NetHealthIface{Available: true, ErrCount: 1}); got != "err" {
		t.Errorf("netRollupDot err = %q", got)
	}
}

func TestMeterAndClampHelpers(t *testing.T) {
	meter := map[int]string{50: "", 80: "warn", 94: "warn", 95: "err", 100: "err"}
	for in, want := range meter {
		if got := meterClass(in); got != want {
			t.Errorf("meterClass(%d) = %q, want %q", in, got, want)
		}
	}
	clamp := map[int]int{-5: 0, 0: 0, 50: 50, 100: 100, 150: 100}
	for in, want := range clamp {
		if got := clampPct(in); got != want {
			t.Errorf("clampPct(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestPoolsOverallPct(t *testing.T) {
	pools := []PoolRow{
		{Allocated: 50, Capacity: 100},
		{Allocated: 50, Capacity: 100},
	}
	if got := poolsOverallPct(pools); got != 50 {
		t.Errorf("poolsOverallPct = %d, want 50", got)
	}
	// Elastic overshoot clamps to 100.
	if got := poolsOverallPct([]PoolRow{{Allocated: 120, Capacity: 100}}); got != 100 {
		t.Errorf("poolsOverallPct overshoot = %d, want 100", got)
	}
	// No capacity -> 0, never a divide-by-zero.
	if got := poolsOverallPct(nil); got != 0 {
		t.Errorf("poolsOverallPct(nil) = %d, want 0", got)
	}
}

// --- Page/partial rendering smoke (no panic + key content) ---

// TestNetHealthRenders renders the Network Health card with mixed-severity
// interfaces (including an unavailable one) and asserts the high-signal content
// surfaces without a templ runtime error.
func TestNetHealthRenders(t *testing.T) {
	v := NetHealthView{Interfaces: []NetHealthIface{
		{Iface: "eth0", Available: true, LinkMode: "flat", OKCount: 2, Rows: []NetHealthRow{
			{Kind: "lldp", Severity: "ok", Title: "LLDP neighbor: core-sw1", Detail: "port Gi1/0/12"},
			{Kind: "igmp", Severity: "ok", Title: "IGMP querier present"},
		}},
		{Iface: "eth0.30", Available: true, LinkMode: "trunk", ErrCount: 1, Rows: []NetHealthRow{
			{Kind: "rogue_dhcp", Severity: "error", Title: "Rogue DHCP server detected", Detail: "server 10.30.0.66"},
		}},
		{Iface: "eth0.40", Available: false, LinkMode: "trunk", Note: "multicast inspection paused - high load"},
	}}
	html := render(t, NetHealth(v))
	for _, want := range []string{
		"eth0", "eth0.30", "eth0.40",
		"Rogue DHCP server detected",
		"LLDP neighbor: core-sw1",
		"multicast inspection paused - high load", // honest unavailable note
		"1 alert", // the trunk iface rollup
	} {
		if !strings.Contains(html, want) {
			t.Errorf("NetHealth render missing %q", want)
		}
	}
}

// TestLeasesBodyVariants renders the lease table body with the distinct row kinds
// the diff-touched leases view supports - a plain dynamic lease, a hardware
// reservation, an online presence dot, and a port-pinned row - and asserts the two
// bits unique to this view: the live-countdown epoch (data-expires) and the online
// presence dot. (The disabled-delete-for-pinned control is asserted in
// leases_actions_test.go.)
func TestLeasesBodyVariants(t *testing.T) {
	rows := []LeaseRow{
		{IPAddress: "10.0.0.50", HWAddress: "00:1f:80:aa:bb:cc", Class: "GGO-BPX", ExpiresIn: "30m", ExpiresAt: 1893456000, Presence: "online"},
		{IPAddress: "10.0.0.9", HWAddress: "00:1f:80:11:22:33", Class: "GGO-WP-X", Reserved: true, SubnetID: 1},
		{IPAddress: "10.0.0.12", HWAddress: "00:1f:80:44:55:66", Class: "GGO-BPX", Reserved: true, PortPinned: true},
	}
	html := render(t, LeasesBody(rows, "tok", true))
	for _, want := range []string{
		"10.0.0.50", "10.0.0.9", "10.0.0.12",
		`data-expires="1893456000"`, // live countdown epoch on the active lease
	} {
		if !strings.Contains(html, want) {
			t.Errorf("LeasesBody render missing %q", want)
		}
	}
	// The online lease shows a presence dot variant (status-dot lease-dot ok).
	if !strings.Contains(html, "lease-dot ok") {
		t.Error("online lease should render an ok presence dot")
	}
}

// TestPoolPlanReadOnlyRenders verifies a read-only (EditAction == "") plan
// renders its rows and reserve foot summary while emitting no live @post handlers -
// the inert path used by static previews and the non-editing /pools view.
func TestPoolPlanReadOnlyRenders(t *testing.T) {
	v := PoolPlanView{
		Mode: "simple", Subnet: "10.0.0.0/24", Gateway: "10.0.0.1",
		Rows: []PoolPlanRow{
			{Name: "Static reserve", Reserve: true, Count: 18},
			{Name: "Beltpacks", Key: "GGO-BPX", Elastic: true, Weight: 1, Size: 235, Range: "10.0.0.20 - 10.0.0.254"},
		},
	}
	html := render(t, PoolPlan(v))
	if !strings.Contains(html, "Beltpacks") {
		t.Error("read-only plan should render its pool rows")
	}
	if !strings.Contains(html, "DHCP server 10.0.0.1") {
		t.Error("read-only plan foot should summarize the DHCP-server address")
	}
	if strings.Contains(html, "@post(") {
		t.Error("read-only plan must not wire any @post handler")
	}
}
