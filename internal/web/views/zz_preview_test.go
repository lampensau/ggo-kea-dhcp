package views

// THROWAWAY preview harness (see static-render-ui-preview memory). Renders the
// PoolPlan component to a static HTML file so it can be screenshotted without
// running the appliance. DELETE this file + static/_preview_*.html before any
// `make pi` (static/* is //go:embed-ed). Gated so a normal `go test` skips it.

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestZZPreviewPoolPlan(t *testing.T) {
	if os.Getenv("GGO_PREVIEW") != "1" {
		t.Skip("preview-only")
	}
	ctx := context.Background()

	staticReserve := PoolPlanRow{Key: "r-static", Name: "Static reserve", Reserve: true, Count: 18, Prefix: "10.0.0.", Start: "2", End: "19"}

	// Simple: device counts are padded with headroom (count → size). The reserve
	// row is summarised in the foot, not shown as a row.
	greengoSimple := PoolPlanView{Mode: "simple", Subnet: "10.0.0.0/24", Gateway: "10.0.0.1", FreeIPs: 0, Rows: []PoolPlanRow{
		staticReserve,
		{Key: "GGO-BPX", Name: "Beltpacks", Icon: "bpx", Codes: "BPX / BP2", Elastic: true, Weight: 3, Size: 151, Range: "10.0.0.20 - 10.0.0.170"},
		{Key: "GGO-MCX-D", Name: "Multi-channel", Icon: "mcx", Codes: "MCX / MCXD", Elastic: true, Weight: 1, Size: 50, Range: "10.0.0.171 - 10.0.0.220"},
		{Key: "GGO-WP-X", Name: "Wall panels", Icon: "wpx", Codes: "WPX / WP", Count: 8, Size: 16, Range: "10.0.0.221 - 10.0.0.236"},
		{Key: "GGO-WAA", Name: "Active antennas", Icon: "radio-tower", Codes: "WAA", Count: 4, Size: 8, Range: "10.0.0.237 - 10.0.0.244"},
		{Key: "OTHERS", Name: "Non-Green-GO", Icon: "cpu", Count: 4, Size: 10, Range: "10.0.0.245 - 10.0.0.254"},
	}}

	// Advanced: exact sizes (no headroom); host-part inputs; reserve is an editable
	// row you can move, plus a second user-added reserve block.
	greengoAdvanced := PoolPlanView{Mode: "advanced", Subnet: "10.0.0.0/24", Gateway: "10.0.0.1", FreeIPs: 0, Rows: []PoolPlanRow{
		staticReserve,
		{Key: "GGO-BPX", Name: "Beltpacks", Icon: "bpx", Codes: "BPX / BP2", Elastic: true, Weight: 3, Size: 154, Range: "10.0.0.20 - 10.0.0.173"},
		{Key: "GGO-MCX-D", Name: "Multi-channel", Icon: "mcx", Codes: "MCX / MCXD", Elastic: true, Weight: 1, Size: 51, Range: "10.0.0.174 - 10.0.0.224"},
		{Key: "GGO-WP-X", Name: "Wall panels", Icon: "wpx", Codes: "WPX / WP", Count: 8, Prefix: "10.0.0.", Start: "225", End: "232"},
		{Key: "r-cams", Name: "Camera island", Reserve: true, Count: 10, Prefix: "10.0.0.", Start: "233", End: "242"},
		{Key: "GGO-WAA", Name: "Active antennas", Icon: "radio-tower", Codes: "WAA", Count: 4, Prefix: "10.0.0.", Start: "243", End: "246"},
		{Key: "OTHERS", Name: "Non-Green-GO", Icon: "cpu", Count: 4, Prefix: "10.0.0.", Start: "247", End: "250"},
	}}

	singlePool := PoolPlanView{Mode: "simple", Subnet: "10.20.0.0/24", Gateway: "10.20.0.1", FreeIPs: 0, Rows: []PoolPlanRow{
		{Key: "r-static", Name: "Static reserve", Reserve: true, Count: 18, Prefix: "10.20.0.", Start: "2", End: "19"},
		{Key: "dynamic", Name: "Dante / AES67", Icon: "bridge", IconEditable: true, Elastic: true, Weight: 1, Size: 235, Range: "10.20.0.20 - 10.20.0.254"},
	}}

	// Custom: all-Fixed vendor islands → leftover stays free reserve. Icons are
	// pickable (non-Green-GO), classifiers are user-set vendors / catch-all.
	custom := PoolPlanView{Mode: "advanced", Subnet: "10.30.0.0/23", Gateway: "10.30.0.1", FreeIPs: 451, Rows: []PoolPlanRow{
		{Key: "r-static", Name: "Static reserve", Reserve: true, Count: 18, Prefix: "10.30.0.", Start: "2", End: "19"},
		{Key: "c-light", Name: "Lighting desks", Icon: "cpu", IconEditable: true, Vendor: "MA · ETC", Count: 6, Prefix: "10.30.0.", Start: "20", End: "25"},
		{Key: "c-audio", Name: "Dante audio", Icon: "bridge", IconEditable: true, Vendor: "Audinate", Count: 24, Prefix: "10.30.0.", Start: "26", End: "49"},
		{Key: "c-fill", Name: "General", Icon: "cpu", IconEditable: true, Count: 10, Prefix: "10.30.0.", Start: "50", End: "59"},
	}}

	// Conflict: edited starts overlap and best-effort repack failed → flag + alert
	// (the live wiring also raises the same toast the dashboard uses).
	conflict := PoolPlanView{Mode: "advanced", Subnet: "10.0.0.0/24", Gateway: "10.0.0.1", FreeIPs: 0,
		Issue: "Wall panels (.239–.246) overlaps Active antennas (.244–.247) and couldn't be repacked automatically - adjust one of the highlighted ranges.",
		Rows: []PoolPlanRow{
			{Key: "GGO-BPX", Name: "Beltpacks", Icon: "bpx", Codes: "BPX / BP2", Elastic: true, Weight: 3, Size: 164, Range: "10.0.0.20 - 10.0.0.183"},
			{Key: "GGO-MCX-D", Name: "Multi-channel", Icon: "mcx", Codes: "MCX / MCXD", Elastic: true, Weight: 1, Size: 55, Range: "10.0.0.184 - 10.0.0.238"},
			{Key: "GGO-WP-X", Name: "Wall panels", Icon: "wpx", Codes: "WPX / WP", Count: 8, Prefix: "10.0.0.", Start: "239", End: "246", Err: true},
			{Key: "GGO-WAA", Name: "Active antennas", Icon: "radio-tower", Codes: "WAA", Count: 4, Prefix: "10.0.0.", Start: "244", End: "247", Err: true},
			{Key: "OTHERS", Name: "Non-Green-GO", Icon: "cpu", Count: 4, Prefix: "10.0.0.", Start: "251", End: "254"},
		}}

	// /pools view: the editor layout + a live Utilization column (ShowUtil).
	poolsUtil := PoolPlanView{Mode: "simple", Subnet: "10.0.0.0/24", Gateway: "10.0.0.1", FreeIPs: 0, ShowUtil: true, Rows: []PoolPlanRow{
		{Key: "r-static", Name: "Static reserve", Reserve: true, Count: 18, Prefix: "10.0.0.", Start: "2", End: "19"},
		{Key: "GGO-BPX", Name: "Beltpacks", Icon: "bpx", Codes: "BPX / BP2", Elastic: true, Weight: 3, Size: 151, Range: "10.0.0.20 - 10.0.0.170", Used: 96, Capacity: 151, Percent: 63},
		{Key: "GGO-MCX-D", Name: "Multi-channel", Icon: "mcx", Codes: "MCX / MCXD", Elastic: true, Weight: 1, Size: 50, Range: "10.0.0.171 - 10.0.0.220", Used: 7, Capacity: 50, Percent: 14},
		{Key: "GGO-WP-X", Name: "Wall panels", Icon: "wpx", Codes: "WPX / WP", Count: 8, Size: 16, Range: "10.0.0.221 - 10.0.0.236", Used: 15, Capacity: 16, Percent: 93},
		{Key: "GGO-WAA", Name: "Active antennas", Icon: "radio-tower", Codes: "WAA", Count: 4, Size: 8, Range: "10.0.0.237 - 10.0.0.244", Used: 8, Capacity: 8, Percent: 100},
		{Key: "OTHERS", Name: "Non-Green-GO", Icon: "cpu", Count: 4, Size: 10, Range: "10.0.0.245 - 10.0.0.254", Used: 2, Capacity: 10, Percent: 20},
	}}

	// Wizard variant: "Devices & pools" heading + a separate size-presets row.
	wizard := PoolPlanView{Mode: "simple", Subnet: "10.0.0.0/24", Gateway: "10.0.0.1", FreeIPs: 0, Heading: "Devices & pools", SizePresets: true, ActiveSize: "medium", Rows: greengoSimple.Rows}

	// /pools EDITABLE: the live editor wiring - EditAction/SaveAction set, so every
	// control is live and the foot gains a primary "Save changes" button.
	poolsEdit := PoolPlanView{Mode: "advanced", Subnet: "10.0.0.0/24", Gateway: "10.0.0.1", FreeIPs: 0, ShowUtil: true,
		Heading: "Address pools", RegionID: "poolplan-0", FieldPrefix: "scopes[0][pool]",
		EditAction: "/pools/edit", SaveAction: "/pools/save?s=0&mode=advanced", Rows: poolsUtil.Rows}

	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en" data-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><link rel="stylesheet" href="style.css"><title>Pool plan preview</title></head><body><main class="container">`)
	section := func(title string, v PoolPlanView) {
		b.WriteString(`<div class="card scope-card"><div class="scope-card-head"><h4 class="no-margin">`)
		b.WriteString(title)
		b.WriteString(`</h4></div>`)
		_ = PoolPlan(v).Render(ctx, &b)
		b.WriteString(`</div>`)
	}
	section("Green-GO - Simple (count + headroom, reorder)", greengoSimple)
	section("Green-GO - Advanced (exact sizes, host ranges, reorder)", greengoAdvanced)
	section("Dante (single elastic catch-all)", singlePool)
	section("Custom - vendor-classified islands + free reserve", custom)
	section("Conflict - best-effort repack failed", conflict)
	section("DHCP Pools - live utilization column (read-only)", poolsUtil)
	section("DHCP Pools - EDITABLE (Save button + wired controls)", poolsEdit)
	section("Wizard - Devices & pools + size presets", wizard)
	b.WriteString(`</main></body></html>`)

	if err := os.WriteFile("../static/_preview_poolplan.html", []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestZZPreviewPools renders the full /pools page (Base + form + datastar + the
// drag script) so the drag-reorder + field renumbering can be exercised in a real
// browser. Preview-only; cleaned up before make pi.
func TestZZPreviewPools(t *testing.T) {
	if os.Getenv("GGO_PREVIEW") != "1" {
		t.Skip("preview-only")
	}
	plan := PoolPlanView{
		Mode: "advanced", Subnet: "10.0.0.0/24", Gateway: "10.0.0.1", ShowUtil: true,
		Heading: "Address pools", RegionID: "poolplan-0", FieldPrefix: "scopes[0][pool]",
		EditAction: "/pools/edit", SaveAction: "/pools/save?s=0&mode=advanced",
		Rows: []PoolPlanRow{
			{Name: "Wall panels", Key: "GGO-WP-X", Icon: "wpx", Count: 8, Size: 16, Range: "10.0.0.20 - 10.0.0.35"},
			{Name: "Lighting / audio", Icon: "cpu", IconEditable: true, VendorList: []string{"e44f29", "001dc1"}, Count: 10, Size: 20, Range: "10.0.0.36 - 10.0.0.55"},
			{Name: "Active antennas", Key: "GGO-WAA", Icon: "radio-tower", Count: 4, Size: 8, Range: "10.0.0.56 - 10.0.0.63"},
			{Name: "Beltpacks", Key: "GGO-BPX", Icon: "bpx", Elastic: true, Weight: 1, Size: 191, Range: "10.0.0.64 - 10.0.0.254"},
		},
	}
	v := PoolsView{
		Page:   PageData{State: "ACTIVE", Authenticated: true, CSRFToken: "tok", CurrentPath: "/pools"},
		Scopes: []PoolScopeView{{Title: "Green-GO Intercom · 10.0.0.0/24", Plan: plan}},
	}
	var b strings.Builder
	if err := Pools(v).Render(context.Background(), &b); err != nil {
		t.Fatal(err)
	}
	html := strings.ReplaceAll(b.String(), "/static/", "")
	if err := os.WriteFile("../static/_preview_pools.html", []byte(html), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestZZPreviewSetupEdit renders the wizard in EDIT mode with a prefill plan, so
// the page's JS (ggoApplyImported → ggoWritePlan) runs in the browser and we can
// confirm the saved plan is written as scopes[0][pool][i][...] fields before the
// data-init seed (exact-restore-on-edit). Preview-only; cleaned up before make pi.
func TestZZPreviewSetupEdit(t *testing.T) {
	if os.Getenv("GGO_PREVIEW") != "1" {
		t.Skip("preview-only")
	}
	prefill := `{"name":"Tour A","scopes":[{"preset":"greengo","vlan_id":0,"cidr":"10.0.0.0/24","uplink":{"enabled":false},` +
		`"pool_plan":[{"kind":"reserve","name":"Static reserve","count":18},` +
		`{"kind":"fixed","class":"GGO-WP-X","name":"Wall panels","sizing":"auto","count":6,"icon":"wpx"},` +
		`{"kind":"elastic","class":"GGO-BPX","name":"Beltpacks","weight":2,"icon":"bpx"}]}]}`
	v := SetupView{
		Page:        PageData{State: "ACTIVE", Authenticated: true, CSRFToken: "tok", Title: "Edit configuration"},
		Editing:     true,
		PrefillJSON: prefill,
		ShieldState: "Active", LinkState: "Trunk", Interface: "eth0",
	}
	var b strings.Builder
	if err := Setup(v).Render(context.Background(), &b); err != nil {
		t.Fatal(err)
	}
	// Rewrite embedded asset paths to relative so the bare static server resolves
	// them (the page's JS - including ggoApplyImported - then runs in the browser).
	html := strings.ReplaceAll(b.String(), "/static/", "")
	if err := os.WriteFile("../static/_preview_setupedit.html", []byte(html), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestZZPreviewDashboard renders the full Dashboard page (Phase 5 layout reorg) so
// the paired 2-column .dash-grid, height-capped card bodies, stat strip, alert
// strip, LLDP chip and PTP panel can be screenshotted together at laptop width.
// Preview-only; cleaned up before make pi.
func TestZZPreviewDashboard(t *testing.T) {
	if os.Getenv("GGO_PREVIEW") != "1" {
		t.Skip("preview-only")
	}
	mk := func(s []int) (string, string) { return SparklinePoints(s), SparklineArea(s) }
	lp, la := mk([]int{30, 31, 33, 36, 38, 40, 41, 41, 42, 42})
	pp, pa := mk([]int{40, 46, 52, 58, 62, 65, 66, 66})
	up, ua := mk([]int{22, 31, 26, 24, 29, 27, 28, 26})
	rp, ra := mk([]int{6, 9, 7, 8, 6, 7, 7, 8})
	ptpP, ptpA := mk([]int{0, 0, 1, 1, 1, 1, 1, 1})

	v := DashboardView{
		Page:        PageData{State: "ACTIVE", Authenticated: true, CSRFToken: "tok", CurrentPath: "/dashboard", Username: "operator", Title: "Dashboard"},
		ProfileName: "Show_Bootstrap", Preset: "Multi-VLAN Trunk", Interface: "eth0, eth0.20, eth0.30", TotalScopes: 3,
		LLDP: LLDPChip{Present: true, Switch: "core-sw1", Port: "Gi1/0/12", NativeVLAN: "1"},
		Stats: []StatTileView{
			{Icon: "network", Label: "Active leases", Value: "42", Dot: "ok", Delta: "+3", DeltaDir: "up", Points: lp, Area: la},
			{Icon: "gauge", Label: "Pool utilization", Value: "66", Unit: "%", Dot: "ok", Points: pp, Area: pa},
			{Icon: "clock", Label: "Lease processing", Value: "7", Unit: "ms", Dot: "ok", Points: rp, Area: ra},
			{Icon: "globe", Label: "Uplink", Value: "28", Unit: "ms", Dot: "ok", Points: up, Area: ua},
			{Icon: "radio-tower", Label: "PTP grandmaster", Value: "Locked", Unit: "domain 0", Dot: "ok", Points: ptpP, Area: ptpA},
		},
		Pools: []PoolRow{
			{ClassName: "GGO-BPX", Label: "Beltpacks", IPRange: "10.0.0.20 - 10.0.0.188", Allocated: 96, Capacity: 169, Percent: 56},
			{ClassName: "GGO-MCX-D", Label: "Multi-channel", IPRange: "10.0.0.189 - 10.0.0.220", Allocated: 18, Capacity: 32, Percent: 56},
			{ClassName: "OTHERS", Label: "Non-Green-GO", IPRange: "10.0.0.221 - 10.0.0.254", Allocated: 4, Capacity: 34, Percent: 12},
		},
		NetHealth: NetHealthView{Interfaces: []NetHealthIface{
			{Iface: "eth0", Available: true, LinkMode: "flat", OKCount: 3, Rows: []NetHealthRow{
				{Kind: "lldp", Severity: "ok", Title: "LLDP neighbor: core-sw1", Detail: "port Gi1/0/12 · native VLAN 1"},
				{Kind: "igmp", Severity: "ok", Title: "IGMP querier present", Detail: "querier 10.0.0.1 v3"},
				{Kind: "rogue_dhcp", Severity: "ok", Title: "No rogue DHCP servers"},
			}},
			{Iface: "eth0.30", Available: true, LinkMode: "trunk", ErrCount: 1, OKCount: 1, Rows: []NetHealthRow{
				{Kind: "rogue_dhcp", Severity: "error", Title: "Rogue DHCP server detected", Detail: "server 10.30.0.66 · 9c:1f:80:de:ad:be"},
				{Kind: "vlan", Severity: "ok", Title: "VLAN tags match configuration"},
			}},
		}},
		PTP: []PTPRow{{Severity: "ok", Domain: "domain 0", Text: "PTP GM 00:1f:80:gm · 2 steps · sync 1/s"}},
		RecentLeases: []LeaseRow{
			{IPAddress: "10.0.0.177", HWAddress: "00:1f:80:20:4e:52", Class: "GGO-BPX", ExpiresIn: "58m"},
			{IPAddress: "10.0.0.42", HWAddress: "00:1f:80:11:22:33", Class: "GGO-MCX-D", ExpiresIn: "1h2m"},
		},
		Activity: []AuditRow{
			{Action: "IGMP querier present", Target: "eth0", Result: "SUCCESS", Timestamp: "2026-06-14T22:15:30Z"},
			{Action: "STARTUP", Target: "ggo-kea-dhcp", Result: "INFO", Timestamp: "2026-06-14T22:15:09Z"},
			{Action: "LEASE_RELEASE", Target: "10.0.0.99", Result: "SUCCESS", Timestamp: "2026-06-14T22:06:59Z"},
		},
		Pinned: []PortRow{
			{PortIdentity: "Gi1/0/8", IPAddress: "10.0.0.50", Label: "FOH rack"},
		},
	}
	var b strings.Builder
	if err := Dashboard(v).Render(context.Background(), &b); err != nil {
		t.Fatal(err)
	}
	html := strings.ReplaceAll(b.String(), "/static/", "")
	if err := os.WriteFile("../static/_preview_dashboard.html", []byte(html), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestZZPreviewNetSignals renders the Phase 4 netmon-derived dashboard pieces -
// the always-on per-interface health header with severity rollup, the LLDP "you
// are here" chip, the high-severity alert strip, and the PTP clock panel - so they
// can be screenshotted without running the appliance. Preview-only; cleaned up
// before make pi.
func TestZZPreviewNetSignals(t *testing.T) {
	if os.Getenv("GGO_PREVIEW") != "1" {
		t.Skip("preview-only")
	}
	ctx := context.Background()

	health := NetHealthView{Interfaces: []NetHealthIface{
		{Iface: "eth0", Available: true, LinkMode: "flat", OKCount: 3, Rows: []NetHealthRow{
			{Kind: "lldp", Severity: "ok", Title: "LLDP neighbor: core-sw1", Detail: "port Gi1/0/12 · native VLAN 1"},
			{Kind: "igmp", Severity: "ok", Title: "IGMP querier present", Detail: "querier 10.0.0.1 v3"},
			{Kind: "ptp", Severity: "ok", Title: "PTP grandmaster locked"},
		}},
		{Iface: "eth0.20", Available: true, LinkMode: "trunk", OKCount: 1, WarnCount: 1, Rows: []NetHealthRow{
			{Kind: "static_in_pool", Severity: "warn", Title: "Static device inside a pool", Detail: "00:1f:80:aa:bb:cc · pool 10.20.0.20-.170"},
			{Kind: "sacn", Severity: "ok", Title: "sACN universe traffic seen"},
		}},
		{Iface: "eth0.30", Available: true, LinkMode: "trunk", ErrCount: 1, OKCount: 1, Rows: []NetHealthRow{
			{Kind: "rogue_dhcp", Severity: "error", Title: "Rogue DHCP server detected", Detail: "server 10.30.0.66 · 9c:1f:80:de:ad:be"},
			{Kind: "vlan", Severity: "ok", Title: "VLAN tags match configuration"},
		}},
		{Iface: "eth0.40", Available: false, LinkMode: "trunk", Note: "multicast inspection paused - high load"},
	}}
	lldp := LLDPChip{Present: true, Switch: "core-sw1", Port: "Gi1/0/12", NativeVLAN: "1"}
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en" data-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><link rel="stylesheet" href="style.css"><title>Net signals preview</title></head><body><main class="container"><div class="dash">`)
	// LLDP chip shown in a stand-in dash header meta line.
	b.WriteString(`<div class="dash-head"><div class="dash-head-id"><h1 class="dash-title"><span class="status-dot ok"></span>Tour A</h1><div class="dash-head-meta"><span>Multi-VLAN Trunk</span><span class="mono">eth0, eth0.20, eth0.30</span><span>4 scopes</span>`)
	_ = DashLLDP(lldp).Render(ctx, &b)
	b.WriteString(`</div></div></div>`)
	_ = NetHealth(health).Render(ctx, &b)
	b.WriteString(`</div></main></body></html>`)
	if err := os.WriteFile("../static/_preview_netsignals.html", []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestZZPreviewStatTiles renders the four live stat tiles with example sparkline
// series (rising ok, warn, offline-no-sparkline, flat) so they can be screenshotted
// without running the appliance. Preview-only; cleaned up before make pi.
func TestZZPreviewStatTiles(t *testing.T) {
	if os.Getenv("GGO_PREVIEW") != "1" {
		t.Skip("preview-only")
	}
	mk := func(s []int) (string, string) { return SparklinePoints(s), SparklineArea(s) }
	lp, la := mk([]int{30, 31, 33, 36, 38, 40, 41, 41, 42, 42})
	pp, pa := mk([]int{70, 76, 82, 88, 92, 95, 96, 96})
	up, ua := mk([]int{22, 31, 26, 24, 29, 27, 28, 26})
	rp, ra := mk([]int{6, 9, 7, 8, 6, 7, 7, 8})
	v := DashboardView{Stats: []StatTileView{
		{Icon: "network", Label: "Active leases", Value: "42", Dot: "ok", Delta: "+3", DeltaDir: "up", Points: lp, Area: la},
		{Icon: "gauge", Label: "Pool utilization", Value: "96", Unit: "%", Dot: "err", Points: pp, Area: pa},
		{Icon: "globe", Label: "Uplink", Value: "28", Unit: "ms", Dot: "ok", Points: up, Area: ua},
		{Icon: "clock", Label: "Lease processing", Value: "7", Unit: "ms", Dot: "ok", Points: rp, Area: ra},
	}}
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en" data-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><link rel="stylesheet" href="style.css"><title>Stat tiles preview</title></head><body><main class="container">`)
	if err := StatTiles(v).Render(context.Background(), &b); err != nil {
		t.Fatal(err)
	}
	b.WriteString(`</main></body></html>`)
	if err := os.WriteFile("../static/_preview_stattiles.html", []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}
