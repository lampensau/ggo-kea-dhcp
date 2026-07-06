package views

// Doc-screenshot harness (same pattern as zz_preview_test.go): renders the six
// pages the user docs screenshot (docs/images/*.png) from ONE shared fixture -
// a touring rig with VLANs, calibrated against the live Pi's real data shapes
// (MikroTik Option-82 remote/circuit IDs, 00:1f:80 device MACs, ~13m leases).
// Gated so a normal `go test` skips it; the rendered static/_preview_doc_*.html
// files are throwaway and must not be committed or embedded (delete before
// `make pi`, like every _preview_*.html).

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"ggo-kea-dhcp/internal/version"
)

func docSkip(t *testing.T) {
	t.Helper()
	if os.Getenv("GGO_PREVIEW") != "1" {
		t.Skip("preview-only")
	}
}

func docWrite(t *testing.T, name, html string) {
	t.Helper()
	html = strings.ReplaceAll(html, "/static/", "")
	if err := os.WriteFile("../static/"+name, []byte(html), 0o644); err != nil {
		t.Fatal(err)
	}
}

func docPage(state, path, title string) PageData {
	return PageData{State: state, Authenticated: state != "FACTORY", CSRFToken: "tok", CurrentPath: path, Username: "operator", Title: title, Version: version.Number}
}

// --- The shared touring-rig fixture -----------------------------------------

const (
	docSwitchCore = "AV-Core-1"
	docSwitchEdge = "AV-Edge-3"
)

// docGreengoPlan is the Green-GO scope's pool plan (10.0.0.0/24, simple mode).
// The rig's device counts are the single source every other number derives from:
// 24 BPX + 5 MCX + 3 WPX + 2 WAA = 34 Green-GO devices (the census row), plus 3
// non-Green-GO on eth0, 26 Dante and 9 sACN leases = 72 leases, 10% overall util.
func docGreengoPlan(showUtil bool) PoolPlanView {
	return PoolPlanView{
		Mode: "simple", Subnet: "10.0.0.0/24", Gateway: "10.0.0.1", FreeIPs: 12,
		ShowUtil: showUtil, Greengo: true,
		Rows: []PoolPlanRow{
			{Key: "r-static", Name: "Static reserve", Reserve: true, Count: 18, Prefix: "10.0.0.", Start: "2", End: "19"},
			{Key: "GGO-BPX", Name: "Beltpacks", Icon: "bpx", Codes: "BPX / BP2", Elastic: true, Weight: 3, Size: 140, Range: "10.0.0.20 - 10.0.0.159", Used: 24, Capacity: 140, Percent: 17},
			{Key: "GGO-MCX-D", Name: "Multi-Channel", Icon: "mcx", Codes: "MCX / MCXD", Elastic: true, Weight: 1, Size: 47, Range: "10.0.0.160 - 10.0.0.206", Used: 5, Capacity: 47, Percent: 11},
			{Key: "GGO-WP-X", Name: "Wall Panels", Icon: "wpx", Codes: "WPX / WP", Count: 6, Floor: 5, Size: 12, Range: "10.0.0.207 - 10.0.0.218", Used: 3, Capacity: 12, Percent: 25},
			{Key: "GGO-WAA", Name: "Active Antennas", Icon: "radio-tower", Codes: "WAA", Count: 4, Floor: 5, Size: 10, Range: "10.0.0.219 - 10.0.0.228", Used: 2, Capacity: 10, Percent: 20},
			{Key: "OTHERS", Name: "Non-Green-GO", Icon: "cpu", Count: 6, Floor: 5, Size: 14, Range: "10.0.0.229 - 10.0.0.242", Used: 3, Capacity: 14, Percent: 21, Locked: true},
		},
	}
}

// docSinglePlan is a dante/sacn scope's single-elastic plan.
func docSinglePlan(name, icon, prefix string, used, cap, pct int) PoolPlanView {
	return PoolPlanView{
		Mode: "simple", Subnet: prefix + "0/24", Gateway: prefix + "1", FreeIPs: 0, ShowUtil: cap > 0,
		Rows: []PoolPlanRow{
			{Key: "r-static", Name: "Static reserve", Reserve: true, Count: 18, Prefix: prefix, Start: "2", End: "19"},
			{Key: "dynamic", Name: name, Icon: icon, IconEditable: true, Elastic: true, Weight: 1, Size: 235, Range: prefix + "20 - " + prefix + "254", Used: used, Capacity: cap, Percent: pct, Locked: true},
		},
	}
}

// docNetHealth is the network-health card state shared by the dashboard and the
// standalone nethealth shot. Every row uses the EXACT snapshot text its detector
// emits (see internal/netmon/detect_*.go), and each interface carries the full
// detector roster the real card shows - healthy, with the teaching findings
// (static-in-pool warn, firmware mix) on show.
func docNetHealth() NetHealthView {
	return NetHealthView{
		Interfaces: []NetHealthIface{
			{Iface: "eth0", ScopeName: "Green-GO Intercom", Available: true, LinkMode: "trunk", OKCount: 10, WarnCount: 1, Rows: []NetHealthRow{
				// 19 + 5 = the rig's 24 beltpacks (docGreengoPlan). Firmware findings
				// are per-interface detector rows on the greengo scope (attachFirmware).
				{Kind: "firmware", Severity: "warn", Title: "Mixed firmware: BPX - 19 on 5.2.1, 5 on 5.1.0", DetailRows: []string{
					"Stage Left · 10.0.0.22 · 5.1.0", "Followspot 2 · 10.0.0.31 · 5.1.0", "SM Desk · 10.0.0.20 · 5.1.0", "+2 more",
				}},
				{Kind: "rogue_dhcp", Severity: "ok", Title: "No rogue DHCP servers"},
				{Kind: "duplicate_ip", Severity: "ok", Title: "No address conflicts"},
				{Kind: "static_in_pool", Severity: "ok", Title: "No static devices in pools"},
				{Kind: "greengo", Severity: "ok", Title: "34 Evenution/Green-GO devices detected", DetailRows: []string{
					"BPX · 10.0.0.20 · 00:1f:80:20:4e:52", "BPX · 10.0.0.22 · 00:1f:80:20:4e:5e", "MCX · 10.0.0.160 · 00:1f:80:dc:2a:11",
				}},
				{Kind: "greengo_config", Severity: "ok", Title: "Green-GO config: Meridian_Main", Detail: "config Meridian_Main"},
				{Kind: "vlan", Severity: "ok", Title: "No unexpected VLAN tags"},
				{Kind: "igmp", Severity: "ok", Title: "IGMP querier present", Detail: "querier 10.0.0.2 v2 · on eth0"},
				{Kind: "ptp", Severity: "info", Title: "No PTP grandmaster seen"},
				{Kind: "lldp", Severity: "ok", Title: "Uplink: " + docSwitchCore + " / sfp-sfpplus1", Detail: "switch " + docSwitchCore + " port sfp-sfpplus1 · native VLAN 1"},
				{Kind: "storm", Severity: "ok", Title: "No broadcast storm"},
				{Kind: "idle", Severity: "ok", Title: "Active network traffic"},
			}},
			{Iface: "eth0.20", ScopeName: "Dante / AES67", Available: true, LinkMode: "trunk", OKCount: 8, Rows: []NetHealthRow{
				{Kind: "rogue_dhcp", Severity: "ok", Title: "No rogue DHCP servers"},
				{Kind: "duplicate_ip", Severity: "ok", Title: "No address conflicts"},
				{Kind: "static_in_pool", Severity: "ok", Title: "No static devices in pools"},
				{Kind: "greengo", Severity: "info", Title: "No Evenution/Green-GO devices seen"},
				{Kind: "greengo_config", Severity: "info", Title: "No Green-GO config announced"},
				{Kind: "vlan", Severity: "ok", Title: "No unexpected VLAN tags"},
				{Kind: "igmp", Severity: "ok", Title: "IGMP querier present", Detail: "querier 10.20.0.2 v3 · on eth0.20"},
				{Kind: "ptp", Severity: "ok", Title: "PTP GM 001dc1fffe0a813c (domain 0)", Detail: "grandmaster clock class 6"},
				// LLDP frames are untagged and link-scoped: only the physical eth0
				// socket sees them, so VLAN sub-interfaces report no neighbor.
				{Kind: "lldp", Severity: "info", Title: "No LLDP/CDP neighbor seen"},
				{Kind: "storm", Severity: "ok", Title: "No broadcast storm"},
				{Kind: "idle", Severity: "ok", Title: "Active network traffic"},
			}},
			{Iface: "eth0.30", ScopeName: "sACN / Art-Net", Available: true, LinkMode: "trunk", OKCount: 6, WarnCount: 1, Rows: []NetHealthRow{
				{Kind: "static_in_pool", Severity: "warn", Title: "Static device 10.30.0.31 (00:0b:02) is using a DHCP pool address", Detail: "10.30.0.31 (00:0b:02:4c:19:a7) · pool 10.30.0.20-254 · on eth0.30"},
				{Kind: "rogue_dhcp", Severity: "ok", Title: "No rogue DHCP servers"},
				{Kind: "duplicate_ip", Severity: "ok", Title: "No address conflicts"},
				{Kind: "greengo", Severity: "info", Title: "No Evenution/Green-GO devices seen"},
				{Kind: "greengo_config", Severity: "info", Title: "No Green-GO config announced"},
				{Kind: "vlan", Severity: "ok", Title: "No unexpected VLAN tags"},
				{Kind: "igmp", Severity: "ok", Title: "IGMP querier present", Detail: "querier 10.30.0.2 v2 · on eth0.30"},
				{Kind: "ptp", Severity: "info", Title: "No PTP grandmaster seen"},
				{Kind: "lldp", Severity: "info", Title: "No LLDP/CDP neighbor seen"},
				{Kind: "storm", Severity: "ok", Title: "No broadcast storm"},
				{Kind: "idle", Severity: "ok", Title: "Active network traffic"},
			}},
		},
	}
}

func docPinnedPorts() []PortRow {
	return []PortRow{
		{PortIdentity: "p1", RemoteID: docSwitchEdge, RemoteIDHex: "41:56:2d:45:64:67:65:2d:33", CircuitID: "ether3", CircuitIDHex: "65:74:68:65:72:33",
			IPAddress: "10.0.0.20", HWAddress: "00:1f:80:20:4e:52", Label: "SM Desk", Pinned: true, LastSeenText: "just now"},
		{PortIdentity: "p2", RemoteID: docSwitchEdge, RemoteIDHex: "41:56:2d:45:64:67:65:2d:33", CircuitID: "ether10", CircuitIDHex: "65:74:68:65:72:31:30",
			IPAddress: "10.0.0.22", HWAddress: "00:1f:80:20:4e:5e", Label: "Stage Left", Pinned: true, LastSeenText: "2m ago"},
		{PortIdentity: "p3", RemoteID: docSwitchCore, RemoteIDHex: "41:56:2d:43:6f:72:65:2d:31", CircuitID: "ether2", CircuitIDHex: "65:74:68:65:72:32",
			IPAddress: "10.0.0.160", HWAddress: "-", Label: "FOH Rack", Pinned: true, LastSeenText: "3d ago", Stale: true},
	}
}

func docLearnablePorts() []PortRow {
	return []PortRow{
		{PortIdentity: "p4", RemoteID: docSwitchEdge, RemoteIDHex: "41:56:2d:45:64:67:65:2d:33", CircuitID: "ether14", CircuitIDHex: "65:74:68:65:72:31:34",
			IPAddress: "10.0.0.187", HWAddress: "c8:ff:bf:0e:6f:e6", Hostname: "workstation", LastSeenText: "just now"},
		{PortIdentity: "p5", RemoteID: docSwitchEdge, RemoteIDHex: "41:56:2d:45:64:67:65:2d:33", CircuitID: "ether5", CircuitIDHex: "65:74:68:65:72:35",
			IPAddress: "10.0.0.24", HWAddress: "00:1f:80:20:4e:61", LastSeenText: "just now"},
		{PortIdentity: "p6", RemoteID: docSwitchCore, RemoteIDHex: "41:56:2d:43:6f:72:65:2d:31", CircuitID: "ether7", CircuitIDHex: "65:74:68:65:72:37",
			IPAddress: "10.0.0.161", HWAddress: "00:1f:80:dc:2a:11", LastSeenText: "5m ago"},
	}
}

// --- The six doc shots -------------------------------------------------------

func TestZZDocDashboard(t *testing.T) {
	docSkip(t)
	mk := func(s []int) (string, string) { return SparklinePoints(s), SparklineArea(s) }
	lp, la := mk([]int{57, 60, 62, 65, 67, 69, 71, 72, 72, 72})
	pp, pa := mk([]int{7, 8, 8, 9, 9, 10, 10, 10})
	rp, ra := mk([]int{6, 8, 6, 7, 5, 6, 7, 6})
	up, ua := mk([]int{22, 26, 24, 23, 25, 24, 24, 23})
	ptpP, ptpA := mk([]int{1, 1, 1, 1, 1, 1, 1, 1})

	v := DashboardView{
		Page:        docPage("ACTIVE", "/dashboard", "Dashboard"),
		ProfileName: "Meridian Tour 2026", Preset: "Multi-VLAN Trunk", Interface: "eth0, eth0.20, eth0.30", TotalScopes: 3,
		LLDP:       LLDPChip{Present: true, Switch: docSwitchCore, Port: "sfp-sfpplus1", NativeVLAN: "1"},
		CanReserve: true,
		Profiles: []ProfileOption{
			{ID: 1, Name: "Meridian Tour 2026", Active: true, ScopeCount: 3},
			{ID: 2, Name: "Shop Config", ScopeCount: 1},
		},
		Stats: []StatTileView{
			{Icon: "network", Label: "Active leases", Value: "72", Dot: "ok", Delta: "+2", DeltaDir: "up", Points: lp, Area: la},
			{Icon: "gauge", Label: "Pool utilization", Value: "10", Unit: "%", Dot: "ok", Points: pp, Area: pa},
			{Icon: "clock", Label: "Lease processing", Value: "6", Unit: "ms", Dot: "ok", Points: rp, Area: ra},
			{Icon: "globe", Label: "Uplink", Value: "23", Unit: "ms", Dot: "ok", Points: up, Area: ua},
			{Icon: "radio-tower", Label: "PTP grandmaster", Value: "Locked", Unit: "domain 0", Dot: "ok", Points: ptpP, Area: ptpA},
		},
		// Allocations mirror docGreengoPlan's device counts; overall 72/693 = 10%,
		// matching the utilization tile and the Address Pools rollup pill.
		Pools: []PoolRow{
			{ClassName: "GGO-BPX", Label: "Beltpacks", IPRange: "10.0.0.20 - 10.0.0.159", Allocated: 24, Capacity: 140, Percent: 17},
			{ClassName: "GGO-MCX-D", Label: "Multi-Channel", IPRange: "10.0.0.160 - 10.0.0.206", Allocated: 5, Capacity: 47, Percent: 11},
			{ClassName: "GGO-WP-X", Label: "Wall Panels", IPRange: "10.0.0.207 - 10.0.0.218", Allocated: 3, Capacity: 12, Percent: 25},
			{ClassName: "GGO-WAA", Label: "Active Antennas", IPRange: "10.0.0.219 - 10.0.0.228", Allocated: 2, Capacity: 10, Percent: 20},
			{ClassName: "OTHERS", Label: "Non-Green-GO", IPRange: "10.0.0.229 - 10.0.0.242", Allocated: 3, Capacity: 14, Percent: 21},
			{ClassName: "DANTE", Label: "Dante / AES67", IPRange: "10.20.0.20 - 10.20.0.254", Allocated: 26, Capacity: 235, Percent: 11},
			{ClassName: "SACN", Label: "sACN / Art-Net", IPRange: "10.30.0.20 - 10.30.0.254", Allocated: 9, Capacity: 235, Percent: 4},
		},
		NetHealth: docNetHealth(),
		PTP:       []PTPRow{{Severity: "ok", Domain: "domain 0", Text: "PTP grandmaster locked", ClockClass: 6}},
		RecentLeases: []LeaseRow{
			{IPAddress: "10.0.0.20", HWAddress: "00:1f:80:20:4e:52", Class: "GGO-BPX", ExpiresIn: "11m", ExpiresAt: time.Now().Unix() + 11*60, Presence: "online"},
			{IPAddress: "10.0.0.22", HWAddress: "00:1f:80:20:4e:5e", Class: "GGO-BPX", ExpiresIn: "9m", ExpiresAt: time.Now().Unix() + 9*60, Presence: "online"},
			{IPAddress: "10.0.0.160", HWAddress: "00:1f:80:dc:2a:11", Class: "GGO-MCX-D", ExpiresIn: "12m", ExpiresAt: time.Now().Unix() + 12*60, Presence: "online"},
			{IPAddress: "10.0.0.187", HWAddress: "c8:ff:bf:0e:6f:e6", Class: "OTHERS", ExpiresIn: "7m", ExpiresAt: time.Now().Unix() + 7*60, Presence: "online"},
			{IPAddress: "10.20.0.34", HWAddress: "00:1d:c1:0a:81:3c", Class: "DANTE", ExpiresIn: "13m", ExpiresAt: time.Now().Unix() + 13*60, Presence: "online"},
			{IPAddress: "10.0.0.31", HWAddress: "00:1f:80:20:4e:77", Class: "GGO-BPX", ExpiresIn: "10m", ExpiresAt: time.Now().Unix() + 10*60, Presence: "offline"},
		},
		// Real audit action tokens (auditActionLabel renders them) mixed with the
		// netmon/system events the real feed carries: those are audited with their
		// human-readable action verbatim and result INFO (gray dot), per
		// auditResult(SevInfo) and clockwatch's TIME_SYNCED entry.
		Activity: []AuditRow{
			{Action: "PIN_PORT", Target: docSwitchEdge + " / ether10", Result: "OK", Timestamp: "2026-07-04 17:42:10"},
			{Action: "RESERVATION_ADD", Target: "10.0.0.160", Result: "OK", Timestamp: "2026-07-04 17:31:04"},
			{Action: "LEASE_RELEASE", Target: "10.0.0.99", Result: "OK", Timestamp: "2026-07-04 16:58:22"},
			{Action: "PTP grandmaster seen", Target: "eth0.20 domain 0", Result: "INFO", Timestamp: "2026-07-04 14:07:02"},
			{Action: "Switch neighbor seen", Target: "eth0", Result: "INFO", Timestamp: "2026-07-04 14:06:31"},
			{Action: "APPLY_PROFILE", Target: "Meridian Tour 2026", Result: "OK", Timestamp: "2026-07-04 14:05:40"},
			{Action: "TIME_SYNCED", Target: "system clock", Result: "INFO", Timestamp: "2026-07-04 14:04:12"},
			{Action: "LOGIN", Target: "operator", Result: "OK", Timestamp: "2026-07-04 14:02:11"},
		},
		Pinned: docPinnedPorts(),
	}
	var b strings.Builder
	if err := Dashboard(v).Render(context.Background(), &b); err != nil {
		t.Fatal(err)
	}
	docWrite(t, "_preview_doc_dashboard.html", b.String())
}

func TestZZDocFactory(t *testing.T) {
	docSkip(t)
	v := FactoryView{Page: docPage("FACTORY", "/factory", "Secure this appliance")}
	var b strings.Builder
	if err := Factory(v).Render(context.Background(), &b); err != nil {
		t.Fatal(err)
	}
	docWrite(t, "_preview_doc_factory.html", b.String())
}

func TestZZDocWizard(t *testing.T) {
	docSkip(t)
	// The wizard builds its scope cards client-side (ggoApplyImported) from the
	// prefill JSON; each card's #poolplan-<i> region normally seeds via a server
	// round-trip that a static preview doesn't have. So: render the page with the
	// prefill, render each scope's PoolPlan separately into hidden stashes, and
	// append a script that swaps them in after the page JS has built the cards.
	prefill := `{"name":"Meridian Tour 2026","scopes":[` +
		`{"name":"Green-GO Intercom","preset":"greengo","vlan_id":0,"cidr":"10.0.0.0/24","uplink":{"enabled":false}},` +
		`{"name":"Dante / AES67","preset":"dante","vlan_id":20,"cidr":"10.20.0.0/24","uplink":{"enabled":false}},` +
		`{"name":"sACN / Art-Net","preset":"sacn","vlan_id":30,"cidr":"10.30.0.0/24","uplink":{"enabled":false}}]}`
	v := SetupView{
		Page:        docPage("ONBOARDING", "/setup", "Profile Setup Wizard"),
		PrefillJSON: prefill,
		ShieldState: "Active", LinkState: "Trunk", Interface: "eth0", LinkDetail: "tagged VIDs seen: 20, 30",
		UplinkEnabled: true, UplinkSSID: "Venue-Production",
	}
	var b strings.Builder
	if err := Setup(v).Render(context.Background(), &b); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	plan0 := docGreengoPlan(false)
	plan0.Heading = "Devices & pools"
	plan0.SizePresets = true
	plan0.ActiveSize = "medium"
	plan0.RegionID = "poolplan-0"
	plan1 := docSinglePlan("Dante / AES67", "bridge", "10.20.0.", 0, 0, 0)
	plan1.Heading = "Devices & pools"
	plan1.SizePresets = true
	plan1.ActiveSize = "flat"
	plan1.RegionID = "poolplan-1"
	plan2 := docSinglePlan("sACN / Art-Net", "cpu", "10.30.0.", 0, 0, 0)
	plan2.Heading = "Devices & pools"
	plan2.SizePresets = true
	plan2.ActiveSize = "flat"
	plan2.RegionID = "poolplan-2"

	var stash strings.Builder
	for i, p := range []PoolPlanView{plan0, plan1, plan2} {
		stash.WriteString(`<div id="doc-plan-`)
		stash.WriteString(itoa(i))
		stash.WriteString(`" hidden>`)
		if err := PoolPlan(p).Render(ctx, &stash); err != nil {
			t.Fatal(err)
		}
		stash.WriteString(`</div>`)
	}
	stash.WriteString(`<script>window.addEventListener('load', function () {
		for (var i = 0; i < 3; i++) {
			var src = document.getElementById('doc-plan-' + i), host = document.getElementById('poolplan-' + i);
			if (src && host) { host.outerHTML = src.innerHTML; src.remove(); }
		}
	});</script>`)

	html := strings.Replace(b.String(), "</body>", stash.String()+"</body>", 1)
	docWrite(t, "_preview_doc_wizard.html", html)
}

func TestZZDocPools(t *testing.T) {
	docSkip(t)
	gg := docGreengoPlan(true)
	gg.Heading = "Address pools"
	gg.RegionID = "poolplan-0"
	gg.FieldPrefix = "scopes[0][pool]"
	gg.EditAction = "/pools/edit"
	gg.SaveAction = "/pools/save?s=0&mode=simple"
	dante := docSinglePlan("Dante / AES67", "bridge", "10.20.0.", 26, 235, 11)
	dante.Heading = "Address pools"
	dante.RegionID = "poolplan-1"
	dante.FieldPrefix = "scopes[1][pool]"
	dante.EditAction = "/pools/edit"
	dante.SaveAction = "/pools/save?s=1&mode=simple"
	sacn := docSinglePlan("sACN / Art-Net", "cpu", "10.30.0.", 9, 235, 4)
	sacn.Heading = "Address pools"
	sacn.RegionID = "poolplan-2"
	sacn.FieldPrefix = "scopes[2][pool]"
	sacn.EditAction = "/pools/edit"
	sacn.SaveAction = "/pools/save?s=2&mode=simple"

	v := PoolsView{
		Page: docPage("ACTIVE", "/pools", "DHCP Pools"),
		Profiles: []ProfileOption{
			{ID: 1, Name: "Meridian Tour 2026", Active: true, ScopeCount: 3},
		},
		Scopes: []PoolScopeView{
			{Title: "Green-GO Intercom · 10.0.0.0/24", Plan: gg, Services: ScopeServicesView{RegionID: "svc-0", DerivedGateway: "10.0.0.1", GlobalLease: 800}, UplinkAvailable: true, UplinkEnabled: true},
			{Title: "Dante / AES67 · VLAN 20 · 10.20.0.0/24", Plan: dante, Services: ScopeServicesView{RegionID: "svc-1", DerivedGateway: "10.20.0.1", GlobalLease: 800}, UplinkAvailable: true},
			{Title: "sACN / Art-Net · VLAN 30 · 10.30.0.0/24", Plan: sacn, Services: ScopeServicesView{RegionID: "svc-2", DerivedGateway: "10.30.0.1", GlobalLease: 800}, UplinkAvailable: true},
		},
	}
	var b strings.Builder
	if err := Pools(v).Render(context.Background(), &b); err != nil {
		t.Fatal(err)
	}
	docWrite(t, "_preview_doc_pools.html", b.String())
}

func TestZZDocNetHealth(t *testing.T) {
	docSkip(t)
	ctx := context.Background()
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en" data-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><link rel="stylesheet" href="style.css"><title>Network health</title></head><body><main class="container"><div class="dash">`)
	if err := NetHealth(docNetHealth()).Render(ctx, &b); err != nil {
		t.Fatal(err)
	}
	b.WriteString(`</div></main></body></html>`)
	docWrite(t, "_preview_doc_nethealth.html", b.String())
}

func TestZZDocPinning(t *testing.T) {
	docSkip(t)
	v := PinningView{
		Page:      docPage("ACTIVE", "/pinning", "Port Pinning"),
		Pinned:    docPinnedPorts(),
		Learnable: docLearnablePorts(),
	}
	var b strings.Builder
	if err := Pinning(v).Render(context.Background(), &b); err != nil {
		t.Fatal(err)
	}
	docWrite(t, "_preview_doc_pinning.html", b.String())
}
