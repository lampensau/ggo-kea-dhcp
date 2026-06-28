package views

import (
	"context"
	"strings"
	"testing"

	"github.com/a-h/templ"
)

// TestAuditActionLabel: SCREAMING_SNAKE tokens humanize; already-human strings (netmon
// events) pass through verbatim so acronyms like DHCP are not lowercased.
func TestAuditActionLabel(t *testing.T) {
	cases := map[string]string{
		"LEASE_REBALANCE":            "Lease rebalance",
		"APPLY_PROFILE":              "Profile applied",
		"Static device in DHCP pool": "Static device in DHCP pool",
		"IGMP querier present":       "IGMP querier present",
	}
	for in, want := range cases {
		if got := auditActionLabel(in); got != want {
			t.Errorf("auditActionLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func render(t *testing.T, c templ.Component) string {
	t.Helper()
	var sb strings.Builder
	if err := c.Render(context.Background(), &sb); err != nil {
		t.Fatalf("render: %v", err)
	}
	return sb.String()
}

// TestEveryPageRenders renders each page to completion with a representative view
// model and asserts a distinctive marker. This catches templ runtime errors
// (bad attribute expressions, nil derefs) without running a server.
func TestEveryPageRenders(t *testing.T) {
	active := PageData{State: "ACTIVE", Authenticated: true, CSRFToken: "tok", CurrentPath: "/dashboard"}
	onboard := PageData{State: "ONBOARDING", Authenticated: true, CSRFToken: "tok"}

	cases := []struct {
		name   string
		comp   templ.Component
		expect string
	}{
		{"dashboard", Dashboard(DashboardView{Page: active, ProfileName: "Show", Preset: "Green-GO", Interface: "eth0",
			TotalScopes: 2, LeaseCount: 7, UplinkActive: false,
			Pools: []PoolRow{{ClassName: "GGO-BPX", Label: "Beltpacks", IPRange: "10.0.0.20 - 10.0.0.254", Allocated: 5, Capacity: 235, Percent: 2}}}), `id="pool-table"`},
		{"dashboard-empty", Dashboard(DashboardView{Page: active}), `No address pools`},
		{"leases", Leases(LeasesView{Page: active, Leases: []LeaseRow{{IPAddress: "10.0.0.50", HWAddress: "00:1f:80:aa:bb:cc", Class: "GGO-BPX", ExpiresIn: "30 min"}}}), `id="leases-body"`},
		{"leases-error", Leases(LeasesView{Page: active, Error: "Kea is down"}), `Kea is down`},
		{"diagnostics", Diagnostics(DiagnosticsView{Page: active, Checks: []DiagRow{{Status: "OK", Name: "Kea", Detail: "3.0"}}, Logs: []AuditRow{{Timestamp: "t", Actor: "admin", Action: "LOGIN", Result: "SUCCESS"}}}), `Prerequisite checks`},
		{"diagnostics-empty", Diagnostics(DiagnosticsView{Page: active}), `No audit entries`},
		{"factory", Factory(FactoryView{Page: PageData{State: "FACTORY"}}), `Create Administrator`},
		{"settings", Settings(SettingsView{Page: active, OnboardingIP: "10.0.0.1/24", GlobalDNS: "1.1.1.1"}), `/settings/restore`},
		{"settings-danger", Settings(SettingsView{Page: active, OnboardingIP: "10.0.0.1/24"}), `dlg-factory`},
		{"pinning", Pinning(PinningView{Page: active, Pinned: []PortRow{{PortIdentity: "1/2", IPAddress: "10.0.0.9", HWAddress: "00:1f:80:20:aa:bb", Pinned: true}}, Learnable: []PortRow{{PortIdentity: "1/3", IPAddress: "10.0.0.12"}}}), `id="pinned-body"`},
		{"pinning-nomdb", Pinning(PinningView{Page: active, Error: "MariaDB not connected"}), `MariaDB not connected`},
		{"setup", Setup(SetupView{Page: onboard, ShieldState: "Active", LinkState: "Trunk", Interface: "eth0"}), `ggo-scope-tpl`},
		{"setup-disconnected", Setup(SetupView{Page: onboard, ShieldState: "Suspended", LinkState: "Disconnected", Interface: "eth0"}), `Link: Disconnected`},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			html := render(t, c.comp)
			if !strings.Contains(html, c.expect) {
				t.Errorf("%s render missing %q", c.name, c.expect)
			}
			// Every authenticated page must carry the shell + CSRF meta.
			if !strings.Contains(html, "/static/datastar.js") {
				t.Errorf("%s missing Datastar runtime", c.name)
			}
		})
	}
}
