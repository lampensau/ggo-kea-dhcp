package web

import (
	"net"
	"testing"

	"ggo-kea-dhcp/internal/web/views"
)

// TestStatusPillView_Aggregates proves statusPillView sums per-interface
// warn/err counts and collects warn+error row titles into Details. Firmware
// mismatches ride along as regular per-interface warn rows (attachFirmware),
// so no separate aggregation path exists. (s.health is nil here, so only the
// netmon contributions are exercised.)
func TestStatusPillView_Aggregates(t *testing.T) {
	s, _ := newTestServer(t)

	nh := views.NetHealthView{
		Interfaces: []views.NetHealthIface{
			{
				Iface:     "eth0",
				WarnCount: 2,
				ErrCount:  2,
				Rows: []views.NetHealthRow{
					{Severity: "warn", Title: "Rogue DHCP"},
					{Kind: "firmware", Severity: "warn", Title: "Mixed firmware: BPX - 2 on 5.1, 1 on 5.0"},
					{Severity: "error", Title: "Duplicate IP"},
					{Severity: "ok", Title: "All good"},   // not surfaced
					{Severity: "info", Title: "Neighbor"}, // not surfaced
				},
			},
			{Iface: "eth0.10", WarnCount: 3, ErrCount: 0},
		},
	}

	v := s.statusPillView("ACTIVE", nh)
	if v.State != "ACTIVE" {
		t.Errorf("State = %q want ACTIVE", v.State)
	}
	// 2+3 interface warns (firmware included); 2+0 errs.
	if v.WarnCount != 5 {
		t.Errorf("WarnCount = %d want 5", v.WarnCount)
	}
	if v.ErrCount != 2 {
		t.Errorf("ErrCount = %d want 2", v.ErrCount)
	}
	// Details: the warn/error row titles, each prefixed with their interface so
	// identical warnings on different scopes are distinguishable (ok/info excluded).
	wantDetails := map[string]bool{
		"eth0: Rogue DHCP":   true,
		"eth0: Duplicate IP": true,
		"eth0: Mixed firmware: BPX - 2 on 5.1, 1 on 5.0": true,
	}
	if len(v.Details) != len(wantDetails) {
		t.Fatalf("Details = %v, want the 3 actionable lines", v.Details)
	}
	for _, d := range v.Details {
		if !wantDetails[d] {
			t.Errorf("unexpected detail %q", d)
		}
	}
}

// TestStatusPillView_Empty proves a clean network yields a zero-count pill.
func TestStatusPillView_Empty(t *testing.T) {
	s, _ := newTestServer(t)
	v := s.statusPillView("ACTIVE", views.NetHealthView{})
	if v.WarnCount != 0 || v.ErrCount != 0 || len(v.Details) != 0 {
		t.Errorf("clean network should yield a zero pill, got %+v", v)
	}
}

// TestPresenceByIP_NoProber asserts the presence reader degrades safely when
// no ARP prober is attached (the test-server default): an empty set, unavailable.
func TestPresenceByIP_NoProber(t *testing.T) {
	s, _ := newTestServer(t)
	reachable, available := s.presenceByIP()
	if available {
		t.Error("available should be false without an ARP prober")
	}
	if reachable == nil || len(reachable) != 0 {
		t.Errorf("reachable should be an empty (non-nil) map, got %v", reachable)
	}
}

// TestSubnetIDForIP maps an IP to the active profile's Kea subnet-id (scope
// index + 1), and fails closed for an out-of-subnet address or no active profile.
func TestSubnetIDForIP(t *testing.T) {
	s, _ := newTestServer(t)

	// No active profile: fail closed.
	if _, ok := s.subnetIDForIP(net.ParseIP("10.0.0.5")); ok {
		t.Fatal("subnetIDForIP should fail closed with no active profile")
	}

	seedScopePreset(t, s, "greengo") // 10.0.0.0/24, the only scope -> subnet-id 1

	if id, ok := s.subnetIDForIP(net.ParseIP("10.0.0.5")); !ok || id != 1 {
		t.Errorf("in-subnet IP -> (%d,%v), want (1,true)", id, ok)
	}
	if _, ok := s.subnetIDForIP(net.ParseIP("192.168.1.1")); ok {
		t.Error("out-of-subnet IP should not match any subnet")
	}
}

// TestListProfiles orders profiles active-first then newest, counts each
// profile's scopes, and excludes rollback stash profiles.
func TestListProfiles(t *testing.T) {
	s, _ := newTestServer(t)

	// Inactive, older profile with 2 scopes.
	r1, _ := s.sqlite.Exec("INSERT INTO profiles (name, active) VALUES ('Old', 0)")
	p1, _ := r1.LastInsertId()
	for i := 0; i < 2; i++ {
		if _, err := s.sqlite.Exec(
			"INSERT INTO scopes (profile_id, vlan_id, cidr, preset) VALUES (?,?,?,?)",
			p1, 0, "10.0.0.0/24", "greengo"); err != nil {
			t.Fatalf("seed scope: %v", err)
		}
	}
	// Active profile with 1 scope (must sort first despite a lower id).
	r2, _ := s.sqlite.Exec("INSERT INTO profiles (name, active) VALUES ('Live', 1)")
	p2, _ := r2.LastInsertId()
	if _, err := s.sqlite.Exec(
		"INSERT INTO scopes (profile_id, vlan_id, cidr, preset) VALUES (?,?,?,?)",
		p2, 0, "10.0.1.0/24", "greengo"); err != nil {
		t.Fatalf("seed scope: %v", err)
	}
	// A rollback stash: must be excluded from the switcher.
	if _, err := s.sqlite.Exec("INSERT INTO profiles (name, active) VALUES ('Live.stash-7', 0)"); err != nil {
		t.Fatalf("seed stash: %v", err)
	}

	got := s.listProfiles()
	if len(got) != 2 {
		t.Fatalf("listProfiles returned %d, want 2 (stash excluded): %+v", len(got), got)
	}
	if !got[0].Active || got[0].Name != "Live" || got[0].ScopeCount != 1 {
		t.Errorf("first entry should be active Live (1 scope), got %+v", got[0])
	}
	if got[1].Active || got[1].Name != "Old" || got[1].ScopeCount != 2 {
		t.Errorf("second entry should be inactive Old (2 scopes), got %+v", got[1])
	}
	for _, p := range got {
		if p.Name == "Live.stash-7" {
			t.Error("rollback stash profile must not appear in the switcher")
		}
	}
}
