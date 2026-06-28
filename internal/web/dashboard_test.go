package web

import (
	"testing"

	"ggo-kea-dhcp/internal/kea"
	"ggo-kea-dhcp/internal/web/views"
)

func TestDashboardPresetLabel(t *testing.T) {
	cases := []struct {
		scopes []ScopeConfig
		want   string
	}{
		{nil, "None"},
		{[]ScopeConfig{{Preset: "greengo"}}, "Green-GO Intercom"},
		{[]ScopeConfig{{Preset: "dante"}}, "Dante / AES67 Audio"},
		{[]ScopeConfig{{Preset: "sacn"}}, "sACN / Art-Net Lighting"},
		{[]ScopeConfig{{Preset: "generic"}}, "Generic / Management"},
		{[]ScopeConfig{{Preset: "greengo"}, {Preset: "dante"}}, "Multi-VLAN Trunk"},
	}
	for _, c := range cases {
		if got := dashboardPresetLabel(c.scopes); got != c.want {
			t.Errorf("dashboardPresetLabel(%d scopes)=%q want %q", len(c.scopes), got, c.want)
		}
	}
}

// A non-greengo scope seeds a static reserve (.2–.19) plus one elastic catch-all
// that fills the rest of the subnet - the same plan the wizard produces - so the
// dashboard shows a single DHCP pool over .20–.254 (the reserve row is omitted).
func TestPoolDataForScopeDante(t *testing.T) {
	ds := ScopeConfig{Preset: "dante", CIDR: "10.0.0.1/24"}
	leases := []kea.ActiveLease{
		{IPAddress: "10.0.0.50"}, // in the elastic pool (.20 - .254)
		{IPAddress: "10.0.0.5"},  // inside the static reserve, below the pool
	}
	data := poolDataForScope(ds, leases)
	if len(data) != 1 {
		t.Fatalf("got %d pools want 1 (reserve is not a DHCP pool)", len(data))
	}
	p := data[0]
	if p.Label != "Dante / AES67" {
		t.Errorf("Label = %v want \"Dante / AES67\"", p.Label)
	}
	if p.IPRange != "10.0.0.20 - 10.0.0.254" {
		t.Errorf("IPRange = %v want 10.0.0.20 - 10.0.0.254", p.IPRange)
	}
	if p.Allocated != 1 {
		t.Errorf("Allocated = %v want 1", p.Allocated)
	}
	if p.Capacity != 235 {
		t.Errorf("Capacity = %v want 235", p.Capacity)
	}
}

func TestPoolDataForScopeBadCIDR(t *testing.T) {
	if data := poolDataForScope(ScopeConfig{Preset: "dante", CIDR: "nonsense"}, nil); data != nil {
		t.Errorf("bad CIDR should yield nil pools, got %v", data)
	}
}

// TestPoolDataForScopeGreengoByClass locks in the fix for the antenna-pool bug:
// a greengo pool's occupancy is counted by the lease's device CLASS, not by which
// numeric range the address falls in. A beltpack pinned to an address inside the
// antenna range must count as beltpack pressure and leave the antenna pool at 0.
func TestPoolDataForScopeGreengoByClass(t *testing.T) {
	sc := ScopeConfig{Preset: "greengo", CIDR: "10.0.0.0/24"}
	// 00:1f:80:20:.. classifies as GGO-BPX (beltpack); the address .100 lands
	// inside the WAA (antenna) pool's numeric range, the trap the old code fell in.
	leases := []kea.ActiveLease{{IPAddress: "10.0.0.100", HWAddress: "00:1f:80:20:00:01"}}

	rows := poolDataForScope(sc, leases)
	var bpx, waa *views.PoolRow
	for i := range rows {
		switch rows[i].ClassName {
		case "GGO-BPX":
			bpx = &rows[i]
		case "GGO-WAA":
			waa = &rows[i]
		}
	}
	if bpx == nil || waa == nil {
		t.Fatalf("expected GGO-BPX and GGO-WAA pools, got %+v", rows)
	}
	if bpx.Allocated != 1 {
		t.Errorf("beltpack pool Allocated=%d want 1 (counted by class)", bpx.Allocated)
	}
	if waa.Allocated != 0 {
		t.Errorf("antenna pool Allocated=%d want 0 (beltpack must not inflate it)", waa.Allocated)
	}
}

func TestLeaseExpiry(t *testing.T) {
	cases := []struct {
		expire, now int64
		want        string
	}{
		{0, 1000, "—"},  // reservation / permanent
		{-1, 1000, "—"}, // defensive
		{500, 1000, "expired"},
		{1000 + 1800, 1000, "30m"},
		{1000 + 3600, 1000, "1h"},
		{1000 + 5400, 1000, "1h 30m"},
	}
	for _, c := range cases {
		if got := leaseExpiry(c.expire, c.now); got != c.want {
			t.Errorf("leaseExpiry(%d,%d)=%q want %q", c.expire, c.now, got, c.want)
		}
	}
}

func TestLeaseExpiryFrom(t *testing.T) {
	cases := []struct {
		cltt, validLft, now int64
		want                string
	}{
		{0, 4000, 1000, "—"},              // no cltt (e.g. reservation / absent timing)
		{1000, 0, 1000, "—"},              // no lifetime
		{1000, 0xffffffff, 1000, "never"}, // Kea infinite-lease sentinel
		{1000, 30, 1005, "25s"},           // sub-minute (e.g. a 30s test lease) shows seconds, not "0m"
		{1000, 3600, 1000, "1h"},          // expiry = cltt + valid-lft = now + 3600
		{1000, 1800, 2000, "13m"},         // 800s remaining
		{1000, 1800, 4000, "expired"},     // already past
	}
	for _, c := range cases {
		if got := leaseExpiryFrom(c.cltt, c.validLft, c.now); got != c.want {
			t.Errorf("leaseExpiryFrom(%d,%d,%d)=%q want %q", c.cltt, c.validLft, c.now, got, c.want)
		}
	}
}

func TestBuildLeaseRowsSortedByIP(t *testing.T) {
	leases := []kea.ActiveLease{
		{IPAddress: "10.0.0.20"},
		{IPAddress: "10.0.0.5"},
		{IPAddress: "10.0.0.100"},
	}
	rows := buildLeaseRows(leases)
	got := []string{rows[0].IPAddress, rows[1].IPAddress, rows[2].IPAddress}
	want := []string{"10.0.0.5", "10.0.0.20", "10.0.0.100"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d = %q want %q (IP-sorted)", i, got[i], want[i])
		}
	}
}

func TestFilterLeasesByFriendlyLabel(t *testing.T) {
	rows := []views.LeaseRow{
		{IPAddress: "10.0.0.1", Class: "GGO-BPX"}, // label "Beltpacks"
		{IPAddress: "10.0.0.2", Class: "GGO-WAA"}, // label "Active antennas"
	}
	got := filterLeases(rows, "beltpack")
	if len(got) != 1 || got[0].Class != "GGO-BPX" {
		t.Errorf("filter 'beltpack' matched %+v; want only the GGO-BPX row via its label", got)
	}
}

func TestSortPoolsByPressure(t *testing.T) {
	pools := []views.PoolRow{
		{Label: "idle", Allocated: 0, Percent: 0},
		{Label: "low", Allocated: 3, Percent: 20},
		{Label: "high", Allocated: 5, Percent: 80},
	}
	sortPoolsByPressure(pools)
	if pools[0].Label != "high" || pools[2].Label != "idle" {
		t.Errorf("order=%q,%q,%q want high..idle (most pressure first)", pools[0].Label, pools[1].Label, pools[2].Label)
	}
}
