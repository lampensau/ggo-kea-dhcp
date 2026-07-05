package web

import (
	"testing"
	"time"

	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/kea"
	"ggo-kea-dhcp/internal/netmon"
	"ggo-kea-dhcp/internal/web/views"
)

// TestDedupeStaleLeases_AllBranches exercises every branch of
// dedupeStaleLeases: empty-MAC always kept, same-MAC+same-subnet collapses to the
// freshest cltt, same-MAC+different-subnet kept, and first-occurrence ordering.
func TestDedupeStaleLeases_AllBranches(t *testing.T) {
	t.Run("empty MAC always kept", func(t *testing.T) {
		in := []kea.ActiveLease{
			{IPAddress: "10.0.0.10", HWAddress: "", SubnetID: 1, Cltt: 100},
			{IPAddress: "10.0.0.11", HWAddress: "", SubnetID: 1, Cltt: 200},
		}
		out := dedupeStaleLeases(in)
		if len(out) != 2 {
			t.Fatalf("empty-MAC leases must all be kept, got %d: %+v", len(out), out)
		}
	})

	t.Run("same MAC and subnet collapses to freshest", func(t *testing.T) {
		in := []kea.ActiveLease{
			{IPAddress: "10.0.0.10", HWAddress: "00:1f:80:aa:bb:cc", SubnetID: 1, Cltt: 100}, // stale
			{IPAddress: "10.0.0.20", HWAddress: "00:1f:80:aa:bb:cc", SubnetID: 1, Cltt: 200}, // fresh
		}
		out := dedupeStaleLeases(in)
		if len(out) != 1 {
			t.Fatalf("same MAC+subnet should collapse to 1, got %d: %+v", len(out), out)
		}
		if out[0].IPAddress != "10.0.0.20" || out[0].Cltt != 200 {
			t.Errorf("kept the wrong (stale) lease: %+v, want the cltt=200 / 10.0.0.20 one", out[0])
		}
	})

	t.Run("freshest wins regardless of input order", func(t *testing.T) {
		// Fresh lease appears FIRST; the later, older one must not overwrite it.
		in := []kea.ActiveLease{
			{IPAddress: "10.0.0.20", HWAddress: "00:1f:80:aa:bb:cc", SubnetID: 1, Cltt: 200}, // fresh first
			{IPAddress: "10.0.0.10", HWAddress: "00:1f:80:aa:bb:cc", SubnetID: 1, Cltt: 100}, // stale second
		}
		out := dedupeStaleLeases(in)
		if len(out) != 1 {
			t.Fatalf("want 1, got %d", len(out))
		}
		if out[0].IPAddress != "10.0.0.20" {
			t.Errorf("an older later lease overwrote the fresher earlier one: %+v", out[0])
		}
	})

	t.Run("same MAC different subnet both kept", func(t *testing.T) {
		// A trunked device legitimately holds one lease per VLAN/subnet.
		in := []kea.ActiveLease{
			{IPAddress: "10.0.0.10", HWAddress: "00:1f:80:aa:bb:cc", SubnetID: 1, Cltt: 100},
			{IPAddress: "10.0.1.10", HWAddress: "00:1f:80:aa:bb:cc", SubnetID: 2, Cltt: 200},
		}
		out := dedupeStaleLeases(in)
		if len(out) != 2 {
			t.Fatalf("different subnets must be kept, got %d: %+v", len(out), out)
		}
	})

	t.Run("MAC formatting is normalized before comparison", func(t *testing.T) {
		// Same MAC, different separators/case: normalizeMAC must collapse them.
		in := []kea.ActiveLease{
			{IPAddress: "10.0.0.10", HWAddress: "00:1F:80:AA:BB:CC", SubnetID: 1, Cltt: 100},
			{IPAddress: "10.0.0.20", HWAddress: "001f80aabbcc", SubnetID: 1, Cltt: 200},
		}
		out := dedupeStaleLeases(in)
		if len(out) != 1 {
			t.Fatalf("normalized-equal MACs should collapse, got %d: %+v", len(out), out)
		}
		if out[0].IPAddress != "10.0.0.20" {
			t.Errorf("kept wrong lease %+v", out[0])
		}
	})

	t.Run("equal cltt keeps the first occurrence", func(t *testing.T) {
		in := []kea.ActiveLease{
			{IPAddress: "10.0.0.10", HWAddress: "00:1f:80:aa:bb:cc", SubnetID: 1, Cltt: 100},
			{IPAddress: "10.0.0.20", HWAddress: "00:1f:80:aa:bb:cc", SubnetID: 1, Cltt: 100},
		}
		out := dedupeStaleLeases(in)
		if len(out) != 1 {
			t.Fatalf("want 1, got %d", len(out))
		}
		// Strictly-greater cltt wins, so equal cltt leaves the first in place.
		if out[0].IPAddress != "10.0.0.10" {
			t.Errorf("equal cltt should keep the first occurrence, got %+v", out[0])
		}
	})

	t.Run("nil and empty input", func(t *testing.T) {
		if out := dedupeStaleLeases(nil); len(out) != 0 {
			t.Errorf("nil input should yield empty, got %+v", out)
		}
		if out := dedupeStaleLeases([]kea.ActiveLease{}); len(out) != 0 {
			t.Errorf("empty input should yield empty, got %+v", out)
		}
	})

	t.Run("distinct MACs preserve order", func(t *testing.T) {
		in := []kea.ActiveLease{
			{IPAddress: "10.0.0.10", HWAddress: "00:1f:80:00:00:01", SubnetID: 1, Cltt: 100},
			{IPAddress: "10.0.0.11", HWAddress: "00:1f:80:00:00:02", SubnetID: 1, Cltt: 100},
			{IPAddress: "10.0.0.12", HWAddress: "00:1f:80:00:00:03", SubnetID: 1, Cltt: 100},
		}
		out := dedupeStaleLeases(in)
		if len(out) != 3 {
			t.Fatalf("distinct MACs all kept, got %d", len(out))
		}
		if out[0].IPAddress != "10.0.0.10" || out[1].IPAddress != "10.0.0.11" || out[2].IPAddress != "10.0.0.12" {
			t.Errorf("order not preserved: %+v", out)
		}
	})
}

// TestUnifiedLeaseRowsWithPins_NoMariaDB drives the merge with a nil-MariaDB
// server (the test harness default): no reservations exist, so the rows are the
// deduped active leases, sorted by IP, with classification filled in. An expired
// lease is dropped by the activeLeases pre-filter.
func TestUnifiedLeaseRowsWithPins_NoMariaDB(t *testing.T) {
	s, _ := newTestServer(t)
	now := time.Now().Unix()

	leases := []kea.ActiveLease{
		// Active (fresh) leases out of IP order to prove the sort.
		{IPAddress: "10.0.0.50", HWAddress: "00:1f:80:20:aa:aa", SubnetID: 1, Cltt: now, ValidLft: 3600},
		{IPAddress: "10.0.0.20", HWAddress: "00:1f:80:20:bb:bb", SubnetID: 1, Cltt: now, ValidLft: 3600},
		// Expired lease (cltt+valid-lft in the past): dropped by activeLeases.
		{IPAddress: "10.0.0.99", HWAddress: "00:1f:80:20:cc:cc", SubnetID: 1, Cltt: now - 7200, ValidLft: 60},
	}

	rows := s.unifiedLeaseRowsWithPins(t.Context(), leases, map[string]bool{}, false, nil, nil, nil, nil)
	if len(rows) != 2 {
		t.Fatalf("expected 2 active rows (expired dropped), got %d: %+v", len(rows), rows)
	}
	if rows[0].IPAddress != "10.0.0.20" || rows[1].IPAddress != "10.0.0.50" {
		t.Errorf("rows not sorted by IP: %+v", rows)
	}
	for _, r := range rows {
		if r.Class == "" {
			t.Errorf("row %s missing class", r.IPAddress)
		}
		if r.Reserved || r.PortPinned {
			t.Errorf("row %s should not be reserved/pinned without MariaDB: %+v", r.IPAddress, r)
		}
	}
}

// TestUnifiedLeaseRowsWithPins_Presence verifies the per-IP presence overlay:
// an IP in the reachable set is "online", an absent one is "offline" (only when
// probing is available).
func TestUnifiedLeaseRowsWithPins_Presence(t *testing.T) {
	s, _ := newTestServer(t)
	now := time.Now().Unix()
	leases := []kea.ActiveLease{
		{IPAddress: "10.0.0.20", HWAddress: "00:1f:80:20:bb:bb", SubnetID: 1, Cltt: now, ValidLft: 3600},
		{IPAddress: "10.0.0.50", HWAddress: "00:1f:80:20:aa:aa", SubnetID: 1, Cltt: now, ValidLft: 3600},
	}
	reachable := map[string]bool{"10.0.0.20": true}

	rows := s.unifiedLeaseRowsWithPins(t.Context(), leases, reachable, true, nil, nil, nil, nil)
	byIP := map[string]string{}
	for _, r := range rows {
		byIP[r.IPAddress] = r.Presence
	}
	if byIP["10.0.0.20"] != "online" {
		t.Errorf("reachable IP should be online, got %q", byIP["10.0.0.20"])
	}
	if byIP["10.0.0.50"] != "offline" {
		t.Errorf("unreachable IP should be offline, got %q", byIP["10.0.0.50"])
	}
}

// TestUnifiedLeaseRowsWithPins_AwaitingRenewal verifies the passively-observed
// unleased-pool-host merge: a host with no lease/reservation row is appended as an
// online "awaiting" (or "static" when Flagged) row with no expiry and no duplicate,
// while hosts already covered by a lease row (same IP or same MAC) are skipped.
func TestUnifiedLeaseRowsWithPins_AwaitingRenewal(t *testing.T) {
	s, _ := newTestServer(t)
	now := time.Now().Unix()
	leases := []kea.ActiveLease{
		{IPAddress: "10.0.0.20", HWAddress: "00:1f:80:20:bb:bb", SubnetID: 1, Cltt: now, ValidLft: 3600},
	}
	awaiting := []netmon.PoolHost{
		{IP: "10.0.0.20", MAC: "aa:aa:aa:aa:aa:01"},                // IP already leased - skipped
		{IP: "10.0.0.60", MAC: "00:1F:80:20:BB:BB"},                // MAC already leased (case-insensitive) - skipped
		{IP: "10.0.0.42", MAC: "00:1f:80:20:cc:cc"},                // genuinely new - awaiting row
		{IP: "10.0.0.77", MAC: "00:1f:80:20:dd:dd", Flagged: true}, // concluded static - static row
	}

	rows := s.unifiedLeaseRowsWithPins(t.Context(), leases, map[string]bool{}, true, nil, nil, awaiting, nil)
	if len(rows) != 3 {
		t.Fatalf("expected lease + 2 awaiting rows, got %d: %+v", len(rows), rows)
	}
	byIP := map[string]views.LeaseRow{}
	for _, r := range rows {
		byIP[r.IPAddress] = r
	}
	aw, ok := byIP["10.0.0.42"]
	if !ok || aw.NoLeaseState != "awaiting" {
		t.Fatalf("expected .42 awaiting row, got %+v", aw)
	}
	if aw.Presence != "online" {
		t.Errorf(".42 must be online by passive observation even though the ARP prober never probed it, got %q", aw.Presence)
	}
	if aw.ExpiresIn != "" || aw.Class == "" {
		t.Errorf(".42 row shape wrong (no expiry, classified): %+v", aw)
	}
	if st := byIP["10.0.0.77"]; st.NoLeaseState != "static" {
		t.Errorf("expected .77 static row, got %+v", st)
	}
	// The real lease row is untouched and sorted first.
	if rows[0].IPAddress != "10.0.0.20" || rows[0].NoLeaseState != "" {
		t.Errorf("lease row disturbed: %+v", rows[0])
	}
}

// TestFilterAwaitingByMAC proves the dashboard card applies the same reservation
// suppression as /leases: an awaiting host whose MAC holds a hw-address reservation
// is dropped (the reservation row represents it there), others pass through, and a
// nil set (no MariaDB) is a no-op.
func TestFilterAwaitingByMAC(t *testing.T) {
	awaiting := []netmon.PoolHost{
		{IP: "10.0.0.42", MAC: "00:1f:80:20:cc:cc"},
		{IP: "10.0.0.77", MAC: "00:1F:80:20:DD:DD"}, // reserved (case differs)
	}
	got := filterAwaitingByMAC(awaiting, map[string]db.HostReservation{normalizeMAC("00:1f:80:20:dd:dd"): {}})
	if len(got) != 1 || got[0].IP != "10.0.0.42" {
		t.Fatalf("expected only .42 to survive, got %+v", got)
	}
	if got := filterAwaitingByMAC(awaiting, nil); len(got) != 2 {
		t.Fatalf("nil MAC set must pass through, got %+v", got)
	}
}
