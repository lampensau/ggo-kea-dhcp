package web

import (
	"reflect"
	"testing"
	"time"

	"ggo-kea-dhcp/internal/kea"
	"ggo-kea-dhcp/internal/web/views"
)

// TestPinningFiltersExpiredLease guards the lease-filter both pinning paths now share:
// the /pinning page (pinning.go) and the dashboard/live pinnings card (fetchPinningSplit)
// both feed mergePortRows the activeLeases-filtered set, so an expired-not-yet-reclaimed
// lease can't surface a phantom learnable port on one view but not the other. (The
// fetchPinningSplit call site itself is MariaDB-gated and can't be unit-driven; this
// guards the filtering that makes the two consistent.)
func TestPinningFiltersExpiredLease(t *testing.T) {
	now := time.Now().Unix()
	expired := kea.ActiveLease{ClientID: "0061622f6364", HWAddress: "aa:bb", IPAddress: "10.0.0.50", SubnetID: 1, Cltt: now - 10000, ValidLft: 100} // cltt+lft in the past
	fresh := kea.ActiveLease{ClientID: "0078", HWAddress: "cc:dd", IPAddress: "10.0.0.51", SubnetID: 1}                                             // no timing -> active
	rows := mergePortRows(nil, nil, activeLeases([]kea.ActiveLease{expired, fresh}), nil, now)
	ips := map[string]bool{}
	for _, r := range rows {
		ips[r.IPAddress] = true
	}
	if ips["10.0.0.50"] {
		t.Fatalf("expired lease surfaced a phantom pinning port: %v", ips)
	}
	if !ips["10.0.0.51"] {
		t.Fatalf("fresh lease's port missing: %v", ips)
	}
}

func leaseRowIPs(rows []views.LeaseRow) map[string]bool {
	m := map[string]bool{}
	for _, r := range rows {
		m[r.IPAddress] = true
	}
	return m
}

// TestDashboardCardMatchesLeasesPage is the consistency guard the earlier unit tests
// missed: the dashboard "Active Leases" card and the /leases page must show the SAME
// set of leases for a given lease set. The original bug was a missing dedupeStaleLeases
// call on the card path only - both functions worked in isolation, but the two display
// paths diverged. This compares their actual output so "one path forgot to dedupe"
// fails the test.
func TestDashboardCardMatchesLeasesPage(t *testing.T) {
	s, _ := newTestServer(t)
	s.metrics = newMetricsStore() // buildDashboardViewWith reads s.metrics for the stat tiles

	// A device that moved switch ports: two active leases, same MAC + subnet (a stale
	// lease lingering under the old flex-id alongside the fresh one), plus an unrelated
	// device.
	leases := []kea.ActiveLease{
		{ClientID: "0061622f6364", HWAddress: "aa:bb:cc:dd:ee:ff", IPAddress: "10.0.0.89", SubnetID: 1, Cltt: 100},
		{ClientID: "0078", HWAddress: "aa:bb:cc:dd:ee:ff", IPAddress: "10.0.0.21", SubnetID: 1, Cltt: 200},
		{ClientID: "00aa", HWAddress: "11:22:33:44:55:66", IPAddress: "10.0.0.20", SubnetID: 1, Cltt: 150},
	}

	card := leaseRowIPs(s.buildDashboardViewWith(views.PageData{}, leases, netSnapshotData{}, false).RecentLeases)
	page := leaseRowIPs(s.unifiedLeaseRowsWithPins(leases, nil, false, nil, nil))

	if !reflect.DeepEqual(card, page) {
		t.Fatalf("dashboard card IPs %v != /leases IPs %v (a display path is missing dedupeStaleLeases)", card, page)
	}
	// Both must have collapsed the moved device to its freshest lease (.21), dropping
	// the stale .89, and kept the unrelated .20.
	if card["10.0.0.89"] || !card["10.0.0.21"] || !card["10.0.0.20"] {
		t.Fatalf("moved-device dedupe wrong on both paths: %v", card)
	}
}
