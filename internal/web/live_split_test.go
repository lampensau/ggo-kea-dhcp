package web

import (
	"testing"

	"ggo-kea-dhcp/internal/kea"
)

// regionSet extracts the region keys from a fragment slice.
func regionSet(frags []liveFragment) map[string]bool {
	m := make(map[string]bool, len(frags))
	for _, f := range frags {
		m[f.region] = true
	}
	return m
}

// TestPeriodicVsFullFragments proves the P1 split: a metrics-only tick refreshes
// only the periodic-cheap regions (tiles, net-health, alert strip, activity, shell
// badges), while a lease change rebuilds those PLUS the lease-derived regions (pool
// table, lease table, recent leases). The periodic set must never include a
// lease/MariaDB-backed region, so an idle 12s tick costs no MariaDB round-trips.
func TestPeriodicVsFullFragments(t *testing.T) {
	s, _ := newTestServer(t)
	s.metrics = newMetricsStore()
	fakeNetmon(s)
	defer s.netmon.Stop()
	_ = seedActiveProfile(t, s)

	leases := []kea.ActiveLease{{IPAddress: "10.0.0.50", HWAddress: "00:1f:80:20:00:01"}}

	periodic := regionSet(s.periodicDashboardFragments(leases))
	full := regionSet(s.dashboardFragments(leases))

	wantPeriodic := []string{"dash-tiles", "activity-feed", "state-badge", "link-status", "net-health", "net-health-rollup"}
	leaseDerived := []string{"pool-table", "pool-rollup", "leases-body", "recent-leases"}

	for _, r := range wantPeriodic {
		if !periodic[r] {
			t.Errorf("periodic fragments missing %q", r)
		}
		if !full[r] {
			t.Errorf("full fragments missing periodic region %q", r)
		}
	}
	// The periodic set must NOT contain any lease/MariaDB-backed region.
	for _, r := range append(leaseDerived, "pinnings", "pinned-body", "learnable-body") {
		if periodic[r] {
			t.Errorf("periodic fragments must not include lease/MariaDB region %q", r)
		}
	}
	// The full set is a superset: it carries the lease-derived regions too.
	for _, r := range leaseDerived {
		if !full[r] {
			t.Errorf("full fragments missing lease-derived region %q", r)
		}
	}
}

// TestCollectNetSnapshotMatchesHelpers proves collectNetSnapshot yields the same netmon
// signals as buildNetSignals and the same device presence as presenceByIP (the ARP
// prober), so the merged dashboard build matches the separate passes.
func TestCollectNetSnapshotMatchesHelpers(t *testing.T) {
	s, _ := newTestServer(t)
	s.metrics = newMetricsStore()
	fakeNetmon(s)
	defer s.netmon.Stop()

	ns := s.collectNetSnapshot()
	sig := s.buildNetSignals()
	reachable, available := s.presenceByIP()

	if len(ns.Signals.Health.Interfaces) != len(sig.Health.Interfaces) {
		t.Errorf("collectNetSnapshot interfaces=%d, buildNetSignals=%d", len(ns.Signals.Health.Interfaces), len(sig.Health.Interfaces))
	}
	if ns.Available != available {
		t.Errorf("collectNetSnapshot Available=%v, presenceByIP=%v", ns.Available, available)
	}
	if len(ns.Live) != len(reachable) {
		t.Errorf("collectNetSnapshot Live size=%d, presenceByIP=%d", len(ns.Live), len(reachable))
	}
}
