package web

import (
	"strings"
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

	periodic := regionSet(s.periodicDashboardFragments(t.Context(), leases))
	full := regionSet(s.dashboardFragments(t.Context(), leases))

	wantPeriodic := []string{"dash-tiles", "activity-feed", "state-badge", "link-status", "shield-status", "net-health", "net-health-rollup"}
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

// TestConnectFragmentsPageScope proves the connect snapshot skips the MariaDB-backed
// build for a page that shows none of those regions: a /settings connect delivers the
// periodic/shell set with NO lease/MariaDB region, while a /dashboard connect still
// carries them. Both must still carry the shell badge, so no page loses its live shell.
func TestConnectFragmentsPageScope(t *testing.T) {
	s, _ := newTestServer(t)
	s.metrics = newMetricsStore()
	fakeNetmon(s)
	defer s.netmon.Stop()
	_ = seedActiveProfile(t, s)

	leases := []kea.ActiveLease{{IPAddress: "10.0.0.50", HWAddress: "00:1f:80:20:00:01"}}

	settings := regionSet(s.connectFragments(t.Context(), leases, "/settings"))
	dashboard := regionSet(s.connectFragments(t.Context(), leases, "/dashboard"))

	for _, r := range []string{"pool-table", "leases-body", "recent-leases", "pinnings", "pinned-body", "learnable-body"} {
		if settings[r] {
			t.Errorf("/settings connect must not build lease/MariaDB region %q", r)
		}
	}
	for _, r := range []string{"pool-table", "leases-body", "recent-leases"} {
		if !dashboard[r] {
			t.Errorf("/dashboard connect missing lease-derived region %q", r)
		}
	}
	// Neither page loses its live shell.
	for _, set := range []map[string]bool{settings, dashboard} {
		if !set["state-badge"] {
			t.Error("connect fragments missing shell region state-badge")
		}
	}
}

// TestTickDashboardKeaOutage proves a Kea outage does not freeze the live stream:
// when GetLeases fails (the test server's Kea endpoint is unreachable),
// tickDashboard still publishes the Kea-independent periodic regions (tiles,
// net-health, diag-audit) and publishes NO lease-derived region - those must
// freeze at their last honest state rather than broadcast a guess.
func TestTickDashboardKeaOutage(t *testing.T) {
	s, _ := newTestServer(t)
	s.live = newLiveHub()
	s.metrics = newMetricsStore()
	fakeNetmon(s)
	defer s.netmon.Stop()
	_ = seedActiveProfile(t, s)

	ch := s.live.subscribe("") // unknown page: receive every region
	defer s.live.unsubscribe(ch)

	s.tickDashboard() // GetLeases fails against 127.0.0.1:1

	var frags []string
drain:
	for {
		select {
		case f := <-ch:
			frags = append(frags, f)
		default:
			break drain
		}
	}
	all := strings.Join(frags, "\n")
	for _, id := range []string{`id="dash-tiles"`, `id="net-health"`, `id="diag-audit"`} {
		if !strings.Contains(all, id) {
			t.Errorf("Kea-down tick did not publish periodic region %s", id)
		}
	}
	for _, id := range []string{`id="leases-body"`, `id="pool-table"`, `id="recent-leases"`, `id="pinnings"`} {
		if strings.Contains(all, id) {
			t.Errorf("Kea-down tick must not publish lease/MariaDB region %s", id)
		}
	}

	// The degraded path must keep flowing across ticks, not fire once: the metrics
	// sampler pushes nothing while Kea is down, so any gate on its signature would
	// freeze after the first tick. A new audit row must reach diag-audit on the
	// NEXT tick.
	_ = s.sqlite.LogAudit("SYSTEM", "KEA_DOWN", "KEA", "", "outage test", "ERROR")
	s.tickDashboard()
	var second []string
drain2:
	for {
		select {
		case f := <-ch:
			second = append(second, f)
		default:
			break drain2
		}
	}
	if !strings.Contains(strings.Join(second, "\n"), `id="diag-audit"`) {
		t.Errorf("second Kea-down tick did not publish the new audit row to diag-audit")
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
