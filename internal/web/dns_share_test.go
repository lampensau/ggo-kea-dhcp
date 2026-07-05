package web

import (
	"context"
	"sync/atomic"
	"testing"

	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/kea"
)

// TestBroadcastFetchesReservationsOnce proves the per-broadcast fetch dedup: a
// lease-changed dashboard broadcast fetches the hw-address reservation map exactly
// once (shared by the DNS zone rebuild and the fragment render), where it used to
// fetch twice. The independent sampler path (maybeRebuildDNSZone) still fetches its
// own map - it holds no shared one.
func TestBroadcastFetchesReservationsOnce(t *testing.T) {
	s, _ := newTestServer(t)
	s.metrics = newMetricsStore()
	s.live = newLiveHub()
	fakeNetmon(s)
	defer s.netmon.Stop()
	_ = seedActiveProfile(t, s)

	var fetches atomic.Int64
	s.hwResFetch = func(context.Context) map[string]db.HostReservation {
		fetches.Add(1)
		return map[string]db.HostReservation{}
	}

	leases := []kea.ActiveLease{{IPAddress: "10.0.0.50", HWAddress: "00:1f:80:20:00:01"}}

	// Broadcast path: one fetch shared by rebuildDNSZoneWith + dashboardFragmentsWith.
	fetches.Store(0)
	s.publishDashboardWithLeases(t.Context(), leases)
	if got := fetches.Load(); got != 1 {
		t.Fatalf("broadcast reservation fetches = %d, want 1", got)
	}

	// Sampler path: rebuildDNSZone fetches independently (no shared map on that path).
	// dnsZoneSig is still zero here (the broadcast's rebuild does not touch it), so the
	// nonzero lease signature forces a rebuild rather than the idle-gate skip.
	fetches.Store(0)
	s.maybeRebuildDNSZone(t.Context(), leases)
	if got := fetches.Load(); got != 1 {
		t.Fatalf("sampler reservation fetches = %d, want 1 (independent fetch)", got)
	}
}
