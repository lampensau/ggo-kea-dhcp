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
	defer s.mon.Netmon.Stop()
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
	// zone.sig is still zero here (the broadcast's rebuild does not touch it), so the
	// nonzero lease signature forces a rebuild rather than the idle-gate skip.
	fetches.Store(0)
	s.maybeRebuildDNSZone(t.Context(), leases)
	if got := fetches.Load(); got != 1 {
		t.Fatalf("sampler reservation fetches = %d, want 1 (independent fetch)", got)
	}
}

// TestDNSZoneGenerationGuard proves last-writer-by-generation: a rebuild dispatched
// earlier (a slow detached primeDNSZone carrying a lower generation) cannot clobber a
// zone a later-dispatched rebuild already installed. zone.appliedGen is written only
// alongside SetZone under the gate's mutex, so its value reports which rebuild's SetZone won.
func TestDNSZoneGenerationGuard(t *testing.T) {
	s, _ := newTestServer(t) // s.dns is a real (non-listening) dns.Server
	res := map[string]db.HostReservation{}
	leases := []kea.ActiveLease{{IPAddress: "10.0.0.50", HWAddress: "00:1f:80:20:00:01"}}

	if !s.rebuildDNSZoneWith(leases, res, 10) {
		t.Fatal("first rebuild (gen 10) should report applied")
	}
	if s.zone.appliedGen != 10 {
		t.Fatalf("applied generation = %d, want 10", s.zone.appliedGen)
	}
	// A lower generation (stale detached prime landing late) must be refused, and it
	// must report NOT applied so a signature-tracking caller does not latch it.
	if s.rebuildDNSZoneWith(leases, res, 5) {
		t.Error("stale generation 5 reported applied over 10")
	}
	if s.zone.appliedGen != 10 {
		t.Errorf("stale generation 5 was applied over 10 (now %d)", s.zone.appliedGen)
	}
	// A higher generation wins and reports applied.
	if !s.rebuildDNSZoneWith(leases, res, 12) {
		t.Error("higher generation 12 should report applied")
	}
	if s.zone.appliedGen != 12 {
		t.Errorf("applied generation = %d, want 12", s.zone.appliedGen)
	}
	// The current generation re-applies: only a STRICTLY older dispatch loses, so a
	// caller that re-runs its own rebuild is not silently dropped.
	if !s.rebuildDNSZoneWith(leases, res, 12) {
		t.Error("re-applying the current generation 12 should report applied")
	}
	if s.zone.appliedGen != 12 {
		t.Errorf("applied generation = %d, want 12", s.zone.appliedGen)
	}
}
