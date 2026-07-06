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

// TestDNSZoneGenerationGuard proves last-writer-by-generation: a rebuild dispatched
// earlier (a slow detached primeDNSZone carrying a lower generation) cannot clobber a
// zone a later-dispatched rebuild already installed. dnsZoneAppliedGen is written only
// alongside SetZone under dnsZoneMu, so its value reports which rebuild's SetZone won.
func TestDNSZoneGenerationGuard(t *testing.T) {
	s, _ := newTestServer(t) // s.dns is a real (non-listening) dns.Server
	res := map[string]db.HostReservation{}
	leases := []kea.ActiveLease{{IPAddress: "10.0.0.50", HWAddress: "00:1f:80:20:00:01"}}

	if !s.rebuildDNSZoneWith(leases, res, 10) {
		t.Fatal("first rebuild (gen 10) should report applied")
	}
	if s.dnsZoneAppliedGen != 10 {
		t.Fatalf("applied generation = %d, want 10", s.dnsZoneAppliedGen)
	}
	// A lower generation (stale detached prime landing late) must be refused, and it
	// must report NOT applied so a signature-tracking caller does not latch it.
	if s.rebuildDNSZoneWith(leases, res, 5) {
		t.Error("stale generation 5 reported applied over 10")
	}
	if s.dnsZoneAppliedGen != 10 {
		t.Errorf("stale generation 5 was applied over 10 (now %d)", s.dnsZoneAppliedGen)
	}
	// A higher generation wins and reports applied.
	if !s.rebuildDNSZoneWith(leases, res, 12) {
		t.Error("higher generation 12 should report applied")
	}
	if s.dnsZoneAppliedGen != 12 {
		t.Errorf("applied generation = %d, want 12", s.dnsZoneAppliedGen)
	}
	// Generation 0 (unversioned callers/tests) always applies.
	if !s.rebuildDNSZoneWith(leases, res, 0) {
		t.Error("gen 0 should always report applied")
	}
	if s.dnsZoneAppliedGen != 0 {
		t.Errorf("gen 0 must always apply, applied generation = %d", s.dnsZoneAppliedGen)
	}
}
