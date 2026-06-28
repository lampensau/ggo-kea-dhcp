package web

import (
	"fmt"
	"testing"

	"ggo-kea-dhcp/internal/kea"
)

// rebalanceScope is a /24 with a small (size-10) GGO-BPX pool plus the two elastic
// catch-alls, used to exercise rebalanceTargets.
func rebalanceScope() (ScopeConfig, map[string][2]uint32) {
	sc := ScopeConfig{Preset: "greengo", CIDR: "10.0.0.0/24", Plan: PoolPlan{
		{Kind: PoolKindReserve, Name: "Static reserve", Count: 18},
		{Kind: PoolKindFixed, Class: "GGO-BPX", Sizing: "explicit", Count: 10},
		{Kind: PoolKindElastic, Class: kea.ClassNameGGOOthers, Weight: 2},
		{Kind: PoolKindElastic, Class: kea.ClassNameOthers, Weight: 1},
	}}
	placements, err := kea.LayoutPools(sc.CIDR, sc.Plan.ToSpecs())
	if err != nil {
		panic(err)
	}
	rng := map[string][2]uint32{}
	for _, p := range placements {
		if lo, hi, ok := kea.ParsePoolRange(p.Range); ok {
			rng[p.Class] = [2]uint32{lo, hi}
		}
	}
	return sc, rng
}

func ipInClass(rng map[string][2]uint32, class string, offset uint32) string {
	return kea.Uint32ToIP(rng[class][0] + offset).String()
}

// TestRebalanceTargets covers the routing decisions: a classified beltpack moves into
// its own pool from EITHER catch-all (GGO-OTHERS or, now that OTHERS is non-Green-GO,
// the OTHERS pool too); a correctly-placed one, an unpooled type, and a non-Green-GO
// device in OTHERS are all left alone.
func TestRebalanceTargets(t *testing.T) {
	sc, rng := rebalanceScope()
	bpx0 := "00:1f:80:20:00:01" // GGO-BPX, stuck in GGO-OTHERS
	bpx1 := "00:1f:80:20:00:02" // GGO-BPX, correctly placed
	bpx2 := "00:1f:80:20:00:03" // GGO-BPX, stuck in OTHERS (now migratable)
	mcx := "00:1f:80:22:00:01"  // GGO-MCX-D (no MCX pool here)
	oth := "aa:bb:cc:dd:ee:01"  // non-Green-GO -> OTHERS
	moveFrom := map[string]string{
		ipInClass(rng, kea.ClassNameGGOOthers, 0): bpx0, // -> MOVE to BPX
		ipInClass(rng, kea.ClassNameOthers, 0):    bpx2, // -> MOVE to BPX (was the residual)
	}
	keep := map[string]string{
		ipInClass(rng, "GGO-BPX", 1):              bpx1, // already in own pool
		ipInClass(rng, kea.ClassNameGGOOthers, 1): mcx,  // no own pool -> stays in catch-all
		ipInClass(rng, kea.ClassNameOthers, 1):    oth,  // non-Green-GO, own pool IS OTHERS
	}
	var leases []kea.ActiveLease
	for ip, mac := range moveFrom {
		leases = append(leases, kea.ActiveLease{IPAddress: ip, HWAddress: mac})
	}
	for ip, mac := range keep {
		leases = append(leases, kea.ActiveLease{IPAddress: ip, HWAddress: mac})
	}

	moved := map[string]string{}
	for _, m := range rebalanceTargets([]ScopeConfig{sc}, leases, nil) {
		moved[m.IP] = m.ToClass
	}
	for ip := range moveFrom {
		if moved[ip] != "GGO-BPX" {
			t.Errorf("expected %s to move to GGO-BPX, got %q", ip, moved[ip])
		}
	}
	for ip := range keep {
		if to, ok := moved[ip]; ok {
			t.Errorf("did not expect %s to move (went to %q)", ip, to)
		}
	}
	if len(moved) != len(moveFrom) {
		t.Errorf("expected %d moves, got %d", len(moveFrom), len(moved))
	}
}

// TestRebalanceTargets_FixedNotMoved verifies a mis-placed device whose IP is fixed (a
// switch-port pin or a hw-address reservation) is NEVER rebalanced: deleting its lease
// would just make it vanish from the table until its next renewal, since Kea re-grants
// the same fixed IP. The same device without the fixed flag WOULD move, proving the only
// difference is the exclusion set.
func TestRebalanceTargets_FixedNotMoved(t *testing.T) {
	sc, rng := rebalanceScope()
	bpxIP := ipInClass(rng, kea.ClassNameGGOOthers, 0) // a GGO-BPX device stuck in GGO-OTHERS
	leases := []kea.ActiveLease{{IPAddress: bpxIP, HWAddress: "00:1f:80:20:00:01"}}

	// Without the fixed set it migrates into GGO-BPX (baseline).
	if moves := rebalanceTargets([]ScopeConfig{sc}, leases, nil); len(moves) != 1 {
		t.Fatalf("baseline: expected 1 move, got %d (%+v)", len(moves), moves)
	}
	// Pinned/reserved at that IP: no move.
	if moves := rebalanceTargets([]ScopeConfig{sc}, leases, map[string]bool{bpxIP: true}); len(moves) != 0 {
		t.Errorf("fixed IP must not be rebalanced, got %+v", moves)
	}
}

// TestRebalanceTargets_FullPoolNoMove verifies a device in a catch-all is NOT moved
// when its own pool is already full (the never-NAK overflow stays put).
func TestRebalanceTargets_FullPoolNoMove(t *testing.T) {
	sc, rng := rebalanceScope()
	capacity := int(rng["GGO-BPX"][1] - rng["GGO-BPX"][0] + 1)

	var leases []kea.ActiveLease
	for i := 0; i < capacity; i++ { // fill the BPX pool completely
		leases = append(leases, kea.ActiveLease{
			IPAddress: ipInClass(rng, "GGO-BPX", uint32(i)),
			HWAddress: fmt.Sprintf("00:1f:80:20:00:%02x", i+1),
		})
	}
	// One more beltpack overflowed into the Green-GO catch-all.
	leases = append(leases, kea.ActiveLease{
		IPAddress: ipInClass(rng, kea.ClassNameGGOOthers, 0),
		HWAddress: "00:1f:80:20:00:ff",
	})
	if moves := rebalanceTargets([]ScopeConfig{sc}, leases, nil); len(moves) != 0 {
		t.Errorf("BPX pool is full - expected no moves, got %+v", moves)
	}
}
