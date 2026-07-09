package appliance

import (
	"net"
	"testing"

	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/kea"
)

func remapScopes(cidrs ...string) []ScopeConfig {
	scopes := make([]ScopeConfig, len(cidrs))
	for i, c := range cidrs {
		scopes[i].CIDR = c
	}
	return scopes
}

func hostRow(mac string, idType, subnetID int, ip string) db.HostReservation {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		panic(err)
	}
	return db.HostReservation{
		Identifier:     []byte(hw),
		IdentifierType: idType,
		SubnetID:       subnetID,
		IPv4Address:    kea.IPToUint32(net.ParseIP(ip)),
	}
}

// TestPlanSubnetRemapsScopeRemoved is the #17 repro: a reservation made in scope B
// (subnet-id 2) while scope A existed must follow scope B to its new positional id
// (1) once scope A is dropped. Port pins (type 4) move the same way.
func TestPlanSubnetRemapsScopeRemoved(t *testing.T) {
	rows := []db.HostReservation{
		hostRow("00:1f:80:00:00:01", 0, 2, "10.8.0.50"),
		hostRow("00:1f:80:00:00:02", 4, 2, "10.8.0.51"),
	}
	// Profile edited: scope A (10.7.0.0/24) deleted, scope B is now subnet 1.
	moves, orphans, skipped := planSubnetRemaps(rows, SubnetMatcherForScopes(remapScopes("10.8.0.0/24")))
	if len(orphans) != 0 || len(skipped) != 0 {
		t.Fatalf("orphans=%d skipped=%d, want none", len(orphans), len(skipped))
	}
	if len(moves) != 2 {
		t.Fatalf("moves=%d, want 2", len(moves))
	}
	for _, mv := range moves {
		if mv.newID != 1 || mv.row.SubnetID != 2 {
			t.Errorf("move %s: %d -> %d, want 2 -> 1", hostIdentDisplay(mv.row), mv.row.SubnetID, mv.newID)
		}
	}
}

// TestPlanSubnetRemapsNoChange proves the remap is a no-op when the stored ids
// already match the scope order - the every-boot converge must not churn rows.
func TestPlanSubnetRemapsNoChange(t *testing.T) {
	rows := []db.HostReservation{
		hostRow("00:1f:80:00:00:01", 0, 1, "10.7.0.50"),
		hostRow("00:1f:80:00:00:02", 0, 2, "10.8.0.50"),
	}
	moves, orphans, skipped := planSubnetRemaps(rows, SubnetMatcherForScopes(remapScopes("10.7.0.0/24", "10.8.0.0/24")))
	if len(moves) != 0 || len(orphans) != 0 || len(skipped) != 0 {
		t.Fatalf("moves=%d orphans=%d skipped=%d, want all zero", len(moves), len(orphans), len(skipped))
	}
}

// TestPlanSubnetRemapsOrphan: a row whose IP is outside every scope is reported
// but never moved (the operator cleans it up; guessing a subnet would be worse).
func TestPlanSubnetRemapsOrphan(t *testing.T) {
	rows := []db.HostReservation{
		hostRow("00:1f:80:00:00:01", 0, 2, "192.168.99.50"),
	}
	moves, orphans, skipped := planSubnetRemaps(rows, SubnetMatcherForScopes(remapScopes("10.8.0.0/24")))
	if len(moves) != 0 || len(skipped) != 0 {
		t.Fatalf("moves=%d skipped=%d, want none", len(moves), len(skipped))
	}
	if len(orphans) != 1 || orphans[0].SubnetID != 2 {
		t.Fatalf("orphans=%v, want the untouched original row", orphans)
	}
}

// TestPlanSubnetRemapsCollisionSkipped: a device with rows in two subnets whose
// IPs now both land in one scope may only keep one row per Kea's unique
// (identifier, type, subnet) key - the second move is skipped, not attempted.
func TestPlanSubnetRemapsCollisionSkipped(t *testing.T) {
	rows := []db.HostReservation{
		hostRow("00:1f:80:00:00:01", 0, 1, "10.8.0.50"), // already correct at subnet 1
		hostRow("00:1f:80:00:00:01", 0, 2, "10.8.0.60"), // wants subnet 1 too -> occupied
	}
	moves, orphans, skipped := planSubnetRemaps(rows, SubnetMatcherForScopes(remapScopes("10.8.0.0/24")))
	if len(moves) != 0 || len(orphans) != 0 {
		t.Fatalf("moves=%d orphans=%d, want none", len(moves), len(orphans))
	}
	if len(skipped) != 1 || skipped[0].row.SubnetID != 2 || skipped[0].newID != 1 {
		t.Fatalf("skipped=%v, want the subnet-2 row targeting 1", skipped)
	}
}

// TestPlanSubnetRemapsSwap: two rows of the SAME device exchanging subnets (a
// trunk-port pin reserved in two VLANs whose scopes reordered) must BOTH move -
// the executor's park-id two-phase makes the swap achievable, so the planner must
// not demote either side.
func TestPlanSubnetRemapsSwap(t *testing.T) {
	rows := []db.HostReservation{
		hostRow("00:1f:80:00:00:01", 0, 1, "10.8.0.50"), // moves 1 -> 2
		hostRow("00:1f:80:00:00:01", 0, 2, "10.7.0.50"), // moves 2 -> 1
	}
	moves, orphans, skipped := planSubnetRemaps(rows, SubnetMatcherForScopes(remapScopes("10.7.0.0/24", "10.8.0.0/24")))
	if len(orphans) != 0 || len(skipped) != 0 {
		t.Fatalf("orphans=%d skipped=%d, want none", len(orphans), len(skipped))
	}
	if len(moves) != 2 {
		t.Fatalf("moves=%d, want 2 (the swap must complete in one pass)", len(moves))
	}
}

// TestPlanSubnetRemapsDemotionCascades: a mover demoted to staying can itself
// block a later mover's target - the fixpoint must catch the chain, not just the
// first collision. Same device: an orphan holds subnet 1, so the row targeting 1
// stays at 3, so the row targeting 3 must stay too.
func TestPlanSubnetRemapsDemotionCascades(t *testing.T) {
	rows := []db.HostReservation{
		hostRow("00:1f:80:00:00:01", 0, 1, "192.168.9.9"), // orphan, stays at 1
		hostRow("00:1f:80:00:00:01", 0, 3, "10.1.0.5"),    // wants 1 - blocked by the orphan
		hostRow("00:1f:80:00:00:01", 0, 2, "10.3.0.5"),    // wants 3 - blocked by the demoted row above
	}
	moves, orphans, skipped := planSubnetRemaps(rows, SubnetMatcherForScopes(remapScopes("10.1.0.0/24", "10.2.0.0/24", "10.3.0.0/24")))
	if len(orphans) != 1 {
		t.Fatalf("orphans=%d, want 1", len(orphans))
	}
	if len(moves) != 0 {
		t.Fatalf("moves=%v, want none (both movers blocked, one transitively)", moves)
	}
	if len(skipped) != 2 {
		t.Fatalf("skipped=%d, want 2", len(skipped))
	}
}

// TestSubnetMatcherForScopesBadCIDR: an unparseable stored CIDR matches nothing
// but must not shift the positional ids of the scopes after it.
func TestSubnetMatcherForScopesBadCIDR(t *testing.T) {
	match := SubnetMatcherForScopes(remapScopes("not-a-cidr", "10.8.0.0/24"))
	if id, ok := match(net.ParseIP("10.8.0.50")); !ok || id != 2 {
		t.Errorf("10.8.0.50 = (%d,%v), want (2,true) - bad CIDR must keep its slot", id, ok)
	}
	if _, ok := match(net.ParseIP("10.7.0.50")); ok {
		t.Error("10.7.0.50 matched, want no match")
	}
}

// TestRemapReservationSubnetsNoMariaDB: the reconcile-time remap is a silent no-op
// without the optional MariaDB backend.
func TestRemapReservationSubnetsNoMariaDB(t *testing.T) {
	r, _ := newTestReconciler(t)
	r.RemapReservationSubnets(t.Context(), remapScopes("10.8.0.0/24"), ModeApply)
}
