package web

import (
	"fmt"
	"log"
	"net"

	"ggo-kea-dhcp/internal/kea"
)

// rebalanceMove is one lease the sweep wants to release so its device migrates into
// its own device-class pool: the address to free, the device, and the from/to classes
// (for the audit line).
type rebalanceMove struct {
	IP, HW, FromClass, ToClass string
}

// poolBound is one DHCP pool's class and inclusive uint32 range.
type poolBound struct {
	class  string
	lo, hi uint32
}

// rebalanceTargets decides which leases to release so a device sitting in the WRONG
// pool for its class moves into its own device-class pool. It returns a move only when
// the device's class HAS a pool in the scope, the lease is currently in a DIFFERENT
// pool, and that own pool has free space. It deliberately skips:
//   - devices whose class has no pool here (they belong in a catch-all - correct);
//   - leases already in their own pool (a non-Green-GO device in OTHERS lands here too);
//   - a full own pool (leave the device as overflow rather than NAK it).
//
// Pure over its inputs (no Kea/DB access) so it is unit-testable. Releasing the lease
// works because the catch-all guards are exclusive of the device's class (scope-relative
// GGO-OTHERS, and OTHERS excludes all Green-GO): the device is NOT a member of the pool
// it currently sits in, so on re-request Kea NAKs the old address and it re-DISCOVERs
// into its own pool (precedence ordering). This is also why a release alone does NOT
// work while a pool is member('ALL') - the device is re-granted the same address; the
// rebalance only frees the address sooner than the device's own next-renewal NAK.
//
// fixed is the set of lease IPs whose address is INTENTIONALLY pinned (switch-port
// flex-id) or reserved (hw-address): those are never rebalanced - the device would just
// be re-granted the same fixed IP, and deleting the lease only makes it vanish from the
// table until the device re-requests at its next renewal. They are still counted toward
// pool occupancy (they really do occupy their slot), just never selected as a move.
func rebalanceTargets(scopes []ScopeConfig, leases []kea.ActiveLease, fixed map[string]bool) []rebalanceMove {
	var moves []rebalanceMove
	for _, sc := range scopes {
		_, ipnet, err := net.ParseCIDR(sc.CIDR)
		if err != nil {
			continue
		}
		placements, err := kea.LayoutPools(sc.CIDR, sc.Plan.ToSpecs())
		if err != nil {
			continue
		}
		var pools []poolBound
		for _, p := range placements {
			if p.Kind == kea.PoolReserve || p.Range == "" || p.Class == "" {
				continue
			}
			if lo, hi, ok := kea.ParsePoolRange(p.Range); ok {
				pools = append(pools, poolBound{class: p.Class, lo: lo, hi: hi})
			}
		}

		// Per-pool occupancy from the scope's current leases.
		occ := make([]int, len(pools))
		var scopeLeases []kea.ActiveLease
		for _, l := range leases {
			ip := net.ParseIP(l.IPAddress).To4()
			if ip == nil || !ipnet.Contains(ip) {
				continue
			}
			scopeLeases = append(scopeLeases, l)
			if i := poolIndex(pools, kea.IPToUint32(ip)); i >= 0 {
				occ[i]++
			}
		}

		for _, l := range scopeLeases {
			if fixed[l.IPAddress] {
				continue // pinned/reserved: the IP is intentional, never rebalance it
			}
			ip := net.ParseIP(l.IPAddress).To4()
			if ip == nil {
				continue
			}
			u := kea.IPToUint32(ip)
			class := kea.ClassifyMAC(l.HWAddress)
			own, cur := classIndex(pools, class), poolIndex(pools, u)
			if own < 0 || cur < 0 || cur == own {
				continue // no own pool (catch-all is correct), or already placed right
			}
			capacity := capacityOf(pools[own].lo, pools[own].hi)
			if occ[own] >= capacity {
				continue // own pool full - keep the device in its overflow pool
			}
			moves = append(moves, rebalanceMove{IP: l.IPAddress, HW: l.HWAddress, FromClass: pools[cur].class, ToClass: class})
			occ[own]++ // reserve the destination slot so we don't over-migrate
			occ[cur]--
		}
	}
	return moves
}

// fixedLeaseIPs returns the set of lease IPs whose address is intentionally fixed - by a
// switch-port pin (flex-id) or a hw-address reservation - so the rebalancer leaves them
// alone. Such a device would only be re-granted the same IP on re-request, so deleting
// its lease just makes it disappear from the table until its next renewal. Empty (nothing
// fixed) when MariaDB is absent, which also disables rebalance migration of those rows.
func (s *Server) fixedLeaseIPs(leases []kea.ActiveLease) map[string]bool {
	fixed := map[string]bool{}
	if s.mariadb == nil {
		return fixed
	}
	resMACs := map[string]bool{}
	if list, err := s.mariadb.HWReservations(); err == nil {
		for _, rsv := range list {
			resMACs[normalizeMAC(net.HardwareAddr(rsv.Identifier).String())] = true
		}
	} else {
		log.Printf("[Rebalance] reservation read failed: %v", err)
	}
	pinnedKeys := s.pinnedPortKeys()
	for _, l := range leases {
		if resMACs[normalizeMAC(l.HWAddress)] {
			fixed[l.IPAddress] = true
			continue
		}
		if len(pinnedKeys) > 0 {
			if id, ok := decodePortIdentity(l.ClientID); ok && pinnedKeys[id.Key] {
				fixed[l.IPAddress] = true
			}
		}
	}
	return fixed
}

// poolIndex returns the index of the pool whose range contains u, or -1.
func poolIndex(pools []poolBound, u uint32) int {
	for i := range pools {
		if u >= pools[i].lo && u <= pools[i].hi {
			return i
		}
	}
	return -1
}

// classIndex returns the index of the pool guarding the given class, or -1.
func classIndex(pools []poolBound, class string) int {
	for i := range pools {
		if pools[i].class == class {
			return i
		}
	}
	return -1
}

// rebalanceLeases releases the leases rebalanceTargets selects so mis-placed devices
// re-DHCP into their own device-class pool. Best-effort and ACTIVE-only: lookups and
// deletes are logged/audited but never fail a reconcile. Run after a successful Kea
// reload (the new, exclusive class guards must be live first - otherwise a released
// device could be re-granted its old address).
func (s *Server) rebalanceLeases(scopes []ScopeConfig) {
	if s.kea == nil {
		return
	}
	leases, err := s.kea.GetLeases(1000)
	if err != nil {
		log.Printf("[Rebalance] lease fetch failed: %v", err)
		return
	}
	fixed := s.fixedLeaseIPs(leases)
	moved := 0
	for _, m := range rebalanceTargets(scopes, leases, fixed) {
		if err := s.kea.DeleteLease(m.IP); err != nil {
			log.Printf("[Rebalance] lease4-del %s failed: %v", m.IP, err)
			continue
		}
		moved++
		_ = s.sqlite.LogAudit("system", "LEASE_REBALANCE",
			fmt.Sprintf("%s (%s): %s pool -> %s pool", m.IP, m.HW, m.FromClass, m.ToClass), "", "", "SUCCESS")
	}
	if moved > 0 {
		log.Printf("[Rebalance] released %d mis-placed lease(s) to migrate into their device-class pools", moved)
	}
}
