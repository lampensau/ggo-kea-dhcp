package web

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/kea"
)

// Kea subnet-ids are positional: the renderer numbers scopes (index + 1) over scope
// order, so a profile edit or switch renumbers them while a host row's
// dhcp4_subnet_id stays as stamped at creation. A stale id makes Kea ignore the
// reservation (or, worse, honor it in the wrong profile's subnet 1). The remap here
// re-derives every row's subnet-id from its IP - the stable key - over the scopes
// being reconciled, and moves the rows that differ.

// subnetMatcherForScopes returns the canonical IP -> positional Kea subnet-id
// mapping ((scope index + 1) over scope order, the same numbering RenderProfile
// assigns) for an already-loaded scope list. An unparseable stored CIDR is logged
// and matches nothing.
func subnetMatcherForScopes(scopes []ScopeConfig) func(net.IP) (int, bool) {
	nets := make([]*net.IPNet, 0, len(scopes))
	for _, sc := range scopes {
		_, ipnet, err := net.ParseCIDR(sc.CIDR)
		if err != nil {
			log.Printf("[scopes] scope CIDR %q unparseable, skipping in subnet matcher: %v", sc.CIDR, err)
		}
		nets = append(nets, ipnet) // nil for an unparseable CIDR; skipped below
	}
	return func(ip net.IP) (int, bool) {
		for i, n := range nets {
			if n != nil && n.Contains(ip) {
				return i + 1, true
			}
		}
		return 0, false
	}
}

// subnetRemap is one host row that should move to a new positional subnet-id.
type subnetRemap struct {
	row   db.HostReservation
	newID int
}

// hostKey is Kea's hosts unique key (dhcp_identifier, dhcp_identifier_type,
// dhcp4_subnet_id) as a map key.
func hostKey(identifier []byte, identifierType, subnetID int) string {
	return string(identifier) + "|" + strconv.Itoa(identifierType) + "|" + strconv.Itoa(subnetID)
}

// planSubnetRemaps is the pure decision core of remapReservationSubnets, split out
// so it is testable without a live MariaDB. For each host row it derives the
// current subnet-id from the row's IP via subnetFor and classifies the row: moves
// (stored id differs from the derived one), orphans (IP no longer inside any scope
// - left untouched for the operator to clean up), or skipped (the move's target
// triple would violate Kea's unique (identifier, type, subnet) key - only possible
// between rows of the SAME device, e.g. one device reserved in two subnets whose
// IPs now both land in one scope). The executor two-phases the moves through park
// ids (UpdateReservationSubnets), so move ORDER never matters here - same-device
// rows swapping subnets both move; only a target genuinely held by a row that
// stays put demotes a move. A demoted mover itself stays put and can block
// further movers, hence the fixpoint loop. It mutates nothing.
func planSubnetRemaps(rows []db.HostReservation, subnetFor func(net.IP) (int, bool)) (moves []subnetRemap, orphans []db.HostReservation, skipped []subnetRemap) {
	// Triples of rows that stay where they are: already-correct rows, orphans, and
	// (as the fixpoint demotes them) skipped movers.
	staying := make(map[string]bool, len(rows))
	var movers []subnetRemap
	for _, r := range rows {
		target, ok := subnetFor(kea.Uint32ToIP(r.IPv4Address))
		if !ok {
			orphans = append(orphans, r)
			staying[hostKey(r.Identifier, r.IdentifierType, r.SubnetID)] = true
			continue
		}
		if target == r.SubnetID {
			staying[hostKey(r.Identifier, r.IdentifierType, r.SubnetID)] = true
			continue
		}
		movers = append(movers, subnetRemap{row: r, newID: target})
	}
	skip := make([]bool, len(movers))
	for {
		demoted := false
		claimed := make(map[string]bool, len(staying)+len(movers))
		for k := range staying {
			claimed[k] = true
		}
		for i, mv := range movers {
			if skip[i] {
				continue
			}
			newKey := hostKey(mv.row.Identifier, mv.row.IdentifierType, mv.newID)
			if claimed[newKey] {
				skip[i] = true
				staying[hostKey(mv.row.Identifier, mv.row.IdentifierType, mv.row.SubnetID)] = true
				demoted = true
				continue
			}
			claimed[newKey] = true
		}
		if !demoted {
			break
		}
	}
	for i, mv := range movers {
		if skip[i] {
			skipped = append(skipped, mv)
		} else {
			moves = append(moves, mv)
		}
	}
	return moves, orphans, skipped
}

// hostIdentDisplay renders a host row's identifier for logs/audit: a MAC for a
// client (type 0) reservation, the opaque port identity for a flex-id (type 4) pin.
func hostIdentDisplay(r db.HostReservation) string {
	if r.IdentifierType == 0 && len(r.Identifier) == 6 {
		return net.HardwareAddr(r.Identifier).String()
	}
	return bytesToPortIdentity(r.Identifier)
}

// remapReservationSubnets re-stamps every host reservation/pin's dhcp4_subnet_id
// from its IP over the scopes being reconciled, so reservations keep working when
// a profile edit or switch renumbers the positional subnet-ids. Idempotent (rows
// already correct are untouched) and best-effort: MariaDB is an optional backend,
// so failures are logged/audited but never fail the reconcile. Orphans (IP outside
// every scope) are audited only on ModeApply - the profile-change moment - so
// routine boot/settings converges don't re-audit the same stale rows forever.
func (r *reconciler) remapReservationSubnets(ctx context.Context, scopes []ScopeConfig, mode ReconcileMode) {
	if r.mariadb == nil {
		return
	}
	rows, err := r.mariadb.AllReservations(ctx)
	if err != nil {
		log.Printf("[remap] host reservation read failed, skipping subnet remap: %v", err)
		return
	}
	moves, orphans, skipped := planSubnetRemaps(rows, subnetMatcherForScopes(scopes))

	applied := 0
	var details []string
	if len(moves) > 0 {
		updates := make([]db.SubnetIDUpdate, len(moves))
		for i, mv := range moves {
			updates[i] = db.SubnetIDUpdate{
				Identifier:     mv.row.Identifier,
				IdentifierType: mv.row.IdentifierType,
				OldSubnetID:    mv.row.SubnetID,
				NewSubnetID:    mv.newID,
			}
		}
		if err := r.mariadb.UpdateReservationSubnets(ctx, updates); err != nil {
			// The batch is one transaction, so nothing moved. A duplicate key means a
			// concurrent reservation write raced the plan snapshot; either way the next
			// reconcile re-plans from fresh rows.
			if db.IsDuplicateKey(err) {
				log.Printf("[remap] a concurrent reservation write raced the subnet remap, retrying on the next reconcile: %v", err)
			} else {
				log.Printf("[remap] subnet remap of %d row(s) failed: %v", len(moves), err)
			}
			return
		}
		applied = len(moves)
		for _, mv := range moves {
			if len(details) < 5 {
				details = append(details, fmt.Sprintf("%s %s: %d -> %d",
					hostIdentDisplay(mv.row), kea.Uint32ToIP(mv.row.IPv4Address), mv.row.SubnetID, mv.newID))
			}
		}
	}
	for _, mv := range skipped {
		log.Printf("[remap] %s (%s): subnet %d -> %d skipped - target already reserved for this device",
			hostIdentDisplay(mv.row), kea.Uint32ToIP(mv.row.IPv4Address), mv.row.SubnetID, mv.newID)
	}
	if applied > 0 || len(skipped) > 0 {
		result := "SUCCESS"
		if len(skipped) > 0 {
			result = "WARNING"
		}
		_ = r.sqlite.LogAudit("SYSTEM", "RESERVATION_REMAP",
			fmt.Sprintf("%d remapped, %d skipped", applied, len(skipped)),
			"", strings.Join(details, "; "), result)
	}
	if len(orphans) > 0 {
		var names []string
		for _, r := range orphans {
			if len(names) < 5 {
				names = append(names, fmt.Sprintf("%s %s", hostIdentDisplay(r), kea.Uint32ToIP(r.IPv4Address)))
			}
		}
		log.Printf("[remap] %d reservation(s)/pin(s) outside every configured scope, left as-is: %s",
			len(orphans), strings.Join(names, "; "))
		if mode == ModeApply {
			_ = r.sqlite.LogAudit("SYSTEM", "RESERVATION_ORPHANED",
				fmt.Sprintf("%d reservation(s) outside every scope", len(orphans)),
				"", strings.Join(names, "; "), "WARNING")
		}
	}
}
