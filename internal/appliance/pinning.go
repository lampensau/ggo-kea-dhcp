package appliance

import (
	"context"
	"log"

	"ggo-kea-dhcp/internal/db"
)

// BytesToPortIdentity renders raw flex-id bytes as the opaque port-identity KEY
// (the value posted in pin/unpin/label forms and used to match reservations and
// labels): ALWAYS lowercase colon-hex, so flexIDToBytes round-trips every byte
// shape exactly. The key is deliberately not the printable text even when the
// flex-id is printable - a printable identifier that happens to look like
// colon-hex (an ASCII-text MAC remote-id, "aa:bb:cc:dd:ee:ff") would otherwise
// decode to the wrong bytes, and a lone binary octet ("1f") would collide with
// the two-char ASCII string. Humans never see the key: the UI shows the decoded
// remote/circuit halves (PortIdent.RemoteID/CircuitID).
func BytesToPortIdentity(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return colonHex(b)
}

// FetchPinnedPorts reads the Kea host reservations (flex-id pins) from MariaDB,
// keyed by port identity. Nil when MariaDB is absent (a documented degraded mode),
// which every caller reads as "nothing is pinned".
func (r *Reconciler) FetchPinnedPorts(ctx context.Context) (map[string]db.HostReservation, error) {
	if r.mariadb == nil {
		return nil, nil
	}
	rows, err := r.mariadb.QueryContext(ctx, "SELECT dhcp_identifier, dhcp4_subnet_id, ipv4_address, hostname FROM hosts WHERE dhcp_identifier_type = 4")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	pinned := make(map[string]db.HostReservation)
	for rows.Next() {
		var res db.HostReservation
		var ipVal uint32
		if rows.Scan(&res.Identifier, &res.SubnetID, &ipVal, &res.Hostname) == nil {
			res.IdentifierType = 4
			res.IPv4Address = ipVal
			pinned[BytesToPortIdentity(res.Identifier)] = res
		}
	}
	return pinned, rows.Err()
}

// PinnedPortKeys returns the set of pinned switch-port identities (flex-id, type-4
// reservations), keyed the same way DecodePortIdentity renders a lease's port. Nil
// when MariaDB is absent or the query fails. The dashboard broadcast builds the
// equivalent set from the pins it already fetched, so it never queries twice per render.
func (r *Reconciler) PinnedPortKeys(ctx context.Context) map[string]bool {
	p, err := r.FetchPinnedPorts(ctx)
	if err != nil {
		log.Printf("[Reservations] pinned-port read failed: %v", err)
		return nil
	}
	keys := make(map[string]bool, len(p))
	for k := range p {
		keys[k] = true
	}
	return keys
}
