package web

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/kea"
	"ggo-kea-dhcp/internal/web/views"

	"github.com/starfederation/datastar-go/datastar"
)

// colonHexRe matches a lowercase/uppercase colon-separated hex octet string like
// "00:47:4f" (a single bare octet like "1f" included) - the form
// bytesToPortIdentity renders every key in.
var colonHexRe = regexp.MustCompile(`^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2})*$`)

// flexIDToBytes converts a port-identity key back to the RAW flex-id bytes Kea
// stores in (and matches against) dhcp_identifier. Every key bytesToPortIdentity
// produces is colon-hex, so the hex decode is the whole contract; the ASCII
// fallback only catches a malformed hand-posted value. This is the crux of port
// pinning: Kea matches the reservation against the raw flex-id bytes, so a key
// that decodes to the wrong bytes never matches and the device keeps getting a
// dynamic lease.
func flexIDToBytes(portIdentity string) []byte {
	if colonHexRe.MatchString(portIdentity) {
		if b, err := hex.DecodeString(strings.ReplaceAll(portIdentity, ":", "")); err == nil {
			return b
		}
	}
	return []byte(portIdentity)
}

// bytesToPortIdentity renders raw flex-id bytes as the opaque port-identity KEY
// (the value posted in pin/unpin/label forms and used to match reservations and
// labels): ALWAYS lowercase colon-hex, so flexIDToBytes round-trips every byte
// shape exactly. The key is deliberately not the printable text even when the
// flex-id is printable - a printable identifier that happens to look like
// colon-hex (an ASCII-text MAC remote-id, "aa:bb:cc:dd:ee:ff") would otherwise
// decode to the wrong bytes, and a lone binary octet ("1f") would collide with
// the two-char ASCII string. Humans never see the key: the UI shows the decoded
// remote/circuit halves (portIdent.RemoteID/CircuitID).
func bytesToPortIdentity(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return colonHex(b)
}

func (s *Server) handlePinning(w http.ResponseWriter, r *http.Request) {
	pinningErr := func(msg string) {
		s.renderTempl(w, r, views.Pinning(views.PinningView{Page: s.pageData(w, r, "Port Pinning"), Error: msg}))
	}
	if s.mariadb == nil {
		pinningErr("MariaDB (Kea host storage) is not connected, so port reservations can't be read or written. Port pinning needs the relay/host store online.")
		return
	}

	labels, err := s.fetchPortLabels()
	if err != nil {
		log.Printf("SQLite labels query failed: %v", err)
		pinningErr(fmt.Sprintf("SQLite database error: %v", err))
		return
	}

	pinned, err := s.fetchPinnedPorts(r.Context())
	if err != nil {
		log.Printf("MariaDB hosts query failed: %v", err)
		pinningErr(fmt.Sprintf("Failed to query port reservations from MariaDB: %v", err))
		return
	}

	leases, err := s.kea.GetLeases(r.Context(), 200)
	if err != nil {
		log.Printf("Kea API leases query failed: %v", err)
		pinningErr(fmt.Sprintf("Failed to query active leases from Kea: %v", err))
		return
	}

	// Only live leases: an expired/reclaimed lease (state != 0 or past its lifetime)
	// must not linger as a learnable port after its device is gone.
	all := mergePortRows(labels, pinned, activeLeases(leases), s.lastSeenSnapshot(), time.Now().Unix())
	var pinnedRows, learnable []views.PortRow
	for _, p := range all {
		if p.Pinned {
			pinnedRows = append(pinnedRows, p)
		} else {
			learnable = append(learnable, p)
		}
	}
	s.renderTempl(w, r, views.Pinning(views.PinningView{
		Page:      s.pageData(w, r, "Port Pinning"),
		Pinned:    pinnedRows,
		Learnable: learnable,
	}))
}

// fetchPortLabels reads the SQLite flex-id -> label map.
func (s *Server) fetchPortLabels() (map[string]string, error) {
	rows, err := s.sqlite.Query("SELECT flex_id_hex, label FROM port_labels")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	labels := make(map[string]string)
	for rows.Next() {
		var portID, lbl string
		if rows.Scan(&portID, &lbl) == nil {
			// Translate a legacy key on read: before the key became always-hex, a
			// printable flex-id was stored as its own text, whose raw bytes are that
			// ASCII (the old flexIDToBytes contract). Re-encoding on read keeps old
			// labels attached to their ports without a migration.
			if !colonHexRe.MatchString(portID) {
				portID = colonHex([]byte(portID))
			}
			labels[portID] = lbl
		}
	}
	return labels, rows.Err()
}

// fetchPinnedPorts reads the Kea host reservations (flex-id pins) from MariaDB,
// keyed by port identity.
func (s *Server) fetchPinnedPorts(ctx context.Context) (map[string]db.HostReservation, error) {
	rows, err := s.mariadb.QueryContext(ctx, "SELECT dhcp_identifier, dhcp4_subnet_id, ipv4_address, hostname FROM hosts WHERE dhcp_identifier_type = 4")
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
			pinned[bytesToPortIdentity(res.Identifier)] = res
		}
	}
	return pinned, rows.Err()
}

// mergePortRows folds pinned reservations, active leases, and labels into the
// sorted per-port view rows shown on the pinning page. Pinned ports seed the set;
// active leases fill in the live MAC/hostname or add unpinned Option-82 ports.
// lastSeen (identity -> epoch) and now drive the "last active" column and the stale
// flag on a pinned-but-offline port. Pure over its inputs, so it is unit-testable.
func mergePortRows(labels map[string]string, pinned map[string]db.HostReservation, leases []kea.ActiveLease, lastSeen map[string]int64, now int64) []views.PortRow {
	portRows := make(map[string]views.PortRow)
	cltt := make(map[string]int64) // flex-id key -> lease cltt, for the same-MAC dedup below
	delim := make(map[string]bool) // flex-id key -> new-format (delimited) flex-id

	for portID, pin := range pinned {
		// portID is bytesToPortIdentity(pin.Identifier); decode the same bytes back
		// so the remote/circuit split matches the lease-derived rows.
		id := portIdentFromFlex(flexIDToBytes(portID))
		delim[portID] = id.Delimited
		portRows[portID] = views.PortRow{
			PortIdentity: portID,
			RemoteID:     id.RemoteID, RemoteIDHex: id.RemoteHex,
			CircuitID: id.CircuitID, CircuitIDHex: id.CircuitHex,
			IPAddress: kea.Uint32ToIP(pin.IPv4Address).String(),
			HWAddress: "-", // Pinned but offline
			Hostname:  pin.Hostname,
			SubnetID:  pin.SubnetID,
			Label:     labels[portID],
			Pinned:    true,
		}
	}

	for _, l := range leases {
		// Only genuine Option-82 flex-ids are ports (decodePortIdentity returns
		// ok=false for a normal client-id / no Option-82 / empty id) - otherwise a
		// plain DHCP client like a workstation would show up as a phantom port.
		id, ok := decodePortIdentity(l.ClientID)
		if !ok {
			continue
		}
		cltt[id.Key] = l.Cltt
		delim[id.Key] = id.Delimited
		if row, exists := portRows[id.Key]; exists {
			row.HWAddress = l.HWAddress
			if l.Hostname != "" {
				row.Hostname = l.Hostname
			}
			portRows[id.Key] = row
		} else {
			portRows[id.Key] = views.PortRow{
				PortIdentity: id.Key,
				RemoteID:     id.RemoteID, RemoteIDHex: id.RemoteHex,
				CircuitID: id.CircuitID, CircuitIDHex: id.CircuitHex,
				IPAddress: l.IPAddress,
				HWAddress: l.HWAddress,
				Hostname:  l.Hostname,
				SubnetID:  l.SubnetID,
				Label:     labels[id.Key],
				Pinned:    false,
			}
		}
	}

	// A device (MAC) is physically on exactly one switch port, but a stale lease
	// lingers in Kea after the device re-leases under a new client-id (e.g. when the
	// Option-82 flex-id format changed, or the device moved ports) until that old
	// lease's lifetime elapses. That makes the same MAC show on two "ports" for a
	// while. Per MAC, prefer the new-format (delimited) entry over a pre-upgrade
	// old-format one - the old flex-id can never match a new reservation - and within
	// the same format keep only the most-recently-active (highest cltt) row, so the
	// superseded entry drops out of the UI immediately while its lease still expires
	// naturally in Kea. Pinned rows are intentional and never dropped (and a pinned
	// offline row has no live MAC, so it neither suppresses nor is suppressed).
	hasNew := make(map[string]bool)        // normalized MAC -> a new-format row exists
	freshest := make(map[string]int64)     // normalized MAC -> highest cltt in the winning format
	freshestKey := make(map[string]string) // normalized MAC -> the single row holding that cltt
	for key, row := range portRows {
		if mac := liveMAC(row.HWAddress); mac != "" && delim[key] {
			hasNew[mac] = true
		}
	}
	for key, row := range portRows {
		mac := liveMAC(row.HWAddress)
		if mac == "" || (hasNew[mac] && !delim[key]) {
			continue // ignore old-format rows when a new-format one exists for this MAC
		}
		// Pick exactly one winner per MAC: highest cltt, ties broken by lowest key so
		// two leases sharing the max cltt don't both survive the dedup below.
		if w, seen := freshestKey[mac]; !seen || cltt[key] > freshest[mac] || (cltt[key] == freshest[mac] && key < w) {
			freshest[mac] = cltt[key]
			freshestKey[mac] = key
		}
	}

	ports := make([]views.PortRow, 0, len(portRows))
	for key, row := range portRows {
		if !row.Pinned {
			if mac := liveMAC(row.HWAddress); mac != "" {
				if hasNew[mac] && !delim[key] {
					continue // an old-format dupe while a new-format entry exists
				}
				if key != freshestKey[mac] {
					continue // a fresher (or tie-broken) lease for this device won the row
				}
			}
		} else if mac := liveMAC(row.HWAddress); mac != "" && freshestKey[mac] != "" && key != freshestKey[mac] {
			// The pinned port's device moved to another port: a fresher lease for this MAC
			// exists elsewhere, yet a lingering old lease still tags this pinned row with
			// the device's identity. Blank it so the moved-away pin shows as an empty port
			// (its operator Label survives) instead of impersonating the device until the
			// old lease expires.
			row.HWAddress = "-"
			row.Hostname = ""
		}
		if ts := lastSeen[row.PortIdentity]; ts > 0 {
			row.LastSeen = ts
			row.LastSeenText = relativeAgo(ts, now)
			// A pinned port with no live lease (HWAddress "-") that hasn't been seen
			// in a long while is flagged stale (a hint the device is gone, unpin it).
			row.Stale = row.HWAddress == "-" && now-ts > portStaleAfter
		}
		ports = append(ports, row)
	}
	sanitizePortHostnames(ports)
	sort.Slice(ports, func(i, j int) bool {
		return ports[i].PortIdentity < ports[j].PortIdentity
	})
	return ports
}

func (s *Server) handlePin(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	portIdentity := r.FormValue("port_identity")
	ipStr := r.FormValue("ip")
	hostname := slugifyHostname(r.FormValue("hostname")) // stored as a DNS label, like every reservation
	macStr := r.FormValue("mac")                         // the learned device's MAC, used to clear its stale leases

	log.Printf("[Pinning] Pinning port %s to IP %s...", logSafe(portIdentity), logSafe(ipStr))

	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To4() == nil {
		s.handleError(w, r, "invalid IPv4 address", http.StatusBadRequest)
		return
	}
	ipVal := kea.IPToUint32(ip)

	// The operator may have edited the IP in the dialog, so derive the subnet from
	// the chosen address rather than trusting the learned lease's subnet. Reject an
	// IP outside every configured scope - a pin into a nonexistent Kea subnet is
	// never served (matches handleReservationAdd).
	subnetID, ok := s.subnetIDForIP(ip)
	if !ok {
		s.handleError(w, r, "IP is not inside any configured scope", http.StatusBadRequest)
		return
	}

	// Refuse only a real conflict: the IP already pinned/reserved for a different
	// device, or a different device live on it right now. Pinning a port to the
	// address its own device already holds is the normal case and stays allowed.
	if reason, conflict := s.reservationConflict(r.Context(), subnetID, ipVal, ipStr, flexIDToBytes(portIdentity), 4, macStr); conflict {
		_ = s.sqlite.LogAudit(s.getActor(r), "PIN_PORT", portIdentity+" -> "+ipStr, "", reason, "WARNING")
		s.handleError(w, r, reason, http.StatusConflict)
		return
	}

	// Save reservation to MariaDB
	if s.mariadb != nil {
		res := db.HostReservation{
			Identifier:     flexIDToBytes(portIdentity),
			IdentifierType: 4, // Flex-ID
			SubnetID:       subnetID,
			IPv4Address:    ipVal,
			Hostname:       hostname,
		}
		err := s.mariadb.InsertReservation(r.Context(), res)
		if err != nil {
			log.Printf("Failed to insert reservation: %v", err)
			s.handleError(w, r, "Database error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// Clear leases that would conflict with the pin, but leave the device's lease
		// alone if it is already on the reserved IP (so pinning a device to the address
		// it already holds doesn't knock it offline). Also clears the device's stale
		// leases on other IPs - e.g. an old-format flex-id lease left from before the
		// Option-82 change - so it stops showing as a duplicate learnable port.
		// Post-commit best-effort cleanup: on context.Background(), not r.Context() -
		// the pin is committed, so a mid-request disconnect must not skip freeing the
		// conflicting leases the pinned device needs to adopt its address.
		s.evictForPin(context.Background(), ipStr, normalizeMAC(macStr), portIdentity)
	} else {
		s.handleError(w, r, "MariaDB connection is not active", http.StatusInternalServerError)
		return
	}

	// A label supplied in the pin dialog is saved in the same step, so an operator
	// can name a port as they pin it (empty leaves any existing label untouched).
	if label := r.FormValue("label"); label != "" {
		if _, err := s.sqlite.Exec("INSERT INTO port_labels (flex_id_hex, label) VALUES (?, ?) ON CONFLICT(flex_id_hex) DO UPDATE SET label=excluded.label", portIdentity, label); err != nil {
			log.Printf("[Pinning] pin-time label save failed for %s: %v", logSafe(portIdentity), err)
		}
	}

	// Update audit log
	_ = s.sqlite.LogAudit(s.getActor(r), "PIN_PORT", fmt.Sprintf("%s -> %s", portIdentity, ipStr), "", "", "SUCCESS")

	// Push the pinning/lease regions to any other open page now - the metrics-only
	// live tick no longer re-renders the MariaDB-backed regions, so this mutation
	// must propagate event-driven rather than waiting for the next lease change.
	s.publishDashboard()

	msg := fmt.Sprintf("Port %s pinned to %s - the device adopts it on its next DHCP renewal (within a few minutes).", portIdentity, ipStr)
	// Offer a reboot-to-apply when the pinned device is a Green-GO client online now
	// (its learned MAC ties the port to a scan-inventory device). The reboot reaches
	// the device at its current address so it re-DHCPs onto the pinned IP immediately.
	if dev, ok := s.rebootOfferForMAC(macStr); ok {
		s.setFlashDevice(w, r, msg, "success", dev)
	} else {
		s.setFlash(w, r, msg, "success")
	}

	// Redirect back to pinning page
	s.redirectHTMX(w, r, "/pinning")
}

func (s *Server) handleUnpin(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	portIdentity := r.FormValue("port_identity")

	log.Printf("[Pinning] Unpinning port %s...", logSafe(portIdentity))

	if s.mariadb == nil {
		s.handleError(w, r, "MariaDB connection is not active", http.StatusInternalServerError)
		return
	}
	n, err := s.mariadb.DeleteReservation(r.Context(), flexIDToBytes(portIdentity), 4)
	if err != nil {
		log.Printf("Failed to delete reservation: %v", err)
		s.handleError(w, r, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Clear the SQLite port label too, symmetric with pin (which writes both) - and do
	// it even when the MariaDB pin row was already gone (outage / restore / manual
	// delete). The label can outlive the pin, and is exactly what would otherwise
	// re-attach a stale name to the next device learned on this port - so unpin must be
	// able to clear it regardless.
	var labelN int64
	if res, e := s.sqlite.Exec("DELETE FROM port_labels WHERE flex_id_hex = ?", portIdentity); e != nil {
		log.Printf("[Pinning] failed to clear port label for %s: %v", logSafe(portIdentity), e)
	} else {
		labelN, _ = res.RowsAffected()
	}
	if n == 0 && labelN == 0 {
		s.handleError(w, r, "No matching pin was found to remove for "+portIdentity+".", http.StatusNotFound)
		return
	}
	_ = s.sqlite.LogAudit(s.getActor(r), "UNPIN_PORT", portIdentity, "", "", "SUCCESS")

	// Event-driven propagation (see handlePin) - the metrics-only tick skips the
	// MariaDB pinning regions, so broadcast the unpin now.
	s.publishDashboard()

	s.setFlash(w, r, fmt.Sprintf("Port %s successfully unbound", portIdentity), "success")

	s.redirectHTMX(w, r, "/pinning")
}

func (s *Server) handleLabel(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	portIdentity := r.FormValue("port_identity")
	label := r.FormValue("label")

	log.Printf("[Pinning] Updating label for port %s to '%s'...", logSafe(portIdentity), logSafe(label))

	// Save to SQLite
	_, err := s.sqlite.Exec("INSERT INTO port_labels (flex_id_hex, label) VALUES (?, ?) ON CONFLICT(flex_id_hex) DO UPDATE SET label=excluded.label", portIdentity, label)
	if err != nil {
		s.handleError(w, r, "Failed to update label: "+err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.sqlite.LogAudit(s.getActor(r), "LABEL_PORT", portIdentity, "", "", "SUCCESS")

	// A label change alters the pinned/learnable rows (and the dashboard pinnings
	// card) on other open pages; the metrics-only tick no longer re-renders them,
	// so broadcast event-driven.
	s.publishDashboard()

	// Confirm via a toast without reloading the page.
	if isDatastar(r) {
		toast(datastar.NewSSE(w, r), "Label updated for "+portIdentity, "success")
		return
	}
	s.setFlash(w, r, "Label updated for "+portIdentity, "success")
	s.redirectHTMX(w, r, "/pinning")
}
