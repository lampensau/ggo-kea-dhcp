package web

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/kea"
	"ggo-kea-dhcp/internal/web/views"
)

// reservationConflict reports whether assigning ip (in subnetID) to the device
// identified by (identifier, idType, ownMAC) would collide with ANOTHER device, with a
// human reason if so. Manual reservations span the whole subnet (in-pool addresses and
// the device's own current lease are fine); the only refusals are:
//   - (A) an existing reservation (type 0) or port pin (type 4) for a DIFFERENT
//     identifier - a config-level double assignment, and
//   - (B) a different device actively answering ARP on the address right now.
//
// ownMAC == "" (a pin from a row with no learned MAC) skips the ARP check rather than
// risk blocking a legitimate re-pin; if ARP is unavailable, liveness is unknown and (B)
// is likewise skipped (never block on unknown).
func (s *Server) reservationConflict(subnetID int, ip uint32, ipStr string, identifier []byte, idType int, ownMAC string) (string, bool) {
	if s.mariadb != nil {
		if existing, found, err := s.mariadb.ReservationByIP(subnetID, ip); err != nil {
			log.Printf("[reservation] conflict lookup for %s failed: %v", ipStr, err)
		} else if found && (existing.IdentifierType != idType || !bytes.Equal(existing.Identifier, identifier)) {
			what := "reserved for another device"
			if existing.IdentifierType == 4 {
				what = "pinned to another port"
			}
			return ipStr + " is already " + what + " - remove that first or choose another address.", true
		}
	}
	if s.arp != nil && ownMAC != "" {
		if mac, alive := s.arp.ProbeHost(ipStr); alive && normalizeMAC(mac) != normalizeMAC(ownMAC) {
			return ipStr + " is currently in use on the network by " + mac + " - release that device or choose another address.", true
		}
	}
	return "", false
}

// subnetIDForIP maps an IPv4 to the active profile's Kea subnet-id, which the
// renderer assigns as (scope index + 1) over loadScopeConfigs order (see
// renderKeaForScopes / RenderProfile). Returns false when no configured scope's
// CIDR contains the address - so a reservation can't be filed against a subnet that
// does not exist.
func (s *Server) subnetIDForIP(ip net.IP) (int, bool) {
	var profileID int
	if err := s.sqlite.QueryRow("SELECT id FROM profiles WHERE active = 1 LIMIT 1").Scan(&profileID); err != nil {
		return 0, false
	}
	scopes, err := s.loadScopeConfigs(profileID)
	if err != nil {
		return 0, false
	}
	for i, sc := range scopes {
		if _, ipnet, err := net.ParseCIDR(sc.CIDR); err == nil && ipnet.Contains(ip) {
			return i + 1, true
		}
	}
	return 0, false
}

// importSubnetMatcher resolves the active profile's scopes once and returns a
// matcher with the same (scope index + 1) -> Kea subnet-id mapping as
// subnetIDForIP, so a bulk import doesn't re-query + re-decode scopes per row.
// On any error it returns a matcher that matches nothing (rows are then skipped
// as "not in any configured subnet"), matching subnetIDForIP's fail-closed shape.
func (s *Server) importSubnetMatcher() func(net.IP) (int, bool) {
	var profileID int
	nets := []*net.IPNet{}
	if err := s.sqlite.QueryRow("SELECT id FROM profiles WHERE active = 1 LIMIT 1").Scan(&profileID); err == nil {
		if scopes, err := s.loadScopeConfigs(profileID); err == nil {
			for _, sc := range scopes {
				_, ipnet, _ := net.ParseCIDR(sc.CIDR)
				nets = append(nets, ipnet) // nil for an unparseable CIDR; skipped below
			}
		}
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

// evictForReservation frees the addresses involved in a freshly-created reservation
// so the reserved IP can take effect on the device's NEXT renewal (within minutes,
// given the short active lease timers) instead of only when its current lease lapses.
// It deletes (a) any lease currently held by the reserved client (matched by isOwner)
// and (b) any lease occupying the reserved IP itself. Best-effort: lookups/deletes are
// logged but never fail the reservation. This does NOT force an immediate switch - the
// server cannot push a renew; the device adopts the reserved IP when it next re-DHCPs.
func (s *Server) evictForReservation(reservedIP string, isOwner func(kea.ActiveLease) bool) {
	if s.kea == nil {
		return
	}
	leases, err := s.kea.GetLeases(1000)
	if err != nil {
		log.Printf("[Reservation] lease lookup for eviction failed: %v", err)
		return
	}
	del := map[string]bool{}
	for _, l := range leases {
		if l.IPAddress == reservedIP || isOwner(l) {
			del[l.IPAddress] = true
		}
	}
	for ip := range del {
		if err := s.kea.DeleteLease(ip); err != nil {
			log.Printf("[Reservation] lease4-del %s failed: %v", ip, err)
		}
	}
}

// evictForPin frees the addresses that would conflict with a freshly-created port
// pin, while deliberately NOT disturbing the pinned device's lease if it is already
// on the reserved IP - so pinning a device to the address it already has does not
// knock it offline (the old behavior, which deleted the reserved-IP lease
// unconditionally, left the device "Offline" until its next DHCP). It deletes:
//   - any lease on the reserved IP held by a DIFFERENT device (a squatter), so the
//     reserved device can take the address, and
//   - any OTHER lease held by the pinned device (matched by MAC, or by the pinned
//     flex-id) that is NOT on the reserved IP - e.g. a stale old-format flex-id lease
//     left over from an Option-82 format change, which would otherwise linger as a
//     duplicate learnable port.
//
// wantMAC may be empty (pin from a row with no live MAC); then only the reserved IP
// and the pinned flex-id identify the device. Best-effort: lookups/deletes are logged
// but never fail the pin.
func (s *Server) evictForPin(reservedIP, wantMAC, portIdentity string) {
	if s.kea == nil {
		return
	}
	leases, err := s.kea.GetLeases(1000)
	if err != nil {
		log.Printf("[Pinning] lease lookup for eviction failed: %v", err)
		return
	}
	del := map[string]bool{}
	for _, l := range leases {
		onReservedIP := l.IPAddress == reservedIP
		isPinnedDevice := wantMAC != "" && normalizeMAC(l.HWAddress) == wantMAC
		if !isPinnedDevice {
			if id, ok := decodePortIdentity(l.ClientID); ok && id.Key == portIdentity {
				isPinnedDevice = true
			}
		}
		switch {
		case isPinnedDevice && !onReservedIP:
			del[l.IPAddress] = true // the device's stale/other lease on a different IP
		case onReservedIP && !isPinnedDevice:
			del[l.IPAddress] = true // a different device squatting on the reserved IP
		}
		// isPinnedDevice && onReservedIP -> keep: already correct, deleting it is churn.
	}
	for ip := range del {
		if err := s.kea.DeleteLease(ip); err != nil {
			log.Printf("[Pinning] lease4-del %s failed: %v", ip, err)
		}
	}
}

// formReturn returns a safe same-site redirect target from the posted "return"
// field (must be a root-relative path), else def. Prevents an open redirect.
func formReturn(r *http.Request, def string) string {
	if rt := r.FormValue("return"); strings.HasPrefix(rt, "/") && !strings.HasPrefix(rt, "//") {
		return rt
	}
	return def
}

// handleReservationAdd creates a client (hardware-address) host reservation - a
// fixed IP for a specific MAC. The subnet-id is derived from the chosen IP so the
// reservation always lands in the right Kea subnet. Kea's MySQL host backend reads
// it live (same path as switch-port pins), so no reload is needed.
func (s *Server) handleReservationAdd(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if s.mariadb == nil {
		s.handleError(w, r, "MariaDB (Kea host storage) is not connected, so reservations can't be saved.", http.StatusServiceUnavailable)
		return
	}
	macStr := strings.TrimSpace(r.FormValue("mac"))
	ipStr := strings.TrimSpace(r.FormValue("ip"))
	hostname := strings.TrimSpace(r.FormValue("hostname"))

	hw, err := net.ParseMAC(macStr)
	if err != nil || len(hw) != 6 {
		s.handleError(w, r, "Enter a valid MAC address (e.g. 00:1f:80:12:34:56).", http.StatusBadRequest)
		return
	}
	// Carry the auto/default Green-GO hostname into a manual reservation: if the
	// operator left the hostname blank, adopt the scanned device name (slugified).
	// Only fills a blank - an explicit operator hostname is never overridden.
	if hostname == "" {
		hostname = s.defaultHostnameFor(hw.String())
	}
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To4() == nil {
		s.handleError(w, r, "Enter a valid IPv4 address.", http.StatusBadRequest)
		return
	}
	subnetID, ok := s.subnetIDForIP(ip)
	if !ok {
		s.handleError(w, r, ipStr+" is not inside any configured subnet.", http.StatusBadRequest)
		return
	}
	if reason, conflict := s.reservationConflict(subnetID, kea.IPToUint32(ip), ipStr, []byte(hw), 0, hw.String()); conflict {
		_ = s.sqlite.LogAudit(s.getActor(r), "RESERVATION_ADD", macStr+" -> "+ipStr, "", reason, "WARNING")
		s.handleError(w, r, reason, http.StatusConflict)
		return
	}
	res := db.HostReservation{
		Identifier:     []byte(hw),
		IdentifierType: 0, // hardware-address
		SubnetID:       subnetID,
		IPv4Address:    kea.IPToUint32(ip),
		Hostname:       hostname,
	}
	if err := s.mariadb.InsertReservation(res); err != nil {
		s.handleError(w, r, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Free the device's current lease and anything on the reserved IP so the device
	// adopts the reservation on its next renewal rather than clinging to its old lease.
	wantMAC := normalizeMAC(hw.String())
	s.evictForReservation(ipStr, func(l kea.ActiveLease) bool { return normalizeMAC(l.HWAddress) == wantMAC })
	_ = s.sqlite.LogAudit(s.getActor(r), "RESERVATION_ADD", macStr+" -> "+ipStr, "", "", "SUCCESS")
	// Propagate to other open pages now: the metrics-only live tick skips the
	// MariaDB-backed lease/pinning regions, so a reservation that evicts no lease
	// would otherwise not appear until the next lease change.
	s.publishDashboard()
	s.setFlash(w, fmt.Sprintf("Reserved %s for %s - the device adopts it on its next DHCP renewal (within a few minutes).", ipStr, macStr), "success")
	s.redirectHTMX(w, r, formReturn(r, "/leases"))
}

// handleReservationImport bulk-creates client (hardware-address) reservations from
// an uploaded CSV (header "mac,ip,hostname"; hostname optional). Each row reuses the
// single-add validation (parse + subnet match + conflict check) and a blank hostname
// adopts the scanned Green-GO name. Valid rows are written in one transaction
// (InsertReservations) and their devices evicted so they adopt the reservation on the
// next renewal; invalid rows are skipped and summarized. Kea's MySQL host backend
// reads the rows live, so no reload is needed.
func (s *Server) handleReservationImport(w http.ResponseWriter, r *http.Request) {
	if s.mariadb == nil {
		s.handleError(w, r, "MariaDB (Kea host storage) is not connected, so reservations can't be imported.", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBackupUpload) // bound the upload before csv.ReadAll loads it all into memory
	file, _, err := r.FormFile("file")
	if err != nil {
		s.handleError(w, r, "Choose a CSV file to import (mac,ip,hostname).", http.StatusBadRequest)
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1 // tolerate rows with/without the optional hostname
	reader.TrimLeadingSpace = true
	records, err := reader.ReadAll()
	if err != nil {
		s.handleError(w, r, "Could not read the CSV: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Resolve the active profile's scopes ONCE into a subnet matcher: subnetIDForIP
	// re-queries the active profile and re-decodes every scope on each call, an N+1
	// over the whole file.
	subnetFor := s.importSubnetMatcher()

	toInsert, owners, skipped, problems := buildImportReservations(records,
		subnetFor,
		// Skip the per-row ARP liveness probe (pass ownMAC=""): with it, each of N
		// rows blocks up to ~400ms probing an almost-always-unused IP (a 200-row
		// import would hang for ~80s). The IP-level config conflict check still runs.
		func(subnetID int, ipU uint32, ipStr string, id []byte, mac string) (string, bool) {
			return s.reservationConflict(subnetID, ipU, ipStr, id, 0, "")
		},
		s.defaultHostnameFor,
	)

	if len(toInsert) > 0 {
		if err := s.mariadb.InsertReservations(toInsert); err != nil {
			s.handleError(w, r, "Database error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		for _, o := range owners {
			wantMAC := normalizeMAC(o.mac)
			s.evictForReservation(o.ip, func(l kea.ActiveLease) bool { return normalizeMAC(l.HWAddress) == wantMAC })
		}
	}

	result := "SUCCESS"
	if len(toInsert) == 0 {
		result = "WARNING"
	}
	_ = s.sqlite.LogAudit(s.getActor(r), "RESERVATION_IMPORT", fmt.Sprintf("%d imported, %d skipped", len(toInsert), skipped), "", strings.Join(problems, "; "), result)
	s.publishDashboard()

	msg := fmt.Sprintf("Imported %d reservation(s)", len(toInsert))
	if skipped > 0 {
		msg += fmt.Sprintf(", skipped %d (%s)", skipped, strings.Join(problems, "; "))
		s.setFlash(w, msg, "warning")
	} else {
		msg += " - devices adopt them on their next DHCP renewal."
		s.setFlash(w, msg, "success")
	}
	s.redirectHTMX(w, r, formReturn(r, "/leases"))
}

// allBlank reports whether every field in a CSV record is empty after trimming, so a
// trailing newline (one empty field) or a ",,"-style line is ignored, not flagged.
func allBlank(rec []string) bool {
	for _, f := range rec {
		if strings.TrimSpace(f) != "" {
			return false
		}
	}
	return true
}

// importOwner pairs an imported reservation's IP with its MAC, for the post-insert
// lease eviction (so the device adopts its reserved IP on the next renewal).
type importOwner struct{ ip, mac string }

// buildImportReservations is the pure CSV-row decision core of handleReservationImport,
// split out so it is testable without a live Server/DB. It validates each row (MAC, IP,
// subnet membership via subnetFor, conflict via conflictFn) the same way the single-add
// path does, fills a blank hostname from hostnameFor, drops blank/header/half/duplicate
// rows, and returns the reservations to insert, their owners, the skip count, and up to
// five human-readable skip reasons. It mutates nothing.
func buildImportReservations(
	records [][]string,
	subnetFor func(net.IP) (int, bool),
	conflictFn func(subnetID int, ipU uint32, ipStr string, id []byte, mac string) (string, bool),
	hostnameFor func(mac string) string,
) (toInsert []db.HostReservation, owners []importOwner, skipped int, problems []string) {
	seenIP := map[uint32]bool{}  // guard intra-file duplicate IPs (the DB conflict check can't see them yet)
	seenMAC := map[string]bool{} // guard intra-file duplicate MACs (ON DUPLICATE KEY would silently collapse them)
	skip := func(row int, reason string) {
		skipped++
		if len(problems) < 5 { // cap the summary; the rest are just counted
			problems = append(problems, fmt.Sprintf("row %d: %s", row, reason))
		}
	}
	for i, rec := range records {
		if allBlank(rec) {
			continue // blank line (one empty field, or ",,"-style all-empty)
		}
		// Strip a UTF-8 BOM (Excel/Sheets prepend one) so the header check and the
		// first MAC parse don't see a BOM-prefixed first field.
		macStr := strings.TrimSpace(strings.TrimPrefix(rec[0], "\ufeff"))
		// Skip a "mac" header row wherever it appears (not just row 0): a blank leading
		// line would push the header to row 1, and "mac" is never a valid MAC anyway.
		if strings.EqualFold(macStr, "mac") {
			continue
		}
		if len(rec) < 2 {
			skip(i+1, "expected at least mac,ip")
			continue
		}
		ipStr := strings.TrimSpace(rec[1])
		hostname := ""
		if len(rec) >= 3 {
			hostname = strings.TrimSpace(rec[2])
		}
		hw, perr := net.ParseMAC(macStr)
		if perr != nil || len(hw) != 6 {
			skip(i+1, "invalid MAC "+macStr)
			continue
		}
		if seenMAC[hw.String()] {
			skip(i+1, macStr+" duplicated in file")
			continue
		}
		ip := net.ParseIP(ipStr)
		if ip == nil || ip.To4() == nil {
			skip(i+1, "invalid IPv4 "+ipStr)
			continue
		}
		ipU := kea.IPToUint32(ip)
		if seenIP[ipU] {
			skip(i+1, ipStr+" duplicated in file")
			continue
		}
		subnetID, ok := subnetFor(ip)
		if !ok {
			skip(i+1, ipStr+" not in any configured subnet")
			continue
		}
		if reason, conflict := conflictFn(subnetID, ipU, ipStr, []byte(hw), hw.String()); conflict {
			skip(i+1, reason)
			continue
		}
		if hostname == "" {
			hostname = hostnameFor(hw.String())
		}
		seenIP[ipU] = true
		seenMAC[hw.String()] = true
		toInsert = append(toInsert, db.HostReservation{
			Identifier:     []byte(hw),
			IdentifierType: 0,
			SubnetID:       subnetID,
			IPv4Address:    ipU,
			Hostname:       hostname,
		})
		owners = append(owners, importOwner{ip: ipStr, mac: hw.String()})
	}
	return toInsert, owners, skipped, problems
}

// handleReservationDelete removes a client (hardware-address) reservation.
func (s *Server) handleReservationDelete(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if s.mariadb == nil {
		s.handleError(w, r, "MariaDB is not connected.", http.StatusServiceUnavailable)
		return
	}
	macStr := strings.TrimSpace(r.FormValue("mac"))
	hw, err := net.ParseMAC(macStr)
	if err != nil || len(hw) != 6 {
		s.handleError(w, r, "invalid MAC address", http.StatusBadRequest)
		return
	}
	n, err := s.mariadb.DeleteReservation([]byte(hw), 0)
	if err != nil {
		s.handleError(w, r, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if n == 0 {
		s.handleError(w, r, "No matching reservation was found to remove for "+macStr+".", http.StatusNotFound)
		return
	}
	_ = s.sqlite.LogAudit(s.getActor(r), "RESERVATION_DELETE", macStr, "", "", "SUCCESS")
	// Event-driven propagation (see handleReservationAdd).
	s.publishDashboard()
	s.setFlash(w, "Removed reservation for "+macStr, "success")
	s.redirectHTMX(w, r, formReturn(r, "/leases"))
}

// unifiedLeaseRows is the /leases model: active DHCP leases merged with client
// (MAC) reservations into one list. Active leases (expired ones dropped) are tagged
// Reserved when a reservation exists for their MAC; reservations with no current
// lease (offline devices) are appended so the reservation stays visible and
// removable. Presence (online/offline) is tagged from the active ARP prober (keyed by
// IP). Sorted by IP.
func (s *Server) unifiedLeaseRows(leases []kea.ActiveLease) []views.LeaseRow {
	reachable, available := s.presenceByIP()
	return s.unifiedLeaseRowsWith(leases, reachable, available)
}

// unifiedLeaseRowsWith is unifiedLeaseRows over an already-collected presence set, so the
// live broadcast can share one prober snapshot with the dashboard view build. It fetches
// the pinned-port set itself (the /leases page path); the dashboard broadcast reuses the
// pins it already fetched via unifiedLeaseRowsWithPins.
func (s *Server) unifiedLeaseRowsWith(leases []kea.ActiveLease, reachable map[string]bool, available bool) []views.LeaseRow {
	// /leases path: no shared scanner snapshot here, so self-fetch the name map.
	return s.unifiedLeaseRowsWithPins(leases, reachable, available, s.pinnedPortKeys(), s.ggoNamesByMAC())
}

// pinnedPortKeys returns the set of pinned switch-port identities (flex-id, type-4
// reservations), keyed the same way decodePortIdentity renders a lease's port. Returns
// nil when MariaDB is absent or the query fails. The dashboard broadcast builds the
// equivalent set from the pins buildDashboardViewWith already fetched (v.Pinned), so it
// never queries type-4 reservations twice per render.
func (s *Server) pinnedPortKeys() map[string]bool {
	if s.mariadb == nil {
		return nil
	}
	p, err := s.fetchPinnedPorts()
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

// dedupeStaleLeases collapses two active leases that share a MAC AND a subnet down to
// the most-recently-active one. This happens when a device moves switch ports: its
// Option-82 flex-id changes, Kea treats it as a new client and grants a fresh lease
// while the old lease lingers until expiry, so the same device shows on two IPs. Leases
// in DIFFERENT subnets are kept (a trunked device legitimately holds one per VLAN), and
// a lease with no MAC is always kept.
func dedupeStaleLeases(leases []kea.ActiveLease) []kea.ActiveLease {
	idx := make(map[string]int, len(leases)) // "mac|subnet" -> position in out
	out := make([]kea.ActiveLease, 0, len(leases))
	for _, l := range leases {
		mac := normalizeMAC(l.HWAddress)
		if mac == "" {
			out = append(out, l)
			continue
		}
		key := mac + "|" + strconv.Itoa(l.SubnetID)
		if i, ok := idx[key]; ok {
			if l.Cltt > out[i].Cltt {
				out[i] = l // newer lease wins; the older one was the stale port move
			}
			continue
		}
		idx[key] = len(out)
		out = append(out, l)
	}
	return out
}

// unifiedLeaseRowsWithPins is unifiedLeaseRowsWith over an already-resolved pinned-port
// key set, so the dashboard broadcast shares the single fetchPinnedPorts that
// buildDashboardViewWith already ran (instead of querying type-4 reservations twice).
// A lease whose flex-id matches a pinned port is fixed by its port; the row must not
// offer a MAC reservation (Kea's flex-id reservation wins, so a hw-address one is
// shadowed) - but a leftover hw-address reservation stays removable (see LeasesBody).
func (s *Server) unifiedLeaseRowsWithPins(leases []kea.ActiveLease, reachable map[string]bool, available bool, pinnedKeys map[string]bool, ggoNames map[string]string) []views.LeaseRow {
	rows := buildLeaseRows(dedupeStaleLeases(activeLeases(leases)))

	res := map[string]db.HostReservation{}
	if s.mariadb != nil {
		if list, err := s.mariadb.HWReservations(); err == nil {
			for _, rsv := range list {
				res[normalizeMAC(net.HardwareAddr(rsv.Identifier).String())] = rsv
			}
		} else {
			log.Printf("[Reservations] read failed: %v", err)
		}
	}

	seen := make(map[string]bool, len(rows))
	for i := range rows {
		key := normalizeMAC(rows[i].HWAddress)
		if rsv, ok := res[key]; ok {
			rows[i].Reserved = true
			rows[i].SubnetID = rsv.SubnetID
		}
		// A lease arriving on a pinned port carries the port's flex-id in its client-id
		// (flex_id with replace-client-id). decodePortIdentity returns ok=false for an
		// ordinary client, so non-Option-82 devices never false-match.
		if len(pinnedKeys) > 0 {
			if id, ok := decodePortIdentity(rows[i].ClientID); ok && pinnedKeys[id.Key] {
				rows[i].PortPinned = true
			}
		}
		// Only a NON-pinned row counts its MAC as "seen" for the offline-reservation
		// fallback below. A pinned-port row shows the IP the port pin assigns and is not
		// deletable here (the pin is managed on Port Pinning); a separate hw-address
		// reservation for that same device must still surface its own deletable row at
		// the reserved IP - otherwise a leftover reservation for a now-pinned device
		// becomes invisible and uncleanable once its old dynamic lease expires.
		if !rows[i].PortPinned {
			seen[key] = true
		}
	}
	// Reserved devices with no active lease (offline): list them so the reservation
	// is visible and removable.
	for key, rsv := range res {
		if seen[key] {
			continue
		}
		mac := net.HardwareAddr(rsv.Identifier).String()
		rows = append(rows, views.LeaseRow{
			IPAddress: kea.Uint32ToIP(rsv.IPv4Address).String(),
			HWAddress: mac,
			Hostname:  rsv.Hostname,
			Class:     kea.ClassifyMAC(mac),
			Reserved:  true,
			SubnetID:  rsv.SubnetID,
		})
	}
	// Fill any still-nameless row with the device's scanned Green-GO name (display
	// only; never overrides a hostname the lease/reservation already carries).
	s.overlayGgoNamesWith(rows, ggoNames)
	sort.SliceStable(rows, func(i, j int) bool { return leaseIPKey(rows[i].IPAddress) < leaseIPKey(rows[j].IPAddress) })
	// Presence is keyed by IP from the active ARP prober: a row is online iff the device
	// holding that address answered an ARP recently. Because it is per-IP, a pinned device
	// shows online at its pin's IP while an unused reservation IP for the same MAC simply
	// does not answer (offline) - no per-MAC sibling correction needed.
	s.markLeasePresenceWith(reachable, available, rows)
	s.markLeaseLastSeen(rows)
	return rows
}

// markLeaseLastSeen tags each row with when its MAC was last observed active (from
// the persisted last-seen tracker). For a live lease this is "just now"; for an
// offline reservation it is the real age, and a reservation unseen past the stale
// threshold is flagged so the operator can spot a long-gone device.
func (s *Server) markLeaseLastSeen(rows []views.LeaseRow) {
	ls := s.lastSeenSnapshot()
	if len(ls) == 0 {
		return
	}
	// A MAC online at one IP must not lend its "just now" to a DIFFERENT row for the same
	// MAC - a pinned device's shadow hw-address reservation at another IP. That shadow is
	// offline at its own address; the device's recent activity belongs to the IP it holds,
	// not this one. Presence is per-IP but last-seen is keyed by MAC, so without this guard
	// the shadow shows the live device's timestamp ("just now") though nothing is there.
	onlineMAC := make(map[string]bool)
	for i := range rows {
		if rows[i].Presence == "online" {
			onlineMAC[normalizeMAC(rows[i].HWAddress)] = true
		}
	}
	now := time.Now().Unix()
	for i := range rows {
		mac := normalizeMAC(rows[i].HWAddress)
		// Shadow of a device online at another IP: leave last-seen blank (renders "—").
		// Only when presence is the explicit "offline" - an "" (probing unavailable)
		// row keeps its prior behaviour, since we cannot know the device is online elsewhere.
		if rows[i].Presence == "offline" && onlineMAC[mac] {
			continue
		}
		ts := ls[mac]
		if ts <= 0 {
			continue
		}
		rows[i].LastSeen = ts
		rows[i].LastSeenText = relativeAgo(ts, now)
		rows[i].Stale = rows[i].Presence != "online" && now-ts > portStaleAfter
	}
}
