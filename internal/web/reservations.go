package web

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"ggo-kea-dhcp/internal/appliance"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/kea"
	"ggo-kea-dhcp/internal/netmon"
	"ggo-kea-dhcp/internal/web/views"

	"github.com/starfederation/datastar-go/datastar"
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
func (s *Server) reservationConflict(ctx context.Context, subnetID int, ip uint32, ipStr string, identifier []byte, idType int, ownMAC string) (string, bool) {
	if s.mariadb != nil {
		if existing, found, err := s.mariadb.ReservationByIP(ctx, subnetID, ip); err != nil {
			log.Printf("[reservation] conflict lookup for %s failed: %v", logSafe(ipStr), err)
		} else if found && (existing.IdentifierType != idType || !bytes.Equal(existing.Identifier, identifier)) {
			what := "reserved for another device"
			if existing.IdentifierType == 4 {
				what = "pinned to another port"
			}
			return ipStr + " is already " + what + " - remove that first or choose another address.", true
		}
	}
	if s.mon.Arp != nil && ownMAC != "" {
		if mac, alive := s.mon.Arp.ProbeHost(ipStr); alive && normalizeMAC(mac) != normalizeMAC(ownMAC) {
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
	if err := s.sqlite.QueryRow("SELECT id FROM profiles WHERE active = 1 LIMIT 1").Scan(&profileID); err == nil {
		if scopes, err := s.loadScopeConfigs(profileID); err == nil {
			return appliance.SubnetMatcherForScopes(scopes)
		}
	}
	return func(net.IP) (int, bool) { return 0, false }
}

// evictForReservations frees the addresses involved in one or more freshly-created
// reservations so each reserved IP can take effect on the device's NEXT renewal (within
// minutes, given the short active lease timers) instead of only when its current lease
// lapses. It dumps the lease set ONCE and deletes every lease that collides with any
// reservation (holds a reserved IP, or is owned by a reserved MAC) - so a bulk import is
// one GetLeases, not one per row. Best-effort: lookups/deletes are logged but never fail
// the reservation. This does NOT force an immediate switch - the server cannot push a
// renew; the device adopts the reserved IP when it next re-DHCPs.
func (s *Server) evictForReservations(ctx context.Context, owners []importOwner) {
	if s.kea == nil || len(owners) == 0 {
		return
	}
	leases, err := s.kea.GetLeases(ctx, defaultLeasePageSize)
	if err != nil {
		log.Printf("[Reservation] lease lookup for eviction failed: %v", err)
		return
	}
	reservedIP := make(map[string]bool, len(owners))
	reservedMAC := make(map[string]bool, len(owners))
	for _, o := range owners {
		reservedIP[o.ip] = true
		if m := normalizeMAC(o.mac); m != "" {
			reservedMAC[m] = true
		}
	}
	del := map[string]bool{}
	for _, l := range leases {
		if reservedIP[l.IPAddress] || reservedMAC[normalizeMAC(l.HWAddress)] {
			del[l.IPAddress] = true
		}
	}
	for ip := range del {
		if err := s.kea.DeleteLease(ctx, ip); err != nil {
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
func (s *Server) evictForPin(ctx context.Context, reservedIP, wantMAC, portIdentity string) {
	if s.kea == nil {
		return
	}
	leases, err := s.kea.GetLeases(ctx, defaultLeasePageSize)
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
		if err := s.kea.DeleteLease(ctx, ip); err != nil {
			log.Printf("[Pinning] lease4-del %s failed: %v", ip, err)
		}
	}
}

// formReturn returns a safe same-site redirect target from the posted "return"
// field (must be a root-relative path), else def. Prevents an open redirect.
func formReturn(r *http.Request, def string) string {
	if rt := r.FormValue("return"); isValidRedirect(rt) {
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
	// The hostname is stored as a DNS label, so sanitize unconditionally. A blank
	// (or garbage-only) name adopts the scanned Green-GO device name; an explicit
	// operator hostname is never replaced, only normalized.
	if hostname = slugifyHostname(hostname); hostname == "" {
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
	res := db.HostReservation{
		Identifier:     []byte(hw),
		IdentifierType: 0, // hardware-address
		SubnetID:       subnetID,
		IPv4Address:    kea.IPToUint32(ip),
		Hostname:       hostname,
	}
	// Check + insert under reservationMu so a concurrent add/import can't slip a same-IP
	// row in between them (see the field comment). Deferred unlock in a closure: a panic
	// in the check or insert must not leave the lock held and wedge every future write.
	var reason string
	var conflict bool
	var insErr error
	func() {
		s.reservationMu.Lock()
		defer s.reservationMu.Unlock()
		if reason, conflict = s.reservationConflict(r.Context(), subnetID, kea.IPToUint32(ip), ipStr, []byte(hw), 0, hw.String()); conflict {
			return
		}
		insErr = s.mariadb.InsertReservation(r.Context(), res)
	}()
	if conflict {
		_ = s.sqlite.LogAudit(s.getActor(r), "RESERVATION_ADD", macStr+" -> "+ipStr, "", reason, "WARNING")
		s.handleError(w, r, reason, http.StatusConflict)
		return
	}
	if insErr != nil {
		s.handleError(w, r, "Database error: "+insErr.Error(), http.StatusInternalServerError)
		return
	}
	// Free the device's current lease and anything on the reserved IP so the device
	// adopts the reservation on its next renewal rather than clinging to its old lease.
	// Post-commit best-effort cleanup: must NOT be tied to r.Context() - if the
	// operator navigates away now, the reservation is already committed and the
	// eviction (so the device adopts it quickly) still has to run to completion.
	s.evictForReservations(context.Background(), []importOwner{{ip: ipStr, mac: hw.String()}})
	_ = s.sqlite.LogAudit(s.getActor(r), "RESERVATION_ADD", macStr+" -> "+ipStr, "", "", "SUCCESS")
	// Propagate to other open pages now: the metrics-only live tick skips the
	// MariaDB-backed lease/pinning regions, so a reservation that evicts no lease
	// would otherwise not appear until the next lease change.
	s.publishDashboard()
	msg := fmt.Sprintf("Reserved %s for %s - the device adopts it on its next DHCP renewal (within a few minutes).", ipStr, macStr)
	// If the reserved device is a Green-GO client that is online now, offer to reboot it
	// so the change applies immediately instead of waiting out the renewal.
	dev, offer := s.rebootOfferForMAC(hw.String())

	// Live path: the reserve dialog is opened from several pages (dashboard,
	// leases), so the regions refresh on the operator's own SSE stream via the
	// publishDashboard above and we answer with a toast. The reboot dialog opens
	// only where its opener is mounted (rebootExecScript's guard no-ops elsewhere).
	if isDatastar(r) {
		sse := datastar.NewSSE(w, r)
		toast(sse, msg, "success")
		if offer {
			rebootExecScript(sse, dev)
		}
		return
	}
	if offer {
		s.setFlashDevice(w, r, msg, "success", dev)
	} else {
		s.setFlash(w, r, msg, "success")
	}
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
	// No MaxBytesReader here: lifecycleMiddleware's CSRF check already parsed (and
	// bounded, maxRequestBody) the multipart body before this handler runs.
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

	// Hold reservationMu across the whole conflict-check + insert of this batch, so it
	// is mutually exclusive with a single add (or another import) checking the same IPs
	// (see the field comment). Deferred unlock in a closure so a panic in the build or
	// insert can't strand the lock; released before the eviction, which needs no guard.
	var toInsert []db.HostReservation
	var owners []importOwner
	var skipped int
	var problems []string
	var insErr error
	func() {
		s.reservationMu.Lock()
		defer s.reservationMu.Unlock()
		toInsert, owners, skipped, problems = buildImportReservations(records,
			subnetFor,
			// Skip the per-row ARP liveness probe (pass ownMAC=""): with it, each of N
			// rows blocks up to ~400ms probing an almost-always-unused IP (a 200-row
			// import would hang for ~80s). The IP-level config conflict check still runs.
			func(subnetID int, ipU uint32, ipStr string, id []byte, mac string) (string, bool) {
				return s.reservationConflict(r.Context(), subnetID, ipU, ipStr, id, 0, "")
			},
			s.defaultHostnameFor,
		)
		if len(toInsert) > 0 {
			insErr = s.mariadb.InsertReservations(r.Context(), toInsert)
		}
	}()
	if insErr != nil {
		s.handleError(w, r, "Database error: "+insErr.Error(), http.StatusInternalServerError)
		return
	}
	if len(toInsert) > 0 {
		// Post-commit eviction dumps leases once for the whole batch: a large import
		// must not be abortable by the operator's browser disconnecting mid-request -
		// the rows are already committed - so it runs on a background context.
		s.evictForReservations(context.Background(), owners)
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
		s.setFlash(w, r, msg, "warning")
	} else {
		msg += " - devices adopt them on their next DHCP renewal."
		s.setFlash(w, r, msg, "success")
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
	seenIP := map[uint32]bool{}        // guard intra-file duplicate IPs (the DB conflict check can't see them yet)
	seenMACSubnet := map[string]bool{} // guard intra-file duplicate MAC+subnet (the hosts unique key is per-subnet, so the SAME MAC in a different subnet - a trunked device - is legal and must NOT be collapsed)
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
		// Dedupe on MAC+subnet, not MAC alone: a trunked device legitimately reserves
		// one IP per subnet under the same MAC (the hosts unique key is per-subnet), so
		// keying on MAC alone here would wrongly drop the second row as a file duplicate.
		macKey := fmt.Sprintf("%s|%d", hw.String(), subnetID)
		if seenMACSubnet[macKey] {
			skip(i+1, macStr+" duplicated in file for subnet "+strconv.Itoa(subnetID))
			continue
		}
		if reason, conflict := conflictFn(subnetID, ipU, ipStr, []byte(hw), hw.String()); conflict {
			skip(i+1, reason)
			continue
		}
		// Stored as a DNS label - sanitize unconditionally, matching the single add.
		if hostname = slugifyHostname(hostname); hostname == "" {
			hostname = hostnameFor(hw.String())
		}
		seenIP[ipU] = true
		seenMACSubnet[macKey] = true
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
	n, err := s.mariadb.DeleteReservation(r.Context(), []byte(hw), 0)
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
	s.setFlash(w, r, "Removed reservation for "+macStr, "success")
	s.redirectHTMX(w, r, formReturn(r, "/leases"))
}

// unifiedLeaseRows is the /leases model: active DHCP leases merged with client
// (MAC) reservations into one list. Active leases (expired ones dropped) are tagged
// Reserved when a reservation exists for their MAC; reservations with no current
// lease (offline devices) are appended so the reservation stays visible and
// removable. Presence (online/offline) is tagged from the active ARP prober (keyed by
// IP). Sorted by IP.
func (s *Server) unifiedLeaseRows(ctx context.Context, leases []kea.ActiveLease) []views.LeaseRow {
	reachable, available := s.presenceByIP()
	// Page-render path: no shared snapshots here, so self-fetch every source.
	return s.unifiedLeaseRowsFrom(ctx, leases, leaseRowSources{
		Reachable:  reachable,
		Available:  available,
		PinnedKeys: s.recon.PinnedPortKeys(ctx),
		GgoNames:   s.ggoNamesByMAC(),
		Awaiting:   s.awaitingPoolHosts(),
		Res:        s.fetchHWReservationMap(ctx),
	})
}

// leaseRowSources carries the pre-collected inputs unifiedLeaseRowsFrom merges,
// so the live broadcast can share the snapshots it already fetched for the
// dashboard build instead of re-querying per region (this replaced a positional
// staircase of overloads that had grown to eight parameters).
type leaseRowSources struct {
	Reachable  map[string]bool               // ARP presence by IP
	Available  bool                          // whether the presence prober ran at all
	PinnedKeys map[string]bool               // pinned-port flex-id keys
	GgoNames   map[string]string             // device-scan names by MAC
	Awaiting   []netmon.PoolHost             // static-in-pool hosts awaiting adoption
	Res        map[string]db.HostReservation // hw-address reservations by MAC
}

// fetchHWReservationMap returns the client (hw-address) reservations keyed by
// normalized MAC, or an empty map when MariaDB is absent or the read fails. Fetched
// once per build and shared by the lease-row merge and the dashboard card's awaiting
// suppression.
func (s *Server) fetchHWReservationMap(ctx context.Context) map[string]db.HostReservation {
	if s.hwResFetch != nil {
		return s.hwResFetch(ctx)
	}
	res := map[string]db.HostReservation{}
	if s.mariadb == nil {
		return res
	}
	list, err := s.mariadb.HWReservations(ctx)
	if err != nil {
		log.Printf("[Reservations] read failed: %v", err)
		return res
	}
	for _, rsv := range list {
		res[normalizeMAC(net.HardwareAddr(rsv.Identifier).String())] = rsv
	}
	return res
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

// unifiedLeaseRowsFrom merges leases with the pre-collected source snapshots in
// src, so the dashboard broadcast shares the single fetch of each source that
// buildDashboardViewWith already ran (instead of querying per region).
// A lease whose flex-id matches a pinned port is fixed by its port; the row must not
// offer a MAC reservation (Kea's flex-id reservation wins, so a hw-address one is
// shadowed) - but a leftover hw-address reservation stays removable (see LeasesBody).
// awaiting is netmon's passively-observed in-pool-but-unleased host set; hosts not
// already covered by a lease or reservation row are appended as "awaiting renewal"
// rows so a client whose lease was purged (clock step, wipe) stays visible. res is
// the prefetched hw-address reservation map (fetchHWReservationMap) - passed in so
// the dashboard broadcast shares ONE HWReservations query with the card build
// instead of re-querying per consumer (same rationale as pinnedKeys).
func (s *Server) unifiedLeaseRowsFrom(ctx context.Context, leases []kea.ActiveLease, src leaseRowSources) []views.LeaseRow {
	reachable, available := src.Reachable, src.Available
	pinnedKeys, ggoNames, awaiting, res := src.PinnedKeys, src.GgoNames, src.Awaiting, src.Res
	rows := buildLeaseRows(dedupeStaleLeases(activeLeases(leases)))

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
	rows = appendAwaitingRows(rows, awaiting)
	// Fill any still-nameless row with the device's scanned Green-GO name (display
	// only; never overrides a hostname the lease/reservation already carries).
	s.overlayGgoNamesWith(rows, ggoNames)
	// The row set is final: funnel every name (client-announced, stored, and
	// scan-filled alike) through the sanitize+dedupe pass.
	sanitizeLeaseHostnames(rows)
	sort.SliceStable(rows, func(i, j int) bool { return leaseIPKey(rows[i].IPAddress) < leaseIPKey(rows[j].IPAddress) })
	// Presence is keyed by IP from the active ARP prober: a row is online iff the device
	// holding that address answered an ARP recently. Because it is per-IP, a pinned device
	// shows online at its pin's IP while an unused reservation IP for the same MAC simply
	// does not answer (offline) - no per-MAC sibling correction needed.
	s.markLeasePresenceWith(reachable, available, rows)
	s.markLeaseLastSeen(rows)
	return rows
}

// appendAwaitingRows appends a row for each passively-observed host using a pool
// address without a lease (netmon's unleased-pool-host set), so a client whose lease
// vanished underneath it (clock-step purge, wipe) stays visible until it renews at T1.
// Any host already represented - by IP (its lease reappeared; the detector's 30s lease
// snapshot lags GetLeases) or by MAC (a reservation row) - is skipped, so scope stays
// "no lease, no reservation, no pin" with no duplicates. Shared by the /leases table
// and the dashboard's Active Leases card.
func appendAwaitingRows(rows []views.LeaseRow, awaiting []netmon.PoolHost) []views.LeaseRow {
	if len(awaiting) == 0 {
		return rows
	}
	ipSeen := make(map[string]bool, len(rows))
	macSeen := make(map[string]bool, len(rows))
	for i := range rows {
		ipSeen[rows[i].IPAddress] = true
		macSeen[normalizeMAC(rows[i].HWAddress)] = true
	}
	for _, h := range awaiting {
		if ipSeen[h.IP] || macSeen[normalizeMAC(h.MAC)] {
			continue
		}
		state := "awaiting"
		if h.Flagged {
			state = "static"
		}
		rows = append(rows, views.LeaseRow{
			IPAddress: h.IP,
			HWAddress: h.MAC,
			Class:     kea.ClassifyMAC(h.MAC),
			// Online by passive observation - the ARP prober only probes lease IPs,
			// so markLeasePresenceWith must not (and does not) override this.
			Presence:     "online",
			NoLeaseState: state,
		})
	}
	return rows
}

// filterAwaitingByMAC drops awaiting hosts whose normalized MAC appears in the
// reservation map (hosts a reservation row already represents). A nil/empty map
// passes through.
func filterAwaitingByMAC(awaiting []netmon.PoolHost, res map[string]db.HostReservation) []netmon.PoolHost {
	if len(res) == 0 || len(awaiting) == 0 {
		return awaiting
	}
	out := make([]netmon.PoolHost, 0, len(awaiting))
	for _, h := range awaiting {
		if _, ok := res[normalizeMAC(h.MAC)]; !ok {
			out = append(out, h)
		}
	}
	return out
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
