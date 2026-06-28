package web

import (
	"net"
	"testing"

	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/kea"
)

// TestFlexIDRoundTrip locks in the port-pinning identifier encoding. The decisive
// bug: flex_id with replace-client-id reports the client-id as a 0x00 byte PREPENDED
// to the flex-id, but the host reservation Kea matches uses the flex-id WITHOUT that
// byte. The pin flow must store the stripped flex-id, or Kea never matches and the
// device keeps getting a dynamic lease.
func TestFlexIDRoundTrip(t *testing.T) {
	// Kea's client-id: 0x00 + "GGO-Edge-10/4" (a pre-delimiter / single-sub-option
	// flex-id). decodePortIdentity must strip the zero byte; a printable flex-id with
	// no 0x1f delimiter surfaces whole under the remote-id half, and the opaque Key is
	// the printable text itself.
	clientID := "00:47:47:4f:2d:45:64:67:65:2d:31:30:2f:34"
	id, ok := decodePortIdentity(clientID)
	if !ok || id.Key != "GGO-Edge-10/4" || id.RemoteID != "GGO-Edge-10/4" {
		t.Fatalf("decodePortIdentity(%q) = %+v ok=%v, want Key/remote GGO-Edge-10/4", clientID, id, ok)
	}
	// The stored reservation identifier = the 13-byte flex-id (NOT 14, no leading 0).
	raw := flexIDToBytes(id.Key)
	if string(raw) != "GGO-Edge-10/4" || len(raw) != 13 {
		t.Fatalf("flexIDToBytes(%q) = %q (len %d), want %q (len 13)", id.Key, raw, len(raw), "GGO-Edge-10/4")
	}
	if got := bytesToPortIdentity(raw); got != id.Key {
		t.Errorf("display round-trip = %q, want %q", got, id.Key)
	}

	// Binary (non-printable) flex-id: 0x00 prefix stripped, rendered as colon-hex,
	// round-trips back to the same flex-id bytes.
	bin, ok := decodePortIdentity("00:01:02:ff") // 0x00 + flex-id {01,02,ff}
	if !ok || bin.Key != "01:02:ff" {
		t.Fatalf("decodePortIdentity binary = %+v ok=%v, want Key 01:02:ff", bin, ok)
	}
	if string(flexIDToBytes(bin.Key)) != "\x01\x02\xff" {
		t.Errorf("binary flex-id bytes = %x, want 0102ff", flexIDToBytes(bin.Key))
	}
}

func TestMergePortRowsPinnedOnly(t *testing.T) {
	labels := map[string]string{"ab/cd": "Door Panel"}
	pinned := map[string]db.HostReservation{
		"ab/cd": {IPv4Address: kea.IPToUint32(net.ParseIP("1.2.3.4")), SubnetID: 7, Hostname: "panel"},
	}
	rows := mergePortRows(labels, pinned, nil, nil, 0)
	if len(rows) != 1 {
		t.Fatalf("got %d rows want 1", len(rows))
	}
	r := rows[0]
	if r.PortIdentity != "ab/cd" || r.IPAddress != "1.2.3.4" || r.SubnetID != 7 ||
		r.Hostname != "panel" || r.Label != "Door Panel" || !r.Pinned || r.HWAddress != "-" {
		t.Errorf("pinned row wrong: %+v", r)
	}
}

func TestMergePortRowsLeaseFillsPinned(t *testing.T) {
	pinned := map[string]db.HostReservation{
		"ab/cd": {IPv4Address: kea.IPToUint32(net.ParseIP("1.2.3.4")), SubnetID: 7, Hostname: "panel"},
	}
	// 0x00 + hex of "ab/cd" (the flex-id form) so the lease maps onto the pinned port.
	leases := []kea.ActiveLease{{ClientID: "0061622f6364", HWAddress: "aa:bb:cc:dd:ee:ff"}}
	rows := mergePortRows(nil, pinned, leases, nil, 0)
	if len(rows) != 1 {
		t.Fatalf("got %d rows want 1", len(rows))
	}
	if rows[0].HWAddress != "aa:bb:cc:dd:ee:ff" || !rows[0].Pinned {
		t.Errorf("lease did not fill pinned row: %+v", rows[0])
	}
}

func TestMergePortRowsUnpinnedLease(t *testing.T) {
	leases := []kea.ActiveLease{{ClientID: "0061622f6364", HWAddress: "aa:bb", IPAddress: "9.9.9.9"}}
	rows := mergePortRows(nil, nil, leases, nil, 0)
	if len(rows) != 1 {
		t.Fatalf("got %d rows want 1", len(rows))
	}
	r := rows[0]
	if r.PortIdentity != "ab/cd" || r.Pinned || r.IPAddress != "9.9.9.9" {
		t.Errorf("unpinned lease row wrong: %+v", r)
	}
}

func TestMergePortRowsSkipsEmptyClientID(t *testing.T) {
	rows := mergePortRows(nil, nil, []kea.ActiveLease{{ClientID: ""}}, nil, 0)
	if len(rows) != 0 {
		t.Errorf("empty client-id lease should be skipped, got %d rows", len(rows))
	}
}

// TestMergePortRowsDedupesByMAC checks that when one MAC has two active leases under
// different flex-ids (a stale old lease lingering after the device re-leased on its
// current port), only the most-recently-active learnable row is kept.
func TestMergePortRowsDedupesByMAC(t *testing.T) {
	leases := []kea.ActiveLease{
		// Stale: old-format flex-id "ab/cd", older cltt.
		{ClientID: "0061622f6364", HWAddress: "aa:bb:cc:dd:ee:ff", IPAddress: "10.0.0.183", Cltt: 100},
		// Current: a different flex-id, fresher cltt, same MAC.
		{ClientID: "0078", HWAddress: "aa:bb:cc:dd:ee:ff", IPAddress: "10.0.0.83", Cltt: 200},
	}
	rows := mergePortRows(nil, nil, leases, nil, 0)
	if len(rows) != 1 {
		t.Fatalf("same-MAC stale lease should be deduped, got %d rows: %+v", len(rows), rows)
	}
	if rows[0].IPAddress != "10.0.0.83" {
		t.Errorf("kept the stale row %+v, want the freshest (IP 10.0.0.83)", rows[0])
	}
}

// TestMergePortRowsPrefersNewFormat checks that for one device, a new-format
// (delimited) flex-id entry wins over a pre-upgrade old-format one even when the old
// lease has a more recent cltt (it kept renewing via unicast). The old flex-id can
// never match a new reservation, so showing it would be misleading.
func TestMergePortRowsPrefersNewFormat(t *testing.T) {
	leases := []kea.ActiveLease{
		// Old-format flex-id "x" (no delimiter), MORE recent cltt.
		{ClientID: "0078", HWAddress: "aa:bb:cc:dd:ee:ff", IPAddress: "10.0.0.183", Cltt: 200},
		// New-format flex-id "x" + 0x1f + "y" (delimited), older cltt, same device.
		{ClientID: "00781f79", HWAddress: "aa:bb:cc:dd:ee:ff", IPAddress: "10.0.0.83", Cltt: 100},
	}
	rows := mergePortRows(nil, nil, leases, nil, 0)
	if len(rows) != 1 {
		t.Fatalf("expected 1 row (new-format preferred), got %d: %+v", len(rows), rows)
	}
	if rows[0].IPAddress != "10.0.0.83" || rows[0].CircuitID != "y" {
		t.Errorf("kept wrong row %+v, want new-format (IP 10.0.0.83 / circuit y)", rows[0])
	}
}

// TestMergePortRowsPinnedDeviceMovedAway: a device pinned to port A moves to port B.
// The lingering old lease on port A still tags the pinned row with the device's MAC, but
// a fresher lease for that MAC exists on port B, so the pinned row's stale identity is
// blanked (an empty pinned port) while its operator Label and reserved IP survive. The
// device's new learnable row on port B is kept.
func TestMergePortRowsPinnedDeviceMovedAway(t *testing.T) {
	labels := map[string]string{"ab/cd": "Door Panel"}
	pinned := map[string]db.HostReservation{
		"ab/cd": {IPv4Address: kea.IPToUint32(net.ParseIP("1.2.3.4")), SubnetID: 7, Hostname: "panel"},
	}
	leases := []kea.ActiveLease{
		// Lingering old lease on the pinned port "ab/cd", older cltt.
		{ClientID: "0061622f6364", HWAddress: "aa:bb:cc:dd:ee:ff", IPAddress: "1.2.3.4", Cltt: 100},
		// Fresher lease for the SAME MAC on a different port "x".
		{ClientID: "0078", HWAddress: "aa:bb:cc:dd:ee:ff", IPAddress: "10.0.0.83", Cltt: 200},
	}
	rows := mergePortRows(labels, pinned, leases, nil, 0)
	if len(rows) != 2 {
		t.Fatalf("got %d rows want 2 (empty pin + moved device): %+v", len(rows), rows)
	}
	pinIdx, learnIdx := -1, -1
	for i := range rows {
		if rows[i].Pinned {
			pinIdx = i
		} else {
			learnIdx = i
		}
	}
	if pinIdx < 0 || learnIdx < 0 {
		t.Fatalf("want one pinned + one learnable, got %+v", rows)
	}
	if pin := rows[pinIdx]; pin.HWAddress != "-" || pin.Hostname != "" {
		t.Errorf("moved-away pinned row should be blanked, got %+v", pin)
	} else if pin.Label != "Door Panel" || pin.IPAddress != "1.2.3.4" {
		t.Errorf("pinned row should keep Label + reserved IP, got %+v", pin)
	}
	if learn := rows[learnIdx]; learn.IPAddress != "10.0.0.83" || learn.HWAddress != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("moved device's learnable row wrong: %+v", learn)
	}
}

// TestMergePortRowsLastSeenStale checks that a pinned-but-offline port picks up its
// last-active time and is flagged stale past the threshold.
func TestMergePortRowsLastSeenStale(t *testing.T) {
	pinned := map[string]db.HostReservation{
		"ab/cd": {IPv4Address: kea.IPToUint32(net.ParseIP("1.2.3.4")), SubnetID: 7},
	}
	now := int64(1_000_000_000)
	lastSeen := map[string]int64{"ab/cd": now - 30*24*60*60} // 30 days ago
	rows := mergePortRows(nil, pinned, nil, lastSeen, now)
	if len(rows) != 1 {
		t.Fatalf("got %d rows want 1", len(rows))
	}
	r := rows[0]
	if r.LastSeen != now-30*24*60*60 || r.LastSeenText != "30d ago" || !r.Stale {
		t.Errorf("stale pinned row wrong: LastSeen=%d text=%q stale=%v", r.LastSeen, r.LastSeenText, r.Stale)
	}
}
