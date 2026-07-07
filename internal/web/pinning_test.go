package web

import (
	"net"
	"testing"

	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/kea"
	"ggo-kea-dhcp/internal/web/views"
)

// TestFlexIDRoundTrip locks in the port-pinning identifier encoding. The decisive
// bug: flex_id with replace-client-id reports the client-id as a 0x00 byte PREPENDED
// to the flex-id, but the host reservation Kea matches uses the flex-id WITHOUT that
// byte. The pin flow must store the stripped flex-id, or Kea never matches and the
// device keeps getting a dynamic lease.
func TestFlexIDRoundTrip(t *testing.T) {
	// Kea's client-id: 0x00 + "GGO-Edge-10/4" (a pre-delimiter / single-sub-option
	// flex-id). decodePortIdentity must strip the zero byte; a printable flex-id with
	// no 0x1f delimiter surfaces whole under the remote-id half for DISPLAY, while
	// the opaque Key is always colon-hex so it can never be misdecoded (a printable
	// flex-id that looks like colon-hex, e.g. an ASCII MAC, decoded wrongly before).
	clientID := "00:47:47:4f:2d:45:64:67:65:2d:31:30:2f:34"
	id, ok := decodePortIdentity(clientID)
	if !ok || id.Key != "47:47:4f:2d:45:64:67:65:2d:31:30:2f:34" || id.RemoteID != "GGO-Edge-10/4" {
		t.Fatalf("decodePortIdentity(%q) = %+v ok=%v, want hex Key + remote GGO-Edge-10/4", clientID, id, ok)
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
	key := bytesToPortIdentity([]byte("ab/cd")) // maps are keyed by the opaque hex key
	labels := map[string]string{key: "Door Panel"}
	pinned := map[string]db.HostReservation{
		key: {IPv4Address: kea.IPToUint32(net.ParseIP("1.2.3.4")), SubnetID: 7, Hostname: "panel"},
	}
	rows := mergePortRows(labels, pinned, nil, nil, 0, nil)
	if len(rows) != 1 {
		t.Fatalf("got %d rows want 1", len(rows))
	}
	r := rows[0]
	if r.PortIdentity != key || r.IPAddress != "1.2.3.4" || r.SubnetID != 7 ||
		r.Hostname != "panel" || r.Label != "Door Panel" || !r.Pinned || r.HWAddress != "-" {
		t.Errorf("pinned row wrong: %+v", r)
	}
}

func TestMergePortRowsLeaseFillsPinned(t *testing.T) {
	pinned := map[string]db.HostReservation{
		bytesToPortIdentity([]byte("ab/cd")): {IPv4Address: kea.IPToUint32(net.ParseIP("1.2.3.4")), SubnetID: 7, Hostname: "panel"},
	}
	// 0x00 + hex of "ab/cd" (the flex-id form) so the lease maps onto the pinned port.
	leases := []kea.ActiveLease{{ClientID: "0061622f6364", HWAddress: "aa:bb:cc:dd:ee:ff"}}
	rows := mergePortRows(nil, pinned, leases, nil, 0, nil)
	if len(rows) != 1 {
		t.Fatalf("got %d rows want 1", len(rows))
	}
	if rows[0].HWAddress != "aa:bb:cc:dd:ee:ff" || !rows[0].Pinned {
		t.Errorf("lease did not fill pinned row: %+v", rows[0])
	}
}

func TestMergePortRowsUnpinnedLease(t *testing.T) {
	leases := []kea.ActiveLease{{ClientID: "0061622f6364", HWAddress: "aa:bb", IPAddress: "9.9.9.9"}}
	rows := mergePortRows(nil, nil, leases, nil, 0, nil)
	if len(rows) != 1 {
		t.Fatalf("got %d rows want 1", len(rows))
	}
	r := rows[0]
	if r.PortIdentity != bytesToPortIdentity([]byte("ab/cd")) || r.Pinned || r.IPAddress != "9.9.9.9" {
		t.Errorf("unpinned lease row wrong: %+v", r)
	}
}

func TestMergePortRowsSkipsEmptyClientID(t *testing.T) {
	rows := mergePortRows(nil, nil, []kea.ActiveLease{{ClientID: ""}}, nil, 0, nil)
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
	rows := mergePortRows(nil, nil, leases, nil, 0, nil)
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
	rows := mergePortRows(nil, nil, leases, nil, 0, nil)
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
	key := bytesToPortIdentity([]byte("ab/cd"))
	labels := map[string]string{key: "Door Panel"}
	pinned := map[string]db.HostReservation{
		key: {IPv4Address: kea.IPToUint32(net.ParseIP("1.2.3.4")), SubnetID: 7, Hostname: "panel"},
	}
	leases := []kea.ActiveLease{
		// Lingering old lease on the pinned port "ab/cd", older cltt.
		{ClientID: "0061622f6364", HWAddress: "aa:bb:cc:dd:ee:ff", IPAddress: "1.2.3.4", Cltt: 100},
		// Fresher lease for the SAME MAC on a different port "x".
		{ClientID: "0078", HWAddress: "aa:bb:cc:dd:ee:ff", IPAddress: "10.0.0.83", Cltt: 200},
	}
	rows := mergePortRows(labels, pinned, leases, nil, 0, nil)
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
	rows := mergePortRows(nil, pinned, nil, lastSeen, now, nil)
	if len(rows) != 1 {
		t.Fatalf("got %d rows want 1", len(rows))
	}
	r := rows[0]
	if r.LastSeen != now-30*24*60*60 || r.LastSeenText != "30d ago" || !r.Stale {
		t.Errorf("stale pinned row wrong: LastSeen=%d text=%q stale=%v", r.LastSeen, r.LastSeenText, r.Stale)
	}
}

// TestFlexIDKeyRoundTripUnambiguous pins the key-encoding contract for
// arbitrary flex-id byte shapes: flexIDToBytes(bytesToPortIdentity(b)) must
// return exactly b, for every relay out there - not just the delimited
// remote+circuit shape our own identifier expression builds. The named cases
// are real-world: a lone delimiter byte (a relay whose present Option-82
// sub-options are empty), a single-byte circuit-id, and a pre-upgrade
// non-delimited flex-id that is an ASCII-text MAC - printable AND colon-hex
// shaped, which the old printable-first encoding decoded to the wrong bytes.
func TestFlexIDKeyRoundTripUnambiguous(t *testing.T) {
	cases := [][]byte{
		{0x1f},                       // lone delimiter: both sub-options present but empty
		{0x05},                       // single-byte binary circuit-id
		{0x31, 0x66},                 // ASCII "1f" - must not collide with the byte 0x1f
		[]byte("aa:bb:cc:dd:ee:ff"),  // ASCII MAC remote-id (printable, colon-hex shaped)
		[]byte("00:47"),              // short printable colon-hex lookalike
		[]byte("GGO-Edge-10\x1f4/7"), // the normal delimited shape
		[]byte("switch/Gi1/0/4"),     // plain printable legacy flex-id
		{0x00, 0xff, 0x10},           // arbitrary binary
	}
	for _, b := range cases {
		key := bytesToPortIdentity(b)
		got := flexIDToBytes(key)
		if string(got) != string(b) {
			t.Errorf("round-trip %x: key %q decoded to %x", b, key, got)
		}
	}
}

// TestFetchPortLabelsTranslatesLegacyKeys proves labels stored under the old
// printable key form (before the key became always-hex) stay attached to their
// ports: fetchPortLabels re-encodes them on read to the hex key the rest of the
// page now derives, with no migration.
func TestFetchPortLabelsTranslatesLegacyKeys(t *testing.T) {
	s, _ := newTestServer(t)
	seed := map[string]string{
		"switch/Gi1/0/4":    "Stage Left", // legacy printable key
		"61:62:2f:63:64":    "Door Panel", // current hex key, kept as-is
		"aa:bb:cc:dd:ee:ff": "FOH Sw",     // legacy printable key that LOOKS like hex (ASCII MAC)
	}
	for k, v := range seed {
		if _, err := s.sqlite.Exec("INSERT INTO port_labels (flex_id_hex, label) VALUES (?, ?)", k, v); err != nil {
			t.Fatalf("seed %q: %v", k, err)
		}
	}
	labels, err := s.fetchPortLabels()
	if err != nil {
		t.Fatalf("fetchPortLabels: %v", err)
	}
	if got := labels[bytesToPortIdentity([]byte("switch/Gi1/0/4"))]; got != "Stage Left" {
		t.Errorf("legacy printable key not translated: %v", labels)
	}
	if got := labels["61:62:2f:63:64"]; got != "Door Panel" {
		t.Errorf("hex key must pass through untouched: %v", labels)
	}
	// The colon-hex-shaped ASCII key is INDISTINGUISHABLE from a real hex key, so
	// it passes through as-is - the accepted residual for legacy rows only (new
	// keys are always genuine hex). Pinned here so the trade-off is deliberate.
	if got := labels["aa:bb:cc:dd:ee:ff"]; got != "FOH Sw" {
		t.Errorf("hex-shaped legacy key should pass through: %v", labels)
	}
}

// TestLegacyLabelAliasCleared pins the zombie-label fix: a label row stored
// under the pre-hex printable key must be cleared by any write under the new
// hex key - otherwise a rename is shadowed and a cleared label resurrects
// through fetchPortLabels' translate-on-read.
func TestLegacyLabelAliasCleared(t *testing.T) {
	s, _ := newTestServer(t)
	raw := []byte("switch/Gi1/0/4")
	hexKey := bytesToPortIdentity(raw)
	if _, err := s.sqlite.Exec("INSERT INTO port_labels (flex_id_hex, label) VALUES (?, ?)", string(raw), "Old Name"); err != nil {
		t.Fatal(err)
	}

	// A rename under the new key must not leave the old row shadowing.
	if _, err := s.sqlite.Exec("INSERT INTO port_labels (flex_id_hex, label) VALUES (?, ?)", hexKey, "New Name"); err != nil {
		t.Fatal(err)
	}
	s.clearLegacyLabelAlias(hexKey)
	labels, err := s.fetchPortLabels()
	if err != nil {
		t.Fatal(err)
	}
	if got := labels[hexKey]; got != "New Name" {
		t.Errorf("label = %q, want the rename to win over the legacy alias", got)
	}
	var n int
	_ = s.sqlite.QueryRow("SELECT COUNT(*) FROM port_labels").Scan(&n)
	if n != 1 {
		t.Errorf("port_labels rows = %d, want the legacy alias gone", n)
	}
}

// TestMergePortRowsOverlaysGgoName is the #116 guard: a Green-GO port announces no
// DHCP hostname, so its row's hostname is filled from the ggoscan name map (keyed by
// live MAC) - the same overlay the Leases page applies - instead of rendering blank.
// A device that DOES announce a name keeps it (overlay only fills empties).
func TestMergePortRowsOverlaysGgoName(t *testing.T) {
	const mac = "00:1f:80:20:4e:5e"
	// Green-GO learnable port: Option-82 flex-id, no announced hostname.
	ggo := []kea.ActiveLease{{ClientID: "0061622f6364", HWAddress: mac, IPAddress: "10.0.0.22"}}
	// A non-Green-GO device on another port that announces its own hostname.
	named := []kea.ActiveLease{{ClientID: "0078", HWAddress: "c8:ff:bf:0e:6f:e6", IPAddress: "10.0.0.187", Hostname: "workstation-6fe6"}}
	ggoNames := map[string]string{
		normalizeMAC(mac):                 "bpx-19678",
		normalizeMAC("c8:ff:bf:0e:6f:e6"): "should-not-win",
	}

	rows := mergePortRows(nil, nil, append(ggo, named...), nil, 0, ggoNames)

	got := map[string]string{}
	derived := map[string]bool{}
	for _, r := range rows {
		got[r.IPAddress] = r.Hostname
		derived[r.IPAddress] = r.HostnameDerived
	}
	if got["10.0.0.22"] != "bpx-19678" {
		t.Errorf("Green-GO port hostname = %q, want scan name %q", got["10.0.0.22"], "bpx-19678")
	}
	if got["10.0.0.187"] != "workstation-6fe6" {
		t.Errorf("announced hostname was overwritten: got %q, want %q", got["10.0.0.187"], "workstation-6fe6")
	}
	// #117: the scan-filled name is flagged derived; the device-announced one is not.
	if !derived["10.0.0.22"] {
		t.Error("scan-filled port hostname should be marked HostnameDerived")
	}
	if derived["10.0.0.187"] {
		t.Error("device-announced hostname must not be marked HostnameDerived")
	}
}

// TestOverlayGgoNamesWithMarksDerived is the leases-side #117 guard: overlayGgoNamesWith
// flags a row it fills from the scan as derived, and leaves an announced-name row alone.
func TestOverlayGgoNamesWithMarksDerived(t *testing.T) {
	const mac = "00:1f:80:20:4e:5e"
	s := &Server{}
	rows := []views.LeaseRow{
		{IPAddress: "10.0.0.22", HWAddress: mac},                                                // Green-GO: no announced name
		{IPAddress: "10.0.0.187", HWAddress: "c8:ff:bf:0e:6f:e6", Hostname: "workstation-6fe6"}, // announced
	}
	s.overlayGgoNamesWith(rows, map[string]string{
		normalizeMAC(mac):                 "bpx-19678",
		normalizeMAC("c8:ff:bf:0e:6f:e6"): "should-not-win",
	})
	if rows[0].Hostname != "bpx-19678" || !rows[0].HostnameDerived {
		t.Errorf("scan-filled lease row = %q derived=%v, want bpx-19678 derived=true", rows[0].Hostname, rows[0].HostnameDerived)
	}
	if rows[1].Hostname != "workstation-6fe6" || rows[1].HostnameDerived {
		t.Errorf("announced lease row = %q derived=%v, want workstation-6fe6 derived=false", rows[1].Hostname, rows[1].HostnameDerived)
	}
}
