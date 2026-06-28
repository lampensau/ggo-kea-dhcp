package web

import (
	"net"
	"strings"
	"testing"

	"ggo-kea-dhcp/internal/kea"
)

func TestIPToUint32RoundTrip(t *testing.T) {
	for _, s := range []string{"0.0.0.0", "10.0.0.1", "192.168.1.254", "255.255.255.255"} {
		ip := net.ParseIP(s).To4()
		if got := kea.Uint32ToIP(kea.IPToUint32(ip)).String(); got != s {
			t.Errorf("round trip %s -> %s", s, got)
		}
	}
}

func TestRangeBounds(t *testing.T) {
	lo, hi, ok := kea.ParsePoolRange("10.0.0.1 - 10.0.0.10")
	wantLo := kea.IPToUint32(net.ParseIP("10.0.0.1").To4())
	wantHi := kea.IPToUint32(net.ParseIP("10.0.0.10").To4())
	if !ok || lo != wantLo || hi != wantHi {
		t.Errorf("rangeBounds good case: lo=%d hi=%d ok=%v want lo=%d hi=%d", lo, hi, ok, wantLo, wantHi)
	}
	if _, _, ok := kea.ParsePoolRange("10.0.0.1"); ok {
		t.Error("range missing separator should not parse")
	}
	if _, _, ok := kea.ParsePoolRange("bad - range"); ok {
		t.Error("non-ip bounds should not parse")
	}
}

func TestParseRangeCapacity(t *testing.T) {
	if got := parseRangeCapacity("10.0.0.1 - 10.0.0.10"); got != 10 {
		t.Errorf("capacity = %d want 10", got)
	}
	if got := parseRangeCapacity("10.0.0.1"); got != 0 {
		t.Errorf("malformed range capacity = %d want 0", got)
	}
	if got := parseRangeCapacity("bad - range"); got != 0 {
		t.Errorf("non-ip range capacity = %d want 0", got)
	}
	// Full-width range must report its real count, not wrap uint32 to 0.
	if got := parseRangeCapacity("0.0.0.0 - 255.255.255.255"); got != 1<<32 {
		t.Errorf("full-range capacity = %d want %d", got, int64(1)<<32)
	}
}

func TestDecodeHex(t *testing.T) {
	if got := decodeHex("4869"); got != "Hi" {
		t.Errorf("decodeHex(4869)=%q want Hi", got)
	}
	if got := decodeHex("48:69"); got != "Hi" {
		t.Errorf("decodeHex with colons =%q want Hi", got)
	}
	if got := decodeHex("zzz"); got != "zzz" {
		t.Errorf("decodeHex(invalid) =%q want passthrough", got)
	}
}

func TestIsPrintable(t *testing.T) {
	if !isPrintable("Gi0/1") {
		t.Error("printable string reported non-printable")
	}
	if isPrintable("") {
		t.Error("empty string must be non-printable")
	}
	if isPrintable("a\x01b") {
		t.Error("control char must be non-printable")
	}
}

func TestDecodePortIdentity(t *testing.T) {
	// Kea client-ids carry the replace-client-id 0x00 prefix; decodePortIdentity
	// strips it, then splits the flex-id on the 0x1f delimiter the identifier-
	// expression inserts between remote-id and circuit-id. Mikrotik case: remote-id
	// "AV-Edge-1", circuit-id "ether7" (neither contains a slash) - both must decode
	// to readable ASCII, not a hex chain. client-id =
	//   00 + hex("AV-Edge-1") + 1f + hex("ether7")
	id, ok := decodePortIdentity("0041562d456467652d311f657468657237")
	if !ok || id.RemoteID != "AV-Edge-1" || id.CircuitID != "ether7" {
		t.Errorf("decodePortIdentity mikrotik = %+v ok=%v, want remote AV-Edge-1 / circuit ether7", id, ok)
	}
	// The opaque Key carries the 0x1f delimiter, so it renders as colon-hex and
	// round-trips through flexIDToBytes back to the same reservation bytes.
	if !strings.Contains(id.Key, ":") {
		t.Errorf("delimited flex-id Key = %q, want colon-hex", id.Key)
	}
	if got := string(flexIDToBytes(id.Key)); got != "AV-Edge-1\x1fether7" {
		t.Errorf("Key round-trip = %q, want AV-Edge-1\\x1fether7", got)
	}
	// A binary flex-id with no delimiter surfaces as colon-hex under remote-id.
	id, ok = decodePortIdentity("0001ff")
	if !ok || id.Key != "01:ff" || id.RemoteID != "01:ff" || id.CircuitID != "" {
		t.Errorf("decodePortIdentity binary = %+v ok=%v, want Key 01:ff / remote 01:ff / circuit ''", id, ok)
	}
	// A normal client-id (0x01 + MAC, no Option-82) is NOT a port -> ok=false.
	if _, ok := decodePortIdentity("01c8ffbf0e6fe6"); ok {
		t.Error("decodePortIdentity should reject a normal 0x01-type client-id (not an Option-82 port)")
	}
	// Empty and 0x00-only ids are not ports either.
	if _, ok := decodePortIdentity(""); ok {
		t.Error("decodePortIdentity should reject an empty client-id")
	}
	if _, ok := decodePortIdentity("00"); ok {
		t.Error("decodePortIdentity should reject a 0x00-only (empty flex-id) client-id")
	}
}

func TestRenderIDPart(t *testing.T) {
	cases := []struct {
		name      string
		in        []byte
		wantASCII string
		wantHex   string
	}{
		{"empty", nil, "", ""},
		{"printable", []byte("ether7"), "ether7", "65:74:68:65:72:37"},
		{"nul-padded ascii", []byte("ether7\x00\x00"), "ether7", "65:74:68:65:72:37:00:00"},
		{"binary interior", []byte{0x00, 0x14, 0x03}, "00:14:03", "00:14:03"},
		{"binary high bit", []byte{0xde, 0xad}, "de:ad", "de:ad"},
		{"all nul", []byte{0x00, 0x00}, "00:00", "00:00"},
	}
	for _, c := range cases {
		ascii, hexStr := renderIDPart(c.in)
		if ascii != c.wantASCII || hexStr != c.wantHex {
			t.Errorf("%s: renderIDPart=(%q,%q), want (%q,%q)", c.name, ascii, hexStr, c.wantASCII, c.wantHex)
		}
	}
}

func TestRelativeAgo(t *testing.T) {
	const now = 1_000_000
	cases := []struct {
		then int64
		want string
	}{
		{0, ""},
		{now - 30, "just now"},
		{now - 300, "5m ago"},
		{now - 7200, "2h ago"},
		{now - 3*86400, "3d ago"},
	}
	for _, c := range cases {
		if got := relativeAgo(c.then, now); got != c.want {
			t.Errorf("relativeAgo(%d, %d) = %q, want %q", c.then, now, got, c.want)
		}
	}
}

func TestBuildLeaseRows(t *testing.T) {
	// No cltt/valid-lft (e.g. a reservation or absent timing); expiry renders as an
	// em dash. (The remaining-time formatting is covered deterministically by
	// TestLeaseExpiry; the cltt+valid-lft combination by TestLeaseExpiryFrom.)
	rows := buildLeaseRows([]kea.ActiveLease{
		{IPAddress: "10.0.0.50", HWAddress: "001f8020aaaa", ClientID: "cid", Hostname: "host"},
	})
	if len(rows) != 1 {
		t.Fatalf("got %d rows want 1", len(rows))
	}
	r := rows[0]
	if r.IPAddress != "10.0.0.50" || r.Hostname != "host" || r.ExpiresIn != "—" {
		t.Errorf("row fields wrong: %+v", r)
	}
	if r.Class != "GGO-BPX" {
		t.Errorf("class = %q want GGO-BPX", r.Class)
	}
}
