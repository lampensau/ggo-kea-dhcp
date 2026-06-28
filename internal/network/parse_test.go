package network

import (
	"bytes"
	"testing"
)

// TestSplitNmcliTerseEdgeCases exercises the backslash escaping rules of
// nmcli --terse output beyond the single colon-in-SSID case already covered.
func TestSplitNmcliTerseEdgeCases(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"plain", "TestNet:72:WPA2", []string{"TestNet", "72", "WPA2"}},
		{"colon in field", `My\:Net:72:WPA2`, []string{"My:Net", "72", "WPA2"}},
		{"escaped backslash then real colon", `a\\:b`, []string{"a\\", "b"}},
		{"empty fields", "::", []string{"", "", ""}},
		{"leading empty field", ":72:WPA2", []string{"", "72", "WPA2"}},
		{"trailing empty field", "TestNet:72:", []string{"TestNet", "72", ""}},
		{"trailing lone backslash kept literally", `abc\`, []string{`abc\`}},
		{"no separator", "single", []string{"single"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := splitNmcliTerse(c.in)
			if len(got) != len(c.want) {
				t.Fatalf("splitNmcliTerse(%q) = %#v, want %#v", c.in, got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("field %d = %q, want %q (full=%#v)", i, got[i], c.want[i], got)
				}
			}
		})
	}
}

// TestParseNmcliScanMalformed checks that lines with fewer than 3 fields, empty
// SSIDs, and duplicate SSIDs are all dropped, while a colon-bearing SSID survives.
func TestParseNmcliScanMalformed(t *testing.T) {
	out := "" +
		"GoodNet:80:WPA2\n" + // valid
		"TooFew:90\n" + // < 3 fields, dropped
		":50:WPA2\n" + // empty SSID, dropped
		"GoodNet:30:WPA2\n" + // duplicate of GoodNet, dropped
		"\n" + // blank line, skipped
		`Has\:Colon:65:WPA3` + "\n" // colon-bearing SSID survives
	aps := parseNmcliScan(out, make(map[string]bool))
	if len(aps) != 2 {
		t.Fatalf("got %d APs want 2: %+v", len(aps), aps)
	}
	byName := map[string]WifiAP{}
	for _, ap := range aps {
		byName[ap.SSID] = ap
	}
	if got, ok := byName["GoodNet"]; !ok || got.Signal != 80 || got.Security != "WPA2" {
		t.Errorf("GoodNet wrong/missing: %+v", got)
	}
	if got, ok := byName["Has:Colon"]; !ok || got.Signal != 65 || got.Security != "WPA3" {
		t.Errorf("Has:Colon wrong/missing: %+v", got)
	}
}

// TestParseNmcliScanSeenSharedAcrossCalls verifies the caller-supplied seen map
// dedups across multiple parse calls (the scan path reuses it for the rescan).
func TestParseNmcliScanSeenSharedAcrossCalls(t *testing.T) {
	seen := make(map[string]bool)
	first := parseNmcliScan("Net-A:70:WPA2\n", seen)
	if len(first) != 1 {
		t.Fatalf("first call got %d want 1", len(first))
	}
	second := parseNmcliScan("Net-A:99:WPA2\nNet-B:60:Open\n", seen)
	if len(second) != 1 || second[0].SSID != "Net-B" {
		t.Fatalf("second call got %+v want only Net-B (Net-A already seen)", second)
	}
}

// TestParseIwlistScanPositiveSignal covers the iwlist branch where the signal is
// already expressed as a 0-100 quality percentage (positive), not dBm.
func TestParseIwlistScanPositiveSignal(t *testing.T) {
	out := `          Cell 01 - Address: AA:BB:CC:DD:EE:FF
                    ESSID:"QualityNet"
                    Signal level=63 dBm
`
	aps := parseIwlistScan(out)
	if len(aps) != 1 {
		t.Fatalf("got %d APs want 1: %+v", len(aps), aps)
	}
	// A positive "Signal level=" is treated as an already-computed quality, passed through.
	if aps[0].Signal != 63 {
		t.Errorf("positive signal passthrough = %d, want 63", aps[0].Signal)
	}
}

// TestParseIwScanWPABranch covers the WPA: security marker (vs the RSN: line the
// existing test exercises) and an AP with no SSID line being dropped.
func TestParseIwScanWPABranch(t *testing.T) {
	out := `BSS aa:bb:cc:dd:ee:ff(on wlan0)
	signal: -55.00 dBm
	WPA:	 * Version: 1
	SSID: WpaOnly
BSS 11:22:33:44:55:66(on wlan0)
	signal: -70.00 dBm
`
	aps := parseIwScan(out)
	// The second BSS has no SSID, so it is flushed away; only WpaOnly remains.
	if len(aps) != 1 {
		t.Fatalf("got %d APs want 1 (SSID-less BSS dropped): %+v", len(aps), aps)
	}
	if aps[0].SSID != "WpaOnly" || aps[0].Security != "WPA2/WPA3" {
		t.Errorf("WpaOnly parsed wrong: %+v", aps[0])
	}
}

// TestDbmToQualityMidRange adds intermediate and clamp points to the existing
// boundary table.
func TestDbmToQualityMidRange(t *testing.T) {
	cases := map[int]int{
		-90:  20,
		-95:  10,
		-100: 0,
		-101: 0, // clamp low
		-49:  100,
		-40:  100, // clamp high
		-75:  50,
		-60:  80,
	}
	for dbm, want := range cases {
		if got := dbmToQuality(dbm); got != want {
			t.Errorf("dbmToQuality(%d) = %d, want %d", dbm, got, want)
		}
	}
}

// dnsQuery builds a minimal well-formed DNS A-query: 12-byte header + one
// question (labels, zero terminator, type A, class IN).
func dnsQuery(txHi, txLo byte) []byte {
	q := []byte{
		txHi, txLo, // transaction ID
		0x01, 0x00, // flags: standard query, recursion desired
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
	}
	// question name: www.example.com
	q = append(q, 3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0x00)
	q = append(q, 0x00, 0x01) // QTYPE A
	q = append(q, 0x00, 0x01) // QCLASS IN
	return q
}

// TestBuildResponseValidQuery checks the DNS response builder echoes the
// transaction id, sets the response flags, claims one answer, and embeds the
// configured answer IP.
func TestBuildResponseValidQuery(t *testing.T) {
	d, err := NewDNSRedirector("127.0.0.1", "10.0.0.1")
	if err != nil {
		t.Fatalf("NewDNSRedirector: %v", err)
	}
	req := dnsQuery(0xAB, 0xCD)
	resp, err := d.buildResponse(req)
	if err != nil {
		t.Fatalf("buildResponse: %v", err)
	}
	if resp[0] != 0xAB || resp[1] != 0xCD {
		t.Errorf("txID not echoed: %x %x", resp[0], resp[1])
	}
	if resp[2] != 0x81 || resp[3] != 0x80 {
		t.Errorf("response flags = %x %x, want 81 80", resp[2], resp[3])
	}
	if resp[6] != 0x00 || resp[7] != 0x01 {
		t.Errorf("ANCOUNT = %x %x, want 00 01", resp[6], resp[7])
	}
	// Answer must include the compressed-name pointer 0xc00c and the answer IP.
	if !bytes.Contains(resp, []byte{0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01}) {
		t.Errorf("answer RR header (pointer+A+IN) missing: % x", resp)
	}
	if !bytes.HasSuffix(resp, []byte{10, 0, 0, 1}) {
		t.Errorf("response does not end with the answer IP 10.0.0.1: % x", resp)
	}
}

// TestBuildResponseTooShort verifies a packet whose question section never
// terminates is rejected rather than read out of bounds.
func TestBuildResponseTooShort(t *testing.T) {
	d, err := NewDNSRedirector("127.0.0.1", "10.0.0.1")
	if err != nil {
		t.Fatalf("NewDNSRedirector: %v", err)
	}
	// 12-byte header only, no question labels/terminator: offset+4 > len → malformed.
	req := []byte{0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := d.buildResponse(req); err == nil {
		t.Error("expected malformed-packet error on a header-only request, got nil")
	}
}

// TestNewDNSRedirectorRejectsBadIPs covers the constructor validation paths.
func TestNewDNSRedirectorRejectsBadIPs(t *testing.T) {
	if _, err := NewDNSRedirector("not-an-ip", "10.0.0.1"); err == nil {
		t.Error("expected error for invalid bind IP")
	}
	if _, err := NewDNSRedirector("127.0.0.1", "nope"); err == nil {
		t.Error("expected error for invalid answer IP")
	}
	// IPv6 answer is unsupported (only A records are built).
	if _, err := NewDNSRedirector("127.0.0.1", "::1"); err == nil {
		t.Error("expected error for IPv6 answer IP")
	}
}

// TestRecordingCommanderOutputs documents the test-double behavior other packages
// rely on: canned per-command output, error override, and call recording.
func TestRecordingCommanderOutputs(t *testing.T) {
	rec := &RecordingCommander{Outputs: map[string]string{"nmcli": "canned"}}
	out, err := rec.Run("nmcli", "device", "status")
	if err != nil || out != "canned" {
		t.Errorf("Run nmcli = (%q,%v), want (canned,nil)", out, err)
	}
	if !rec.Ran("nmcli") {
		t.Error("Ran(nmcli) = false, want true")
	}
	if rec.Ran("iw") {
		t.Error("Ran(iw) = true, want false")
	}
	recErr := &RecordingCommander{Err: errDummy}
	if _, err := recErr.Run("anything"); err == nil {
		t.Error("expected the canned error to surface")
	}
}
