package network

import (
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
	aps := parseNmcliScan(out)
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
