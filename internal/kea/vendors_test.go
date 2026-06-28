package kea

import (
	"strings"
	"testing"
)

// TestVendorClassTest verifies the OUI test matches each prefix at its OWN length
// (6/7/9 hex), so a sub-block prefix matches exactly that assignment and a bare
// 6-hex parent doesn't over-catch a shared block.
func TestVendorClassTest(t *testing.T) {
	got := VendorClassTest([]string{"00:1d:c1", "0055da4", "70b3d5ee8"})
	for _, want := range []string{
		"substring(hexstring(pkt4.mac, ''), 0, 6) == '001dc1'",
		"substring(hexstring(pkt4.mac, ''), 0, 7) == '0055da4'",
		"substring(hexstring(pkt4.mac, ''), 0, 9) == '70b3d5ee8'",
		" or ",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("VendorClassTest missing %q in:\n%s", want, got)
		}
	}
	if VendorClassTest([]string{"xyz", "12"}) != "" {
		t.Error("invalid prefixes should yield an empty test")
	}
}

// TestNormalizeOUI accepts 6–12 hex prefixes (MA-L/M/S) and strips separators.
func TestNormalizeOUI(t *testing.T) {
	cases := map[string]string{
		"00:1D:C1":   "001dc1",
		"70b3d5ee8":  "70b3d5ee8",
		"00-55-da-4": "0055da4",
		"abc":        "", // too short
		"":           "",
		"0050c2145":  "0050c2145",
	}
	for in, want := range cases {
		if got := NormalizeOUI(in); got != want {
			t.Errorf("NormalizeOUI(%q) = %q, want %q", in, got, want)
		}
	}
}
