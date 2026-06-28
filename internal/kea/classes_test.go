package kea

import "testing"

// TestClassifyMACEdgeCases covers the tricky classification cases: the 210/211
// prefix disambiguation, the Green-GO catch-all, and the length guard.
func TestClassifyMACEdgeCases(t *testing.T) {
	cases := []struct {
		mac, want string
	}{
		{"001f80210000", "GGO-MCD-MCR"},        // prefix 210
		{"001f80211000", "GGO-INTERFACE-Q4WR"}, // prefix 211, must not match 210
		{"001f80990000", ClassNameGGOOthers},   // Green-GO OUI, unmapped suffix -> GGO catch-all (not OTHERS)
		{"001f80", ClassNameOthers},            // too short (< 8 hex chars)
		{"", ClassNameOthers},                  // empty
	}
	for _, c := range cases {
		if got := ClassifyMAC(c.mac); got != c.want {
			t.Errorf("ClassifyMAC(%q)=%q want %q", c.mac, got, c.want)
		}
	}
}

// TestClassifyMACMatchesClientClasses ensures every mapped band is reachable via
// ClassifyMAC using its first prefix, so dashboard labels and Kea client-classes
// stay in lockstep (the single-source-of-truth invariant).
func TestClassifyMACMatchesClientClasses(t *testing.T) {
	for _, dc := range DeviceClasses {
		mac := greenGOOUI + dc.Prefixes[0]
		for len(mac) < 12 { // pad past the length guard
			mac += "0"
		}
		if got := ClassifyMAC(mac); got != dc.Name {
			t.Errorf("ClassifyMAC(%q)=%q want %q", mac, got, dc.Name)
		}
	}
}
