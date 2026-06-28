package web

import (
	"testing"

	"ggo-kea-dhcp/internal/ggoscan"
)

func TestSlugifyHostname(t *testing.T) {
	cases := map[string]string{
		"Multichannel X": "multichannel-x",
		"BPX-12":         "bpx-12",
		"  weird__name ": "weird-name",
		"TestingMCXD":    "testingmcxd",
		"!!!":            "",
		"":               "",
	}
	for in, want := range cases {
		if got := slugifyHostname(in); got != want {
			t.Errorf("slugifyHostname(%q) = %q, want %q", in, got, want)
		}
	}
	// Over-long names are capped to the 63-char DNS label limit.
	long := ""
	for range 80 {
		long += "a"
	}
	if got := slugifyHostname(long); len(got) != 63 {
		t.Errorf("slug length = %d, want 63", len(got))
	}
}

func TestBuildFirmwareRows(t *testing.T) {
	snap := ggoscan.Snapshot{Devices: []ggoscan.Device{
		{MAC: "00:1f:80:22:00:01", Name: "bp-a", IP: "10.0.0.11", Model: "MCXi", Version: "5.0.7.9165"},
		{MAC: "00:1f:80:22:00:02", Name: "bp-b", IP: "10.0.0.12", Model: "MCXi", Version: "5.0.7.9165"},
		{MAC: "00:1f:80:22:00:03", Name: "bp-c", IP: "10.0.0.13", Model: "MCXi", Version: "5.0.4.5846"},
		{MAC: "00:1f:80:21:00:01", Name: "wp-a", IP: "10.0.0.20", Model: "WPXi", Version: "5.0.7.9165"},
	}}
	rows := buildFirmwareRows(snap)
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1 (only MCXi diverges)", len(rows))
	}
	if rows[0].Summary != "MCXi - 2 on 5.0.7.9165, 1 on 5.0.4.5846" {
		t.Errorf("summary = %q", rows[0].Summary)
	}
	if len(rows[0].Devices) != 3 || rows[0].More != 0 {
		t.Errorf("devices = %d more = %d, want 3/0", len(rows[0].Devices), rows[0].More)
	}

	// A uniform fleet yields no firmware rows.
	if got := buildFirmwareRows(ggoscan.Snapshot{Devices: snap.Devices[:2]}); got != nil {
		t.Errorf("uniform fleet rows = %v, want nil", got)
	}
}
