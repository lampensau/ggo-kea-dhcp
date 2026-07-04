package web

import (
	"net"
	"strings"
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

func TestFirmwareFindings(t *testing.T) {
	devices := []ggoscan.Device{
		{MAC: "00:1f:80:22:00:01", Name: "bp-a", IP: "10.0.0.11", Model: "MCXi", Version: "5.0.7.9165"},
		{MAC: "00:1f:80:22:00:02", Name: "bp-b", IP: "10.0.0.12", Model: "MCXi", Version: "5.0.7.9165"},
		{MAC: "00:1f:80:22:00:03", Name: "bp-c", IP: "10.0.0.13", Model: "MCXi", Version: "5.0.4.5846"},
		{MAC: "00:1f:80:21:00:01", Name: "wp-a", IP: "10.0.0.20", Model: "WPXi", Version: "5.0.7.9165"},
	}
	cidr := func(c string) *net.IPNet { _, n, _ := net.ParseCIDR(c); return n }
	scopes := []fwScope{
		{iface: "eth0", net: cidr("10.0.0.0/24")},
		{iface: "eth0.20", net: cidr("10.20.0.0/24")},
	}
	found := firmwareFindings(devices, scopes)
	if len(found) != 1 {
		t.Fatalf("findings = %d, want exactly 1 (the single fleet-wide release check)", len(found))
	}
	f := found[0]
	// Attributed to the scope holding the devices' addresses; rendered as a plain
	// warn detector row with the per-device roster in DetailRows.
	if len(f.ifaces) != 1 || f.ifaces[0] != "eth0" {
		t.Errorf("ifaces = %v want [eth0]", f.ifaces)
	}
	if f.row.Kind != "firmware" || f.row.Severity != "warn" {
		t.Errorf("row kind/severity = %q/%q", f.row.Kind, f.row.Severity)
	}
	if f.row.Title != "Mixed firmware: 3 on 5.0.7, 1 on 5.0.4" {
		t.Errorf("title = %q", f.row.Title)
	}
	if len(f.row.DetailRows) != 4 {
		t.Errorf("detail rows = %d, want 4", len(f.row.DetailRows))
	}
	roster := strings.Join(f.row.DetailRows, "\n")
	if !strings.Contains(roster, "bp-c · 10.0.0.13 · 5.0.4.5846") {
		t.Errorf("roster missing the diverging device: %q", roster)
	}

	// A fleet spanning two scopes is attributed to both sub-cards.
	spanDevs := []ggoscan.Device{
		{MAC: "00:1f:80:22:00:06", Name: "foh-a", IP: "10.0.0.30", Model: "BPX", Version: "5.1.0.1"},
		{MAC: "00:1f:80:22:00:07", Name: "stage-a", IP: "10.20.0.30", Model: "MCXi", Version: "5.0.0.2"},
	}
	if got := firmwareFindings(spanDevs, scopes); len(got) != 1 || len(got[0].ifaces) != 2 {
		t.Errorf("cross-scope attribution = %+v, want one finding on both scopes", got)
	}

	// Devices outside every scanned scope attribute to the first scope (fallback).
	vlanDevs := []ggoscan.Device{
		{MAC: "00:1f:80:22:00:04", Name: "x-a", IP: "169.254.9.9", Model: "BPX", Version: "5.1.0.1"},
		{MAC: "00:1f:80:22:00:05", Name: "x-b", IP: "169.254.9.10", Model: "BPX", Version: "5.0.0.2"},
	}
	if got := firmwareFindings(vlanDevs, scopes); len(got) != 1 || len(got[0].ifaces) != 1 || got[0].ifaces[0] != "eth0" {
		t.Errorf("fallback attribution = %+v, want one finding on eth0", got)
	}

	// A uniform fleet, or no scanned scopes, yields no findings.
	if got := firmwareFindings(devices[:2], scopes); got != nil {
		t.Errorf("uniform fleet findings = %v, want nil", got)
	}
	if got := firmwareFindings(devices, nil); got != nil {
		t.Errorf("no-scope findings = %v, want nil", got)
	}
}
