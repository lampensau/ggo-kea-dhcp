package network

import (
	"strings"
	"testing"
)

func TestValidateSoftAP(t *testing.T) {
	cases := []struct {
		name       string
		ssid, pass string
		wantErr    bool
	}{
		{"ok open", "GGO-Onboarding", "", false},
		{"ok wpa2", "GGO-Onboarding", "password1", false},
		{"empty ssid", "", "", true},
		{"ssid too long", strings.Repeat("a", 33), "", true},
		{"ssid newline injection", "GGO\nfoo", "", true},
		{"pass too short", "GGO", "short", true},
		{"pass too long", "GGO", strings.Repeat("a", 64), true},
		{"pass control char", "GGO", "pass\x00word", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateSoftAP(c.ssid, c.pass)
			if (err != nil) != c.wantErr {
				t.Errorf("validateSoftAP(%q,%q) err=%v wantErr=%v", c.ssid, c.pass, err, c.wantErr)
			}
		})
	}
}

// TestStopSoftAPRemovesAddress guards the wlan0-shadow bug: StopSoftAP must drop
// the SoftAP address (not just kill hostapd), or it lingers after onboarding and
// its /24 route shadows an overlapping eth0 operator subnet, blackholing replies
// to clients in that /24. The del targets the specific CIDR so a WiFi-uplink
// address on wlan0 survives.
func TestStopSoftAPRemovesAddress(t *testing.T) {
	rec := &RecordingCommander{}
	m := NewManagerWithCommander(rec)
	if err := m.StopSoftAP(); err != nil {
		t.Fatalf("StopSoftAP: %v", err)
	}
	if !callContaining(rec, "ip", "addr", "del", softAPWlanCIDR, "dev", "wlan0") {
		t.Errorf("StopSoftAP must remove %s from wlan0; calls=%v", softAPWlanCIDR, rec.Calls)
	}
}

// TestStartSoftAPFlushesStaleAddr guards the other half of the wlan0 role
// transition: raising the SoftAP must first flush wlan0's IPv4 so a leftover
// WiFi-uplink address can't leave the interface dual-homed - which makes Kea
// (reloaded right after) bind stale sockets and silently never answer the
// SoftAP's DHCP.
func TestStartSoftAPFlushesStaleAddr(t *testing.T) {
	rec := &RecordingCommander{}
	m := NewManagerWithCommander(rec)
	if err := m.StartSoftAP("GGO-Onboarding", "password1"); err != nil {
		t.Fatalf("StartSoftAP: %v", err)
	}
	if !callContaining(rec, "ip", "-4", "addr", "flush", "dev", "wlan0") {
		t.Errorf("StartSoftAP must flush wlan0 before assigning the SoftAP IP; calls=%v", rec.Calls)
	}
}

func TestHasControlChar(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"normal text", false},
		{"with space", false}, // 0x20 is allowed
		{"tab\there", true},   // 0x09 < 0x20
		{"newline\n", true},
		{"del\x7f", true}, // 0x7f
		{"", false},
	}
	for _, c := range cases {
		if got := hasControlChar(c.in); got != c.want {
			t.Errorf("hasControlChar(%q)=%v want %v", c.in, got, c.want)
		}
	}
}
