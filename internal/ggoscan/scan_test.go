package ggoscan

import (
	"net"
	"testing"
)

// reply0x11 builds a G-G device-info reply: header + body with name@0, MAC@0x12,
// firmware@0x2e.
func reply0x11(name string, mac [6]byte, fw string) []byte {
	body := make([]byte, 0x2e+0x40)
	copy(body, name) // NUL-padded by the zeroed buffer
	copy(body[0x12:], mac[:])
	copy(body[0x2e:], fw)
	return append([]byte{0x47, 0x2d, 0x47, 0x00, 0x00, 0x11, 0x00, 0x00}, body...)
}

func TestParseScanReply(t *testing.T) {
	mac := [6]byte{0x00, 0x1f, 0x80, 0x22, 0x51, 0x30}
	dev, ok := parseScanReply(reply0x11("TestingMCXD", mac, "MCXi 5.0.7.9165"), "10.0.0.50")
	if !ok {
		t.Fatal("parse failed on a valid 0x11 reply")
	}
	if dev.Name != "TestingMCXD" {
		t.Errorf("name = %q, want TestingMCXD", dev.Name)
	}
	if dev.MAC != "00:1f:80:22:51:30" {
		t.Errorf("mac = %q, want 00:1f:80:22:51:30", dev.MAC)
	}
	if dev.IP != "10.0.0.50" {
		t.Errorf("ip = %q, want 10.0.0.50", dev.IP)
	}
	if dev.Model != "MCXi" || dev.Version != "5.0.7.9165" {
		t.Errorf("model/version = %q/%q, want MCXi/5.0.7.9165", dev.Model, dev.Version)
	}

	// A non-0x11 frame (e.g. the 0x10 request echoed) and a too-short frame are rejected.
	if _, ok := parseScanReply([]byte{0x47, 0x2d, 0x47, 0x00, 0x00, 0x10, 0x00, 0x00}, "x"); ok {
		t.Error("parsed a 0x10 request as a reply")
	}
	if _, ok := parseScanReply([]byte{0x47, 0x2d, 0x47, 0x00}, "x"); ok {
		t.Error("parsed a truncated frame")
	}
}

func TestFirmwareMismatches(t *testing.T) {
	mac := func(n byte) [6]byte { return [6]byte{0, 0x1f, 0x80, 0x22, 0, n} }
	devs := []Device{
		{MAC: macStr(mac(1)), Name: "bp-a", Model: "MCXi", Version: "5.0.7.9165"},
		{MAC: macStr(mac(2)), Name: "bp-b", Model: "MCXi", Version: "5.0.7.9165"},
		{MAC: macStr(mac(3)), Name: "bp-c", Model: "MCXi", Version: "5.0.4.5846"},
		{MAC: macStr(mac(4)), Name: "wp-a", Model: "WPXi", Version: "5.0.7.9165"}, // uniform family
	}
	groups := FirmwareMismatches(devs)
	if len(groups) != 1 {
		t.Fatalf("groups = %d, want 1 (only MCXi diverges)", len(groups))
	}
	g := groups[0]
	if g.Model != "MCXi" {
		t.Fatalf("model = %q, want MCXi", g.Model)
	}
	if len(g.Counts) != 2 || g.Counts[0].Version != "5.0.7.9165" || g.Counts[0].N != 2 {
		t.Errorf("counts = %+v, want majority 5.0.7.9165 x2 first", g.Counts)
	}
	if len(g.Devices) != 3 {
		t.Errorf("devices = %d, want 3", len(g.Devices))
	}

	// A fully uniform fleet produces no mismatch.
	if got := FirmwareMismatches(devs[:2]); len(got) != 0 {
		t.Errorf("uniform fleet returned %d groups, want 0", len(got))
	}
}

// TestOnlyEmitsScan is the safety guard: the single frame this package can transmit
// is the read-only device-scan request (type 0x10), never a mutating opcode.
func TestOnlyEmitsScan(t *testing.T) {
	want := []byte{0x47, 0x2d, 0x47, 0x00, 0x00, 0x10, 0x00, 0x00}
	if len(scanFrame) != len(want) {
		t.Fatalf("scanFrame len = %d, want %d", len(scanFrame), len(want))
	}
	for i, b := range want {
		if scanFrame[i] != b {
			t.Fatalf("scanFrame[%d] = 0x%02x, want 0x%02x", i, scanFrame[i], b)
		}
	}
	// The opcode byte (index 5) must be 0x10. Mutating opcodes (0x90 reboot, 0xa0
	// memory-clear, 0x20/0x30/0x140/0x250 firmware, 0x310 save-default) must never
	// appear in the only frame builder.
	if scanFrame[5] != 0x10 {
		t.Fatalf("scan opcode = 0x%02x, want 0x10 (read-only)", scanFrame[5])
	}
}

// macStr formats 6 bytes as a colon-separated MAC for building test devices by value.
func macStr(b [6]byte) string { return net.HardwareAddr(b[:]).String() }
