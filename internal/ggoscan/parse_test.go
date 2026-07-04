package ggoscan

import (
	"encoding/hex"
	"testing"
	"time"
)

// TestParseScanReplyLiveBPX parses a real BPX reply captured on the wire
// (broadcast scan, firmware 5.1.0.14479). It pins the 0x55aa marker handling:
// the firmware string sits at body offset 0x30 behind the marker, and reading
// it at 0x2e would yield the mangled model "U\xaaBPX".
func TestParseScanReplyLiveBPX(t *testing.T) {
	body, err := hex.DecodeString(
		"425058203139363636000000000000000000001f80204e524cd2000000000000" +
			"00000000ffffff00200f0000000055aa42505820352e312e302e313434373900" +
			"000000000000000000c60000200f0003cdc00802000008020100ffffffffffff" +
			"ffffffffffffffffffffffffffff000000000000000000000000000000000000" +
			"0000000000000000000000000000000000000000000000000000000000000000" +
			"00000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	frame := append([]byte{0x47, 0x2d, 0x47, 0x00, 0x00, 0x11, 0x00, 0x00}, body...)
	dev, ok := parseScanReply(frame, "10.0.0.20")
	if !ok {
		t.Fatal("live BPX reply did not parse")
	}
	if dev.Name != "BPX 19666" {
		t.Errorf("name = %q, want BPX 19666", dev.Name)
	}
	if dev.MAC != "00:1f:80:20:4e:52" {
		t.Errorf("mac = %q", dev.MAC)
	}
	if dev.Model != "BPX" || dev.Version != "5.1.0.14479" {
		t.Errorf("model/version = %q/%q, want BPX/5.1.0.14479", dev.Model, dev.Version)
	}
}

// TestParseScanReplyFirmwareMissing covers the boundary where the body is just
// long enough for name+MAC (through 0x18) but carries no firmware field: fw, model
// and version come back empty while name/MAC still parse.
func TestParseScanReplyFirmwareMissing(t *testing.T) {
	mac := [6]byte{0x00, 0x1f, 0x80, 0x01, 0x02, 0x03}
	body := make([]byte, 0x18) // exactly through the MAC, no firmware
	copy(body, "NoFwDevice")
	copy(body[0x12:], mac[:])
	frame := append([]byte{0x47, 0x2d, 0x47, 0x00, 0x00, 0x11, 0x00, 0x00}, body...)

	dev, ok := parseScanReply(frame, "10.0.0.9")
	if !ok {
		t.Fatal("expected a name+MAC-only reply to parse")
	}
	if dev.Name != "NoFwDevice" {
		t.Errorf("name = %q, want NoFwDevice", dev.Name)
	}
	if dev.MAC != "00:1f:80:01:02:03" {
		t.Errorf("mac = %q", dev.MAC)
	}
	if dev.Firmware != "" || dev.Model != "" || dev.Version != "" {
		t.Errorf("expected empty firmware fields, got fw=%q model=%q ver=%q", dev.Firmware, dev.Model, dev.Version)
	}
}

// TestParseScanReplyFirmwareNoSpace checks a firmware string with no space splits
// to model=whole, version="" (strings.Cut without separator).
func TestParseScanReplyFirmwareNoSpace(t *testing.T) {
	mac := [6]byte{0, 0x1f, 0x80, 0, 0, 1}
	dev, ok := parseScanReply(reply0x11("dev", mac, "MONOLITH"), "10.0.0.10")
	if !ok {
		t.Fatal("parse failed")
	}
	if dev.Model != "MONOLITH" || dev.Version != "" {
		t.Errorf("model/version = %q/%q, want MONOLITH/\"\"", dev.Model, dev.Version)
	}
}

// TestParseScanReplyRejects covers the rejection paths: wrong magic, wrong opcode,
// and a body too short to hold name+MAC.
func TestParseScanReplyRejects(t *testing.T) {
	mac := [6]byte{0, 0x1f, 0x80, 0, 0, 1}
	good := reply0x11("d", mac, "X 1")

	// Corrupt the 4th magic byte (must be 0x00).
	badMagic := append([]byte(nil), good...)
	badMagic[3] = 0xff
	if _, ok := parseScanReply(badMagic, "x"); ok {
		t.Error("accepted a frame with a bad magic byte")
	}

	// Opcode 0x12 (not the 0x11 reply).
	badOp := append([]byte(nil), good...)
	badOp[5] = 0x12
	if _, ok := parseScanReply(badOp, "x"); ok {
		t.Error("accepted a non-0x11 opcode")
	}

	// Valid header but body shorter than 0x18.
	shortBody := append([]byte{0x47, 0x2d, 0x47, 0x00, 0x00, 0x11, 0x00, 0x00}, make([]byte, 0x10)...)
	if _, ok := parseScanReply(shortBody, "x"); ok {
		t.Error("accepted a body too short for name+MAC")
	}
}

// TestReleaseMismatch covers THE firmware check: devices are compared on their
// release (major.minor.patch) across all families, builds are ignored, and
// incomplete devices are skipped.
func TestReleaseMismatch(t *testing.T) {
	// Same release, different per-model builds: uniform, no finding.
	uniform := []Device{
		{MAC: "1", Name: "bp-a", Model: "BPX", Version: "5.2.2.25270"},
		{MAC: "2", Name: "mc-a", Model: "MCXi", Version: "5.2.2.25269"},
		{MAC: "3", Name: "noversion", Model: "BPX", Version: ""}, // skipped
		{MAC: "4", Name: "nomodel", Model: "", Version: "9.9"},   // skipped
	}
	if sp := ReleaseMismatch(uniform); sp != nil {
		t.Errorf("uniform releases = %+v, want nil", sp)
	}

	// Releases diverge across families: one finding with both releases counted,
	// most common first, and the device roster version-sorted.
	mixed := []Device{
		{MAC: "1", Name: "bp-a", Model: "BPX", Version: "5.2.2.25270"},
		{MAC: "2", Name: "bp-b", Model: "BPX", Version: "5.2.2.25270"},
		{MAC: "3", Name: "mc-a", Model: "MCXi", Version: "5.1.0.14479"},
	}
	sp := ReleaseMismatch(mixed)
	if sp == nil {
		t.Fatal("mixed releases yielded no finding")
	}
	if len(sp.Releases) != 2 || sp.Releases[0].Release != "5.2.2" || sp.Releases[0].N != 2 || sp.Releases[1].Release != "5.1.0" {
		t.Errorf("releases = %+v, want 5.2.2 x2 then 5.1.0 x1", sp.Releases)
	}
	if len(sp.Devices) != 3 || sp.Devices[0].Name != "mc-a" {
		t.Errorf("roster = %+v, want version-sorted with mc-a first", sp.Devices)
	}
}

// TestReleaseMismatchLegacyExemption pins the legacy carve-out: a legacy family
// on its final release never counts against a newer fleet, but a legacy device
// BELOW the final release still does.
func TestReleaseMismatchLegacyExemption(t *testing.T) {
	// Legacy on the sanctioned final release beside a newer fleet: no finding.
	sanctioned := []Device{
		{MAC: "1", Name: "bp2-a", Model: "BP2", Version: legacyFinalRelease + ".24127"},
		{MAC: "2", Name: "wp-a", Model: "WP", Version: legacyFinalRelease + ".24127"},
		{MAC: "3", Name: "bp-a", Model: "BPX", Version: "5.3.0.30001"},
		{MAC: "4", Name: "bp-b", Model: "BPX", Version: "5.3.0.30001"},
	}
	if sp := ReleaseMismatch(sanctioned); sp != nil {
		t.Errorf("legacy on final release = %+v, want nil", sp)
	}

	// Legacy BELOW the final release: it participates and warns.
	outdated := []Device{
		{MAC: "1", Name: "bp2-a", Model: "BP2", Version: "5.2.0.20001"},
		{MAC: "2", Name: "bp-a", Model: "BPX", Version: "5.3.0.30001"},
	}
	sp := ReleaseMismatch(outdated)
	if sp == nil || len(sp.Releases) != 2 {
		t.Fatalf("outdated legacy = %+v, want a 2-release finding", sp)
	}

	// A pure legacy fleet on the final release compares as empty: no finding.
	if sp := ReleaseMismatch(sanctioned[:2]); sp != nil {
		t.Errorf("all-legacy final-release fleet = %+v, want nil", sp)
	}
}

// TestInventoryTTLPrune exercises the inventory record/snapshot path including the
// TTL eviction the live snapshot relies on.
func TestInventoryTTLPrune(t *testing.T) {
	inv := newInventory()
	base := time.Unix(1_000_000, 0)
	inv.record(Device{MAC: "aa", Name: "fresh"}, base)
	inv.record(Device{MAC: "bb", Name: "stale"}, base)

	// Snapshot at base sees both.
	if got := inv.snapshot(base); len(got) != 2 {
		t.Fatalf("snapshot at base = %d devices, want 2", len(got))
	}

	// Re-touch only "aa", then advance past the TTL: "bb" must be pruned.
	later := base.Add(deviceTTL - 1)
	inv.record(Device{MAC: "aa", Name: "fresh"}, later)
	probe := base.Add(deviceTTL + 1) // bb is now > deviceTTL old, aa is not
	got := inv.snapshot(probe)
	if len(got) != 1 || got[0].MAC != "aa" {
		t.Fatalf("snapshot after TTL = %+v, want only aa", got)
	}
}
