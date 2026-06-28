package ggoscan

import (
	"testing"
	"time"
)

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

// TestFirmwareMismatchesSkipsIncomplete confirms devices with an empty Model or
// Version are excluded entirely (they cannot be classified).
func TestFirmwareMismatchesSkipsIncomplete(t *testing.T) {
	devs := []Device{
		{MAC: "00:1f:80:00:00:01", Name: "a", Model: "MCXi", Version: "1.0"},
		{MAC: "00:1f:80:00:00:02", Name: "b", Model: "MCXi", Version: "2.0"},
		{MAC: "00:1f:80:00:00:03", Name: "noversion", Model: "MCXi", Version: ""}, // skipped
		{MAC: "00:1f:80:00:00:04", Name: "nomodel", Model: "", Version: "9.9"},    // skipped
	}
	groups := FirmwareMismatches(devs)
	if len(groups) != 1 || groups[0].Model != "MCXi" {
		t.Fatalf("groups = %+v, want one MCXi group", groups)
	}
	// Only the two complete devices are in the family.
	if len(groups[0].Devices) != 2 {
		t.Errorf("devices in MCXi = %d, want 2 (incomplete ones excluded)", len(groups[0].Devices))
	}
}

// TestFirmwareMismatchesCountTieBreak verifies the version-count ordering tie-break
// (equal counts ordered by version ascending).
func TestFirmwareMismatchesCountTieBreak(t *testing.T) {
	devs := []Device{
		{MAC: "00:1f:80:00:00:01", Name: "a", Model: "WPXi", Version: "2.0.0"},
		{MAC: "00:1f:80:00:00:02", Name: "b", Model: "WPXi", Version: "1.0.0"},
	}
	groups := FirmwareMismatches(devs)
	if len(groups) != 1 {
		t.Fatalf("groups = %d, want 1", len(groups))
	}
	c := groups[0].Counts
	if len(c) != 2 || c[0].Version != "1.0.0" || c[1].Version != "2.0.0" {
		t.Errorf("tie-break order = %+v, want 1.0.0 before 2.0.0", c)
	}
}

// TestFirmwareMismatchesDeterministicModelOrder confirms multiple diverging model
// families come back sorted by model name.
func TestFirmwareMismatchesDeterministicModelOrder(t *testing.T) {
	devs := []Device{
		{MAC: "1", Name: "z1", Model: "ZPXi", Version: "1"},
		{MAC: "2", Name: "z2", Model: "ZPXi", Version: "2"},
		{MAC: "3", Name: "a1", Model: "APXi", Version: "1"},
		{MAC: "4", Name: "a2", Model: "APXi", Version: "2"},
	}
	groups := FirmwareMismatches(devs)
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(groups))
	}
	if groups[0].Model != "APXi" || groups[1].Model != "ZPXi" {
		t.Errorf("model order = [%q,%q], want [APXi,ZPXi]", groups[0].Model, groups[1].Model)
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
