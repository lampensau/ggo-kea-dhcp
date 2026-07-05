package netmon

import (
	"testing"
	"time"
)

// selfMAC is the box's own NIC MAC (dhcpFrameFrom / dhcpFrame stamp their source
// MAC, so tests can distinguish the appliance's own OFFERs from a foreign one).
var selfMAC = [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0xaa}

func TestRogueDHCP_FlagsForeignServerNotSelf(t *testing.T) {
	self := [4]byte{10, 0, 0, 1}
	d := newRogueDHCPDetector("eth0", selfMAC, true, 120*time.Second)

	// Our own server's OFFER (source MAC == the box MAC) is suppressed.
	d.Consume(dhcpFrameFrom(selfMAC, self, 2), at(1*time.Second))
	if ev := d.Tick(at(1 * time.Second)); ev != nil {
		t.Fatalf("self OFFER flagged as rogue: %v", ev)
	}

	// A foreign server's OFFER (a different source MAC) is a high-severity rogue.
	foreignMAC := [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	d.Consume(dhcpFrameFrom(foreignMAC, [4]byte{10, 0, 0, 250}, 2), at(2*time.Second))
	ev := d.Tick(at(2 * time.Second))
	if len(ev) != 1 || ev[0].Severity != SevError {
		t.Fatalf("expected one error event, got %v", ev)
	}
	s := d.Snapshot()
	if s.Severity != SevError || s.Fields["server"] != "10.0.0.250" {
		t.Fatalf("snapshot = %+v", s)
	}
	if s.Fields["mac"] == "" {
		t.Fatal("rogue server MAC not captured")
	}

	// Still present on the next tick (no duplicate event).
	d.Consume(dhcpFrameFrom(foreignMAC, [4]byte{10, 0, 0, 250}, 5), at(60*time.Second))
	if ev := d.Tick(at(60 * time.Second)); ev != nil {
		t.Fatalf("duplicate event while rogue still present: %v", ev)
	}

	// Gone past the absence window → cleared (info), snapshot back to ok.
	if ev := d.Tick(at(200 * time.Second)); len(ev) != 1 || ev[0].Severity != SevInfo {
		t.Fatalf("expected one gone event, got %v", ev)
	}
	if s := d.Snapshot(); s.Severity != SevOK {
		t.Fatalf("snapshot after clear = %+v", s)
	}
}

// TestRogueDHCP_ForgedServerIDStillDetected is the security regression: a rogue
// that forges option-54 (server-id) to the box's own IP must STILL be flagged,
// because self-suppression keys on the source MAC (an L2 fact), not the
// attacker-controlled server-id.
func TestRogueDHCP_ForgedServerIDStillDetected(t *testing.T) {
	boxIP := [4]byte{10, 0, 0, 1}
	d := newRogueDHCPDetector("eth0", selfMAC, true, 120*time.Second)

	rogueMAC := [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	d.Consume(dhcpFrameFrom(rogueMAC, boxIP, 2), at(1*time.Second)) // forged server-id == box IP
	if ev := d.Tick(at(1 * time.Second)); len(ev) != 1 || ev[0].Severity != SevError {
		t.Fatalf("forged-server-id rogue not detected, events=%v", ev)
	}
	if s := d.Snapshot(); s.Severity != SevError || s.Fields["server"] != "10.0.0.1" {
		t.Fatalf("snapshot = %+v", s)
	}
}

// TestRogueDHCP_UnknownSelfMACSuppressesEmission proves the safety degrade: when
// the box's own NIC MAC could not be read (macKnown=false) the detector cannot tell
// its own OFFERs from a rogue's, so it emits nothing (never phantom-flagging the
// appliance) and reports Unverified rather than a confident all-clear.
func TestRogueDHCP_UnknownSelfMACSuppressesEmission(t *testing.T) {
	d := newRogueDHCPDetector("eth0", [6]byte{}, false, 120*time.Second)

	// Even a would-be foreign OFFER produces no event while the self-MAC is unknown -
	// we cannot verify it is not our own, so we stay silent instead of phantom-flagging.
	foreignMAC := [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	d.Consume(dhcpFrameFrom(foreignMAC, [4]byte{10, 0, 0, 250}, 2), at(1*time.Second))
	if ev := d.Tick(at(1 * time.Second)); ev != nil {
		t.Fatalf("emitted a rogue event while self-MAC unknown: %v", ev)
	}
	// Unverified, not a confident all-clear: SevInfo is distinct from SevOK, so this
	// single assertion covers both "reports Unverified" and "never reports SevOK".
	s := d.Snapshot()
	if s.Severity != SevInfo {
		t.Fatalf("unknown self-MAC should report Unverified (SevInfo), got %+v", s)
	}
}

// TestRogueDHCP_SuppressesOwnVLANOffers proves the mixed untagged+VLAN case: the
// box's own OFFER on a tagged VLAN scope carries a different server-id (the VLAN
// interface's IP) but the SAME physical NIC source MAC, so MAC-based suppression
// covers every VLAN and the box never self-flags.
func TestRogueDHCP_SuppressesOwnVLANOffers(t *testing.T) {
	d := newRogueDHCPDetector("eth0", selfMAC, true, 120*time.Second)

	// Untagged scope OFFER (server-id 10.0.0.1) and a tagged VLAN scope OFFER
	// (server-id 10.0.10.1) - both from the box, same source MAC.
	d.Consume(dhcpFrameFrom(selfMAC, [4]byte{10, 0, 0, 1}, 2), at(1*time.Second))
	d.Consume(taggedDHCPOfferFrom(selfMAC, 10, [4]byte{10, 0, 10, 1}), at(1*time.Second))
	if ev := d.Tick(at(1 * time.Second)); ev != nil {
		t.Fatalf("box's own OFFERs flagged as rogue: %v", ev)
	}
	if s := d.Snapshot(); s.Severity != SevOK {
		t.Fatalf("snapshot = %+v", s)
	}
}
