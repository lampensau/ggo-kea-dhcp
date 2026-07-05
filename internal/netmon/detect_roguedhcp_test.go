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
	d := newRogueDHCPDetector("eth0", selfMAC, true, 0, 120*time.Second)

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
	d := newRogueDHCPDetector("eth0", selfMAC, true, 0, 120*time.Second)

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
	d := newRogueDHCPDetector("eth0", [6]byte{}, false, 0, 120*time.Second)

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
	d := newRogueDHCPDetector("eth0", selfMAC, true, 0, 120*time.Second)

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

// TestRogueDHCP_ScopedToServedVLAN proves a rogue is judged only by the monitor
// whose served VLAN it is on. A foreign OFFER tagged for VLAN 10 must be ignored by
// the untagged eth0 monitor (which also sees trunk-leaked tagged frames) and flagged
// by the eth0.10 monitor - so one rogue is counted once, on the right segment, and a
// server on an unserved VLAN never raises the untagged scope's banner.
func TestRogueDHCP_ScopedToServedVLAN(t *testing.T) {
	rogueMAC := [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	rogueID := [4]byte{10, 0, 10, 250}

	untagged := newRogueDHCPDetector("eth0", selfMAC, true, 0, 120*time.Second)
	untagged.Consume(taggedDHCPOfferFrom(rogueMAC, 10, rogueID), at(1*time.Second))
	if ev := untagged.Tick(at(1 * time.Second)); ev != nil {
		t.Fatalf("untagged monitor flagged a VLAN-10 rogue that belongs to eth0.10: %v", ev)
	}
	if s := untagged.Snapshot(); s.Severity != SevOK {
		t.Fatalf("untagged snapshot should be clean: %+v", s)
	}

	tagged := newRogueDHCPDetector("eth0.10", selfMAC, true, 10, 120*time.Second)
	tagged.Consume(taggedDHCPOfferFrom(rogueMAC, 10, rogueID), at(1*time.Second))
	if ev := tagged.Tick(at(1 * time.Second)); len(ev) != 1 || ev[0].Severity != SevError {
		t.Fatalf("eth0.10 monitor should flag its own VLAN's rogue exactly once: %v", ev)
	}
}

// TestRogueDHCP_SustainedGate proves the sustained flag distinguishes a single (forgeable)
// OFFER - which confirms presence for the Network Health row but must NOT be reported as
// sustained - from a rogue seen repeatedly across the sustain window. The web layer gates
// the loud one-click stand-down banner on this flag.
func TestRogueDHCP_SustainedGate(t *testing.T) {
	d := newRogueDHCPDetector("eth0", selfMAC, true, 0, 120*time.Second)
	rogue := [4]byte{10, 0, 0, 250}

	// One OFFER: presence is confirmed (the detector row is immediate) but NOT sustained.
	d.Consume(dhcpFrame(67, rogue, 2), at(1*time.Second))
	d.Tick(at(1 * time.Second))
	s := d.Snapshot()
	if s.Severity != SevError {
		t.Fatalf("a single OFFER should still flag the detector row: %+v", s)
	}
	if s.Fields["sustained"] != "0" {
		t.Fatalf("a single OFFER must not be reported as sustained: %+v", s)
	}

	// A second OFFER past the sustain window: the run now spans it -> sustained.
	d.Consume(dhcpFrame(67, rogue, 5), at(35*time.Second))
	d.Tick(at(35 * time.Second))
	if s := d.Snapshot(); s.Fields["sustained"] != "1" {
		t.Fatalf("a rogue seen across the sustain window should be sustained: %+v", s)
	}
}
