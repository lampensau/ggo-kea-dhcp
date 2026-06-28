package netmon

import (
	"testing"
	"time"
)

func TestVLAN_TrunkedNoScopeWarns(t *testing.T) {
	d := newVLANDetector("eth0", []int{10, 20}, nil)

	// A configured VID is expected (has a scope) → ignored.
	d.Consume(taggedFrame(10), at(1*time.Second))
	if ev := d.Tick(at(1 * time.Second)); ev != nil {
		t.Fatalf("configured VID flagged: %v", ev)
	}

	// A VID with no scope → one warn event + warn snapshot (actionable: add a scope).
	d.Consume(taggedFrame(99), at(2*time.Second))
	ev := d.Tick(at(2 * time.Second))
	if len(ev) != 1 || ev[0].Severity != SevWarn {
		t.Fatalf("expected one warn event, got %v", ev)
	}
	if s := d.Snapshot(); s.Severity != SevWarn || s.Fields["vids"] != "99" {
		t.Fatalf("snapshot = %+v", s)
	}
}

func TestVLAN_AuxdataConfirmsVisibilityAndRecoversTag(t *testing.T) {
	d := newVLANDetector("eth0", []int{10}, nil)

	// An untagged frame whose PACKET_AUXDATA confirms tag visibility (RX-VLAN
	// offload active): no unexpected VID, and the snapshot is a genuine all-clear,
	// not the "limited" blindness state.
	d.Consume(Frame{Iface: "eth0", Data: make([]byte, ethHdrLen), VLANKnown: true, VLAN: 0}, at(1*time.Second))
	d.Tick(at(1 * time.Second))
	if s := d.Snapshot(); s.Severity != SevOK {
		t.Fatalf("confirmed-visibility empty snapshot = %+v, want SevOK all-clear", s)
	}

	// An offload-stripped unexpected tag: Data carries no in-band 0x8100 tag, the
	// VID comes only from AUXDATA - still flagged.
	d.Consume(Frame{Iface: "eth0", Data: make([]byte, ethHdrLen), VLANKnown: true, VLAN: 99}, at(2*time.Second))
	if ev := d.Tick(at(2 * time.Second)); len(ev) != 1 || ev[0].Severity != SevWarn {
		t.Fatalf("offload-stripped unexpected VID not flagged: %v", ev)
	}
	if s := d.Snapshot(); s.Fields["vids"] != "99" {
		t.Fatalf("snapshot vids = %q, want 99", s.Fields["vids"])
	}
}

// TestVLAN_LatchesNoFlapping proves an observed unexpected VID is announced ONCE and stays
// reported across later ticks with no new frames - no "gone"/re-"seen" flapping. The prior
// aging model emitted a seen/gone pair (and an audit row each) whenever a VLAN's traffic was
// sparser than the 120s window, which a single quiet talker easily exceeds.
func TestVLAN_LatchesNoFlapping(t *testing.T) {
	d := newVLANDetector("eth0", []int{10}, nil)
	d.Consume(taggedFrame(200), at(1*time.Second))
	if ev := d.Tick(at(1 * time.Second)); len(ev) != 1 {
		t.Fatalf("first sighting: want 1 event, got %v", ev)
	}
	// Many minutes later with no new frames: still reported, and no further events.
	for i := 2; i < 10; i++ {
		if ev := d.Tick(at(time.Duration(i) * time.Minute)); len(ev) != 0 {
			t.Fatalf("tick @%dm emitted %v - latch must neither re-announce nor age out", i, ev)
		}
	}
	if s := d.Snapshot(); s.Fields["vids"] != "200" {
		t.Fatalf("snapshot vids = %q, want 200 (latched)", s.Fields["vids"])
	}
}

// auxTaggedFrame builds an offload-stripped tagged frame (VID only in AUXDATA), which
// sets the detector's tag-visibility flag - required for the self-heal path.
func auxTaggedFrame(vid int) Frame {
	return Frame{Iface: "eth0", Data: make([]byte, ethHdrLen), VLANKnown: true, VLAN: vid}
}

// TestVLAN_SelfHealsAfterLongAbsence proves the latch is not eternal: once tag visibility
// is confirmed, a VID that stops appearing for longer than vlanSelfHeal is dropped and
// reported gone - so a single stray frame can't pin the card amber forever.
func TestVLAN_SelfHealsAfterLongAbsence(t *testing.T) {
	d := newVLANDetector("eth0", []int{10}, nil)
	d.Consume(auxTaggedFrame(99), at(1*time.Second)) // sets visible + latches 99
	if ev := d.Tick(at(1 * time.Second)); len(ev) != 1 || ev[0].Severity != SevWarn {
		t.Fatalf("first sighting: want 1 warn, got %v", ev)
	}
	// Still within the window: latched, no events.
	if ev := d.Tick(at(10 * time.Minute)); len(ev) != 0 {
		t.Fatalf("within self-heal window emitted %v", ev)
	}
	// Past the window with visibility confirmed: one "no longer seen" info, cleared.
	ev := d.Tick(at(1*time.Second + vlanSelfHeal + time.Minute))
	if len(ev) != 1 || ev[0].Severity != SevInfo {
		t.Fatalf("expected one self-heal info event, got %v", ev)
	}
	if s := d.Snapshot(); s.Severity == SevWarn {
		t.Fatalf("snapshot still warns after self-heal: %+v", s)
	}
}

// TestVLAN_ClearsOnLinkDown proves a link drop wipes the latch immediately (the trunk is
// gone), reusing the same link-state seam as the LLDP detector.
func TestVLAN_ClearsOnLinkDown(t *testing.T) {
	up := true
	d := newVLANDetector("eth0", []int{10}, func() bool { return up })
	d.Consume(taggedFrame(200), at(1*time.Second))
	if ev := d.Tick(at(1 * time.Second)); len(ev) != 1 {
		t.Fatalf("first sighting: want 1 event, got %v", ev)
	}
	up = false
	d.Tick(at(2 * time.Second))
	if s := d.Snapshot(); s.Fields["vids"] == "200" {
		t.Fatalf("VID still latched after link down: %+v", s)
	}
}

// TestVLAN_QinQNotLatched proves a double-tagged frame's outer S-VID is never latched
// (etherInfo rejects QinQ), so a provider tag can't become a phantom no-scope VLAN.
func TestVLAN_QinQNotLatched(t *testing.T) {
	d := newVLANDetector("eth0", []int{10}, nil)
	// Outer 0x8100 tag (VID 100), inner ethertype also 0x8100 => QinQ.
	qinq := buildEthVLAN(macTestSwitch, macTestSwitch, 100, etherTypeVLAN, []byte{0x00})
	d.Consume(Frame{Iface: "eth0", Data: qinq}, at(1*time.Second))
	if ev := d.Tick(at(1 * time.Second)); len(ev) != 0 {
		t.Fatalf("QinQ frame produced events %v - outer S-VID must not latch", ev)
	}
	if s := d.Snapshot(); s.Fields["vids"] != "" {
		t.Fatalf("QinQ outer VID latched: %+v", s)
	}
}
