package netmon

import (
	"testing"
	"time"

	"golang.org/x/net/bpf"
)

// taggedDHCPOffer builds a server OFFER riding a single in-band 802.1Q tag (a
// rogue server on a trunked VLAN, RX-VLAN offload off).
func taggedDHCPOffer(vid int, serverID [4]byte) Frame {
	return taggedDHCPOfferFrom(macTestSwitch, vid, serverID)
}

func TestRogueOfferFilter(t *testing.T) {
	vm, err := bpf.NewVM(rogueOfferInstructions())
	if err != nil {
		t.Fatalf("assemble/VM: %v", err)
	}
	run := func(f Frame) bool {
		t.Helper()
		n, err := vm.Run(f.Data)
		if err != nil {
			t.Fatalf("VM run: %v", err)
		}
		return n > 0
	}

	if !run(dhcpFrame(67, [4]byte{10, 0, 0, 250}, 2)) {
		t.Error("filter dropped an untagged server OFFER, want accept")
	}
	if !run(taggedDHCPOffer(20, [4]byte{10, 0, 20, 1})) {
		t.Error("filter dropped a VLAN-tagged server OFFER, want accept")
	}
	// Client-side DHCP (sport 68) is not a server answering - drop it.
	if run(declineFrame([4]byte{10, 0, 0, 9})) {
		t.Error("filter accepted a client-side DHCP frame, want drop")
	}
	if run(arpFrame(2, [6]byte{1, 2, 3, 4, 5, 6}, [4]byte{10, 0, 0, 9})) {
		t.Error("filter accepted ARP, want drop")
	}
	if run(danteLikeFrame()) {
		t.Error("filter accepted the audio flood, want drop")
	}
}

func TestRogueProbe_DetectsForeignOffer(t *testing.T) {
	p := NewRogueProbe()
	fs := NewFakeSniffer()
	p.begin("eth0", fs, [6]byte{}, false)
	defer p.Stop()

	if ip, _, ok := p.Server(); ok {
		t.Fatalf("server %s reported before any traffic", ip)
	}

	fs.Push(dhcpFrame(67, [4]byte{10, 0, 0, 250}, 2))
	deadline := time.Now().Add(2 * time.Second)
	for {
		ip, mac, ok := p.Server()
		if ok {
			if ip != "10.0.0.250" {
				t.Fatalf("server ip = %q, want 10.0.0.250", ip)
			}
			if mac == "" {
				t.Fatal("server MAC not captured")
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("OFFER never surfaced via Server()")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRogueProbe_SuppressesOwnOffers(t *testing.T) {
	// The box serves its own onboarding pool on eth0, so its OFFERs are on the
	// wire; passing its own source MAC must keep the badge from flagging itself,
	// even when the OFFER's server-id equals the box IP.
	boxMAC := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0xaa}
	p := NewRogueProbe()
	fs := NewFakeSniffer()
	p.begin("eth0", fs, boxMAC, true)
	defer p.Stop()

	fs.Push(dhcpFrameFrom(boxMAC, [4]byte{10, 0, 0, 1}, 2))
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if ip, _, ok := p.Server(); ok {
			t.Fatalf("own OFFER from %s flagged as a rogue server", ip)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRogueProbe_WatchingReflectsRealCapture(t *testing.T) {
	p := NewRogueProbe()
	// Inert (never started): not watching, so the shield stays honestly unverified.
	if p.Watching() {
		t.Fatal("inert probe reports Watching")
	}

	// A real (non-nop) capture is watching.
	p.begin("eth0", NewFakeSniffer(), [6]byte{}, false)
	if !p.Watching() {
		t.Fatal("live capture does not report Watching")
	}
	p.Stop()

	// A nop sniffer (no CAP_NET_RAW / dev sandbox) is blind - not watching even
	// though the read loop runs, because it can never see a frame.
	p.begin("eth0", newNopSniffer(), [6]byte{}, false)
	if p.Watching() {
		t.Fatal("blind nop sniffer reports Watching")
	}

	// Stopped: not watching (the ACTIVE edit-page case).
	p.Stop()
	if p.Watching() {
		t.Fatal("stopped probe reports Watching")
	}
}

func TestRogueProbe_StopClearsAndIsIdempotent(t *testing.T) {
	p := NewRogueProbe()
	// Never started: quiet, and Stop is safe.
	if _, _, ok := p.Server(); ok {
		t.Fatal("inert probe reported a server")
	}
	p.Stop()
	p.Stop()

	fs := NewFakeSniffer()
	p.begin("eth0", fs, [6]byte{}, false)
	fs.Push(dhcpFrame(67, [4]byte{10, 0, 0, 250}, 2))
	p.Stop()
	if ip, _, ok := p.Server(); ok {
		t.Fatalf("server %s reported after Stop", ip)
	}
	// A restart begins with a fresh detector (no latched sighting).
	fs2 := NewFakeSniffer()
	p.begin("eth0", fs2, [6]byte{}, false)
	defer p.Stop()
	if ip, _, ok := p.Server(); ok {
		t.Fatalf("restarted probe inherited server %s", ip)
	}
}

// killSniffer models a real capture whose read loop dies fatally mid-run: closing
// its Frames channel (as afpacketSniffer.readLoop does on a fatal error) WITHOUT
// an orderly Stop. Used to prove Watching() falls to false so the shield reads
// "Unverified" instead of a confident all-clear.
type killSniffer struct{ ch chan Frame }

func (k *killSniffer) Frames() <-chan Frame { return k.ch }
func (k *killSniffer) Close() error         { return nil }

func TestRogueProbe_WatchingFalseAfterFatalDeath(t *testing.T) {
	p := NewRogueProbe()
	ks := &killSniffer{ch: make(chan Frame)}
	p.begin("eth0", ks, [6]byte{}, false)
	defer p.Stop()

	if !p.Watching() {
		t.Fatal("live capture does not report Watching")
	}

	// The capture dies fatally: the frame channel closes without a Stop.
	close(ks.ch)

	deadline := time.Now().Add(2 * time.Second)
	for p.Watching() {
		if time.Now().After(deadline) {
			t.Fatal("Watching still true after a fatal capture death - shield would show a false all-clear")
		}
		time.Sleep(2 * time.Millisecond)
	}
	// Server() must also stop confirming an all-clear (detector cleared).
	if _, _, ok := p.Server(); ok {
		t.Fatal("Server reported after a fatal capture death")
	}
}
