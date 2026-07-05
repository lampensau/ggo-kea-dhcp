package netmon

import (
	"testing"
	"time"

	"golang.org/x/net/bpf"
)

// taggedDHCPOffer builds a server OFFER riding a single in-band 802.1Q tag (a
// rogue server on a trunked VLAN, RX-VLAN offload off).
func taggedDHCPOffer(vid int, serverID [4]byte) Frame {
	chaddr := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x03}
	dhcp := buildDHCP(2, chaddr, serverID, 2)
	udp := buildUDP(67, 68, dhcp)
	ip := buildIPv4(ipProtoUDP, serverID, [4]byte{255, 255, 255, 255}, udp)
	return Frame{Iface: "eth0", TS: base, Data: buildEthVLAN(macBroadcast, macTestSwitch, vid, etherTypeIPv4, ip)}
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
	p.begin("eth0", fs, nil)
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
	// wire; passing its IP as a self-IP must keep the badge from flagging itself.
	p := NewRogueProbe()
	fs := NewFakeSniffer()
	p.begin("eth0", fs, [][4]byte{{10, 0, 0, 1}})
	defer p.Stop()

	fs.Push(dhcpFrame(67, [4]byte{10, 0, 0, 1}, 2))
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if ip, _, ok := p.Server(); ok {
			t.Fatalf("own OFFER from %s flagged as a rogue server", ip)
		}
		time.Sleep(5 * time.Millisecond)
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
	p.begin("eth0", fs, nil)
	fs.Push(dhcpFrame(67, [4]byte{10, 0, 0, 250}, 2))
	p.Stop()
	if ip, _, ok := p.Server(); ok {
		t.Fatalf("server %s reported after Stop", ip)
	}
	// A restart begins with a fresh detector (no latched sighting).
	fs2 := NewFakeSniffer()
	p.begin("eth0", fs2, nil)
	defer p.Stop()
	if ip, _, ok := p.Server(); ok {
		t.Fatalf("restarted probe inherited server %s", ip)
	}
}
