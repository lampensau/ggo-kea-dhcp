package netmon

import (
	"testing"

	"golang.org/x/net/bpf"
)

// danteLikeFrame builds a high-rate audio-style UDP frame (port 4321) that the
// filter must drop.
func danteLikeFrame() Frame {
	udp := buildUDP(4321, 4321, make([]byte, 200))
	ip := buildIPv4(ipProtoUDP, [4]byte{10, 0, 0, 5}, [4]byte{239, 69, 0, 1}, udp)
	return Frame{Iface: "eth0", Data: buildEth(macTestSwitch, macTestSwitch, etherTypeIPv4, ip)}
}

func runFilter(t *testing.T, multicastSniff, greengo bool, f Frame) bool {
	t.Helper()
	vm, err := bpf.NewVM(buildBPFInstructions(multicastSniff, greengo))
	if err != nil {
		t.Fatalf("assemble/VM: %v", err)
	}
	n, err := vm.Run(f.Data)
	if err != nil {
		t.Fatalf("VM run: %v", err)
	}
	return n > 0
}

func TestBPFFilter_AcceptsInterestingDropsFlood(t *testing.T) {
	// Assembles cleanly to raw form (catches a bad skip), across the sniff/greengo combos.
	for _, mc := range []bool{false, true} {
		for _, gg := range []bool{false, true} {
			if _, err := buildFilter(mc, gg); err != nil {
				t.Fatalf("buildFilter(%v,%v): %v", mc, gg, err)
			}
		}
	}

	accept := map[string]Frame{
		"igmp":  igmpQuery([4]byte{10, 0, 0, 1}, 2),
		"lldp":  lldpFrame("sw", "p1", 10),
		"arp":   arpFrame(2, [6]byte{1, 2, 3, 4, 5, 6}, [4]byte{10, 0, 0, 9}),
		"ptpL2": ptpAnnounce(0, 0x1, 128, 128, false),
		"bpdu":  bpduFrame(true),
		"dhcp":  dhcpFrame(67, [4]byte{10, 0, 0, 1}, 2),
		"vlan":  taggedFrame(99),
	}
	for name, f := range accept {
		if !runFilter(t, false, false, f) {
			t.Errorf("filter dropped %s, want accept", name)
		}
	}

	// The audio flood must be dropped without multicast-sniff.
	if runFilter(t, false, false, danteLikeFrame()) {
		t.Error("filter accepted Dante-like flood, want drop")
	}

	// sACN is dropped by default, accepted only under multicast-sniff.
	sacn := sacnData(1, cid16(0xa1), 100)
	if runFilter(t, false, false, sacn) {
		t.Error("filter accepted sACN without multicast-sniff, want drop")
	}
	if !runFilter(t, true, false, sacn) {
		t.Error("filter dropped sACN under multicast-sniff, want accept")
	}
}

// busFrameSub builds a UDP:5810 frame whose G5 payload carries the given subtype,
// to exercise the 'h'-specific (0x68) BPF clause.
func busFrameSub(subtype byte) Frame {
	pl := []byte{0x47, 0x35, subtype, 0, 0, 0, 0, 0} // "G5" + subtype + filler
	udp := buildUDP(ggoBusPort, ggoBusPort, pl)
	ip := buildIPv4(ipProtoUDP, [4]byte{10, 0, 0, 9}, [4]byte{10, 0, 0, 255}, udp)
	return Frame{Iface: "eth0", Data: buildEth(macTestSwitch, macTestSwitch, etherTypeIPv4, ip)}
}

func TestBPFFilter_Greengo(t *testing.T) {
	// On a Green-GO interface the 'h' announce (subtype 0x68) on 5810 is accepted...
	if !runFilter(t, false, true, busFrameSub(0x68)) {
		t.Error("filter dropped Green-GO 'h' announce, want accept")
	}
	// ...but the 0x60 state beacon / 0x06 audio on 5810 are dropped in kernel.
	if runFilter(t, false, true, busFrameSub(0x60)) {
		t.Error("filter accepted 0x60 beacon, want drop")
	}
	if runFilter(t, false, true, busFrameSub(0x06)) {
		t.Error("filter accepted 0x06 audio, want drop")
	}
	// On a non-Green-GO interface 5810 is not captured at all (even the 'h' announce).
	if runFilter(t, false, false, busFrameSub(0x68)) {
		t.Error("non-Green-GO filter accepted 5810 'h', want drop")
	}
}

func TestBPFFilter_PTPUDPAccepted(t *testing.T) {
	if !runFilter(t, false, false, ptpAnnounce(0, 0x1, 128, 128, true)) {
		t.Error("filter dropped PTP-UDP announce, want accept")
	}
}
