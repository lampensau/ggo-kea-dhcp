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

func runFilter(t *testing.T, greengo bool, f Frame) bool {
	t.Helper()
	vm, err := bpf.NewVM(buildBPFInstructions(greengo))
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
	// Assembles cleanly to raw form (catches a bad skip), on both interface kinds.
	for _, gg := range []bool{false, true} {
		if _, err := buildFilter(gg); err != nil {
			t.Fatalf("buildFilter(%v): %v", gg, err)
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
		if !runFilter(t, false, f) {
			t.Errorf("filter dropped %s, want accept", name)
		}
	}

	// The audio flood must be dropped in kernel.
	if runFilter(t, false, danteLikeFrame()) {
		t.Error("filter accepted Dante-like flood, want drop")
	}
}

// busFrameSub builds a UDP:5810 frame carrying the given subtype byte, to exercise the
// subtype BPF clause.
func busFrameSub(subtype byte) Frame {
	pl := []byte{0x47, 0x35, subtype, 0, 0, 0, 0, 0}
	udp := buildUDP(ggoBusPort, ggoBusPort, pl)
	ip := buildIPv4(ipProtoUDP, [4]byte{10, 0, 0, 9}, [4]byte{10, 0, 0, 255}, udp)
	return Frame{Iface: "eth0", Data: buildEth(macTestSwitch, macTestSwitch, etherTypeIPv4, ip)}
}

func TestBPFFilter_Greengo(t *testing.T) {
	// On a Green-GO interface the accepted subtype on 5810 passes...
	if !runFilter(t, true, busFrameSub(0x68)) {
		t.Error("filter dropped the accepted subtype, want accept")
	}
	// ...but other 5810 subtypes are dropped in kernel.
	if runFilter(t, true, busFrameSub(0x60)) {
		t.Error("filter accepted a dropped subtype, want drop")
	}
	if runFilter(t, true, busFrameSub(0x06)) {
		t.Error("filter accepted a dropped subtype, want drop")
	}
	// On a non-Green-GO interface 5810 is not captured at all.
	if runFilter(t, false, busFrameSub(0x68)) {
		t.Error("non-Green-GO filter accepted 5810 traffic, want drop")
	}
}

func TestBPFFilter_PTPUDPAccepted(t *testing.T) {
	if !runFilter(t, false, ptpAnnounce(0, 0x1, 128, 128, true)) {
		t.Error("filter dropped PTP-UDP announce, want accept")
	}
}

func TestBPFAsm_ResolvePanicsOnUndefinedLabel(t *testing.T) {
	a := newBPFAsm()
	a.jump(bpf.JumpEqual, 1, "no-such-label", "")
	a.emit(bpf.RetConstant{Val: bpfReject})
	defer func() {
		if recover() == nil {
			t.Fatal("resolve() with an undefined label did not panic - a missing label would silently assemble a wrong filter")
		}
	}()
	a.resolve()
}
