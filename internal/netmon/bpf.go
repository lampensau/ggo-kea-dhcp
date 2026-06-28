package netmon

import "golang.org/x/net/bpf"

// The combined classic-BPF filter is the efficiency lever: it runs in-kernel and
// drops the audio flood (Dante/AES67/NDI/sACN-data) before it ever wakes
// userspace, so the read loop sees only the ~handful of interesting frame classes.
// One OR-program accepts:
//
//	(1) any 802.1Q-tagged frame  - handed to userspace so the VLAN-reality detector
//	    can read tags (low-rate cross-VLAN leakage; the audio flood on a VLAN
//	    sub-interface arrives untagged, so this does not let the flood through)
//	(2) LLDP (0x88cc) · (3) PTP-L2 (0x88f7) · (4) ARP (0x0806)
//	(5) CDP dst MAC 01:00:0c:cc:cc:cc · (6) BPDU dst MAC 01:80:c2:00:00:00
//	(7) IPv4 + IGMP (proto 2)
//	(8) IPv4 + UDP port 67 (DHCP, either direction) and PTP-UDP 319/320
//	(9) [multicast-sniff only] UDP sACN 5568
//
// Storm volume is read from sysfs counter deltas, not this filter (a storm must
// not turn into a per-packet userspace cost).
const (
	bpfAccept = 0x40000 // accept up to 256 KiB - i.e. the whole frame
	bpfReject = 0
)

// bpfAsm is a tiny label-resolving assembler so the OR-filter can be written as
// readable blocks instead of hand-counted relative skips (a miscounted skip
// silently drops frames a detector needs). Jumps name a target label; skips are
// computed by resolve() once all labels are known.
type bpfAsm struct {
	ins    []bpf.Instruction
	labels map[string]int
	jumps  []bpfJump
}

type bpfJump struct {
	idx     int
	onTrue  string // label to jump to when the condition holds ("" = fall through)
	onFalse string // label to jump to when it does not ("" = fall through)
}

func newBPFAsm() *bpfAsm { return &bpfAsm{labels: make(map[string]int)} }

func (a *bpfAsm) emit(i bpf.Instruction) { a.ins = append(a.ins, i) }

func (a *bpfAsm) label(name string) { a.labels[name] = len(a.ins) }

// jump emits a conditional jump whose skip distances resolve() patches in.
func (a *bpfAsm) jump(cond bpf.JumpTest, val uint32, onTrue, onFalse string) {
	a.jumps = append(a.jumps, bpfJump{idx: len(a.ins), onTrue: onTrue, onFalse: onFalse})
	a.emit(bpf.JumpIf{Cond: cond, Val: val})
}

// resolve patches every recorded jump's SkipTrue/SkipFalse from its label. All
// targets are forward (labels defined after the jump), so skips are non-negative.
func (a *bpfAsm) resolve() {
	for _, j := range a.jumps {
		ji := a.ins[j.idx].(bpf.JumpIf)
		if j.onTrue != "" {
			ji.SkipTrue = uint8(a.labels[j.onTrue] - j.idx - 1)
		}
		if j.onFalse != "" {
			ji.SkipFalse = uint8(a.labels[j.onFalse] - j.idx - 1)
		}
		a.ins[j.idx] = ji
	}
}

// buildAsm constructs the combined filter program (unresolved jumps). greengo adds
// the Green-GO 'h'-announce clause (UDP 5810 + "G5"/0x68 payload) - attached only on
// a Green-GO-preset interface so other deployments never capture 5810.
func buildAsm(multicastSniff, greengo bool) *bpfAsm {
	a := newBPFAsm()

	// --- L2 ethertype classes (offset 12, untagged) ---
	a.emit(bpf.LoadAbsolute{Off: 12, Size: 2})
	a.jump(bpf.JumpEqual, etherTypeVLAN, "accept", "") // tagged → userspace (VLAN detector)
	a.jump(bpf.JumpEqual, etherTypeLLDP, "accept", "")
	a.jump(bpf.JumpEqual, etherTypePTP, "accept", "")
	a.jump(bpf.JumpEqual, etherTypeARP, "accept", "")

	// --- CDP: dst MAC 01:00:0c:cc:cc:cc (word@0 + half@4) ---
	a.emit(bpf.LoadAbsolute{Off: 0, Size: 4})
	a.jump(bpf.JumpEqual, 0x01000ccc, "", "after_cdp")
	a.emit(bpf.LoadAbsolute{Off: 4, Size: 2})
	a.jump(bpf.JumpEqual, 0xcccc, "accept", "")
	a.label("after_cdp")

	// --- BPDU: dst MAC 01:80:c2:00:00:00 ---
	a.emit(bpf.LoadAbsolute{Off: 0, Size: 4})
	a.jump(bpf.JumpEqual, 0x0180c200, "", "after_bpdu")
	a.emit(bpf.LoadAbsolute{Off: 4, Size: 2})
	a.jump(bpf.JumpEqual, 0x0000, "accept", "")
	a.label("after_bpdu")

	// --- IPv4 classes ---
	a.emit(bpf.LoadAbsolute{Off: 12, Size: 2})
	a.jump(bpf.JumpEqual, etherTypeIPv4, "ipv4", "reject")
	a.label("ipv4")
	a.emit(bpf.LoadAbsolute{Off: 23, Size: 1}) // IP protocol (14+9)
	a.jump(bpf.JumpEqual, ipProtoIGMP, "accept", "")
	a.jump(bpf.JumpEqual, ipProtoUDP, "udp", "reject") // not UDP & not IGMP → reject
	a.label("udp")
	a.emit(bpf.LoadAbsolute{Off: 20, Size: 2})    // IP flags/frag offset (14+6)
	a.jump(bpf.JumpBitsSet, 0x1fff, "reject", "") // non-first fragment → can't read ports
	a.emit(bpf.LoadMemShift{Off: 14})             // X = IP header length
	a.emit(bpf.LoadIndirect{Off: 16, Size: 2})    // UDP dport (X+14+2)
	a.jump(bpf.JumpEqual, 67, "accept", "")
	a.jump(bpf.JumpEqual, 320, "accept", "")
	a.jump(bpf.JumpEqual, 319, "accept", "")
	if multicastSniff {
		a.jump(bpf.JumpEqual, sacnPort, "accept", "")
	}
	if greengo {
		a.jump(bpf.JumpEqual, ggoBusPort, "g5h", "") // 5810 dport → verify it's an 'h' announce
	}
	a.emit(bpf.LoadIndirect{Off: 14, Size: 2}) // UDP sport (X+14)
	a.jump(bpf.JumpEqual, 67, "accept", "")
	if multicastSniff {
		a.jump(bpf.JumpEqual, sacnPort, "accept", "")
	}
	if greengo {
		a.jump(bpf.JumpEqual, ggoBusPort, "g5h", "reject") // 5810 sport → 'h' check; else reject

		// --- Green-GO 'h' (0x68) announce on UDP 5810 ---
		// Accept ONLY frames whose G5 payload starts with the "G5" magic (0x4735) and
		// subtype 0x68, so the 0x60/0x06 multicast flood (incl. audio) is dropped in
		// kernel even under promiscuous capture. X is still the IP header length
		// (LoadMemShift above); the UDP payload begins at X+22.
		a.label("g5h")
		a.emit(bpf.LoadIndirect{Off: 22, Size: 2}) // payload[0:2] == "G5"
		a.jump(bpf.JumpEqual, 0x4735, "", "reject")
		a.emit(bpf.LoadIndirect{Off: 24, Size: 1}) // payload[2] == subtype 'h'
		a.jump(bpf.JumpEqual, 0x68, "accept", "reject")
	}
	// fall through to reject

	a.label("reject")
	a.emit(bpf.RetConstant{Val: bpfReject})
	a.label("accept")
	a.emit(bpf.RetConstant{Val: bpfAccept})
	return a
}

// buildBPFInstructions returns the resolved combined filter as bpf.Instructions
// (the form the in-process VM tests run).
func buildBPFInstructions(multicastSniff, greengo bool) []bpf.Instruction {
	a := buildAsm(multicastSniff, greengo)
	a.resolve()
	return a.ins
}

// rejectAllFilter drops every frame. It is attached before bind (see
// openCapture) to close the window where an unbound ETH_P_ALL socket could
// capture frames from other interfaces. It's a constant one-instruction program,
// so assembly cannot fail.
var rejectAllFilter = func() []bpf.RawInstruction {
	raw, err := bpf.Assemble([]bpf.Instruction{bpf.RetConstant{Val: bpfReject}})
	if err != nil {
		panic("netmon: reject-all BPF failed to assemble: " + err.Error())
	}
	return raw
}()

// buildFilter assembles the combined filter to raw instructions for
// SO_ATTACH_FILTER. An assemble error is a programming bug (bad skip); the caller
// falls back to no kernel filter - correctness is preserved (detectors still
// ignore uninteresting frames), only CPU suffers.
func buildFilter(multicastSniff, greengo bool) ([]bpf.RawInstruction, error) {
	return bpf.Assemble(buildBPFInstructions(multicastSniff, greengo))
}
