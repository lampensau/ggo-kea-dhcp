package netmon

import (
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/net/bpf"
)

// rogueOfferInstructions builds the probe's kernel filter: accept only IPv4 UDP
// frames with source port 67 - a DHCP server (or relay) answering - whole frame,
// untagged or behind a single in-band 802.1Q tag (when RX-VLAN offload strips
// the tag, the kernel runs BPF on the stripped bytes and the untagged clauses
// match). Everything else is dropped in-kernel, so the probe wakes userspace
// only for server-side DHCP traffic.
func rogueOfferInstructions() []bpf.Instruction {
	a := newBPFAsm()

	a.emit(bpf.LoadAbsolute{Off: 12, Size: 2})
	a.jump(bpf.JumpEqual, etherTypeVLAN, "tagged", "")
	a.jump(bpf.JumpEqual, etherTypeIPv4, "", "reject")
	a.emit(bpf.LoadAbsolute{Off: 23, Size: 1}) // IP protocol (14+9)
	a.jump(bpf.JumpEqual, ipProtoUDP, "", "reject")
	a.emit(bpf.LoadAbsolute{Off: 20, Size: 2})    // IP flags/frag offset (14+6)
	a.jump(bpf.JumpBitsSet, 0x1fff, "reject", "") // non-first fragment: can't read ports
	a.emit(bpf.LoadMemShift{Off: 14})             // X = IP header length
	a.emit(bpf.LoadIndirect{Off: 14, Size: 2})    // UDP sport (14+X)
	a.jump(bpf.JumpEqual, 67, "accept", "reject")

	// The same clauses shifted 4 bytes for a single-tagged frame.
	a.label("tagged")
	a.emit(bpf.LoadAbsolute{Off: 16, Size: 2})
	a.jump(bpf.JumpEqual, etherTypeIPv4, "", "reject")
	a.emit(bpf.LoadAbsolute{Off: 27, Size: 1})
	a.jump(bpf.JumpEqual, ipProtoUDP, "", "reject")
	a.emit(bpf.LoadAbsolute{Off: 24, Size: 2})
	a.jump(bpf.JumpBitsSet, 0x1fff, "reject", "")
	a.emit(bpf.LoadMemShift{Off: 18})
	a.emit(bpf.LoadIndirect{Off: 18, Size: 2})
	a.jump(bpf.JumpEqual, 67, "accept", "reject")

	a.label("reject")
	a.emit(bpf.RetConstant{Val: bpfReject})
	a.label("accept")
	a.emit(bpf.RetConstant{Val: bpfAccept})
	a.resolve()
	return a.ins
}

var rogueOfferFilter = func() []bpf.RawInstruction {
	raw, err := bpf.Assemble(rogueOfferInstructions())
	if err != nil {
		panic("netmon: rogue-offer BPF failed to assemble: " + err.Error())
	}
	return raw
}()

// RogueProbe passively watches an interface during ONBOARDING for a DHCP server
// already answering on the segment the appliance is about to serve (the common
// case: the venue's managed switch still runs its own DHCP). It feeds captured
// frames to the same rogueDHCPDetector the ACTIVE monitor uses. The box already
// serves its own onboarding pool on eth0, so its own OFFERs are on the wire;
// Start reads eth0's own MAC and hands it to the detector so those OFFERs are
// suppressed (by source MAC, not the forgeable option-54 server-id) and the badge
// never flags the appliance itself. Purely passive: it sends nothing.
//
// It reliably sees a rogue's BROADCAST OFFERs and answers directed at the box.
// It does NOT reliably see a rogue that only unicasts OFFER/ACK to other clients:
// on a switched segment the switch forwards those out the victim's port, not
// ours. The capture opens promiscuous (a brief, bounded onboarding window with no
// live show to protect), which relaxes our NIC's own receive filter but not the
// switch's forwarding - so it does not conjure that unicast visibility; it only
// helps on a hub or a mirror/SPAN port. Best-effort like TrunkProbe: without
// CAP_NET_RAW it stays inert and the wizard's shield badge falls back to
// carrier-only.
type RogueProbe struct {
	mu       sync.Mutex
	det      *rogueDHCPDetector
	sniffer  Sniffer
	macKnown bool
	quit     chan struct{}
	wg       sync.WaitGroup
}

// NewRogueProbe returns an inert probe; call Start to begin capturing.
func NewRogueProbe() *RogueProbe { return &RogueProbe{} }

// Start (re)starts the probe on iface. Safe to call repeatedly - it stops any
// prior capture first and resets the detector. It reads iface's own MAC and hands
// it to the detector so the box's onboarding OFFERs are suppressed by source MAC.
// A capture that can't open (no CAP_NET_RAW / dev sandbox) leaves the probe inert
// rather than erroring.
func (p *RogueProbe) Start(iface string) {
	p.Stop()
	selfMAC, macKnown := interfaceHWAddr(iface)
	sn, err := openCapture(iface, true, rogueOfferFilter)
	if err != nil {
		log.Printf("[RogueProbe] capture on %s unavailable: %v", iface, err)
		return
	}
	p.begin(iface, sn, selfMAC, macKnown)
}

// interfaceHWAddr reads iface's 6-byte hardware address (macKnown=false when the
// interface is absent or has no 48-bit MAC, e.g. the dev sandbox). A VLAN
// sub-interface inherits its parent's MAC, so this works for eth0.<vid> too.
func interfaceHWAddr(iface string) (mac [6]byte, macKnown bool) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil || len(ifi.HardwareAddr) != 6 {
		return mac, false
	}
	copy(mac[:], ifi.HardwareAddr)
	return mac, true
}

// begin wires a fresh detector to sn and starts the read loop (the test seam:
// tests inject a FakeSniffer here).
func (p *RogueProbe) begin(iface string, sn Sniffer, selfMAC [6]byte, macKnown bool) {
	quit := make(chan struct{})
	p.mu.Lock()
	p.det = newRogueDHCPDetector(iface, selfMAC, macKnown, 0, 0) // onboarding serves the untagged eth0 pool: servedVID 0
	p.sniffer = sn
	p.macKnown = macKnown
	p.quit = quit
	p.mu.Unlock()
	p.wg.Add(1)
	go p.loop(sn, quit)
}

// loop drains frames until the sniffer's channel closes OR quit fires - the
// select (rather than a bare range, as in TrunkProbe) because FakeSniffer's
// Close does not close its Frames channel.
func (p *RogueProbe) loop(sn Sniffer, quit chan struct{}) {
	defer p.wg.Done()
	for {
		select {
		case f, ok := <-sn.Frames():
			if !ok {
				// The capture's frame channel closed. If quit did NOT fire, this is a
				// fatal death of the read loop (the socket went away mid-run), not an
				// orderly Stop - mark the probe blind so Watching() drops to false and the
				// shield reads "Unverified" instead of a confident, but false, all-clear.
				select {
				case <-quit:
				default:
					p.markDead(sn)
				}
				return
			}
			// Wall clock, not f.TS: the detector's presence windows are
			// compared against Server()'s clock, and injected test frames
			// carry a fixed past timestamp.
			now := time.Now()
			p.mu.Lock()
			if p.det != nil {
				p.det.Consume(f, now)
			}
			p.mu.Unlock()
		case <-quit:
			return
		}
	}
}

// markDead is called by the read loop when its capture dies fatally (the frame
// channel closed without a Stop). It clears the sniffer + detector so Watching()
// returns false and Server() reports no confirmed all-clear. Guarded by sn ==
// current so a concurrent restart (begin already installed a fresh sniffer) is
// not clobbered.
func (p *RogueProbe) markDead(sn Sniffer) {
	p.mu.Lock()
	if p.sniffer == sn {
		p.sniffer = nil
		p.det = nil
	}
	p.mu.Unlock()
}

// Stop tears down the capture and clears the detector. Idempotent.
func (p *RogueProbe) Stop() {
	p.mu.Lock()
	sn := p.sniffer
	quit := p.quit
	p.sniffer = nil
	p.quit = nil
	p.mu.Unlock()
	if quit != nil {
		close(quit)
	}
	if sn != nil {
		_ = sn.Close()
	}
	p.wg.Wait()
	p.mu.Lock()
	p.det = nil
	p.mu.Unlock()
}

// Watching reports whether the probe is actually producing a trustworthy answer: a
// real AF_PACKET socket is open, its read loop is live, AND the box's own MAC is
// known so it can self-suppress. It is false when the probe is stopped (not running
// - e.g. the ACTIVE edit page), when the capture fell back to a nop sniffer (no
// CAP_NET_RAW / dev sandbox), when the read loop died fatally mid-run (markDead
// cleared the sniffer), OR when the self-MAC could not be read (the detector then
// suppresses emission, so a quiet Server() would be a false all-clear, not a
// verified one). In every case Server() answers "none" not because the link is
// clear but because nothing trustworthy is being observed. Callers use this to
// render an honest "unverified" shield rather than a confident all-clear.
func (p *RogueProbe) Watching() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sniffer != nil && !isNop(p.sniffer) && p.macKnown
}

// Server reports the foreign DHCP server currently seen answering on the link
// (the lowest IP when several are), or ok=false when none is present or the
// probe is inert. A server unseen for the detector's absence window clears.
func (p *RogueProbe) Server() (ip, mac string, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.det == nil {
		return "", "", false
	}
	p.det.Tick(time.Now()) // confirm new sightings, expire absent servers
	s := p.det.Snapshot()
	if s.Severity != SevError {
		return "", "", false
	}
	return s.Fields["server"], s.Fields["mac"], true
}
