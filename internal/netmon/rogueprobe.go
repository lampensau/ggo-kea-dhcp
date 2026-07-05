package netmon

import (
	"log"
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
// serves its own onboarding pool on eth0, so its own OFFERs are on the wire and
// promiscuously captured; Start is given the box's own IPs as selfIPs so the
// detector suppresses them and the badge never flags the appliance itself.
// Purely passive: it sends nothing. The capture opens promiscuous so a server's
// unicast OFFER/ACK to
// another client (renewals - the usual traffic on an established segment) is
// visible, not just broadcast answers; nothing else owns the promiscuous bit
// outside ACTIVE, and closing the socket drops the membership. Best-effort like
// TrunkProbe: without CAP_NET_RAW it stays inert and the wizard's shield badge
// falls back to carrier-only.
type RogueProbe struct {
	mu      sync.Mutex
	det     *rogueDHCPDetector
	sniffer Sniffer
	quit    chan struct{}
	wg      sync.WaitGroup
}

// NewRogueProbe returns an inert probe; call Start to begin capturing.
func NewRogueProbe() *RogueProbe { return &RogueProbe{} }

// Start (re)starts the probe on iface. Safe to call repeatedly - it stops any
// prior capture first and resets the detector. selfIPs are the box's own
// addresses on iface, suppressed so the box's onboarding OFFERs are not flagged.
// A capture that can't open (no CAP_NET_RAW / dev sandbox) leaves the probe inert
// rather than erroring.
func (p *RogueProbe) Start(iface string, selfIPs [][4]byte) {
	p.Stop()
	sn, err := openCapture(iface, true, rogueOfferFilter)
	if err != nil {
		log.Printf("[RogueProbe] capture on %s unavailable: %v", iface, err)
		return
	}
	p.begin(iface, sn, selfIPs)
}

// begin wires a fresh detector to sn and starts the read loop (the test seam:
// tests inject a FakeSniffer here).
func (p *RogueProbe) begin(iface string, sn Sniffer, selfIPs [][4]byte) {
	quit := make(chan struct{})
	p.mu.Lock()
	p.det = newRogueDHCPDetector(iface, selfIPs, 0)
	p.sniffer = sn
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

// Watching reports whether the probe is actually capturing frames: a real
// AF_PACKET socket is open and its read loop is live. It is false when the probe
// is stopped (not running - e.g. the ACTIVE edit page) OR when the capture fell
// back to a nop sniffer (no CAP_NET_RAW / dev sandbox), in which case Server()
// will always answer "none" not because the link is clear but because nothing is
// being observed. Callers use this to render an honest "unverified" shield rather
// than a confident all-clear when the probe is blind.
func (p *RogueProbe) Watching() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sniffer != nil && !isNop(p.sniffer)
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
