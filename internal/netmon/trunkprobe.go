package netmon

import (
	"log"
	"sort"
	"sync"

	"golang.org/x/net/bpf"
)

// trunkSnapLen truncates each captured frame to a few header bytes: the trunk probe only
// needs the per-frame VLAN tag, which rides in the PACKET_AUXDATA control message (not the
// frame payload), so copying the body would be pure waste under a busy link.
const trunkSnapLen = 64

// acceptAllFilter accepts every frame (truncated to trunkSnapLen). A trunk can carry any
// traffic, and the VLAN tag is delivered out-of-band via AUXDATA regardless of payload, so
// we don't filter by content - we just need to receive frames to read their tags. One
// constant instruction, so assembly cannot fail.
var acceptAllFilter = func() []bpf.RawInstruction {
	raw, err := bpf.Assemble([]bpf.Instruction{bpf.RetConstant{Val: trunkSnapLen}})
	if err != nil {
		panic("netmon: accept-all BPF failed to assemble: " + err.Error())
	}
	return raw
}()

// TrunkProbe passively detects whether a link carries 802.1Q-tagged VLAN traffic, so the
// onboarding wizard can tell the operator the switch port is a trunk (the full passive
// monitor runs only in ACTIVE). It opens a capture on the interface and latches every VLAN
// id it sees on a tagged frame - the tag recovered via PACKET_AUXDATA because the NIC's
// RX-VLAN offload strips it from the frame bytes. Best-effort: without CAP_NET_RAW it stays
// inert and the badge falls back to the config-derived link state.
//
// Detection is necessarily passive: a configured-but-idle tagged VLAN can't be seen. In
// practice any VLAN with devices floods broadcast/multicast (ARP, etc.) to every trunk port,
// so an in-use VLAN appears within seconds. The seen set latches for the probe's lifetime
// (it restarts on each onboarding reconcile); moving the cable to an access port mid-probe
// would leave a stale "trunk" until the next restart - acceptable for a setup-time hint.
// ponytail: one recvmsg per frame (no mmap ring); fine at setup-time traffic. If an
// onboarding-time multicast flood ever shows up, narrow acceptAllFilter to control frames.
type TrunkProbe struct {
	mu      sync.Mutex
	vids    map[int]bool
	sniffer Sniffer
	wg      sync.WaitGroup
}

// NewTrunkProbe returns an inert probe; call Start to begin capturing.
func NewTrunkProbe() *TrunkProbe { return &TrunkProbe{vids: map[int]bool{}} }

// Start (re)starts the probe on iface. Safe to call repeatedly - it stops any prior capture
// first and resets the seen set. A capture that can't open (no CAP_NET_RAW / dev sandbox)
// leaves the probe inert rather than erroring.
func (p *TrunkProbe) Start(iface string) {
	p.Stop()
	sn, err := openCapture(iface, false, acceptAllFilter)
	if err != nil {
		log.Printf("[TrunkProbe] capture on %s unavailable: %v", iface, err)
		return
	}
	p.mu.Lock()
	p.vids = map[int]bool{}
	p.sniffer = sn
	p.mu.Unlock()
	p.wg.Add(1)
	go p.loop(sn)
}

func (p *TrunkProbe) loop(sn Sniffer) {
	defer p.wg.Done()
	for f := range sn.Frames() {
		// The 802.1Q tag is INLINE in the frame bytes when RX-VLAN offload is off
		// (etherInfo parses it), or STRIPPED into PACKET_AUXDATA when offload is on
		// (f.VLAN). Handle both - mirroring netmon's vlanDetector. Reading only the
		// AUXDATA copy (the original bug) misses every tag on a NIC with offload off,
		// which is the common case (this NIC has it fixed-off).
		_, _, vid, ok := etherInfo(f.Data)
		if !ok {
			continue
		}
		if f.VLANKnown && f.VLAN != 0 {
			vid = f.VLAN
		}
		if vid > 0 {
			p.mu.Lock()
			p.vids[vid] = true
			p.mu.Unlock()
		}
	}
}

// Stop tears down the capture. Idempotent.
func (p *TrunkProbe) Stop() {
	p.mu.Lock()
	sn := p.sniffer
	p.sniffer = nil
	p.mu.Unlock()
	if sn != nil {
		_ = sn.Close() // closes Frames() -> loop returns
	}
	p.wg.Wait()
}

// VLANs returns the sorted tagged VLAN ids seen on the link since Start - empty when none
// were seen, the link is untagged, or the probe is inert.
func (p *TrunkProbe) VLANs() []int {
	p.mu.Lock()
	defer p.mu.Unlock()
	vids := make([]int, 0, len(p.vids))
	for v := range p.vids {
		vids = append(vids, v)
	}
	sort.Ints(vids)
	return vids
}
