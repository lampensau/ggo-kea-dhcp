package netmon

import (
	"sync"
	"time"
)

// base is the fixed reference instant builder frames are stamped with and the
// detector/manager tests advance a fakeClock from. Defined here (not in a _test
// file) because the frame builders below - compiled into the normal package so
// web tests can reuse them - reference it.
var base = time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)

// FakeSniffer is the host-free Sniffer test double - the RecordingCommander
// analogue for the capture path. Inject frames with Push; the monitor drains them
// via Frames(). Close stops delivery and unblocks the monitor read (mirroring a
// real fd close). Each builder below gives every frame its own backing slice, so
// a retained-slice bug surfaces under the netmondebug poison lane rather than
// being masked by a shared buffer.
type FakeSniffer struct {
	ch     chan Frame
	once   sync.Once
	closed chan struct{}

	promiscMu          sync.Mutex
	promiscLog         []bool
	tpDrops, chanDrops uint32
}

// NewFakeSniffer returns a FakeSniffer with a generous buffer so test injection
// never blocks before the monitor starts draining.
func NewFakeSniffer() *FakeSniffer {
	return &FakeSniffer{ch: make(chan Frame, 256), closed: make(chan struct{})}
}

func (f *FakeSniffer) Frames() <-chan Frame { return f.ch }

func (f *FakeSniffer) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

// Push enqueues a frame for delivery. It drops (rather than blocks) once closed or
// the buffer is full, matching the real drop-on-full discipline.
func (f *FakeSniffer) Push(fr Frame) {
	select {
	case <-f.closed:
	case f.ch <- fr:
	default:
	}
}

// --- capControl test shim ---------------------------------------------------
//
// FakeSniffer implements capControl so monitor tests can drive the governor's
// dual overflow signals and assert the promiscuous single-owner behavior.
// socketFD returns -1 so the monitor skips real multicast joins.

func (f *FakeSniffer) setPromiscuous(on bool) error {
	f.promiscMu.Lock()
	f.promiscLog = append(f.promiscLog, on)
	f.promiscMu.Unlock()
	return nil
}

func (f *FakeSniffer) stats() (tpDrops, chanDrops uint32) {
	f.promiscMu.Lock()
	defer f.promiscMu.Unlock()
	return f.tpDrops, f.chanDrops
}

func (f *FakeSniffer) socketFD() int { return -1 }
func (f *FakeSniffer) ifIndex() int  { return 0 }

// SetStats injects the governor's per-tick overflow signals (sustained until
// changed - like a kernel that keeps dropping).
func (f *FakeSniffer) SetStats(tpDrops, chanDrops uint32) {
	f.promiscMu.Lock()
	f.tpDrops, f.chanDrops = tpDrops, chanDrops
	f.promiscMu.Unlock()
}

// PromiscLog returns the recorded promiscuous toggles in order.
func (f *FakeSniffer) PromiscLog() []bool {
	f.promiscMu.Lock()
	defer f.promiscMu.Unlock()
	return append([]bool(nil), f.promiscLog...)
}

// fakeClock is a controllable clock for detector and manager tests: time only
// advances when the test calls Advance, so absence-timeout and debounce edges are
// deterministic and observation-window-independent.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(start time.Time) *fakeClock { return &fakeClock{now: start} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// --- frame builders ---------------------------------------------------------
//
// Each builder returns a frame with its own backing slice (never a shared
// buffer), so the netmondebug poison lane and -race catch any detector that
// retains Frame.Data. They mirror the wire layout the hand-rolled parsers read;
// checksums are left zero (the parsers do not validate them).

// buildEth assembles an untagged ethernet frame.
func buildEth(dst, src [6]byte, etherType uint16, payload []byte) []byte {
	b := make([]byte, ethHdrLen+len(payload))
	copy(b[0:6], dst[:])
	copy(b[6:12], src[:])
	b[12] = byte(etherType >> 8)
	b[13] = byte(etherType)
	copy(b[ethHdrLen:], payload)
	return b
}

// buildEthVLAN assembles an ethernet frame carrying a single 802.1Q tag (VID).
func buildEthVLAN(dst, src [6]byte, vid int, etherType uint16, payload []byte) []byte {
	b := make([]byte, ethHdrLen+vlanTagLen+len(payload))
	copy(b[0:6], dst[:])
	copy(b[6:12], src[:])
	b[12] = byte(etherTypeVLAN >> 8)
	b[13] = byte(etherTypeVLAN & 0xff)
	b[14] = byte((vid >> 8) & 0x0f)
	b[15] = byte(vid)
	b[16] = byte(etherType >> 8)
	b[17] = byte(etherType)
	copy(b[ethHdrLen+vlanTagLen:], payload)
	return b
}

// buildIPv4 assembles a minimal 20-byte-header IPv4 packet (no options).
func buildIPv4(proto uint8, src, dst [4]byte, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	b[0] = 0x45 // version 4, IHL 5
	total := 20 + len(payload)
	b[2] = byte(total >> 8)
	b[3] = byte(total)
	b[8] = 64 // TTL
	b[9] = proto
	copy(b[12:16], src[:])
	copy(b[16:20], dst[:])
	copy(b[20:], payload)
	return b
}

// buildUDP assembles a UDP datagram (8-byte header + payload, checksum 0).
func buildUDP(sport, dport uint16, payload []byte) []byte {
	b := make([]byte, 8+len(payload))
	b[0] = byte(sport >> 8)
	b[1] = byte(sport)
	b[2] = byte(dport >> 8)
	b[3] = byte(dport)
	l := 8 + len(payload)
	b[4] = byte(l >> 8)
	b[5] = byte(l)
	copy(b[8:], payload)
	return b
}

// macFromOUI builds a MAC from a 3-byte OUI and a 3-byte suffix (test helper).
func macFromOUI(oui [3]byte, suffix [3]byte) [6]byte {
	return [6]byte{oui[0], oui[1], oui[2], suffix[0], suffix[1], suffix[2]}
}

var (
	macIGMPGeneral = [6]byte{0x01, 0x00, 0x5e, 0x00, 0x00, 0x01} // 224.0.0.1
	macBroadcast   = [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	macTestSwitch  = [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
)

// igmpQuery builds an IGMP General Query frame from src. version selects the
// on-wire shape the parser version-sniffs (1, 2, or 3).
func igmpQuery(src [4]byte, version int) Frame {
	var igmp []byte
	switch version {
	case 1:
		igmp = []byte{0x11, 0x00, 0, 0, 0, 0, 0, 0} // maxResp 0 → v1
	case 3:
		// v3 query: type, maxResp, csum(2), group(4), resv/S/QRV, QQIC, numSrc(2)
		igmp = []byte{0x11, 0x64, 0, 0, 0, 0, 0, 0, 0x02, 0x0a, 0, 0}
	default:
		igmp = []byte{0x11, 0x64, 0, 0, 0, 0, 0, 0} // v2
	}
	ip := buildIPv4(ipProtoIGMP, src, [4]byte{224, 0, 0, 1}, igmp)
	return Frame{Iface: "eth0", TS: base, Data: buildEth(macIGMPGeneral, macTestSwitch, etherTypeIPv4, ip)}
}

// buildDHCP assembles a BOOTP/DHCP payload (fixed 236-byte header + magic cookie
// + options 53 message-type and 54 server-id + end). chaddr seeds the client MAC.
func buildDHCP(op byte, chaddr [6]byte, serverID [4]byte, msgType byte) []byte {
	b := make([]byte, 240) // 236 BOOTP + 4 magic cookie
	b[0] = op              // 1 request, 2 reply
	b[1] = 1               // htype ethernet
	b[2] = 6               // hlen
	copy(b[28:34], chaddr[:])
	// magic cookie
	b[236], b[237], b[238], b[239] = 99, 130, 83, 99
	// option 53 (message type)
	b = append(b, 53, 1, msgType)
	// option 54 (server identifier)
	b = append(b, 54, 4, serverID[0], serverID[1], serverID[2], serverID[3])
	// end
	b = append(b, 255)
	return b
}

// sacnData builds an E1.31 (sACN) data packet for universe from source cid at
// the given priority. Only the fields the parser reads (CID, priority, universe)
// are populated; the rest is zero padding to a valid length.
func sacnData(universe uint16, cid [16]byte, priority uint8) Frame {
	return sacnDataEx(universe, cid, priority, "", 0)
}

// sacnDataEx builds an E1.31 data frame with an explicit source name and Options
// byte (for the duplicate-CID and stream-terminated paths).
func sacnDataEx(universe uint16, cid [16]byte, priority uint8, name string, options byte) Frame {
	p := make([]byte, 126)
	copy(p[22:38], cid[:])
	p[40], p[41], p[42], p[43] = 0x00, 0x00, 0x00, vectorE131Data // framing vector
	copy(p[44:108], name)
	p[108] = priority
	p[112] = options
	p[113] = byte(universe >> 8)
	p[114] = byte(universe)
	udp := buildUDP(sacnPort, sacnPort, p)
	dstIP := [4]byte{239, 255, byte(universe >> 8), byte(universe)}
	ip := buildIPv4(ipProtoUDP, [4]byte{10, 0, 0, 7}, dstIP, udp)
	dst := [6]byte{0x01, 0x00, 0x5e, 0x7f, byte(universe >> 8), byte(universe)}
	return Frame{Iface: "eth0", TS: base, Data: buildEth(dst, macTestSwitch, etherTypeIPv4, ip)}
}

// arpFrame builds an ARP frame announcing senderIP/senderMAC (op 1 who-has or
// op 2 reply - both carry the sender's claimed IP in spa, which is what the
// static-in-pool detector keys on).
func arpFrame(op uint16, senderMAC [6]byte, senderIP [4]byte) Frame {
	arp := make([]byte, 28)
	arp[0], arp[1] = 0x00, 0x01 // htype ethernet
	arp[2], arp[3] = 0x08, 0x00 // ptype IPv4
	arp[4], arp[5] = 6, 4       // hlen, plen
	arp[6], arp[7] = byte(op>>8), byte(op)
	copy(arp[8:14], senderMAC[:]) // sha
	copy(arp[14:18], senderIP[:]) // spa
	return Frame{Iface: "eth0", TS: base, Data: buildEth(macBroadcast, senderMAC, etherTypeARP, arp)}
}

// taggedFrame builds an 802.1Q-tagged IPv4 frame carrying VID (VLAN-reality).
func taggedFrame(vid int) Frame {
	udp := buildUDP(1024, 1025, []byte{0x00})
	ip := buildIPv4(ipProtoUDP, [4]byte{10, 0, 0, 9}, [4]byte{10, 0, 0, 10}, udp)
	return Frame{Iface: "eth0", TS: base, Data: buildEthVLAN(macTestSwitch, macTestSwitch, vid, etherTypeIPv4, ip)}
}

// cid16 builds a 16-byte CID from a single seed byte (distinct sources in tests).
func cid16(seed byte) [16]byte {
	var c [16]byte
	for i := range c {
		c[i] = seed
	}
	return c
}

// bpduFrame builds a spanning-tree BPDU to the STP group. tcn selects a TCN BPDU
// (type 0x80); otherwise a config BPDU with the topology-change flag set. Padded
// to the 60-byte minimum so the detector's flag-byte read is in range.
func bpduFrame(tcn bool) Frame {
	body := make([]byte, 46)                     // 14 eth + 46 = 60-byte min frame
	body[0], body[1], body[2] = 0x42, 0x42, 0x03 // LLC DSAP/SSAP/control
	// BPDU at offset 3: protocolID(2)=0, version(1)=0, type(1), flags(1).
	if tcn {
		body[6] = 0x80 // TCN BPDU
	} else {
		body[6] = 0x00 // config BPDU
		body[7] = 0x01 // topology-change flag
	}
	return Frame{Iface: "eth0", TS: base, Data: buildEth(macSTP, macTestSwitch, uint16(len(body)), body)}
}

// ptpAnnounce builds a PTP Announce message for domain advertising clockIdentity
// and priorities. viaUDP selects the UDP/320 transport (multicast) over L2 0x88F7.
func ptpAnnounce(domain uint8, clockIdentity uint64, priority1, priority2 uint8, viaUDP bool) Frame {
	ptp := make([]byte, 64)
	ptp[0] = 0x0b // messageType Announce
	ptp[1] = 0x02 // versionPTP 2
	ptp[2], ptp[3] = 0, 64
	ptp[4] = domain
	ptp[47] = priority1
	ptp[52] = priority2
	for i := 0; i < 8; i++ {
		ptp[53+i] = byte(clockIdentity >> (8 * (7 - i)))
	}
	if viaUDP {
		udp := buildUDP(320, 320, ptp)
		ip := buildIPv4(ipProtoUDP, [4]byte{10, 0, 0, 5}, [4]byte{224, 0, 1, 129}, udp)
		dst := [6]byte{0x01, 0x00, 0x5e, 0x00, 0x01, 0x81}
		return Frame{Iface: "eth0", TS: base, Data: buildEth(dst, macTestSwitch, etherTypeIPv4, ip)}
	}
	dst := [6]byte{0x01, 0x1b, 0x19, 0x00, 0x00, 0x00}
	return Frame{Iface: "eth0", TS: base, Data: buildEth(dst, macTestSwitch, etherTypePTP, ptp)}
}

// appendLLDPTLV appends one LLDP TLV (type<<9 | len header + payload).
func appendLLDPTLV(b []byte, typ int, payload []byte) []byte {
	hdr := uint16(typ<<9) | uint16(len(payload)&0x01ff)
	b = append(b, byte(hdr>>8), byte(hdr&0xff))
	return append(b, payload...)
}

// lldpFrame builds an LLDP frame advertising sysName / portID / native VLAN.
func lldpFrame(sysName, portID string, nativeVLAN int) Frame {
	var tlv []byte
	tlv = appendLLDPTLV(tlv, 1, append([]byte{0x04}, 0, 0, 0, 0, 0, 1))  // chassis id (MAC subtype)
	tlv = appendLLDPTLV(tlv, 2, append([]byte{0x05}, []byte(portID)...)) // port id (ifname subtype)
	tlv = appendLLDPTLV(tlv, 3, []byte{0x00, 0x78})                      // TTL 120
	tlv = appendLLDPTLV(tlv, 5, []byte(sysName))                         // system name
	if nativeVLAN > 0 {
		// 802.1 org-specific, OUI 00:80:c2, subtype 1 (port VLAN id) + VID.
		org := []byte{0x00, 0x80, 0xc2, 0x01, byte(nativeVLAN >> 8), byte(nativeVLAN)}
		tlv = appendLLDPTLV(tlv, 127, org)
	}
	tlv = appendLLDPTLV(tlv, 0, nil) // end
	dst := [6]byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}
	return Frame{Iface: "eth0", TS: base, Data: buildEth(dst, macTestSwitch, etherTypeLLDP, tlv)}
}

// dhcpFrame builds a server→client DHCP frame (UDP sport 67 dport 68) from
// serverID with the given DHCP message type (2 OFFER, 5 ACK, 4 DECLINE…).
func dhcpFrame(sport uint16, serverID [4]byte, msgType byte) Frame {
	chaddr := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	dhcp := buildDHCP(2, chaddr, serverID, msgType)
	udp := buildUDP(sport, 68, dhcp)
	ip := buildIPv4(ipProtoUDP, serverID, [4]byte{255, 255, 255, 255}, udp)
	return Frame{Iface: "eth0", TS: base, Data: buildEth(macBroadcast, macTestSwitch, etherTypeIPv4, ip)}
}

// declineFrame builds a client→server DHCPDECLINE (UDP sport 68 dport 67) whose
// option 50 carries the conflicted address.
func declineFrame(declinedIP [4]byte) Frame {
	chaddr := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	b := make([]byte, 240)
	b[0], b[1], b[2] = 1, 1, 6
	copy(b[28:34], chaddr[:])
	b[236], b[237], b[238], b[239] = 99, 130, 83, 99
	b = append(b, 53, 1, 4) // DHCPDECLINE
	b = append(b, 50, 4, declinedIP[0], declinedIP[1], declinedIP[2], declinedIP[3])
	b = append(b, 255)
	udp := buildUDP(68, 67, b)
	ip := buildIPv4(ipProtoUDP, [4]byte{0, 0, 0, 0}, [4]byte{255, 255, 255, 255}, udp)
	return Frame{Iface: "eth0", TS: base, Data: buildEth(macBroadcast, macFromOUI([3]byte{0x02, 0, 0}, [3]byte{0, 0, 2}), etherTypeIPv4, ip)}
}
