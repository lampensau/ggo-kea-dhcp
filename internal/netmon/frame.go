package netmon

import (
	"strings"
	"time"
)

// Frame is one captured layer-2 frame handed to detectors. Data aliases a
// reusable read buffer owned by the sniffer/monitor: a detector must copy out the
// small fields it needs (an IP, a MAC, a VID) and MUST NOT retain the slice past
// the Consume call - the next read overwrites it. The //go:build netmondebug lane
// scribbles the buffer after every Consume to make a retained-slice bug fail
// loudly (see poison_debug.go).
type Frame struct {
	Iface string
	TS    time.Time
	Data  []byte
	// VLAN is the 802.1Q VID the NIC stripped via RX-VLAN offload, recovered from
	// the frame's PACKET_AUXDATA control message (0 when the frame was untagged or
	// the tag is still in-band in Data). VLANKnown is true whenever AUXDATA tag
	// info was available for the frame - even an untagged one - so the VLAN-reality
	// detector knows tag visibility actually works and can treat "no unexpected
	// VID" as a real all-clear instead of blindness. nopSniffer / FakeSniffer leave
	// both zero (the detector then falls back to the in-band tag in Data).
	VLAN      int
	VLANKnown bool
}

// Ethernet / common protocol constants used by the hand-rolled parsers. We parse
// from byte offsets (the same low-level style as the DNS parser in network/dns.go)
// rather than pulling in gopacket/layers - no per-packet allocation or reflection
// on the Pi.
const (
	etherTypeIPv4 = 0x0800
	etherTypeARP  = 0x0806
	etherTypeVLAN = 0x8100
	etherTypeQinQ = 0x88a8 // 802.1ad S-tag (outer tag of a double-tagged frame)
	etherTypeLLDP = 0x88cc
	etherTypePTP  = 0x88f7

	ipProtoICMP = 1
	ipProtoIGMP = 2
	ipProtoUDP  = 17

	ethHdrLen  = 14
	vlanTagLen = 4
)

// macAt copies the 6-byte MAC at b[off:] out into a value (never retains b).
func macAt(b []byte, off int) (mac [6]byte, ok bool) {
	if off+6 > len(b) {
		return mac, false
	}
	copy(mac[:], b[off:off+6])
	return mac, true
}

// dstMAC / srcMAC return the destination / source MAC of an ethernet frame.
func dstMAC(b []byte) ([6]byte, bool) { return macAt(b, 0) }
func srcMAC(b []byte) ([6]byte, bool) { return macAt(b, 6) }

// etherInfo decodes the (optionally single-802.1Q-tagged) ethernet header and
// returns the effective ethertype, the offset at which the L3 payload begins, and
// the VLAN id (0 when untagged). Only a single VLAN tag is handled - that is all the
// appliance's trunk model produces. A double-tagged (QinQ) frame is REJECTED
// (ok=false): its inner ethertype is again 0x8100/0x88a8, and acting on the outer
// S-VID would make the VLAN detector latch a provider tag as a phantom "no-scope"
// VLAN it could never clear.
func etherInfo(b []byte) (etherType uint16, payloadOff int, vlanID int, ok bool) {
	if len(b) < ethHdrLen {
		return 0, 0, 0, false
	}
	et := be16(b, 12)
	off := ethHdrLen
	if et == etherTypeVLAN {
		if len(b) < ethHdrLen+vlanTagLen {
			return 0, 0, 0, false
		}
		vlanID = int(be16(b, 14) & 0x0fff)
		et = be16(b, 16)
		off = ethHdrLen + vlanTagLen
		if et == etherTypeVLAN || et == etherTypeQinQ {
			return 0, 0, 0, false // double-tagged (QinQ) - don't act on the outer tag
		}
	}
	return et, off, vlanID, true
}

// effectiveVID is the frame's real VLAN id from whichever path carried it: the in-band
// 802.1Q tag (inbandVID, from etherInfo) when RX-VLAN offload is OFF (the tag stays in
// the bytes), else the AUXDATA-recovered Frame.VLAN when offload stripped it. 0 means
// genuinely untagged. Detectors that scope to a served VLAN must use THIS, not
// Frame.VLAN alone (which is 0 on a NIC with rx-vlan-offload off).
func effectiveVID(inbandVID int, f Frame) int {
	if inbandVID != 0 {
		return inbandVID
	}
	return f.VLAN
}

// ipv4Info decodes the IPv4 header starting at off, returning the protocol, the
// source/destination addresses (copied out), and the offset of the L4 payload.
// Handles a variable IHL; rejects truncated frames.
func ipv4Info(b []byte, off int) (proto uint8, src, dst [4]byte, l4Off int, ok bool) {
	if off+20 > len(b) {
		return 0, src, dst, 0, false
	}
	ihl := int(b[off]&0x0f) * 4
	if ihl < 20 || off+ihl > len(b) {
		return 0, src, dst, 0, false
	}
	proto = b[off+9]
	copy(src[:], b[off+12:off+16])
	copy(dst[:], b[off+16:off+20])
	return proto, src, dst, off + ihl, true
}

// udpPorts returns the source/destination UDP ports and the offset of the UDP
// payload starting at the L4 offset off.
func udpPorts(b []byte, off int) (sport, dport uint16, payloadOff int, ok bool) {
	if off+8 > len(b) {
		return 0, 0, 0, false
	}
	return be16(b, off), be16(b, off+2), off + 8, true
}

// be16 / be32 read big-endian integers at b[off:], bounds-checked by the callers
// above (each guards its own slice length first).
func be16(b []byte, off int) uint16 {
	return uint16(b[off])<<8 | uint16(b[off+1])
}

func be32(b []byte, off int) uint32 {
	return uint32(b[off])<<24 | uint32(b[off+1])<<16 | uint32(b[off+2])<<8 | uint32(b[off+3])
}

func be64(b []byte, off int) uint64 {
	return uint64(be32(b, off))<<32 | uint64(be32(b, off+4))
}

// hex64 formats a clock identity as 16 lowercase hex digits (no separators).
func hex64(v uint64) string {
	const hex = "0123456789abcdef"
	var buf [16]byte
	for i := 15; i >= 0; i-- {
		buf[i] = hex[v&0x0f]
		v >>= 4
	}
	return string(buf[:])
}

// ipString formats a 4-byte IPv4 address without allocating an net.IP.
func ipString(ip [4]byte) string {
	return itoa(int(ip[0])) + "." + itoa(int(ip[1])) + "." + itoa(int(ip[2])) + "." + itoa(int(ip[3]))
}

// macString formats a 6-byte MAC as colon-separated lowercase hex.
func macString(mac [6]byte) string {
	const hex = "0123456789abcdef"
	buf := make([]byte, 0, 17)
	for i, x := range mac {
		if i > 0 {
			buf = append(buf, ':')
		}
		buf = append(buf, hex[x>>4], hex[x&0x0f])
	}
	return string(buf)
}

// ip4ToU32 packs a 4-byte IPv4 address into a big-endian uint32 for range tests.
func ip4ToU32(ip [4]byte) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// parseU32 parses a dotted-quad IPv4 string into a big-endian uint32. Called off
// the hot path (pool-range parse, slow-tick lease set), so a small alloc is fine.
func parseU32(s string) (uint32, bool) {
	s = strings.TrimSpace(s)
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return 0, false
	}
	var ip [4]byte
	for i, p := range parts {
		n := 0
		if len(p) == 0 || len(p) > 3 {
			return 0, false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return 0, false
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return 0, false
		}
		ip[i] = byte(n)
	}
	return ip4ToU32(ip), true
}

// itoa is a tiny non-negative int formatter (avoids strconv import churn in the
// hot accessors; negative inputs never occur for octets/ports).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
