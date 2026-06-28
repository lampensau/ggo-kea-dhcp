package arpscan

import (
	"net"
	"sync"
	"time"
)

const (
	etherTypeARP  = 0x0806
	etherTypeVLAN = 0x8100
	etherTypeIPv4 = 0x0800
	arpOpRequest  = 1
)

// buildARPRequest assembles a 42-byte broadcast ARP who-has frame: Ethernet header
// (dst broadcast, src = our MAC, ethertype ARP) + the 28-byte ARP request asking which
// MAC holds targetIP, with our MAC/IP as the sender so the target unicasts its reply
// straight back to us.
func buildARPRequest(srcMAC [6]byte, srcIP, targetIP [4]byte) []byte {
	f := make([]byte, 42)
	// Ethernet header.
	for i := 0; i < 6; i++ {
		f[i] = 0xff // dst: broadcast
	}
	copy(f[6:12], srcMAC[:])
	f[12], f[13] = etherTypeARP>>8, etherTypeARP&0xff
	// ARP payload.
	f[14], f[15] = 0x00, 0x01 // htype: Ethernet
	f[16], f[17] = etherTypeIPv4>>8, etherTypeIPv4&0xff
	f[18] = 6 // hlen
	f[19] = 4 // plen
	f[20], f[21] = 0x00, arpOpRequest
	copy(f[22:28], srcMAC[:]) // sender hardware address
	copy(f[28:32], srcIP[:])  // sender protocol address
	// target hardware address left zero (unknown - that's what we're asking)
	copy(f[38:42], targetIP[:]) // target protocol address
	return f
}

// parseARPSender extracts the sender hardware + protocol addresses (SHA + SPA) from
// an ARP frame - the MAC and IPv4 the framing device claims. Used for BOTH replies
// (the device answering our probe) and any other ARP it emits, since either proves
// the IP is live. Handles an optional 802.1Q tag (a frame whose VLAN was not stripped
// by RX offload). Returns ok=false for anything not a well-formed IPv4-over-Ethernet ARP.
func parseARPSender(f []byte) (ip [4]byte, mac [6]byte, ok bool) {
	if len(f) < 14 {
		return ip, mac, false
	}
	off := 12
	et := uint16(f[off])<<8 | uint16(f[off+1])
	if et == etherTypeVLAN {
		if len(f) < 18 {
			return ip, mac, false
		}
		off += 4
		et = uint16(f[off])<<8 | uint16(f[off+1])
	}
	if et != etherTypeARP {
		return ip, mac, false
	}
	arp := f[off+2:]
	if len(arp) < 28 {
		return ip, mac, false
	}
	// IPv4-over-Ethernet ARP: htype 1, ptype 0x0800, hlen 6, plen 4.
	if arp[0] != 0x00 || arp[1] != 0x01 || arp[2] != etherTypeIPv4>>8 || arp[3] != etherTypeIPv4&0xff || arp[4] != 6 || arp[5] != 4 {
		return ip, mac, false
	}
	copy(mac[:], arp[8:14]) // sender hardware address
	copy(ip[:], arp[14:18]) // sender protocol address
	return ip, mac, true
}

// reachTracker records the last time each IPv4 was seen via ARP, and reports the set
// seen within reachWindow (pruning aged entries). Mirrors netmon's hostTracker, keyed
// by IP rather than MAC. Safe for concurrent record (recv goroutines) + within (renders).
type reachTracker struct {
	mu   sync.Mutex
	seen map[[4]byte]time.Time
}

func newReachTracker() *reachTracker { return &reachTracker{seen: make(map[[4]byte]time.Time)} }

func (t *reachTracker) record(ip [4]byte, now time.Time) {
	t.mu.Lock()
	t.seen[ip] = now
	t.mu.Unlock()
}

// within returns the IPs (dotted-decimal) seen within reachWindow of now, pruning the
// rest so the map stays bounded by the number of currently-reachable hosts.
func (t *reachTracker) within(now time.Time) map[string]bool {
	cutoff := now.Add(-reachWindow)
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]bool, len(t.seen))
	for ip, ts := range t.seen {
		if ts.Before(cutoff) {
			delete(t.seen, ip)
			continue
		}
		out[net.IP(ip[:]).String()] = true
	}
	return out
}
