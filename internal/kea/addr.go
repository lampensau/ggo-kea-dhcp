package kea

import (
	"encoding/binary"
	"net"
	"strings"
)

// addr.go holds the shared IPv4 address-geometry helpers used by the pool
// allocator (layout.go): subnet bounds, range parsing/formatting, and the
// interval/gap packing primitives.

// subnetUsableBounds returns the first and last assignable host addresses of an
// IPv4 subnet (network+1 .. broadcast-1) as uint32, ok=false for non-IPv4 or a
// subnet too small to host any address.
func subnetUsableBounds(ipnet *net.IPNet) (lo, hi uint32, ok bool) {
	ip := ipnet.IP.To4()
	if ip == nil {
		return 0, 0, false
	}
	mask := net.IP(ipnet.Mask).To4()
	if mask == nil {
		return 0, 0, false
	}
	network := binary.BigEndian.Uint32(ip) & binary.BigEndian.Uint32(mask)
	broadcast := network | ^binary.BigEndian.Uint32(mask)
	if broadcast < network+2 {
		return 0, 0, false
	}
	return network + 1, broadcast - 1, true
}

// ParsePoolRange parses a "start - end" range into inclusive uint32 bounds.
func ParsePoolRange(r string) (lo, hi uint32, ok bool) {
	startStr, endStr, found := strings.Cut(r, " - ")
	if !found {
		// Tolerate "start-end" without surrounding spaces.
		startStr, endStr, found = strings.Cut(r, "-")
		if !found {
			return 0, 0, false
		}
	}
	start := net.ParseIP(strings.TrimSpace(startStr)).To4()
	end := net.ParseIP(strings.TrimSpace(endStr)).To4()
	if start == nil || end == nil {
		return 0, 0, false
	}
	return binary.BigEndian.Uint32(start), binary.BigEndian.Uint32(end), true
}

// IPToUint32 converts a net.IP (IPv4) to uint32.
func IPToUint32(ip net.IP) uint32 {
	if ip4 := ip.To4(); ip4 != nil {
		return binary.BigEndian.Uint32(ip4)
	}
	return 0
}

// Uint32ToIP converts a uint32 to net.IP.
func Uint32ToIP(n uint32) net.IP {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return net.IP(b)
}

func u32ToIP(n uint32) net.IP {
	return Uint32ToIP(n)
}

// poolIvl is an inclusive [lo,hi] address interval used while packing pools.
type poolIvl struct{ lo, hi uint32 }

// freeGaps returns the free [lo,hi] windows in [from,to] not covered by any
// reserved interval (reserved must be sorted ascending by lo).
func freeGaps(from, to uint32, reserved []poolIvl) []poolIvl {
	var gaps []poolIvl
	cur := from
	for _, iv := range reserved {
		if iv.lo > cur {
			gaps = append(gaps, poolIvl{cur, iv.lo - 1})
		}
		if iv.hi+1 > cur {
			cur = iv.hi + 1
		}
	}
	if cur <= to {
		gaps = append(gaps, poolIvl{cur, to})
	}
	return gaps
}

// firstFitGap returns the index of the lowest-address gap that fits `need`
// addresses (gaps are ordered by start), or -1 if none does. First-fit keeps the
// packing in pool order so an unpinned layout matches the elastic generator.
func firstFitGap(gaps []poolIvl, need int) int {
	for i, g := range gaps {
		if int(g.hi-g.lo)+1 >= need {
			return i
		}
	}
	return -1
}

// largestGapIdx returns the index of the widest gap, or -1 if there are none.
func largestGapIdx(gaps []poolIvl) int {
	best, bestSize := -1, -1
	for i, g := range gaps {
		if sz := int(g.hi-g.lo) + 1; sz > bestSize {
			best, bestSize = i, sz
		}
	}
	return best
}

// shrinkGap removes the [gaps[i].lo, usedHi] span just claimed from gap i,
// dropping the gap entirely when fully consumed.
func shrinkGap(gaps []poolIvl, i int, usedHi uint32) []poolIvl {
	if usedHi < gaps[i].hi {
		gaps[i] = poolIvl{usedHi + 1, gaps[i].hi}
		return gaps
	}
	return append(gaps[:i], gaps[i+1:]...)
}
