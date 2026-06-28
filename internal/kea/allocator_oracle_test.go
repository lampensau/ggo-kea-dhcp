package kea

import (
	"fmt"
	"net"
)

// oracleHeadroom is the historical per-class pool-size multiplier the legacy elastic
// allocator applied. It lives here (test-only) because the live sizing path
// (SizeForClass) no longer multiplies by headroom - this oracle is retained solely as
// the golden reference. Only MCX/D differed from the 2x default.
func oracleHeadroom(class string) int {
	if class == "GGO-MCX-D" {
		return 4
	}
	return 2
}

// oracleOthersHeadroom is the historical OTHERS catch-all multiplier (test-only).
const oracleOthersHeadroom = 2

// DynamicPoolRange returns the inclusive "first - last" range for a single
// dynamic pool over a subnet: from .10 up to the address below broadcast. It
// clamps so subnets too small for a .10 start still yield a valid, in-subnet,
// non-inverted range - a /29 or smaller otherwise produced a broken range
// (first offset past broadcast, with last < first). For /28 and larger the
// result is unchanged (".10 - .<broadcast-1>"). Shared by the non-greengo
// render path and the dashboard utilization view so they never disagree.
func DynamicPoolRange(ipnet *net.IPNet) string {
	maskSize, _ := ipnet.Mask.Size()
	total := 1 << (32 - maskSize)
	firstOff := 10
	lastOff := total - 2
	if firstOff >= lastOff {
		firstOff = max(total/2, 2)
	}
	lastOff = max(lastOff, firstOff)
	return fmt.Sprintf("%s - %s", IncIP(ipnet.IP, firstOff).String(), IncIP(ipnet.IP, lastOff).String())
}

// GenerateElasticPools takes a CIDR network block and calculates dynamic ranges for client classes
// based on target counts of each device group.
func GenerateElasticPools(cidr string, counts map[string]int) ([]PoolConfig, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR block: %w", err)
	}

	// Calculate subnet size
	maskSize, _ := ipnet.Mask.Size()
	if maskSize > 29 {
		return nil, fmt.Errorf("subnet too small (mask /%d)", maskSize)
	}

	baseIP := ipnet.IP.To4()
	if baseIP == nil {
		return nil, fmt.Errorf("only IPv4 subnets are supported")
	}

	// Calculate total IP count in subnet
	totalIPs := 1 << (32 - maskSize)

	// Helper to format ranges
	formatRange := func(startOffset, endOffset int) string {
		start := IncIP(baseIP, startOffset)
		end := IncIP(baseIP, endOffset)
		return fmt.Sprintf("%s - %s", start.String(), end.String())
	}

	// Dynamic pools start at .20 (gateway is .1, static infra reserved .2-.19);
	// the top address (broadcast) is left free.
	const firstDynamic = 20
	const minPool = 5          // every defined class gets at least this many addresses
	const catchAllMin = 10     // GGO-OTHERS / OTHERS floor
	lastUsable := totalIPs - 1 // exclusive upper bound for any pool's end+1

	offset := firstDynamic
	var pools []PoolConfig

	// addPool appends a guaranteed pool for className and advances offset. It
	// returns a surfaced error on overflow rather than silently dropping the
	// pool (which previously left a matching client-class with no leasable
	// addresses at all).
	addPool := func(className string, size int) error {
		if offset+size > lastUsable {
			return fmt.Errorf("subnet /%d too small: no room for %s pool (need %d more addresses)", maskSize, className, size)
		}
		pools = append(pools, PoolConfig{
			Range:       formatRange(offset, offset+size-1),
			ClientClass: className,
		})
		offset += size
		return nil
	}

	// sizeFor sizes a band's guaranteed pool as count × headroom, never below
	// floor. A headroom < 1 falls back to 2× (the historical default).
	sizeFor := func(headroom, count, floor int) int {
		if headroom < 1 {
			headroom = 2
		}
		return max(count*headroom, floor)
	}

	// Every mapped device band EXCEPT BPX (the elastic remainder) gets a
	// guaranteed pool, even when its forecast count is 0 - otherwise a device
	// of that type that shows up unforecast matches its client-class but has no
	// pool it is allowed to lease from. Each band's per-class Headroom controls
	// how generously its forecast count is padded.
	for _, dc := range DeviceClasses {
		if dc.Name == "GGO-BPX" {
			continue
		}
		if err := addPool(dc.Name, sizeFor(oracleHeadroom(dc.Name), counts[dc.CountKey], minPool)); err != nil {
			return nil, err
		}
	}

	// Catch-alls always get a pool too.
	if err := addPool(ClassNameGGOOthers, catchAllMin); err != nil {
		return nil, err
	}
	if err := addPool(ClassNameOthers, sizeFor(oracleOthersHeadroom, counts[CountKeyOthers], catchAllMin)); err != nil {
		return nil, err
	}

	// GGO-BPX is the elastic remainder: everything left up to (but excluding)
	// the broadcast address.
	bpxStart := offset
	bpxEnd := totalIPs - 2
	if bpxStart > bpxEnd {
		return nil, fmt.Errorf("subnet /%d too small to host the BPX remainder pool after sizing all device groups", maskSize)
	}
	pools = append(pools, PoolConfig{
		Range:       formatRange(bpxStart, bpxEnd),
		ClientClass: "GGO-BPX",
	})

	return pools, nil
}
