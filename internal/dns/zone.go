package dns

import (
	"net"
	"sort"
	"strings"
)

// The two public subdomains the appliance is authoritative for. Every device
// name is published under BOTH (aliases of each other); the canonical identity -
// the apex A record and every PTR target - lives under SuffixDHCP.
const (
	SuffixInv  = "inv.greengo.digital"
	SuffixDHCP = "dhcp.greengo.digital"
)

// answerTTL keeps address changes propagating quickly (leases move mid-show).
const answerTTL = 30

// maxZoneNames hard-caps the zone so a hostile or misbehaving LAN cannot grow
// the map without bound. Far above any real fleet (hundreds of devices).
const maxZoneNames = 1024

// Zone is one immutable build of the device maps. The server swaps whole zones
// atomically (SetZone) and answers from whichever build is current, so query
// handling never locks against a rebuild.
type Zone struct {
	a   map[string][4]byte // fqdn -> address, both suffixes populated
	ptr map[[4]byte]string // address -> canonical <name>.dhcp.greengo.digital
}

// NewZone builds a zone from short device labels (already DNS-safe and unique -
// the caller funnels every name through its sanitizer) mapped to IPv4 addresses.
// Each label is published under both suffixes; the PTR map holds exactly one
// canonical reverse name per address. Deterministic: names are processed in
// sorted order, so the same input always yields the same zone (including which
// name wins a shared address and which survive the size cap).
func NewZone(hosts map[string]string) *Zone {
	names := make([]string, 0, len(hosts))
	for n := range hosts {
		if n != "" {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	if len(names) > maxZoneNames {
		names = names[:maxZoneNames]
	}
	z := &Zone{a: make(map[string][4]byte, 2*len(names)), ptr: make(map[[4]byte]string, len(names))}
	for _, n := range names {
		ip4 := net.ParseIP(hosts[n]).To4()
		if ip4 == nil {
			continue
		}
		var ip [4]byte
		copy(ip[:], ip4)
		z.a[n+"."+SuffixInv] = ip
		z.a[n+"."+SuffixDHCP] = ip
		if _, taken := z.ptr[ip]; !taken {
			z.ptr[ip] = n + "." + SuffixDHCP
		}
	}
	return z
}

// inZone reports whether name falls under either authoritative suffix (the
// apexes themselves included).
func inZone(name string) bool {
	return name == SuffixInv || name == SuffixDHCP ||
		strings.HasSuffix(name, "."+SuffixInv) || strings.HasSuffix(name, "."+SuffixDHCP)
}
