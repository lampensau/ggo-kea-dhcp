package web

import (
	"strings"

	"ggo-kea-dhcp/internal/web/views"
)

// hostnameTagLen is how many trailing MAC hex characters tag a colliding slug.
const hostnameTagLen = 4

// HostnameSlugs is the sanitize-and-dedupe funnel for device names. Input maps
// normalized MAC (normalizeMAC form) to raw name (client-announced hostname or
// Green-GO scan name); output maps each MAC to its DNS-safe label: the
// slugifyHostname slug, tagged with a trailing "-<mac hex>" when two different
// devices slugify to the same label (the full MAC when even the short tags
// collide). The output depends only on the input set - never on map order or
// call history - so repeated builds stay byte-identical (the SSE change-only
// broadcast hashes fragments) and the local-DNS zone build can key on the labels.
func HostnameSlugs(names map[string]string) map[string]string {
	slug := make(map[string]string, len(names))
	owners := make(map[string]int, len(names)) // slug -> distinct devices
	for mac, name := range names {
		s := slugifyHostname(name)
		slug[mac] = s
		if s != "" {
			owners[s]++
		}
	}
	out := make(map[string]string, len(names))
	tagged := make(map[string]int, len(names)) // short-tagged label -> devices
	for mac, s := range slug {
		if s != "" && owners[s] > 1 {
			s = tagSlug(s, mac, hostnameTagLen)
			tagged[s]++
		}
		out[mac] = s
	}
	for mac, s := range slug {
		// Colliding devices whose MACs share the same tail collide again on the
		// short tag; the full MAC is unique per device, so it settles those.
		if s != "" && owners[s] > 1 && tagged[tagSlug(s, mac, hostnameTagLen)] > 1 {
			out[mac] = tagSlug(s, mac, len(normalizeMAC(mac)))
		}
	}
	return out
}

// tagSlug appends the last n characters of the normalized MAC to a slug,
// trimming the base first so the result stays within the 63-char label limit.
func tagSlug(s, mac string, n int) string {
	m := normalizeMAC(mac)
	if n < len(m) {
		m = m[len(m)-n:]
	}
	if room := 63 - 1 - len(m); len(s) > room {
		s = strings.TrimRight(s[:room], "-")
	}
	return s + "-" + m
}

// sanitizeLeaseHostnames funnels a finished lease-row set through HostnameSlugs:
// every displayed hostname becomes a valid DNS label, and two different devices
// sharing a name become distinguishable. Rows sharing a MAC (a trunked device
// with one lease per VLAN) keep one common label; a row without a live MAC (the
// pinned-but-offline placeholder) has no identity to tag with and is slugified
// only.
func sanitizeLeaseHostnames(rows []views.LeaseRow) {
	names := make(map[string]string, len(rows))
	for i := range rows {
		if mac := liveMAC(rows[i].HWAddress); mac != "" && rows[i].Hostname != "" {
			if _, ok := names[mac]; !ok {
				names[mac] = rows[i].Hostname
			}
		}
	}
	slugs := HostnameSlugs(names)
	for i := range rows {
		switch mac := liveMAC(rows[i].HWAddress); {
		case rows[i].Hostname == "":
		case mac != "":
			rows[i].Hostname = slugs[mac]
		default:
			rows[i].Hostname = slugifyHostname(rows[i].Hostname)
		}
	}
}

// sanitizePortHostnames is sanitizeLeaseHostnames for the pinning page's port rows.
func sanitizePortHostnames(rows []views.PortRow) {
	names := make(map[string]string, len(rows))
	for i := range rows {
		if mac := liveMAC(rows[i].HWAddress); mac != "" && rows[i].Hostname != "" {
			if _, ok := names[mac]; !ok {
				names[mac] = rows[i].Hostname
			}
		}
	}
	slugs := HostnameSlugs(names)
	for i := range rows {
		switch mac := liveMAC(rows[i].HWAddress); {
		case rows[i].Hostname == "":
		case mac != "":
			rows[i].Hostname = slugs[mac]
		default:
			rows[i].Hostname = slugifyHostname(rows[i].Hostname)
		}
	}
}
