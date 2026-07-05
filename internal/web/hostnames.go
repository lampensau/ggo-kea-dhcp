package web

import (
	"sort"
	"strconv"
	"strings"

	"ggo-kea-dhcp/internal/web/views"
)

// hostnameTagLen is how many trailing MAC hex characters tag a colliding slug.
const hostnameTagLen = 4

// HostnameSlugs is the sanitize-and-dedupe funnel for device names. Input maps
// normalized MAC (normalizeMAC form) to raw name (client-announced hostname or
// Green-GO scan name); output maps each MAC to its DNS-safe label.
//
// Contract for callers (notably the local-DNS zone builder):
//   - A name that slugifies to nothing yields "" - callers MUST skip empty labels.
//   - Every returned label is unique within one call: a bare slugifyHostname slug
//     when a name is unshared, otherwise tagged "-<mac hex>" (the full MAC when
//     even short tags collide, and never colliding with another device's bare
//     slug). Bare and tagged labels alike are distinct across the whole result.
//   - Labels are computed per call over the given input set only: the output is
//     permutation-invariant (identical input map, identical output, regardless of
//     Go's map order), so repeated builds stay byte-identical (the SSE change-only
//     broadcast hashes fragments). But a single device's label can CHANGE between
//     calls when its collision partners change - reserving a second "BPX 19666"
//     turns the first device's "bpx-19666" into "bpx-19666-0001". Consumers that
//     persist labels across calls must tolerate that instability.
func HostnameSlugs(names map[string]string) map[string]string {
	// Assign over sorted MACs so the result is permutation-invariant and the
	// bare-vs-tagged escalation below is deterministic.
	macs := make([]string, 0, len(names))
	for mac := range names {
		macs = append(macs, mac)
	}
	sort.Strings(macs)

	slug := make(map[string]string, len(names))
	owners := make(map[string]int, len(names)) // bare slug -> distinct devices
	for _, mac := range macs {
		s := slugifyHostname(names[mac])
		slug[mac] = s
		if s != "" {
			owners[s]++
		}
	}
	// Count short tags among colliding devices: two devices that share a slug AND
	// the trailing MAC hex collide on the short tag, so both escalate to the full
	// MAC (unique per device).
	tag4 := make(map[string]int, len(names))
	for _, mac := range macs {
		if s := slug[mac]; s != "" && owners[s] > 1 {
			tag4[tagSlug(s, mac, hostnameTagLen)]++
		}
	}

	out := make(map[string]string, len(names))
	used := make(map[string]bool, len(names))
	// Reserve every bare slug first. A single-owner slug is the device's own name
	// and is never rewritten, so a generated tag must yield to it (a device whose
	// bare slug is "foo-0001" outranks another device's "foo" tagged "-0001").
	for _, mac := range macs {
		if s := slug[mac]; s != "" && owners[s] == 1 {
			out[mac] = s
			used[s] = true
		}
	}
	// Assign the colliding devices, escalating the tag until it is unused.
	for _, mac := range macs {
		s := slug[mac]
		if s == "" || owners[s] == 1 {
			continue // empty name (label ""), or an already-reserved bare slug
		}
		label := tagSlug(s, mac, hostnameTagLen)
		if tag4[label] > 1 || used[label] {
			label = tagSlug(s, mac, len(normalizeMAC(mac))) // full MAC
		}
		for n := 2; used[label]; n++ {
			// Pathological only: a bare device is literally named "<slug>-<fullMAC>".
			// Number the tag so the label set stays guaranteed-unique.
			label = numberedTagSlug(s, mac, n)
		}
		out[mac] = label
		used[label] = true
	}
	return out
}

// numberedTagSlug is the last-resort disambiguator: the full-MAC tag with a
// "-<n>" appended, trimmed to the 63-char DNS label limit.
func numberedTagSlug(s, mac string, n int) string {
	suffix := "-" + strconv.Itoa(n)
	base := tagSlug(s, mac, len(normalizeMAC(mac)))
	if room := 63 - len(suffix); len(base) > room {
		base = strings.TrimRight(base[:room], "-")
	}
	return base + suffix
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

// sanitizeHostnames is the shared display funnel behind sanitizeLeaseHostnames
// and sanitizePortHostnames. get returns row i's (MAC, hostname); setLabel writes
// back the deduped display label; and setRaw preserves the pre-funnel name for the
// dialog prefill. Every displayed hostname becomes a valid DNS label, and two
// different devices sharing a name become distinguishable. Rows sharing a MAC (a
// trunked device with one lease per VLAN) keep one common label; a row without a
// live MAC (the pinned-but-offline placeholder) has no identity to tag with and is
// slugified only.
func sanitizeHostnames(n int, get func(i int) (mac, hostname string), setRaw, setLabel func(i int, v string)) {
	names := make(map[string]string, n)
	for i := range n {
		mac, hostname := get(i)
		if m := liveMAC(mac); m != "" && hostname != "" {
			if _, ok := names[m]; !ok {
				names[m] = hostname
			}
		}
	}
	slugs := HostnameSlugs(names)
	for i := range n {
		mac, hostname := get(i)
		// Keep the raw pre-funnel name for the reserve/pin dialog prefill so the
		// ephemeral "-0001" dedupe tag is never stored permanently.
		setRaw(i, hostname)
		switch m := liveMAC(mac); {
		case hostname == "":
		case m != "":
			setLabel(i, slugs[m])
		default:
			setLabel(i, slugifyHostname(hostname))
		}
	}
}

// sanitizeLeaseHostnames runs the display funnel over the leases page's rows.
func sanitizeLeaseHostnames(rows []views.LeaseRow) {
	sanitizeHostnames(len(rows),
		func(i int) (string, string) { return rows[i].HWAddress, rows[i].Hostname },
		func(i int, v string) { rows[i].RawHostname = v },
		func(i int, v string) { rows[i].Hostname = v })
}

// sanitizePortHostnames runs the display funnel over the pinning page's port rows.
func sanitizePortHostnames(rows []views.PortRow) {
	sanitizeHostnames(len(rows),
		func(i int) (string, string) { return rows[i].HWAddress, rows[i].Hostname },
		func(i int, v string) { rows[i].RawHostname = v },
		func(i int, v string) { rows[i].Hostname = v })
}
