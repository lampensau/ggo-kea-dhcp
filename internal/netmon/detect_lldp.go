package netmon

import "time"

// macCDP is the CDP destination multicast (Cisco). LLDP uses ethertype 0x88cc;
// CDP is an 802.3 frame addressed to this group, so we recognize it by dst MAC.
var macCDP = [6]byte{0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc}

// lldpDetector identifies the switch/port the appliance is plugged into by walking
// LLDP TLVs (and best-effort CDP). It is purely informational - knowing the uplink
// port and native VLAN is operator orientation, not an alarm. Passive.
//
// The neighbor LATCHES: the switch/port you are cabled to is a stable fact of the
// wiring, not of the advertisement cadence. Once seen, it stays reported (SevOK, the
// "you are here" chip shown) and is cleared ONLY when the interface link actually
// drops - never on frame silence. The earlier model aged the neighbor out after a
// fixed 90s window, so a switch advertising slower than that (LLDP is commonly
// 60-120s, CDP 60s) or a couple of frames shed under load made the chip flap while
// the cable never moved. A new advertisement simply overwrites the latched fields,
// so re-cabling to a different port self-corrects without a flap.
type lldpDetector struct {
	iface  string
	linkUp linkStateFunc // nil => treated as always up (dev sandbox / tests)

	present     bool // a neighbor is currently latched (link still up)
	announced   bool // the one-time "seen" event for the current latch has fired
	everPresent bool // a neighbor was seen at least once this monitor life
	sysName     string
	portID      string
	nativeVLAN  int
	via         string // "LLDP" | "CDP"
}

func newLLDPDetector(iface string, linkUp linkStateFunc) *lldpDetector {
	return &lldpDetector{iface: iface, linkUp: linkUp}
}

// linkIsUp reports the interface carrier; fail-open (nil reader or read error =>
// up) so the neighbor is never cleared on uncertainty, only on a confirmed drop.
func (d *lldpDetector) linkIsUp() bool {
	if d.linkUp == nil {
		return true
	}
	return d.linkUp()
}

func (d *lldpDetector) Consume(f Frame, _ time.Time) {
	et, off, _, ok := etherInfo(f.Data)
	if !ok {
		return
	}
	switch et {
	case etherTypeLLDP:
		d.parseLLDP(f.Data[off:])
		d.via = "LLDP"
	default:
		// CDP is an 802.3 frame (length in the ethertype slot) to the CDP group.
		if dm, ok := dstMAC(f.Data); ok && dm == macCDP {
			d.parseCDP(f.Data)
			d.via = "CDP"
		} else {
			return
		}
	}
	d.present = true // latch: stays reported until the link drops
	d.everPresent = true
}

// parseLLDP walks the LLDP TLV stream: each TLV is a 2-byte header
// (type<<9 | length) followed by length bytes. We extract Port ID (type 2),
// System Name (type 5), and the 802.1 org-specific native VLAN (type 127, OUI
// 00:80:c2, subtype 1).
//
// Each field is only updated when the frame actually carries it (non-empty) - we
// NEVER blank a known-good value. A switch interleaves frames that don't all carry
// every TLV (e.g. an LLDP frame without a System Name, or a CDP frame alongside the
// LLDP one), and overwriting with the empty value made the "you are here" label flap
// between the rich info and "unknown switch". So the fields latch to the best known
// value until the link drops (which clears everything in Tick).
func (d *lldpDetector) parseLLDP(b []byte) {
	i := 0
	for i+2 <= len(b) {
		hdr := be16(b, i)
		typ := int(hdr >> 9)
		length := int(hdr & 0x01ff)
		i += 2
		if typ == 0 || i+length > len(b) { // End TLV or truncated
			break
		}
		v := b[i : i+length]
		switch typ {
		case 2: // Port ID: subtype byte + id
			if length > 1 {
				if p := printableID(v[1:]); p != "" {
					d.portID = p
				}
			}
		case 5: // System Name
			if s := string(v); s != "" {
				d.sysName = s
			}
		case 127: // org-specific
			if length >= 4 && v[0] == 0x00 && v[1] == 0x80 && v[2] == 0xc2 {
				subtype := v[3]
				if subtype == 1 && length >= 6 { // Port VLAN ID (native)
					if vid := int(be16(v, 4)); vid > 0 {
						d.nativeVLAN = vid
					}
				}
			}
		}
		i += length
	}
}

// parseCDP is best-effort: it skips the 802.2 LLC/SNAP + CDP header and pulls
// Device-ID (0x0001) and Port-ID (0x0003). CDP TLVs are 2-byte type + 2-byte
// length (length covers the whole TLV including the 4-byte header).
func (d *lldpDetector) parseCDP(frame []byte) {
	// dst(6)+src(6)+len(2)=14, LLC AA AA 03 (3), SNAP OUI 00 00 0c + type 20 00 (5),
	// then CDP header version+ttl+checksum (4) → TLVs start at 14+3+5+4 = 26.
	const cdpTLVStart = 26
	b := frame
	i := cdpTLVStart
	for i+4 <= len(b) {
		typ := be16(b, i)
		length := int(be16(b, i+2))
		if length < 4 || i+length > len(b) {
			break
		}
		v := b[i+4 : i+length]
		switch typ {
		case 0x0001: // Device-ID
			if s := printableID(v); s != "" {
				d.sysName = s
			}
		case 0x0003: // Port-ID
			if p := printableID(v); p != "" {
				d.portID = p
			}
		}
		i += length
	}
}

// printableID copies a byte slice to a string, rendering it as MAC-style hex when
// it is not printable text (so a binary chassis/port id is still readable).
func printableID(v []byte) string {
	printable := len(v) > 0
	for _, c := range v {
		if c < 0x20 || c > 0x7e {
			printable = false
			break
		}
	}
	if printable {
		return string(v)
	}
	const hex = "0123456789abcdef"
	buf := make([]byte, 0, len(v)*3)
	for i, c := range v {
		if i > 0 {
			buf = append(buf, ':')
		}
		buf = append(buf, hex[c>>4], hex[c&0x0f])
	}
	return string(buf)
}

func (d *lldpDetector) Tick(_ time.Time) []Event {
	switch {
	case d.present && !d.linkIsUp():
		// The cable was pulled - the only real invalidation of a "you are here".
		// Clear and re-arm so a reconnect re-announces (possibly a new port).
		d.present = false
		d.announced = false
		return []Event{{
			Action:   "Switch neighbor lost",
			Target:   d.iface,
			Before:   d.neighborLabel(),
			After:    "link down",
			Severity: SevInfo,
		}}
	case d.present && !d.announced:
		d.announced = true
		return []Event{{
			Action:   "Switch neighbor seen",
			Target:   d.iface,
			Before:   "none",
			After:    d.neighborLabel(),
			Severity: SevInfo,
		}}
	}
	return nil
}

func (d *lldpDetector) neighborLabel() string {
	if d.sysName == "" {
		return "unknown switch"
	}
	if d.portID != "" {
		return d.sysName + " / " + d.portID
	}
	return d.sysName
}

func (d *lldpDetector) Snapshot() DetectorSnapshot {
	s := DetectorSnapshot{Kind: "lldp", Subject: d.iface}
	switch {
	case d.present:
		s.Severity = SevOK
		s.Subject = d.neighborLabel()
		s.Text = "Uplink: " + d.neighborLabel()
		s.Fields = map[string]string{"switch": d.sysName, "port": d.portID, "via": d.via}
		if d.nativeVLAN > 0 {
			s.Fields["native_vlan"] = itoa(d.nativeVLAN)
		}
	case d.everPresent:
		s.Severity = SevInfo
		s.Text = "Switch neighbor lost (link down)"
	default:
		s.Severity = SevInfo
		s.Text = "No LLDP/CDP neighbor seen"
	}
	return s
}
