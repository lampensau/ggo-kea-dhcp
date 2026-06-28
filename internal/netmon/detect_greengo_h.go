package netmon

import (
	"bytes"
	"sort"
	"strings"
	"time"
)

// ggoBusPort is the Green-GO G5 multicast/broadcast bus UDP port. The 'h' leader
// announce is sent to the subnet-directed broadcast on this port (the BPF accepts
// only the 'h' subtype here; the 0x60/0x06 flood is dropped in kernel).
const ggoBusPort = 5810

// greengoConfigAbsence drops a config from the active set after this long without an
// 'h' announce (cadence ~5s, so ~6 missed announces).
const greengoConfigAbsence = 30 * time.Second

// ror32 rotates a 32-bit value right by n bits.
func ror32(x uint32, n uint) uint32 { return (x >> n) | (x << (32 - n)) }

// leu32 / putLEu32 read/write little-endian uint32 (the G5 cipher words and the
// per-packet seed/checksum are little-endian, unlike the big-endian be32 accessors).
func leu32(b []byte, off int) uint32 {
	return uint32(b[off]) | uint32(b[off+1])<<8 | uint32(b[off+2])<<16 | uint32(b[off+3])<<24
}

func putLEu32(b []byte, off int, v uint32) {
	b[off] = byte(v)
	b[off+1] = byte(v >> 8)
	b[off+2] = byte(v >> 16)
	b[off+3] = byte(v >> 24)
}

// g5DecryptPayload decrypts an encrypted G5 payload (h/i/k/l/n/o frames) given the
// per-packet seed and checksum, both carried in the clear at frame+6/+10: 16-byte
// blocks of four LE u32 words, XOR with ror(K,{6,19,1,7}), a running accumulator,
// and K evolving as ror(K,15)+acc. Returns the decrypted bytes (a fresh slice,
// never aliasing the frame buffer) and whether the checksum validated. A partial
// trailing block is ignored.
func g5DecryptPayload(payload []byte, seed, checksum uint32) ([]byte, bool) {
	nblocks := len(payload) / 16
	out := make([]byte, nblocks*16)
	copy(out, payload[:nblocks*16])
	k := seed
	var acc uint32
	for i := range nblocks {
		o := i * 16
		p0 := ror32(k, 6) ^ leu32(out, o)
		p1 := ror32(k, 19) ^ leu32(out, o+4)
		p2 := ror32(k, 1) ^ leu32(out, o+8)
		p3 := ror32(k, 7) ^ leu32(out, o+12)
		putLEu32(out, o, p0)
		putLEu32(out, o+4, p1)
		putLEu32(out, o+8, p2)
		putLEu32(out, o+12, p3)
		acc += p0 + p1 + p2 + p3
		k = ror32(k, 15) + acc
	}
	return out, checksum+acc == 0
}

// tlvRec is one decoded nibble-TLV record: an accumulated type and its value bytes.
type tlvRec struct {
	typ   int
	value []byte
}

// parseNibbleTLV decodes the Green-GO nibble-delta TLV stream used by the h/k/l/n
// announces. Header byte = low-nibble type-delta
// + high-nibble length; a nibble > 0x0b means read (nibble-0x0b) more big-endian
// bytes; 0x00 ends the stream; 0x10 resets the type accumulator. Values are copied
// out (the input may alias the reusable frame buffer). Returns ok=false on a
// malformed stream.
func parseNibbleTLV(buf []byte) ([]tlvRec, bool) {
	var recs []tlvRec
	pos, acc := 0, 0
	for pos < len(buf) {
		b := int(buf[pos])
		pos++
		if b&0x0f == 0 {
			if b == 0x00 {
				return recs, true // END
			}
			if b>>4 != 1 {
				return recs, false // invalid header
			}
			acc = 0 // 0x10: reset type accumulator
			if pos >= len(buf) {
				return recs, true
			}
			b = int(buf[pos])
			pos++
		}
		tdelta := b & 0x0f
		length := b >> 4
		if tdelta > 0x0b {
			k := tdelta - 0x0b
			tdelta = 0
			for ; k > 0; k-- {
				if pos >= len(buf) {
					return recs, false
				}
				tdelta = tdelta<<8 | int(buf[pos])
				pos++
			}
		}
		if length > 0x0b {
			k := length - 0x0b
			length = 0
			for ; k > 0; k-- {
				if pos >= len(buf) {
					return recs, false
				}
				length = length<<8 | int(buf[pos])
				pos++
			}
		}
		if pos+length > len(buf) {
			return recs, false
		}
		acc += tdelta
		val := make([]byte, length)
		copy(val, buf[pos:pos+length])
		pos += length
		recs = append(recs, tlvRec{typ: acc, value: val})
	}
	return recs, true
}

// ggoConfig is one Green-GO config heard on the bus via 'h' announces.
type ggoConfig struct {
	id       string // configId, 16 hex chars
	name     string // human config name
	group    string // multicast group, dotted
	lastSeen time.Time
}

func (c *ggoConfig) displayName() string {
	if c.name != "" {
		return c.name
	}
	return c.id
}

// greengoHDetector decodes the Green-GO 'h' (0x68) leader announce - the only
// Green-GO frame whose useful payload (configId / multicast group / config name) is
// encrypted, and the only source of config identity (the 6464 scan reply carries no
// configId). The G5 cipher key is on the wire, so decode is offline. It tracks the
// set of distinct configIds currently announcing and warns when two or more are
// live on one segment (two separate Green-GO systems sharing a LAN - a real
// footgun). The BPF delivers only validated 'h' frames.
type greengoHDetector struct {
	iface        string
	servedVID    int // this monitor's served VLAN (0 = untagged eth0); foreign-VID 'h' is ignored
	absence      time.Duration
	configs      map[string]*ggoConfig
	flaggedMulti bool // event-edge state for the multiple-configs warning
	lastCount    int  // config count at the previous Tick, for the audit Before field
}

func newGreengoHDetector(iface string, absence time.Duration, servedVID int) *greengoHDetector {
	if absence <= 0 {
		absence = greengoConfigAbsence
	}
	return &greengoHDetector{
		iface:     iface,
		servedVID: servedVID,
		absence:   absence,
		configs:   make(map[string]*ggoConfig),
	}
}

func (d *greengoHDetector) Consume(f Frame, now time.Time) {
	et, off, vid, ok := etherInfo(f.Data)
	if !ok || et != etherTypeIPv4 {
		return
	}
	// Only count configs announced on THIS monitor's served VLAN. An 'h' from a device
	// on an unserved/foreign VLAN (in-band tag on the trunk) is NOT a config on our
	// served network - the Green-GO census reports that device as "on unserved VLAN N"
	// instead, so it never shows here as a green served config.
	if effectiveVID(vid, f) != d.servedVID {
		return
	}
	proto, _, _, l4, ok := ipv4Info(f.Data, off)
	if !ok || proto != ipProtoUDP {
		return
	}
	sport, dport, payOff, ok := udpPorts(f.Data, l4)
	if !ok || (sport != ggoBusPort && dport != ggoBusPort) {
		return
	}
	g5 := f.Data[payOff:]
	// 'h' header: "G5"(0x47 0x35) + subtype 0x68 + flags + len + seed + checksum.
	if len(g5) < 14 || g5[0] != 0x47 || g5[1] != 0x35 || g5[2] != 0x68 {
		return
	}
	if g5[3]&0x80 == 0 {
		return // 'h' is always encrypted (key in the clear); a plaintext 'h' doesn't occur
	}
	seed := leu32(g5, 6)
	checksum := leu32(g5, 10)
	plain, valid := g5DecryptPayload(g5[14:], seed, checksum)
	if !valid {
		return // checksum failed - not a default-config 'h' we can read
	}
	recs, ok := parseNibbleTLV(plain)
	if !ok {
		return
	}
	var id, name, group string
	for _, r := range recs {
		switch r.typ {
		case 1: // configId (8 bytes)
			if len(r.value) == 8 {
				id = hex64(be64(r.value, 0))
			}
		case 2: // multicast group (u32 BE → dotted)
			if len(r.value) == 4 {
				group = ipString([4]byte{r.value[0], r.value[1], r.value[2], r.value[3]})
			}
		case 4: // config name (ASCII, NUL-padded)
			name = asciiTrim(r.value)
		}
	}
	if id == "" {
		return
	}
	c := d.configs[id]
	if c == nil {
		c = &ggoConfig{id: id}
		d.configs[id] = c
	}
	c.name = name
	c.group = group
	c.lastSeen = now
}

func (d *greengoHDetector) Tick(now time.Time) []Event {
	for id, c := range d.configs {
		if now.Sub(c.lastSeen) > d.absence {
			delete(d.configs, id)
		}
	}
	current := len(d.configs)
	multi := current >= 2
	var events []Event
	switch {
	case multi && !d.flaggedMulti:
		d.flaggedMulti = true
		events = append(events, Event{
			Action:   "Multiple Green-GO configs active on segment",
			Target:   d.iface,
			Before:   itoa(d.lastCount),
			After:    itoa(current),
			Severity: SevWarn,
		})
	case !multi && d.flaggedMulti:
		d.flaggedMulti = false
		events = append(events, Event{
			Action:   "Multiple Green-GO configs cleared",
			Target:   d.iface,
			Before:   itoa(d.lastCount),
			After:    itoa(current),
			Severity: SevInfo,
		})
	}
	d.lastCount = current
	return events
}

func (d *greengoHDetector) Snapshot() DetectorSnapshot {
	s := DetectorSnapshot{Kind: "greengo_config", Subject: d.iface}
	if len(d.configs) == 0 {
		// None heard yet is neutral/unknown, not a confirmed-good state.
		s.Severity = SevInfo
		s.Text = "No Green-GO config announced"
		return s
	}
	names := make([]string, 0, len(d.configs))
	for _, c := range d.configs {
		names = append(names, c.displayName())
	}
	sort.Strings(names)
	if len(d.configs) == 1 {
		var c *ggoConfig
		for _, v := range d.configs {
			c = v
		}
		// Exactly one config on the segment is the expected healthy state.
		s.Severity = SevOK
		s.Subject = c.displayName()
		// Short row text; the multicast group goes to the info bubble (netHealthDetail).
		s.Text = "Green-GO config: " + c.displayName()
		s.Fields = map[string]string{"config": c.displayName(), "group": c.group, "configs": "1"}
		return s
	}
	s.Severity = SevWarn
	s.Text = "Multiple Green-GO configs active on this segment: " + strings.Join(names, ", ")
	s.Fields = map[string]string{"configs": itoa(len(d.configs)), "names": strings.Join(names, ", ")}
	return s
}

// asciiTrim returns the bytes up to the first NUL as a string (config names are
// NUL-padded ASCII).
func asciiTrim(b []byte) string {
	before, _, _ := bytes.Cut(b, []byte{0})
	return string(before)
}
