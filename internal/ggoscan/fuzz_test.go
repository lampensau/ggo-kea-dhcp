package ggoscan

import "testing"

// FuzzParseScanReply throws arbitrary bytes at the Green-GO UDP reply parser, which
// runs on untrusted payloads straight off the wire and does offset slicing
// (body[0x12:0x18], body[0x2e:...]). The property is simply: it must never panic, and
// a successful parse must have consumed enough bytes to hold the MAC.
func FuzzParseScanReply(f *testing.F) {
	valid := append([]byte{0x47, 0x2d, 0x47, 0x00, 0x00, 0x11, 0x00, 0x00}, make([]byte, 0x40)...)
	f.Add(valid, "10.0.0.9")
	f.Add([]byte{0x47, 0x2d, 0x47, 0x00, 0x00, 0x11, 0x00, 0x00}, "x") // header only, short body
	f.Add([]byte{}, "")
	f.Add([]byte{0x47, 0x2d}, "x") // truncated magic

	f.Fuzz(func(t *testing.T, payload []byte, srcIP string) {
		dev, ok := parseScanReply(payload, srcIP)
		if ok && len(payload) < 0x20 {
			t.Errorf("ok=true on a %d-byte payload too short to hold the MAC", len(payload))
		}
		if ok && dev.IP != srcIP {
			t.Errorf("parsed device IP %q != srcIP %q", dev.IP, srcIP)
		}
	})
}
