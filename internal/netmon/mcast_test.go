package netmon

import "testing"

// TestKnownMACs guards the L2 control-plane joins: without these exact dst MACs
// in the join list the NIC filter drops LLDP/CDP/STP and those detectors starve.
func TestKnownMACs(t *testing.T) {
	want := map[[6]byte]string{
		{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}: "LLDP",
		{0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc}: "CDP",
		{0x01, 0x80, 0xc2, 0x00, 0x00, 0x00}: "STP",
	}
	have := make(map[[6]byte]bool)
	for _, m := range knownMACs {
		have[m] = true
	}
	for mac, name := range want {
		if !have[mac] {
			t.Errorf("knownMACs missing %s group %v", name, mac)
		}
	}
}

func TestSACNUniverseGroup(t *testing.T) {
	cases := map[uint16][4]byte{
		1:      {239, 255, 0, 1},
		0x0102: {239, 255, 1, 2},
		511:    {239, 255, 1, 255},
	}
	for universe, want := range cases {
		if got := sacnUniverseGroup(universe); got != want {
			t.Errorf("sacnUniverseGroup(%d) = %v, want %v", universe, got, want)
		}
	}
}

func TestMulticastMAC(t *testing.T) {
	cases := map[[4]byte][6]byte{
		{224, 0, 1, 129}: {0x01, 0x00, 0x5e, 0x00, 0x01, 0x81}, // PTP primary
		{224, 0, 0, 251}: {0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb}, // mDNS
		{239, 255, 0, 1}: {0x01, 0x00, 0x5e, 0x7f, 0x00, 0x01}, // sACN universe 1 (high bit masked)
	}
	for group, want := range cases {
		if got := multicastMAC(group); got != want {
			t.Errorf("multicastMAC(%v) = %x, want %x", group, got, want)
		}
	}
}
