package netmon

import (
	"testing"
	"time"
)

// noControlBytes fails when s carries anything outside printable ASCII - the
// invariant for wire-derived names that become audit-log targets.
func noControlBytes(t *testing.T, what, s string) {
	t.Helper()
	for _, c := range []byte(s) {
		if c < 0x20 || c > 0x7e {
			t.Fatalf("%s contains unprintable byte 0x%02x: %q", what, c, s)
		}
	}
}

// A hostile LLDP System Name (terminal escape bytes) must be rendered through
// the printableID funnel before it becomes the learned switch name.
func TestLLDPSystemNameFiltered(t *testing.T) {
	d := newLLDPDetector("eth0", nil)
	d.Consume(lldpFrame("evil\x1b[2Jsw\x07", "Gi1/0/1", 0), at(1*time.Second))
	d.Tick(at(1 * time.Second))
	s := d.Snapshot()
	if s.Fields["switch"] == "" {
		t.Fatal("hostile name was dropped entirely; want it rendered readably")
	}
	noControlBytes(t, "LLDP switch name", s.Fields["switch"])

	// A clean ASCII name still passes through verbatim.
	d.Consume(lldpFrame("core-sw-1", "Gi1/0/1", 0), at(2*time.Second))
	d.Tick(at(2 * time.Second))
	if got := d.Snapshot().Fields["switch"]; got != "core-sw-1" {
		t.Fatalf("clean name = %q, want core-sw-1", got)
	}
}

// The Green-GO config-name decoder must run wire bytes through the printable funnel.
func TestWireNameDecodersFiltered(t *testing.T) {
	if got := asciiTrim([]byte("cfg\x07name\x00")); got == "" {
		t.Fatal("hostile config name dropped entirely")
	} else {
		noControlBytes(t, "Green-GO config name", got)
	}
	if got := asciiTrim([]byte("MainStage\x00")); got != "MainStage" {
		t.Fatalf("clean config name = %q, want verbatim", got)
	}
}

// One crafted frame must not plant a multi-KB blob into an audit row: the
// funnel truncates past maxWireName in both render modes.
func TestPrintableIDLengthCapped(t *testing.T) {
	long := make([]byte, 4*maxWireName)
	for i := range long {
		long[i] = 'a'
	}
	if got := printableID(long); len(got) != maxWireName+2 || got[len(got)-2:] != ".." {
		t.Errorf("printable blob len=%d tail=%q, want cap+marker", len(got), got[len(got)-2:])
	}
	long[0] = 0x1b // force the hex rendering
	if got := printableID(long); len(got) > maxWireName*3+2 {
		t.Errorf("hex blob len=%d, want capped", len(got))
	} else if got[len(got)-2:] != ".." {
		t.Errorf("hex blob lacks the truncation marker: %q", got[len(got)-8:])
	}
}
