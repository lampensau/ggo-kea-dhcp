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

// The sACN source-name and Green-GO config-name decoders share the invariant.
func TestWireNameDecodersFiltered(t *testing.T) {
	if got := trimName([]byte("desk\x1b[31m\x00pad")); got == "" {
		t.Fatal("hostile sACN name dropped entirely")
	} else {
		noControlBytes(t, "sACN source name", got)
	}
	if got := trimName([]byte("Console A\x00\x00")); got != "Console A" {
		t.Fatalf("clean sACN name = %q, want verbatim", got)
	}

	if got := asciiTrim([]byte("cfg\x07name\x00")); got == "" {
		t.Fatal("hostile config name dropped entirely")
	} else {
		noControlBytes(t, "Green-GO config name", got)
	}
	if got := asciiTrim([]byte("MainStage\x00")); got != "MainStage" {
		t.Fatalf("clean config name = %q, want verbatim", got)
	}
}
