package netmon

import (
	"testing"
	"time"
)

// TestCDPDetector_ParsesDeviceAndPortID drives the CDP path of the shared LLDP/CDP
// detector end to end: a CDP frame to the group MAC yields the switch and port fields,
// mirroring the LLDP latch test. parseCDP had no runtime coverage before this.
func TestCDPDetector_ParsesDeviceAndPortID(t *testing.T) {
	d := newLLDPDetector("eth0", nil) // nil linkUp => always up
	d.Consume(cdpFrame("core-sw-cdp", "GigabitEthernet0/1"), at(1*time.Second))
	d.Tick(at(1 * time.Second))

	s := d.Snapshot()
	if s.Fields["switch"] != "core-sw-cdp" || s.Fields["port"] != "GigabitEthernet0/1" {
		t.Fatalf("CDP fields = %+v, want switch=core-sw-cdp port=GigabitEthernet0/1", s.Fields)
	}
	if s.Severity != SevOK {
		t.Errorf("severity = %q, want ok", s.Severity)
	}
}

// TestCDPParse_MalformedIsSafe feeds parseCDP attacker-shaped TLV streams and asserts it
// neither panics nor over-reads: a truncated stream still yields the leading TLV it fully
// saw, and an oversized length halts the walk without pulling out-of-bounds bytes.
func TestCDPParse_MalformedIsSafe(t *testing.T) {
	full := cdpFrame("sw1", "Gi0/1").Data

	// Truncated mid-Port-ID: the Device-ID TLV is complete and parses; the cut Port-ID
	// TLV's declared length runs past the buffer, so the walk stops there.
	d := newLLDPDetector("eth0", nil)
	d.parseCDP(full[:len(full)-3])
	if d.sysName != "sw1" {
		t.Errorf("truncated frame: sysName = %q, want sw1", d.sysName)
	}
	if d.portID != "" {
		t.Errorf("truncated frame: portID = %q, want empty (TLV cut off)", d.portID)
	}

	// Oversized length on the first TLV (26 = cdpTLVStart, +2 = the length field): the
	// walk must break immediately rather than slice past the end.
	over := append([]byte{}, full...)
	over[28], over[29] = 0xff, 0xff
	d2 := newLLDPDetector("eth0", nil)
	d2.parseCDP(over)
	if d2.sysName != "" || d2.portID != "" {
		t.Errorf("oversized TLV should extract nothing, got sysName=%q portID=%q", d2.sysName, d2.portID)
	}
}
