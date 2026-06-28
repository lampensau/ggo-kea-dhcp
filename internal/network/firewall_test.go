package network

import "testing"

func TestSetIPForwarding(t *testing.T) {
	// enabled -> sysctl ...=1, disabled -> ...=0 (catches an inverted boolean).
	for _, c := range []struct {
		enabled bool
		want    string
	}{{true, "net.ipv4.ip_forward=1"}, {false, "net.ipv4.ip_forward=0"}} {
		rec := &RecordingCommander{}
		m := NewManagerWithCommander(rec)
		if err := m.SetIPForwarding(c.enabled); err != nil {
			t.Fatalf("SetIPForwarding(%v): %v", c.enabled, err)
		}
		if !callContaining(rec, "sysctl", "-w", c.want) {
			t.Errorf("enabled=%v: expected sysctl %q, calls=%v", c.enabled, c.want, rec.Calls)
		}
	}
}

func TestAddPortForward(t *testing.T) {
	rec := &RecordingCommander{}
	m := NewManagerWithCommander(rec)
	if err := m.AddPortForward("eth0", "192.168.1.10", 8080, 80, "tcp"); err != nil {
		t.Fatalf("AddPortForward: %v", err)
	}
	// The nft DNAT rule must carry the external dport, proto, and the local target.
	if !callContaining(rec, "nft", "add", "rule", "prerouting", "iifname", "eth0", "tcp", "dport", "80") {
		t.Errorf("missing dport rule tokens: %v", rec.Calls)
	}
	if !callContaining(rec, "dnat", "to", "192.168.1.10:8080") {
		t.Errorf("missing dnat target: %v", rec.Calls)
	}
}

func TestClearPortForwards(t *testing.T) {
	rec := &RecordingCommander{}
	m := NewManagerWithCommander(rec)
	if err := m.ClearPortForwards(); err != nil {
		t.Fatalf("ClearPortForwards: %v", err)
	}
	if !callContaining(rec, "nft", "flush", "chain", "ggo_nat", "prerouting") {
		t.Errorf("expected prerouting flush, calls=%v", rec.Calls)
	}
}
