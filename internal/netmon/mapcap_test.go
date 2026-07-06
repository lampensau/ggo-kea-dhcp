package netmon

import (
	"testing"
	"time"
)

// The presence maps below are keyed by attacker-controlled wire fields, so each
// enforces a hard cap: a flood of unique spoofed keys must not grow the map past
// it, and the at-cap insert must evict the STALEST entry - a freshly re-seen old
// entry survives. detector.go's cap block enumerates the whole family.

func TestRogueDHCP_ServerMapCapped(t *testing.T) {
	d := newRogueDHCPDetector("eth0", selfMAC, true, 0, 120*time.Second)
	mac := [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	id := func(i int) [4]byte { return [4]byte{192, 168, byte(i >> 8), byte(i)} }

	for i := 0; i < maxRogueServers; i++ {
		d.Consume(dhcpFrameFrom(mac, id(i), 2), at(time.Duration(i)*time.Second))
	}
	d.Consume(dhcpFrameFrom(mac, id(0), 2), at(500*time.Second))               // refresh the oldest
	d.Consume(dhcpFrameFrom(mac, id(maxRogueServers), 2), at(501*time.Second)) // insert at cap

	if len(d.servers) > maxRogueServers {
		t.Fatalf("server map grew past cap: %d", len(d.servers))
	}
	if d.servers[id(0)] == nil {
		t.Fatal("freshly re-seen entry was evicted")
	}
	if d.servers[id(1)] != nil {
		t.Fatal("stalest entry survived the at-cap insert")
	}
	if d.servers[id(maxRogueServers)] == nil {
		t.Fatal("new entry not inserted at cap")
	}
}

func TestStaticInPool_HostMapCapped(t *testing.T) {
	pool, _ := ParsePoolRange("10.0.0.20-10.0.0.200")
	d := newStaticInPoolDetector("eth0", []PoolRange{pool}, nil, func() []LeasedAddr { return nil }, 120*time.Second, 0)
	mac := [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x02}
	ip := func(i int) [4]byte { return [4]byte{10, 1, byte(i >> 8), byte(i)} }

	for i := 0; i < maxStaticPoolHosts; i++ {
		d.Consume(arpFrame(2, mac, ip(i)), at(time.Duration(i)*time.Millisecond))
	}
	d.Consume(arpFrame(2, mac, ip(0)), at(500*time.Second))
	d.Consume(arpFrame(2, mac, ip(maxStaticPoolHosts)), at(501*time.Second))

	if len(d.hosts) > maxStaticPoolHosts {
		t.Fatalf("host map grew past cap: %d", len(d.hosts))
	}
	if d.hosts[ip4ToU32(ip(0))] == nil {
		t.Fatal("freshly re-seen entry was evicted")
	}
	if d.hosts[ip4ToU32(ip(1))] != nil {
		t.Fatal("stalest entry survived the at-cap insert")
	}
}

func TestGreengo_DeviceMapCapped(t *testing.T) {
	d := newGreengoDetector("eth0", func() []LeasedAddr { return nil }, 0, 0)
	sha := func(i int) [6]byte { return [6]byte{0x00, 0x1f, 0x80, 0x20, byte(i >> 8), byte(i)} }

	for i := 0; i < maxGgoDevices; i++ {
		d.see(sha(i), 0x0a000001, "10.0.0.1", 0, at(time.Duration(i)*time.Second))
	}
	d.see(sha(0), 0x0a000001, "10.0.0.1", 0, at(900*time.Second))
	d.see(sha(maxGgoDevices), 0x0a000001, "10.0.0.1", 0, at(901*time.Second))

	if len(d.devices) > maxGgoDevices {
		t.Fatalf("device map grew past cap: %d", len(d.devices))
	}
	if d.devices[macString(sha(0))] == nil {
		t.Fatal("freshly re-seen entry was evicted")
	}
	if d.devices[macString(sha(1))] != nil {
		t.Fatal("stalest entry survived the at-cap insert")
	}
}

func TestPTP_GMMapCapped(t *testing.T) {
	d := newPTPDetector("eth0", 15*time.Second)

	for i := 0; i < maxPTPGMs; i++ {
		d.Consume(ptpAnnounce(0, uint64(i+1), 128, 128, false), at(time.Duration(i)*time.Second))
	}
	d.Consume(ptpAnnounce(0, 1, 128, 128, false), at(200*time.Second))
	d.Consume(ptpAnnounce(0, uint64(maxPTPGMs+1), 128, 128, false), at(201*time.Second))

	gms := d.domains[0].gms
	if len(gms) > maxPTPGMs {
		t.Fatalf("GM map grew past cap: %d", len(gms))
	}
	if gms[1] == nil {
		t.Fatal("freshly re-seen GM was evicted")
	}
	if gms[2] != nil {
		t.Fatal("stalest GM survived the at-cap insert")
	}
}

func TestDuplicateIP_ConflictMapCapped(t *testing.T) {
	d := newDuplicateIPDetector("eth0", 0, 300*time.Second)
	ip := func(i int) [4]byte { return [4]byte{10, 2, byte(i >> 8), byte(i)} }

	for i := 0; i < maxDupIPConflicts; i++ {
		d.Consume(declineFrame(ip(i)), at(time.Duration(i)*time.Millisecond))
	}
	d.Consume(declineFrame(ip(0)), at(500*time.Second))
	d.Consume(declineFrame(ip(maxDupIPConflicts)), at(501*time.Second))

	if len(d.conflicts) > maxDupIPConflicts {
		t.Fatalf("conflict map grew past cap: %d", len(d.conflicts))
	}
	if d.conflicts[ip(0)] == nil {
		t.Fatal("freshly re-seen entry was evicted")
	}
	if d.conflicts[ip(1)] != nil {
		t.Fatal("stalest entry survived the at-cap insert")
	}
}

func TestHostLiveness_SeenMapCapped(t *testing.T) {
	h := newHostTracker()
	mac := func(i int) [6]byte { return [6]byte{0x02, 0, 0, 0, byte(i >> 8), byte(i)} }
	frame := func(i int) Frame { return Frame{Data: arpFrameFor(mac(i), [4]byte{10, 0, 0, 1})} }

	for i := 0; i < maxHostLiveness; i++ {
		h.record(frame(i), at(time.Duration(i)*time.Millisecond))
	}
	h.record(frame(0), at(500*time.Second))
	h.record(frame(maxHostLiveness), at(501*time.Second))

	if len(h.seen) > maxHostLiveness {
		t.Fatalf("seen map grew past cap: %d", len(h.seen))
	}
	if _, ok := h.seen[mac(0)]; !ok {
		t.Fatal("freshly re-seen entry was evicted")
	}
	if _, ok := h.seen[mac(1)]; ok {
		t.Fatal("stalest entry survived the at-cap insert")
	}
}

func TestGreengoH_ConfigMapCapped(t *testing.T) {
	d := newGreengoHDetector("eth0", 0, 0)
	id := func(i int) string { return "cfg" + itoa(i) }

	for i := 0; i < maxGgoConfigs; i++ {
		d.recordConfig(id(i), "n", "10.0.0.1", at(time.Duration(i)*time.Second))
	}
	d.recordConfig(id(0), "n", "10.0.0.1", at(900*time.Second))
	d.recordConfig(id(maxGgoConfigs), "n", "10.0.0.1", at(901*time.Second))

	if len(d.configs) > maxGgoConfigs {
		t.Fatalf("config map grew past cap: %d", len(d.configs))
	}
	if d.configs[id(0)] == nil {
		t.Fatal("freshly re-seen entry was evicted")
	}
	if d.configs[id(1)] != nil {
		t.Fatal("stalest entry survived the at-cap insert")
	}
}
