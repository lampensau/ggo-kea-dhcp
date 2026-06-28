// Package ggoscan is the appliance's active Green-GO device scanner. On a Green-GO
// deployment it periodically broadcasts the plaintext device-scan request on UDP
// 6464 (and unicasts it at newly leased IPs), then parses the device-info replies
// into an inventory of {name, MAC, IP, firmware} - the source for the firmware
// inventory, firmware-mismatch warning, and friendly-hostname assignment.
//
// SAFETY: this package transmits exactly ONE frame type - the read-only scan request
// (type 0x10). The mutating G-G opcodes (reboot, memory-clear, firmware update,
// save-default) are never constructed here. See scanFrame and TestOnlyEmitsScan.
//
// Like arpscan it is best-effort and runs ACTIVE-only: a socket that won't open
// (dev sandbox / no privilege) disables the scanner with a log line, never fatal.
package ggoscan

import (
	"bytes"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	ggoPort = 6464
	// sweepInterval is the broadcast catch-all cadence; pollInterval is how often the
	// lease set is checked so a newly leased device is unicast-scanned promptly.
	sweepInterval = 5 * time.Minute
	pollInterval  = 10 * time.Second
	// deviceTTL drops a device from the inventory after this long unseen (~3 missed
	// broadcast sweeps).
	deviceTTL = 15 * time.Minute
)

// scanFrame is the ONLY frame this package ever sends: G-G magic "G-G\0" + type
// 0x10 (device scan, read-only) + reserved. Never parameterized by opcode, so a
// mutating command (reboot 0x90, memory-clear 0xa0, firmware 0x20/0x30/0x140/0x250,
// save-default 0x310) cannot be emitted.
var scanFrame = []byte{0x47, 0x2d, 0x47, 0x00, 0x00, 0x10, 0x00, 0x00}

// Spec is one Green-GO scope to scan: the subnet-directed broadcast address for its
// periodic sweep, and a closure yielding the current lease IPs to unicast-scan. The
// closure keeps this package free of any kea/web import.
type Spec struct {
	Broadcast [4]byte
	LeaseIPs  func() []string
}

// Device is one Green-GO device learned from a 0x11 scan reply.
type Device struct {
	MAC      string
	Name     string
	IP       string
	Firmware string // full firmware string, e.g. "MCXi 5.0.7.9165"
	Model    string // the firmware string's leading token, e.g. "MCXi"
	Version  string // the remainder, e.g. "5.0.7.9165"
	LastSeen time.Time
}

// Snapshot is the scanner's current inventory plus whether scanning is available.
type Snapshot struct {
	Devices   []Device
	Available bool
}

// Scanner owns a single UDP socket (0.0.0.0:6464) shared across scopes: it sweeps
// each scope's broadcast and unicasts newly leased IPs, and folds replies into one
// inventory.
type Scanner struct {
	open func() (*net.UDPConn, error)

	mu        sync.Mutex
	conn      *net.UDPConn
	specs     []Spec
	quit      chan struct{}
	available bool
	seen      map[string]bool // lease IPs already unicast-scanned this run

	wg  sync.WaitGroup
	inv *inventory
}

// NewScanner builds a scanner that opens a real UDP socket. Tests use the pure
// helpers (parseScanReply, FirmwareMismatches) and never call Start.
func NewScanner() *Scanner { return &Scanner{open: openConn, inv: newInventory()} }

// Start (re)starts scanning for the given Green-GO scopes. Idempotent (stops any
// prior run first). Best-effort: if the socket won't open the scanner stays
// unavailable and the snapshot is empty. An empty spec set also stops it (a profile
// with no Green-GO scope does not scan).
func (s *Scanner) Start(specs []Spec) {
	s.Stop()
	if len(specs) == 0 {
		return
	}
	conn, err := s.open()
	if err != nil {
		log.Printf("[ggoscan] scanning disabled (%v)", err)
		return
	}
	s.mu.Lock()
	s.conn = conn
	s.specs = specs
	s.quit = make(chan struct{})
	s.available = true
	s.seen = map[string]bool{}
	s.mu.Unlock()
	s.wg.Add(2)
	go s.sendLoop()
	go s.recvLoop()
}

// Stop tears down the socket and goroutines. Idempotent.
func (s *Scanner) Stop() {
	s.mu.Lock()
	conn, quit := s.conn, s.quit
	s.conn, s.quit, s.available = nil, nil, false
	s.mu.Unlock()
	if conn == nil {
		return
	}
	close(quit)
	_ = conn.Close() // unblocks recvLoop's ReadFromUDP
	s.wg.Wait()
}

// Snapshot returns the current inventory (TTL-pruned) and availability.
func (s *Scanner) Snapshot() Snapshot {
	s.mu.Lock()
	avail := s.available
	s.mu.Unlock()
	return Snapshot{Devices: s.inv.snapshot(time.Now()), Available: avail}
}

func (s *Scanner) sendLoop() {
	defer s.wg.Done()
	s.sweep()
	s.pollLeases()
	sweepT := time.NewTicker(sweepInterval)
	pollT := time.NewTicker(pollInterval)
	defer sweepT.Stop()
	defer pollT.Stop()
	// Capture quit once: it is set at Start and only niled by Stop (which closes
	// the captured channel first). Re-reading it per iteration would select on a
	// nil channel after Stop, never observe the close, and hang wg.Wait() forever.
	quit := s.quit
	for {
		select {
		case <-quit:
			return
		case <-sweepT.C:
			s.sweep()
		case <-pollT.C:
			s.pollLeases()
		}
	}
}

// sweep broadcasts the scan request to every scope's subnet-directed broadcast.
func (s *Scanner) sweep() {
	s.mu.Lock()
	conn, specs := s.conn, s.specs
	s.mu.Unlock()
	if conn == nil {
		return
	}
	for _, sp := range specs {
		_, _ = conn.WriteToUDP(scanFrame, &net.UDPAddr{IP: net.IP(sp.Broadcast[:]), Port: ggoPort})
	}
}

// pollLeases unicasts the scan request at any lease IP not yet scanned this run, so a
// newly leased device is identified within one poll interval. Prunes the seen set to
// the current lease IPs so a released-then-reused IP is re-scanned.
func (s *Scanner) pollLeases() {
	s.mu.Lock()
	conn, specs, seen := s.conn, s.specs, s.seen
	s.mu.Unlock()
	if conn == nil {
		return
	}
	current := map[string]bool{}
	for _, sp := range specs {
		for _, ipStr := range sp.LeaseIPs() {
			current[ipStr] = true
			if seen[ipStr] {
				continue
			}
			ip := net.ParseIP(ipStr)
			if ip == nil || ip.To4() == nil {
				continue
			}
			if _, err := conn.WriteToUDP(scanFrame, &net.UDPAddr{IP: ip.To4(), Port: ggoPort}); err == nil {
				seen[ipStr] = true
			}
		}
	}
	for ip := range seen {
		if !current[ip] {
			delete(seen, ip)
		}
	}
}

func (s *Scanner) recvLoop() {
	defer s.wg.Done()
	buf := make([]byte, 2048)
	for {
		s.mu.Lock()
		conn := s.conn
		s.mu.Unlock()
		if conn == nil {
			return
		}
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			return // socket closed on Stop
		}
		if dev, ok := parseScanReply(buf[:n], src.IP.String()); ok {
			s.inv.record(dev, time.Now())
		}
	}
}

// parseScanReply decodes a G-G device-scan reply (type 0x11). srcIP is the UDP
// source (the device's address). Field offsets are within the reply body (payload
// after the 8-byte G-G header): name @0, MAC @0x12, firmware @0x2e. The reply
// carries no config id. Returns ok=false for any non-0x11 / too-short frame.
func parseScanReply(payload []byte, srcIP string) (Device, bool) {
	if len(payload) < 8 || payload[0] != 0x47 || payload[1] != 0x2d || payload[2] != 0x47 || payload[3] != 0x00 {
		return Device{}, false
	}
	if uint16(payload[4])<<8|uint16(payload[5]) != 0x11 {
		return Device{}, false
	}
	body := payload[8:]
	if len(body) < 0x18 { // need at least through the MAC
		return Device{}, false
	}
	name := asciiTrim(body[0:0x12])
	mac := net.HardwareAddr(body[0x12:0x18]).String()
	fw := ""
	if len(body) > 0x2e {
		fw = asciiTrim(body[0x2e:min(0x2e+0x40, len(body))])
	}
	model, version, _ := strings.Cut(fw, " ")
	return Device{MAC: mac, Name: name, IP: srcIP, Firmware: fw, Model: model, Version: version}, true
}

// VersionCount is one firmware version and how many devices in a model family run it.
type VersionCount struct {
	Version string
	N       int
}

// ModelGroup is one model family with a firmware spread, ordered by count desc.
type ModelGroup struct {
	Model   string
	Counts  []VersionCount // distinct versions, most common first
	Devices []Device       // devices in this family (for the detail list)
}

// FirmwareMismatches returns, for each model family running two or more distinct
// firmware versions, the version spread and devices - the input for the
// firmware-mismatch warning. Families that are uniform (or have only one device) are
// omitted. Deterministically ordered.
func FirmwareMismatches(devs []Device) []ModelGroup {
	byModel := map[string][]Device{}
	for _, d := range devs {
		if d.Model == "" || d.Version == "" {
			continue
		}
		byModel[d.Model] = append(byModel[d.Model], d)
	}
	var groups []ModelGroup
	for model, list := range byModel {
		counts := map[string]int{}
		for _, d := range list {
			counts[d.Version]++
		}
		if len(counts) < 2 {
			continue // uniform within this family
		}
		vc := make([]VersionCount, 0, len(counts))
		for v, n := range counts {
			vc = append(vc, VersionCount{Version: v, N: n})
		}
		sort.Slice(vc, func(i, j int) bool {
			if vc[i].N != vc[j].N {
				return vc[i].N > vc[j].N
			}
			return vc[i].Version < vc[j].Version
		})
		ds := append([]Device(nil), list...)
		sort.Slice(ds, func(i, j int) bool {
			if ds[i].Version != ds[j].Version {
				return ds[i].Version < ds[j].Version
			}
			return ds[i].Name < ds[j].Name
		})
		groups = append(groups, ModelGroup{Model: model, Counts: vc, Devices: ds})
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Model < groups[j].Model })
	return groups
}

// inventory is the MAC-keyed device set, TTL-pruned on read.
type inventory struct {
	mu      sync.Mutex
	devices map[string]Device
}

func newInventory() *inventory { return &inventory{devices: make(map[string]Device)} }

func (inv *inventory) record(d Device, now time.Time) {
	d.LastSeen = now
	inv.mu.Lock()
	inv.devices[d.MAC] = d
	inv.mu.Unlock()
}

func (inv *inventory) snapshot(now time.Time) []Device {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	out := make([]Device, 0, len(inv.devices))
	for mac, d := range inv.devices {
		if now.Sub(d.LastSeen) > deviceTTL {
			delete(inv.devices, mac)
			continue
		}
		out = append(out, d)
	}
	return out
}

// asciiTrim returns the bytes up to the first NUL (device strings are NUL-padded).
func asciiTrim(b []byte) string {
	before, _, _ := bytes.Cut(b, []byte{0})
	return string(before)
}
