// Package ggoscan is the appliance's active Green-GO device scanner. On a Green-GO
// deployment it periodically broadcasts the plaintext device-scan request on UDP
// 6464 (and unicasts it at newly leased IPs), then parses the device-info replies
// into an inventory of {name, MAC, IP, firmware} - the source for the firmware
// inventory, firmware-mismatch warning, and friendly-hostname assignment.
//
// SAFETY: this package transmits two frames only - the read-only scan request, and,
// solely on an explicit operator action, a device-reboot request (SendReboot). No
// other device-mutating operation is ever constructed here. See scanFrame,
// rebootHeader, and TestOnlyEmitsScanAndReboot.
//
// Like arpscan it is best-effort and runs ACTIVE-only: a socket that won't open
// (dev sandbox / no privilege) disables the scanner with a log line, never fatal.
package ggoscan

import (
	"bytes"
	"fmt"
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

// scanFrame is the read-only device-scan request. It is a fixed 8-byte constant,
// never parameterized, so nothing device-mutating can be built from it.
var scanFrame = []byte{0x47, 0x2d, 0x47, 0x00, 0x00, 0x10, 0x00, 0x00}

// rebootHeader is the fixed prefix of the reboot request SendReboot sends on an explicit
// operator action; rebootFrameFor appends the target address. It shares scanFrame's shape
// and differs in one byte. This and scanFrame are the only frames this package emits (see
// TestOnlyEmitsScanAndReboot).
var rebootHeader = []byte{0x47, 0x2d, 0x47, 0x00, 0x00, 0x90, 0x00, 0x00}

// rebootFrameFor returns the reboot request addressed to ip4. A fresh slice each call, so
// the shared header is never aliased or mutated.
func rebootFrameFor(ip4 net.IP) []byte {
	f := make([]byte, 0, len(rebootHeader)+net.IPv4len)
	f = append(f, rebootHeader...)
	return append(f, ip4...)
}

// Spec is one Green-GO scope to scan: the subnet-directed broadcast address for its
// periodic sweep, and a closure yielding the current lease IPs to unicast-scan. The
// closure keeps this package free of any kea/web import.
type Spec struct {
	Broadcast [4]byte
	LeaseIPs  func() []string
}

// Device is one Green-GO device learned from a scan reply.
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
// helpers (parseScanReply, ReleaseMismatch) and never call Start.
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
	// A (re)start scans a possibly different network (profile switch): drop the
	// previous run's inventory rather than letting up to deviceTTL of the old
	// network's devices color the new profile's census and firmware findings.
	s.inv.clear()
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

// SendReboot asks the device at ip to reboot, so a just-changed address takes effect
// now instead of at the device's next DHCP renewal. It unicasts one request over the
// same transport as the scan (UDP port ggoPort), reusing the live scan socket when the
// scanner is running and otherwise opening a one-shot socket. Best-effort: it returns
// any send error to the caller (which audits the outcome) but changes no local state.
func (s *Scanner) SendReboot(ip string) error {
	addr := net.ParseIP(ip)
	if addr == nil || addr.To4() == nil {
		return fmt.Errorf("ggoscan: invalid device address %q", ip)
	}
	dst := &net.UDPAddr{IP: addr.To4(), Port: ggoPort}
	frame := rebootFrameFor(addr.To4())

	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	if conn != nil {
		_, err := conn.WriteToUDP(frame, dst)
		return err
	}
	// Scanner idle (no served Green-GO scope, or dev sandbox): one-shot socket.
	c, err := s.open()
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.WriteToUDP(frame, dst)
	return err
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

// parseScanReply decodes a device-scan reply into a Device (name, MAC, firmware).
// srcIP is the UDP source, i.e. the device's address. The offsets below were fixed
// against live replies. Returns ok=false for a frame that isn't a well-formed reply.
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
	switch {
	case len(body) > 0x30 && body[0x2e] == 0x55 && body[0x2f] == 0xaa:
		fw = asciiTrim(body[0x30:min(0x30+0x40, len(body))])
	case len(body) > 0x2e:
		fw = asciiTrim(body[0x2e:min(0x2e+0x40, len(body))])
	}
	model, version, _ := strings.Cut(fw, " ")
	return Device{MAC: mac, Name: name, IP: srcIP, Firmware: fw, Model: model, Version: version}, true
}

// Legacy device families are frozen on a final firmware release and interoperate
// with newer system releases by design (vendor guidance), so a legacy device
// running exactly that release is exempt from the release check. Model tokens are
// the firmware string's leading word; adjust if a legacy family reports a
// different token.
const legacyFinalRelease = "5.2.1"

var legacyModels = map[string]bool{"BP2": true, "MCD": true, "MCR": true, "WP": true}

// releaseOf strips the per-model build number from a firmware version:
// "5.1.0.14479" -> "5.1.0". Versions with three or fewer components pass through.
func releaseOf(version string) string {
	parts := strings.SplitN(version, ".", 4)
	if len(parts) == 4 {
		return strings.Join(parts[:3], ".")
	}
	return version
}

// ReleaseCount is one firmware release and how many devices run it.
type ReleaseCount struct {
	Release string
	N       int
}

// ReleaseSpread is the fleet's firmware divergence: the distinct releases with
// device counts, plus every device involved (for attribution and the roster).
type ReleaseSpread struct {
	Releases []ReleaseCount
	Devices  []Device
}

// ReleaseMismatch is THE firmware check: a Green-GO system normally runs one
// firmware release (major.minor.patch) across every device type, so all devices
// are compared on their release - the build number is ignored, since builds
// differ per model within one release. The one sanctioned exception: legacy
// devices frozen on legacyFinalRelease. Returns nil unless the remaining
// devices span two or more releases.
func ReleaseMismatch(devs []Device) *ReleaseSpread {
	spread := &ReleaseSpread{}
	counts := map[string]int{}
	for _, d := range devs {
		if d.Model == "" || d.Version == "" {
			continue
		}
		release := releaseOf(d.Version)
		if legacyModels[d.Model] && release == legacyFinalRelease {
			continue // frozen legacy device on its sanctioned final release
		}
		counts[release]++
		spread.Devices = append(spread.Devices, d)
	}
	if len(counts) < 2 {
		return nil
	}
	for r, n := range counts {
		spread.Releases = append(spread.Releases, ReleaseCount{Release: r, N: n})
	}
	sort.Slice(spread.Releases, func(i, j int) bool {
		if spread.Releases[i].N != spread.Releases[j].N {
			return spread.Releases[i].N > spread.Releases[j].N
		}
		return spread.Releases[i].Release < spread.Releases[j].Release
	})
	sort.Slice(spread.Devices, func(i, j int) bool {
		if spread.Devices[i].Version != spread.Devices[j].Version {
			return spread.Devices[i].Version < spread.Devices[j].Version
		}
		return spread.Devices[i].Name < spread.Devices[j].Name
	})
	return spread
}

// inventory is the MAC-keyed device set, TTL-pruned on read.
type inventory struct {
	mu      sync.Mutex
	devices map[string]Device
}

func newInventory() *inventory { return &inventory{devices: make(map[string]Device)} }

func (inv *inventory) clear() {
	inv.mu.Lock()
	inv.devices = make(map[string]Device)
	inv.mu.Unlock()
}

// maxInventory caps the device census: it is fed from an open UDP socket keyed
// by a claimed MAC, so a spoofed flood must not grow it unbounded across the
// 15-minute TTL. Well above any real Green-GO installation.
const maxInventory = 512

func (inv *inventory) record(d Device, now time.Time) {
	d.LastSeen = now
	inv.mu.Lock()
	if _, ok := inv.devices[d.MAC]; !ok && len(inv.devices) >= maxInventory {
		// Evict the stalest entry so real, recently-seen devices survive a flood.
		first := true
		var oldK string
		var oldT time.Time
		for k, dev := range inv.devices {
			if first || dev.LastSeen.Before(oldT) {
				oldK, oldT, first = k, dev.LastSeen, false
			}
		}
		delete(inv.devices, oldK)
	}
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
