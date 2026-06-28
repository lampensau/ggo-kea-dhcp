// Package arpscan is the appliance's device-presence prober. It actively ARPs each
// active DHCP-lease IP and reports which answered recently - the single source of
// truth for the "is this device online?" dot on the leases/dashboard views.
//
// Why active ARP (not passive capture): the passive monitor (internal/netmon) only
// sees the handful of frame classes its BPF accepts (LLDP/PTP/ARP/DHCP/...), so a
// quiet device that emits none of those is never observed even while present. ARP is
// universal - every IP host answers a who-has on its own subnet - so eliciting a reply
// is the reliable, definitive presence signal. Probing by IP (not MAC) also means a
// device's real address answers while an unused reservation IP for the same MAC does
// not, so there is no per-MAC ambiguity to special-case.
//
// The package is platform-independent here; the real AF_PACKET socket lives behind the
// Transport seam (transport_linux.go), so the prober logic is unit-testable with a fake
// transport on any OS - and the box's existing CAP_NET_RAW covers the real one.
package arpscan

import (
	"log"
	"net"
	"sync"
	"time"
)

const (
	// probeInterval is how often each active lease IP is ARP-probed.
	probeInterval = 10 * time.Second
	// reachWindow is how long after a host's last ARP sighting it still counts as
	// online. Three probe intervals, so a single dropped reply does not flip the dot.
	reachWindow = 30 * time.Second
	// defaultProbeTimeout bounds an on-demand ProbeHost wait. A LAN ARP reply returns
	// in well under a millisecond; this is generous headroom for an interactive call.
	defaultProbeTimeout = 400 * time.Millisecond
	// probeSendBatch / probeSendPace pace the per-cycle who-has burst so a large lease
	// set doesn't fill the socket send buffer and shed its tail to ENOBUFS.
	probeSendBatch = 32
	probeSendPace  = 2 * time.Millisecond
)

// Spec is one served interface to probe: the interface name, the sender L2/L3
// addresses to put in the ARP requests (the appliance's own address on that iface),
// and a closure yielding the current active-lease IPs to probe. The closure keeps this
// package free of any kea/web import (mirrors netmon's lease-snapshot injection).
type Spec struct {
	Iface    string
	SrcIP    [4]byte
	SrcMAC   [6]byte
	LeaseIPs func() []string
}

// Transport is the raw-L2 send/receive seam. The real implementation (Linux AF_PACKET,
// ARP-only BPF) is OpenAFPacket; tests inject a fake. Receive returns the next ARP
// frame's bytes (the BPF guarantees only ARP reaches it); it blocks until a frame
// arrives or the transport is closed (then it returns ok=false).
type Transport interface {
	Send(frame []byte) error
	Receive() (frame []byte, ok bool)
	Close() error
}

// OpenFunc opens a Transport for a spec. Returns an error when the socket can't be
// created (e.g. no CAP_NET_RAW / interface down) - the prober logs and skips that iface.
type OpenFunc func(Spec) (Transport, error)

// Snapshot is the prober's current view: the set of lease IPs (dotted-decimal) seen via
// ARP within reachWindow, and whether probing is actually available (at least one socket
// opened). Available=false (dev sandbox / no CAP_NET_RAW) means callers leave presence
// unknown rather than flagging every device offline - same discipline as netmon.
type Snapshot struct {
	ReachableIPs map[string]bool
	Available    bool
}

// Prober runs one sender + one receiver goroutine per served interface and tracks the
// last-ARP-seen time of each sender IP.
type Prober struct {
	open OpenFunc

	mu        sync.Mutex
	running   []*ifaceRunner
	available bool

	tracker *reachTracker
	probes  *probeWaiters
}

// NewProber builds a prober that opens real AF_PACKET transports. Tests pass a fake
// opener via newProberWithOpen.
func NewProber() *Prober { return newProberWithOpen(OpenAFPacket) }

func newProberWithOpen(open OpenFunc) *Prober {
	return &Prober{open: open, tracker: newReachTracker(), probes: newProbeWaiters()}
}

// ProbeHost actively ARPs a single IP and waits up to defaultProbeTimeout for a reply,
// returning the responder's MAC (colon hex). alive=false means no host answered, or
// probing is unavailable (no socket / dev sandbox) - in which case the caller must
// treat liveness as UNKNOWN and not block on it. Used at reservation/pin time to refuse
// re-IP'ing a device onto an address another live device is actively using.
func (p *Prober) ProbeHost(ipStr string) (mac string, alive bool) {
	ip, ok := ipv4Bytes(ipStr)
	if !ok {
		return "", false
	}
	p.mu.Lock()
	runners := append([]*ifaceRunner(nil), p.running...)
	available := p.available
	p.mu.Unlock()
	if !available || len(runners) == 0 {
		return "", false // probing unavailable -> unknown, caller does not block
	}
	ch := p.probes.register(ip)
	defer p.probes.unregister(ip, ch)
	// The IP could be on any served subnet, so who-has on every running interface.
	for _, r := range runners {
		_ = r.transport.Send(buildARPRequest(r.spec.SrcMAC, r.spec.SrcIP, ip))
	}
	select {
	case m := <-ch:
		return net.HardwareAddr(m[:]).String(), true
	case <-time.After(defaultProbeTimeout):
		return "", false
	}
}

// Start (re)starts probing for the given served interfaces. Idempotent: it stops any
// previous run first, so the reconciler can call it on every ACTIVE entry. Best-effort -
// an interface whose socket won't open is logged and skipped, never fatal.
func (p *Prober) Start(specs []Spec) {
	p.Stop()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, spec := range specs {
		if spec.Iface == "wlan0" { // never probe the uplink
			continue
		}
		t, err := p.open(spec)
		if err != nil {
			log.Printf("[arpscan] %s: probe disabled (%v)", spec.Iface, err)
			continue
		}
		r := &ifaceRunner{spec: spec, transport: t, tracker: p.tracker, probes: p.probes, quit: make(chan struct{})}
		r.start()
		p.running = append(p.running, r)
		p.available = true
	}
}

// Stop tears down all per-interface runners and clears availability.
func (p *Prober) Stop() {
	p.mu.Lock()
	runners := p.running
	p.running = nil
	p.available = false
	p.mu.Unlock()
	for _, r := range runners {
		r.stop()
	}
}

// Snapshot returns the current reachable-IP set and availability.
func (p *Prober) Snapshot() Snapshot {
	p.mu.Lock()
	available := p.available
	p.mu.Unlock()
	return Snapshot{ReachableIPs: p.tracker.within(time.Now()), Available: available}
}

// ifaceRunner owns one interface's transport, sender ticker, and receiver loop.
type ifaceRunner struct {
	spec      Spec
	transport Transport
	tracker   *reachTracker
	probes    *probeWaiters
	quit      chan struct{}
	wg        sync.WaitGroup
}

func (r *ifaceRunner) start() {
	r.wg.Add(2)
	go r.sendLoop()
	go r.recvLoop()
}

func (r *ifaceRunner) stop() {
	close(r.quit)
	_ = r.transport.Close() // unblocks Receive in recvLoop
	r.wg.Wait()
}

// sendLoop broadcasts an ARP who-has for every active lease IP, immediately and then
// every probeInterval. Replies (and any other ARP the device emits) are recorded by
// recvLoop; an IP that never answers simply ages out of the reachability window.
func (r *ifaceRunner) sendLoop() {
	defer r.wg.Done()
	r.probeOnce()
	t := time.NewTicker(probeInterval)
	defer t.Stop()
	for {
		select {
		case <-r.quit:
			return
		case <-t.C:
			r.probeOnce()
		}
	}
}

func (r *ifaceRunner) probeOnce() {
	sent := 0
	for _, ipStr := range r.spec.LeaseIPs() {
		ip, ok := ipv4Bytes(ipStr)
		if !ok {
			continue
		}
		if err := r.transport.Send(buildARPRequest(r.spec.SrcMAC, r.spec.SrcIP, ip)); err != nil {
			// Best-effort per IP: a transient send error (e.g. ENOBUFS under buffer
			// pressure) must not abandon the rest of this cycle, or every other leased
			// device would age out of the reachability window and flip offline. Pause
			// briefly so a full socket buffer can drain instead of hammering it. A real
			// socket close instead ends recvLoop via Receive; Stop/Start re-establishes.
			time.Sleep(probeSendPace)
			continue
		}
		// Drip across a large lease set so the burst doesn't fill the send buffer in the
		// first place (which is what triggers the ENOBUFS tail above). Cheap: at one
		// pause per batch, even hundreds of leases add only a few ms per cycle.
		if sent++; sent%probeSendBatch == 0 {
			time.Sleep(probeSendPace)
		}
	}
}

// recvLoop records the sender IP of every ARP frame the transport delivers (the BPF
// passes only ARP), stamping it live. It ends when Receive reports the transport closed.
func (r *ifaceRunner) recvLoop() {
	defer r.wg.Done()
	for {
		select {
		case <-r.quit:
			return
		default:
		}
		frame, ok := r.transport.Receive()
		if !ok {
			return
		}
		if frame == nil {
			continue // recv-timeout tick: re-check quit and loop (bounds stop())
		}
		if ip, mac, ok := parseARPSender(frame); ok {
			r.tracker.record(ip, time.Now())
			if r.probes != nil {
				r.probes.deliver(ip, mac) // satisfy any on-demand ProbeHost waiter
			}
		}
	}
}

// probeWaiters routes an ARP reply's sender MAC back to a blocked ProbeHost call,
// keyed by the target IP. ProbeHost fires once at interactive pin/reserve time, so a
// single waiter per IP suffices; a second concurrent probe for the same IP simply
// replaces it (the displaced one falls back to its own timeout).
type probeWaiters struct {
	mu sync.Mutex
	m  map[[4]byte]chan [6]byte
}

func newProbeWaiters() *probeWaiters { return &probeWaiters{m: make(map[[4]byte]chan [6]byte)} }

// register installs a one-shot (buffered) waiter for ip and returns its channel.
func (p *probeWaiters) register(ip [4]byte) chan [6]byte {
	ch := make(chan [6]byte, 1)
	p.mu.Lock()
	p.m[ip] = ch
	p.mu.Unlock()
	return ch
}

// unregister removes our waiter on timeout - but only if it's still ours (a later
// probe for the same IP may have replaced it).
func (p *probeWaiters) unregister(ip [4]byte, ch chan [6]byte) {
	p.mu.Lock()
	if p.m[ip] == ch {
		delete(p.m, ip)
	}
	p.mu.Unlock()
}

// deliver hands mac to the waiter for ip (non-blocking; the channel is buffered).
func (p *probeWaiters) deliver(ip [4]byte, mac [6]byte) {
	p.mu.Lock()
	ch := p.m[ip]
	delete(p.m, ip)
	p.mu.Unlock()
	if ch != nil {
		select {
		case ch <- mac:
		default:
		}
	}
}

// ipv4Bytes parses a dotted-decimal IPv4 string into 4 bytes.
func ipv4Bytes(s string) ([4]byte, bool) {
	ip := net.ParseIP(s)
	if ip == nil {
		return [4]byte{}, false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return [4]byte{}, false
	}
	var out [4]byte
	copy(out[:], ip4)
	return out, true
}
