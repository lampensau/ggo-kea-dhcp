package network

import (
	"fmt"
	"log"
	"net"
	"sync"
)

type DNSRedirector struct {
	conn     *net.UDPConn
	bindIP   net.IP // interface address we listen on
	answerIP net.IP // address returned for every A query
	wg       sync.WaitGroup
	quit     chan struct{}
}

// NewDNSRedirector creates an onboarding DNS server that listens on bindIP:53 and
// answers every query with answerIP. For the captive flow bindIP == answerIP so
// each interface's clients are pointed at the box address reachable from THEIR
// subnet (eth0 clients -> eth0 IP, wlan0 SoftAP clients -> wlan0 IP).
func NewDNSRedirector(bindIP, answerIP string) (*DNSRedirector, error) {
	b := net.ParseIP(bindIP)
	if b == nil {
		return nil, fmt.Errorf("invalid bind IP: %s", bindIP)
	}
	a := net.ParseIP(answerIP)
	if a == nil {
		return nil, fmt.Errorf("invalid answer IP: %s", answerIP)
	}
	a4 := a.To4()
	if a4 == nil {
		return nil, fmt.Errorf("only IPv4 answers are supported")
	}
	return &DNSRedirector{
		bindIP:   b,
		answerIP: a4,
		quit:     make(chan struct{}),
	}, nil
}

// Start launches the DNS listener on bindIP:53.
func (d *DNSRedirector) Start() error {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(d.bindIP.String(), "53"))
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s:53: %w", d.bindIP.String(), err)
	}
	d.conn = conn

	d.wg.Add(1)
	go d.serve()

	log.Printf("Onboarding DNS redirector listening on %s:53 -> answers %s", d.bindIP.String(), d.answerIP.String())
	return nil
}

// Stop stops the DNS listener.
func (d *DNSRedirector) Stop() {
	close(d.quit)
	if d.conn != nil {
		d.conn.Close()
	}
	d.wg.Wait()
	log.Printf("Onboarding DNS redirector on %s stopped.", d.bindIP.String())
}

func (d *DNSRedirector) serve() {
	defer d.wg.Done()
	buf := make([]byte, 512)

	for {
		// quit is observed by Close() unblocking ReadFromUDP with an error; the inner
		// select then distinguishes a shutdown from a real read error. (A leading
		// select on quit would never fire - ReadFromUDP blocks, not the select.)
		n, remoteAddr, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-d.quit:
				return
			default:
				log.Printf("DNS read error: %v", err)
				continue
			}
		}

		if n < 12 {
			continue // DNS header is 12 bytes, ignore shorter packets
		}

		response, err := d.buildResponse(buf[:n])
		if err != nil {
			continue
		}

		_, _ = d.conn.WriteToUDP(response, remoteAddr)
	}
}

func (d *DNSRedirector) buildResponse(req []byte) ([]byte, error) {
	txID := req[0:2]

	// Flags: response, recursion available, no error (0x8180)
	flags := []byte{0x81, 0x80}

	questionsCount := req[4:6]
	answersCount := []byte{0x00, 0x01}
	authoritiesCount := []byte{0x00, 0x00}
	additionalCount := []byte{0x00, 0x00}

	resp := append([]byte{}, txID...)
	resp = append(resp, flags...)
	resp = append(resp, questionsCount...)
	resp = append(resp, answersCount...)
	resp = append(resp, authoritiesCount...)
	resp = append(resp, additionalCount...)

	// Walk to the end of the Question section (name labels ending with 0x00,
	// then 4 bytes of Type/Class).
	offset := 12
	for offset < len(req) {
		length := int(req[offset])
		if length == 0 {
			offset++
			break
		}
		offset += length + 1
	}
	if offset+4 > len(req) {
		return nil, fmt.Errorf("malformed dns packet")
	}

	// Copy the Question section verbatim.
	resp = append(resp, req[12:offset+4]...)

	// Answer RR: compressed name pointer to the question name at offset 12.
	resp = append(resp, 0xc0, 0x0c)
	resp = append(resp, 0x00, 0x01)             // Type A
	resp = append(resp, 0x00, 0x01)             // Class IN
	resp = append(resp, 0x00, 0x00, 0x00, 0x3c) // TTL 60s
	resp = append(resp, 0x00, 0x04)             // RDLENGTH 4
	resp = append(resp, d.answerIP...)          // RDATA

	return resp, nil
}

// DNSManager owns one redirector per onboarding interface so each subnet's
// clients are answered with an address reachable from that subnet.
type DNSManager struct {
	mu          sync.Mutex
	redirectors []*DNSRedirector
}

// NewDNSManager returns an empty manager.
func NewDNSManager() *DNSManager {
	return &DNSManager{}
}

// StartOnboarding (re)starts redirectors bound to the given interface IPs.
// Each is best-effort: a bind failure (e.g. wlan0 IP not up yet) is logged and
// skipped rather than aborting onboarding. Pass an empty string to skip an
// interface. Safe to call repeatedly - it stops any existing redirectors first.
func (m *DNSManager) StartOnboarding(ethIP, wlanIP string) {
	m.Stop()

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, ip := range []string{ethIP, wlanIP} {
		if ip == "" {
			continue
		}
		red, err := NewDNSRedirector(ip, ip)
		if err != nil {
			log.Printf("Warning: DNS redirector for %s not created: %v", ip, err)
			continue
		}
		if err := red.Start(); err != nil {
			log.Printf("Warning: DNS redirector for %s not started: %v", ip, err)
			continue
		}
		m.redirectors = append(m.redirectors, red)
	}
}

// Stop tears down all running redirectors.
func (m *DNSManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, red := range m.redirectors {
		red.Stop()
	}
	m.redirectors = nil
}
