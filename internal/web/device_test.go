package web

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ggo-kea-dhcp/internal/arpscan"
	"ggo-kea-dhcp/internal/ggoscan"
)

// fakeScanner is an injectable DeviceScanner: a fixed inventory and a capture of the
// reboot sends, so a handler test never opens a real socket.
type fakeScanner struct {
	devices []ggoscan.Device
	sent    []string // IPs SendReboot was asked to reach
	sendErr error
}

func (f *fakeScanner) Start([]ggoscan.Spec) {}
func (f *fakeScanner) Stop()                {}
func (f *fakeScanner) Snapshot() ggoscan.Snapshot {
	return ggoscan.Snapshot{Devices: f.devices, Available: true}
}
func (f *fakeScanner) SendReboot(ip string) error {
	f.sent = append(f.sent, ip)
	return f.sendErr
}

// fakeProber is an injectable PresenceProber: a fixed reachable set and per-IP MAC,
// so a test can put a device at an address and answer an on-demand probe.
type fakeProber struct {
	reachable map[string]bool
	macAt     map[string]string
}

func (f *fakeProber) Start([]arpscan.Spec) {}
func (f *fakeProber) Stop()                {}
func (f *fakeProber) Snapshot() arpscan.Snapshot {
	return arpscan.Snapshot{ReachableIPs: f.reachable, Available: true}
}
func (f *fakeProber) ProbeHost(ip string) (string, bool) {
	m, ok := f.macAt[ip]
	return m, ok
}

// lastRebootAudit returns the newest DEVICE_REBOOT audit row's result and target.
func lastRebootAudit(t *testing.T, s *Server) (result, target string, found bool) {
	t.Helper()
	for _, a := range s.fetchRecentActivity(50) {
		if a.Action == "DEVICE_REBOOT" {
			return a.Result, a.Target, true
		}
	}
	return "", "", false
}

// TestFlashDeviceRoundTrip proves the extended flash cookie carries the reboot-offer
// device context (mac/ip/name) alongside the message, and getFlash reads it back.
func TestFlashDeviceRoundTrip(t *testing.T) {
	s, _ := newTestServer(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/reservations/add", nil)
	s.setFlashDevice(rec, req, "Reserved 10.0.0.20", "success", FlashDevice{MAC: "00:1f:80:aa:bb:cc", IP: "10.0.0.20", Name: "bpx-19666"})

	cookie := rec.Result().Cookies()[0]
	read := httptest.NewRequest("GET", "/leases", nil)
	read.AddCookie(cookie)
	f := s.getFlash(httptest.NewRecorder(), read)
	if f == nil {
		t.Fatal("getFlash returned nil for a freshly-set flash")
	}
	if f.Message != "Reserved 10.0.0.20" || f.Type != "success" {
		t.Errorf("message/type = %q/%q", f.Message, f.Type)
	}
	if f.Device == nil {
		t.Fatal("device context dropped from the flash")
	}
	if f.Device.IP != "10.0.0.20" || f.Device.Name != "bpx-19666" {
		t.Errorf("device = %+v, want ip 10.0.0.20 / name bpx-19666", f.Device)
	}
}

// TestGetFlashBareStringFallback proves an in-flight pre-schema cookie (a bare JSON
// string rather than the {message,type} object) still surfaces as a message instead
// of being silently dropped across a deploy.
func TestGetFlashBareStringFallback(t *testing.T) {
	s, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/leases", nil)
	req.AddCookie(&http.Cookie{Name: "ggo_flash", Value: hex.EncodeToString([]byte(`"legacy message"`))})
	f := s.getFlash(httptest.NewRecorder(), req)
	if f == nil || f.Message != "legacy message" {
		t.Fatalf("bare-string flash = %+v, want message %q", f, "legacy message")
	}
}

// TestRebootRefusesUnknownIP is the trust-boundary check: with no online Green-GO
// device backing the posted IP, the reboot is refused rather than sent. A bare Server
// (no arp prober, no scanner) can never confirm reachability, so eligibility fails.
func TestRebootRefusesUnknownIP(t *testing.T) {
	s, _ := newTestServer(t)
	if name, mac, fw, ok := s.rebootEligible(context.Background(), "10.0.0.20"); ok {
		t.Errorf("rebootEligible allowed an unbacked IP (name %q mac %q fw %q)", name, mac, fw)
	}
}

func TestFirmwareSupportsReboot(t *testing.T) {
	cases := map[string]bool{
		"BPX 5.2.2.25270": true,  // the 5.2.2 device that rebooted
		"BPX 5.2.0.100":   true,  // exactly the threshold
		"BPX 6.0.0.1":     true,  // newer major
		"BPX 5.3.0.0":     true,  // newer minor
		"BPX 5.1.0.14479": false, // the 5.1.0 device that ignored it
		"MCXi 5.0.7.9165": false,
		"BPX 5.2":         false, // fewer than 3 version fields
		"garbage":         false,
		"":                false,
	}
	for fw, want := range cases {
		if got := firmwareSupportsReboot(fw); got != want {
			t.Errorf("firmwareSupportsReboot(%q) = %v, want %v", fw, got, want)
		}
	}
}

// TestRebootDeviceName proves the display name goes through the shared hostname
// sanitizer, falling back to the MAC when the scan carried no usable name.
func TestRebootDeviceName(t *testing.T) {
	if got := rebootDeviceName(ggoscan.Device{Name: "BPX 19666", MAC: "00:1f:80:aa:bb:cc"}); got != "bpx-19666" {
		t.Errorf("name = %q, want bpx-19666", got)
	}
	if got := rebootDeviceName(ggoscan.Device{Name: "", MAC: "00:1f:80:aa:bb:cc"}); got != "00:1f:80:aa:bb:cc" {
		t.Errorf("nameless fallback = %q, want the MAC", got)
	}
}

// TestRebootHandlerRejectsBadIP proves the handler rejects a non-IPv4 target before
// any lookup or send.
func TestRebootHandlerRejectsBadIP(t *testing.T) {
	s, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/device/reboot", strings.NewReader("ip=not-an-ip"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.handleDeviceReboot(rec, req)
	if rec.Code != http.StatusSeeOther && rec.Code != http.StatusBadRequest {
		t.Errorf("bad-IP reboot status = %d, want a rejection", rec.Code)
	}
}

// postReboot drives the handler with a form body (the CSRF middleware is bypassed by
// calling the handler directly, like the other handler tests).
func postReboot(t *testing.T, s *Server, ip, mac string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	body := "ip=" + ip + "&mac=" + mac
	req := httptest.NewRequest("POST", "/device/reboot", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.handleDeviceReboot(rec, req)
	return rec
}

// rebootServerWithDevice wires a Server whose ARP prober puts one Green-GO device at
// ip (lease absent, so the handler falls to the ARP probe - the just-released path)
// and whose scanner knows that MAC as a Green-GO client.
func rebootServerWithDevice(t *testing.T, ip, mac, name string) (*Server, *fakeScanner) {
	t.Helper()
	s, _ := newTestServer(t)
	sc := &fakeScanner{devices: []ggoscan.Device{{MAC: mac, Name: name, IP: ip, Firmware: "BPX 5.2.2.25270"}}}
	s.mon.Ggoscan = sc
	s.mon.Arp = &fakeProber{
		reachable: map[string]bool{ip: true},
		macAt:     map[string]string{ip: mac},
	}
	return s, sc
}

// TestRebootMACMismatchRefused is the TOCTOU gate: the operator was offered a reboot
// for one device, but by confirm time the address is answered by a different MAC (the
// pool re-issued it). The posted MAC no longer matches the live occupant, so the reboot
// must be refused and audited, never sent.
func TestRebootMACMismatchRefused(t *testing.T) {
	ip := "10.0.0.20"
	live := "00:1f:80:aa:bb:cc" // who actually holds .20 now
	s, sc := rebootServerWithDevice(t, ip, live, "BPX 19666")

	// The operator confirms with the MAC of the device that USED to be at .20.
	postReboot(t, s, ip, "00:1f:80:11:22:33")

	if len(sc.sent) != 0 {
		t.Fatalf("reboot was sent to %v despite a MAC mismatch", sc.sent)
	}
	result, _, found := lastRebootAudit(t, s)
	if !found || result != "WARNING" {
		t.Errorf("mismatch audit = %q (found %v), want a WARNING", result, found)
	}
}

// TestRebootMissingMACRefused proves a confirm without a target MAC (a forged or
// pre-freshness-gate request) is refused even when a valid Green-GO device is at the IP.
func TestRebootMissingMACRefused(t *testing.T) {
	ip := "10.0.0.20"
	mac := "00:1f:80:aa:bb:cc"
	s, sc := rebootServerWithDevice(t, ip, mac, "BPX 19666")

	postReboot(t, s, ip, "")

	if len(sc.sent) != 0 {
		t.Fatalf("reboot sent with no target MAC: %v", sc.sent)
	}
	if result, _, found := lastRebootAudit(t, s); !found || result != "WARNING" {
		t.Errorf("no-MAC audit = %q (found %v), want a WARNING", result, found)
	}
}

// TestRebootSuccess is the positive path: a known Green-GO device answers ARP at the
// IP with the same MAC the operator confirmed, so the reboot is sent once and audited
// SUCCESS. Exercises the just-released flow (no lease, MAC via the ARP probe).
func TestRebootSuccess(t *testing.T) {
	ip := "10.0.0.20"
	mac := "00:1f:80:aa:bb:cc"
	s, sc := rebootServerWithDevice(t, ip, mac, "BPX 19666")

	// A mixed-case, colon-form posted MAC must still match (normalized comparison).
	postReboot(t, s, ip, "00:1F:80:AA:BB:CC")

	if len(sc.sent) != 1 || sc.sent[0] != ip {
		t.Fatalf("reboot sends = %v, want exactly [%s]", sc.sent, ip)
	}
	result, target, found := lastRebootAudit(t, s)
	if !found || result != "SUCCESS" {
		t.Errorf("success audit = %q (found %v), want SUCCESS", result, found)
	}
	if !strings.Contains(target, "bpx-19666") {
		t.Errorf("audit target = %q, want the sanitized device name", target)
	}
}

// TestRebootUnbackedIPRefused proves an IP with no online device behind it (nil scanner
// and prober) is refused with a WARNING audit and never sent.
func TestRebootUnbackedIPRefused(t *testing.T) {
	s, _ := newTestServer(t)
	rec := postReboot(t, s, "10.0.0.99", "00:1f:80:aa:bb:cc")
	_ = rec
	if result, _, found := lastRebootAudit(t, s); !found || result != "WARNING" {
		t.Errorf("unbacked audit = %q (found %v), want a WARNING", result, found)
	}
}
