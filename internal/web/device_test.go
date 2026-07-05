package web

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ggo-kea-dhcp/internal/ggoscan"
)

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
	if name, ok := s.rebootEligible(context.Background(), "10.0.0.20"); ok {
		t.Errorf("rebootEligible allowed an unbacked IP (name %q)", name)
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
