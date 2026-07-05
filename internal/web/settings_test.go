package web

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"ggo-kea-dhcp/internal/db"
)

// flashCookie returns the ggo_flash Set-Cookie from a recorded response, or nil.
func flashCookie(rr *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rr.Result().Cookies() {
		if c.Name == "ggo_flash" {
			return c
		}
	}
	return nil
}

// TestFlashCookieFlags proves the flash cookie carries the same protective flags
// as the session cookie (HttpOnly + SameSite=Strict + conditional Secure) on both
// the set and the delete write - it is only ever read server-side by getFlash.
func TestFlashCookieFlags(t *testing.T) {
	s := &Server{}

	rr := httptest.NewRecorder()
	s.setFlash(rr, httptest.NewRequest("GET", "/", nil), "hello", "info")
	c := flashCookie(rr)
	if c == nil {
		t.Fatal("setFlash wrote no ggo_flash cookie")
	}
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Errorf("setFlash cookie flags: HttpOnly=%v SameSite=%v, want HttpOnly=true SameSite=Strict", c.HttpOnly, c.SameSite)
	}
	if c.Secure {
		t.Error("setFlash over plain HTTP must not set Secure (onboarding runs on the HTTP SoftAP)")
	}

	// Over HTTPS (mirroring the session cookie's isHTTPS) Secure must be set.
	tlsReq := httptest.NewRequest("GET", "https://box/", nil)
	tlsReq.TLS = &tls.ConnectionState{}
	rrTLS := httptest.NewRecorder()
	s.setFlash(rrTLS, tlsReq, "hello", "info")
	if ct := flashCookie(rrTLS); ct == nil || !ct.Secure {
		t.Error("setFlash over HTTPS must set Secure")
	}

	// The delete rewrite in getFlash must carry the same flags.
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "ggo_flash", Value: c.Value})
	rr2 := httptest.NewRecorder()
	if f := s.getFlash(rr2, req); f == nil || f.Message != "hello" {
		t.Fatalf("getFlash did not round-trip the message, got %+v", f)
	}
	d := flashCookie(rr2)
	if d == nil {
		t.Fatal("getFlash wrote no delete cookie")
	}
	if !d.HttpOnly || d.SameSite != http.SameSiteStrictMode || d.MaxAge != -1 {
		t.Errorf("delete cookie flags: HttpOnly=%v SameSite=%v MaxAge=%d, want true/Strict/-1", d.HttpOnly, d.SameSite, d.MaxAge)
	}
}

// TestSettingsSaveActiveGuardHeld proves a soft change saved in ACTIVE while
// another reconcile holds the guard is refused OUTRIGHT: nothing persists (a value
// saved mid-apply would be silently clobbered by the apply's failure rollback,
// which restores the pre-apply uplink keys) and the operator is told to retry.
func TestSettingsSaveActiveGuardHeld(t *testing.T) {
	s, _ := newTestServer(t)
	if err := s.sqlite.SetState(db.LifecycleStateKey, db.StateActive); err != nil {
		t.Fatalf("set state: %v", err)
	}

	// Hold the guard, as an in-flight apply/switch would.
	if !s.beginReconcile() {
		t.Fatal("could not take the reconcile guard")
	}
	defer s.endReconcile()

	// A lease-lifetime different from the current value makes this a soft change
	// that wants the ACTIVE ModeConverge reconcile.
	form := url.Values{"lease_lifetime": {"3600"}}
	if s.leaseLifetime() == 3600 {
		form.Set("lease_lifetime", "7200")
	}
	req := httptest.NewRequest("POST", "/settings/save", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	s.handleSettingsSave(rr, req)

	c := flashCookie(rr)
	if c == nil {
		t.Fatal("no flash cookie set")
	}
	req2 := httptest.NewRequest("GET", "/settings", nil)
	req2.AddCookie(&http.Cookie{Name: "ggo_flash", Value: c.Value})
	f := s.getFlash(httptest.NewRecorder(), req2)
	if f == nil {
		t.Fatal("flash did not decode")
	}
	if !strings.Contains(f.Message, "NOT saved") || f.Type != "info" {
		t.Errorf("guard-held save flashed %q (%s), want the not-saved notice", f.Message, f.Type)
	}
	// The refused save must not have persisted anything: persisting before the
	// guard was the race that let an apply rollback clobber a mid-apply save.
	if got, _ := s.sqlite.GetState("lease_lifetime"); got == form.Get("lease_lifetime") {
		t.Errorf("refused save persisted lease_lifetime=%q anyway", got)
	}
}

// A save while an apply is mid-flight (CONFIGURING) persists the values but can
// schedule no reconcile - it must flash the deferred notice, not plain success,
// and must not claim the reconcile guard (issue #19).
func TestSettingsSaveConfiguringDefers(t *testing.T) {
	s, _ := newTestServer(t)
	if err := s.sqlite.SetState(db.LifecycleStateKey, db.StateConfiguring); err != nil {
		t.Fatalf("set state: %v", err)
	}

	form := url.Values{"lease_lifetime": {"3600"}}
	if s.leaseLifetime() == 3600 {
		form.Set("lease_lifetime", "7200")
	}
	req := httptest.NewRequest("POST", "/settings/save", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	s.handleSettingsSave(rr, req)

	c := flashCookie(rr)
	if c == nil {
		t.Fatal("no flash cookie set")
	}
	req2 := httptest.NewRequest("GET", "/settings", nil)
	req2.AddCookie(&http.Cookie{Name: "ggo_flash", Value: c.Value})
	f := s.getFlash(httptest.NewRecorder(), req2)
	if f == nil {
		t.Fatal("flash did not decode")
	}
	if f.Message != settingsDeferredMsg || f.Type != "info" {
		t.Errorf("CONFIGURING save flashed %q (%s), want the deferred notice", f.Message, f.Type)
	}
	// The handler must not have claimed the guard on this path: the in-flight
	// apply owns it. If the save took it, this begin would fail.
	if !s.beginReconcile() {
		t.Error("guard left claimed after a CONFIGURING save")
	} else {
		s.endReconcile()
	}
}

// A settings form rendered while ACTIVE carries the WiFi-uplink fields, but the
// uplink block runs only in ACTIVE - a submit landing after the flip to
// CONFIGURING drops them entirely. The deferred flash must say so instead of
// implying every field was saved.
func TestSettingsSaveConfiguringNamesDroppedUplink(t *testing.T) {
	s, _ := newTestServer(t)
	if err := s.sqlite.SetState(db.LifecycleStateKey, db.StateConfiguring); err != nil {
		t.Fatalf("set state: %v", err)
	}

	form := url.Values{
		"lease_lifetime": {"3600"},
		"uplink_enabled": {"on"},
		"uplink_ssid":    {"VenueNet"},
		"uplink_pass":    {"secret-pass"},
	}
	req := httptest.NewRequest("POST", "/settings/save", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	s.handleSettingsSave(rr, req)

	c := flashCookie(rr)
	if c == nil {
		t.Fatal("no flash cookie set")
	}
	req2 := httptest.NewRequest("GET", "/settings", nil)
	req2.AddCookie(&http.Cookie{Name: "ggo_flash", Value: c.Value})
	f := s.getFlash(httptest.NewRecorder(), req2)
	if f == nil {
		t.Fatal("flash did not decode")
	}
	if !strings.Contains(f.Message, "uplink") {
		t.Errorf("flash %q does not mention the dropped uplink fields", f.Message)
	}
	if ssid, _ := s.sqlite.GetState("uplink_ssid"); ssid == "VenueNet" {
		t.Error("the uplink fields were persisted in CONFIGURING - the message would then be wrong the other way")
	}

	// A submit WITHOUT uplink fields keeps the plain deferred message.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/settings/save", strings.NewReader(url.Values{"lease_lifetime": {"7200"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.handleSettingsSave(rr, req)
	c = flashCookie(rr)
	if c == nil {
		t.Fatal("no flash cookie on the second save")
	}
	req2 = httptest.NewRequest("GET", "/settings", nil)
	req2.AddCookie(&http.Cookie{Name: "ggo_flash", Value: c.Value})
	if f := s.getFlash(httptest.NewRecorder(), req2); f == nil || strings.Contains(f.Message, "uplink") {
		t.Errorf("uplink warning appeared on a save without uplink fields: %+v", f)
	}
}
