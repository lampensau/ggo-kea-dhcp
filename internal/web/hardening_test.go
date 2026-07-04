package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// seedAdmin inserts an admin user with a known password so the re-auth helper (which
// resolves the actor to "admin" when there is no session) has a credential to check.
func seedAdmin(t *testing.T, s *Server, password string) {
	t.Helper()
	h, err := hashPassword(password)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if _, err := s.sqlite.Exec("INSERT INTO users (username, password_hash) VALUES ('admin', ?)", h); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
}

func postForm(values url.Values) *http.Request {
	req := httptest.NewRequest("POST", "/", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestReauthCurrentPassword(t *testing.T) {
	s, _ := newTestServer(t)
	seedAdmin(t, s, "correct horse battery staple")

	if ok, _ := s.reauthCurrentPassword(postForm(url.Values{"current_password": {"correct horse battery staple"}})); !ok {
		t.Error("correct password should re-auth")
	}
	if ok, reason := s.reauthCurrentPassword(postForm(url.Values{"current_password": {"wrong"}})); ok || reason == "" {
		t.Errorf("wrong password should fail with a reason, got ok=%v reason=%q", ok, reason)
	}
	if ok, _ := s.reauthCurrentPassword(postForm(url.Values{})); ok {
		t.Error("missing password should fail")
	}
}

// TestHandleResetFactoryRejectsWrongPassword proves the factory-reset handler
// re-auths before wiping: a wrong password is rejected and the admin survives.
func TestHandleResetFactoryRejectsWrongPassword(t *testing.T) {
	s, _ := newTestServer(t)
	seedAdmin(t, s, "the-real-password")

	rr := httptest.NewRecorder()
	s.handleResetFactory(rr, postForm(url.Values{"current_password": {"nope"}}))

	// The handler surfaces form errors as a flash + redirect, not a raw 400 - the
	// security property to assert is that the wipe did NOT run: the admin survives.
	if rr.Code == http.StatusOK {
		t.Errorf("wrong-password factory reset returned 200 (interstitial) - it should have been refused before the wipe")
	}
	var n int
	if err := s.sqlite.QueryRow("SELECT COUNT(*) FROM users").Scan(&n); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if n != 1 {
		t.Errorf("admin was wiped despite a wrong password (users=%d) - re-auth did not gate the wipe", n)
	}
}

func TestValidateUplinkRejectsInjectionAndBadPassphrase(t *testing.T) {
	cases := []struct {
		name, ssid, pass string
		wantOK           bool
	}{
		{"valid", "ShowNet", "goodpass8", true},
		{"leading dash SSID", "-h", "goodpass8", false},
		{"double dash SSID", "--help", "goodpass8", false},
		{"non-ascii passphrase", "ShowNet", "passéword", false},
		{"control char passphrase", "ShowNet", "pass\tword", false},
		{"open network ok", "ShowNet", "", true},
		{"empty ssid", "", "goodpass8", false},
	}
	for _, c := range cases {
		msg := validateUplink(c.ssid, c.pass)
		if (msg == "") != c.wantOK {
			t.Errorf("%s: validateUplink(%q,%q)=%q, wantOK=%v", c.name, c.ssid, c.pass, msg, c.wantOK)
		}
	}
}

func TestSameOriginRequest(t *testing.T) {
	mk := func(method, origin, referer string) *http.Request {
		r := httptest.NewRequest(method, "http://box.local/factory/setup", nil)
		r.Host = "box.local"
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if referer != "" {
			r.Header.Set("Referer", referer)
		}
		return r
	}
	cases := []struct {
		name   string
		req    *http.Request
		wantOK bool
	}{
		{"GET always ok", mk("GET", "https://evil.example", ""), true},
		{"same-origin POST", mk("POST", "http://box.local", ""), true},
		{"cross-origin POST", mk("POST", "https://evil.example", ""), false},
		{"no origin, no referer - allowed", mk("POST", "", ""), true},
		{"cross-origin via referer", mk("POST", "", "https://evil.example/x"), false},
		{"same-origin via referer", mk("POST", "", "http://box.local/factory"), true},
	}
	for _, c := range cases {
		if got := sameOriginRequest(c.req); got != c.wantOK {
			t.Errorf("%s: sameOriginRequest = %v, want %v", c.name, got, c.wantOK)
		}
	}
}
