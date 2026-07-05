package web

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"ggo-kea-dhcp/internal/db"
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

// TestSystemPowerControlsRequireReauth proves reboot and poweroff re-auth like the
// other danger-zone actions: a wrong or absent current password is refused before the
// privileged command is scheduled (the handler returns an error, not the interstitial).
func TestSystemPowerControlsRequireReauth(t *testing.T) {
	cases := []struct {
		name    string
		handler func(*Server) func(http.ResponseWriter, *http.Request)
	}{
		{"reboot", func(s *Server) func(http.ResponseWriter, *http.Request) { return s.handleSystemReboot }},
		{"poweroff", func(s *Server) func(http.ResponseWriter, *http.Request) { return s.handleSystemPowerOff }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, _ := newTestServer(t)
			seedAdmin(t, s, "the-real-password")
			h := c.handler(s)

			// Wrong password: refused, not the reconnect interstitial (200).
			rr := httptest.NewRecorder()
			h(rr, postForm(url.Values{"current_password": {"nope"}}))
			if rr.Code == http.StatusOK {
				t.Errorf("wrong-password %s returned 200 - it should have been refused before the command", c.name)
			}
			// Absent password: also refused.
			rr = httptest.NewRecorder()
			h(rr, postForm(url.Values{}))
			if rr.Code == http.StatusOK {
				t.Errorf("no-password %s returned 200 - it should have been refused", c.name)
			}
		})
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

// TestMiddlewareBoundsRequestBody proves the CSRF middleware's form-parse fallback
// cannot be abused to spill an unbounded upload: an over-cap multipart POST is
// rejected with 413 before any handler runs, a within-cap form with the session's
// token still passes, and an empty stored CSRF token never matches an empty
// submission.
func TestMiddlewareBoundsRequestBody(t *testing.T) {
	s, _ := newTestServer(t)
	seedAdmin(t, s, "pw")
	if err := s.sqlite.SetState(db.LifecycleStateKey, db.StateActive); err != nil {
		t.Fatalf("set state: %v", err)
	}
	sid, err := s.createSession("admin")
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	_, csrf, ok := s.sessionUser(sid)
	if !ok || csrf == "" {
		t.Fatal("sessionUser should return the fresh session with a csrf token")
	}

	var reached bool
	h := s.lifecycleMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	serve := func(req *http.Request) *httptest.ResponseRecorder {
		reached = false
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	// Over-cap multipart upload: the middleware bounds the body before the CSRF
	// form-parse, so the handler never runs and the rejection surfaces as an in-app
	// error (flash + 303 redirect via handleError), not a bare 413 page.
	var big bytes.Buffer
	mw := multipart.NewWriter(&big)
	fw, _ := mw.CreateFormFile("backup", "huge.json")
	_, _ = fw.Write(bytes.Repeat([]byte("x"), maxRequestBody+1024))
	_ = mw.Close()
	req := httptest.NewRequest("POST", "/settings/restore", &big)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr := serve(req)
	if rr.Code != http.StatusSeeOther {
		t.Errorf("over-cap upload: status=%d want 303 (in-app error flash + redirect)", rr.Code)
	}
	if reached {
		t.Error("over-cap upload reached the handler")
	}
	if flashCookie(rr) == nil {
		t.Error("over-cap upload should set an error flash (in-app notification)")
	}

	// Within-cap form carrying the right token: passes through to the handler.
	req = postForm(url.Values{"csrf_token": {csrf}})
	if rr := serve(req); !reached {
		t.Errorf("valid within-cap form did not reach the handler (status=%d)", rr.Code)
	}

	// An empty stored token must not match an empty submission (the sessions read
	// COALESCEs NULL to "" - an equal-empty compare would be a CSRF bypass).
	if _, err := s.sqlite.Exec("UPDATE sessions SET csrf_token = '' WHERE session_id = ?", sid); err != nil {
		t.Fatalf("blank csrf token: %v", err)
	}
	req = postForm(url.Values{})
	if rr := serve(req); rr.Code != http.StatusForbidden {
		t.Errorf("empty-token request with empty stored token: status=%d want 403", rr.Code)
	}
	if reached {
		t.Error("empty-vs-empty CSRF compare reached the handler")
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
		{"no origin, no referer - rejected (fail closed)", mk("POST", "", ""), false},
		{"cross-origin via referer", mk("POST", "", "https://evil.example/x"), false},
		{"same-origin via referer", mk("POST", "", "http://box.local/factory"), true},
	}
	for _, c := range cases {
		if got := sameOriginRequest(c.req); got != c.wantOK {
			t.Errorf("%s: sameOriginRequest = %v, want %v", c.name, got, c.wantOK)
		}
	}
}
