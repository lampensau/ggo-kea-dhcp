package web

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"ggo-kea-dhcp/internal/db"
)

// Guard-chain tests for the auth and pre-auth-restore handlers: the logic below
// them is tested elsewhere, but the ORDER of the guards is what a one-line
// regression breaks - and here that means pre-auth database overwrite or a
// throttle bypass.

func authTestServer(t *testing.T) *Server {
	t.Helper()
	s, _ := newTestServer(t)
	s.loginThrottle = newLoginThrottle()
	return s
}

func loginPost(user, pass string) *http.Request {
	v := url.Values{"username": {user}, "password": {pass}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func factoryRestoreReq(t *testing.T, bundle []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("backup", "b.json")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write(bundle)
	_ = mw.Close()
	req := httptest.NewRequest("POST", "/factory/restore", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

func validBundle(t *testing.T, s *Server, withUsers bool) []byte {
	t.Helper()
	var schema int
	_ = s.sqlite.QueryRow("PRAGMA user_version;").Scan(&schema)
	b := &Backup{Format: backupFormat, AppSchema: schema, Lifecycle: db.StateOnboarding}
	if withUsers {
		b.Users = []BackupUser{{Username: "restored", PasswordHash: "hash"}}
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func auditCount(t *testing.T, s *Server, action string) int {
	t.Helper()
	var n int
	if err := s.sqlite.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action = ?", action).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", action, err)
	}
	return n
}

// The lifecycle guard must fire FIRST: outside FACTORY the pre-auth restore is a
// takeover primitive (it installs the bundle's admin hash with no password), so
// a configured box refuses before touching the throttle, the audit trail, or
// the upload.
func TestFactoryRestoreRefusedOutsideFactory(t *testing.T) {
	for _, state := range []string{db.StateOnboarding, db.StateConfiguring, db.StateActive} {
		t.Run(state, func(t *testing.T) {
			s := authTestServer(t)
			if err := s.sqlite.SetState(db.LifecycleStateKey, state); err != nil {
				t.Fatal(err)
			}
			rr := httptest.NewRecorder()
			s.handleFactoryRestore(rr, factoryRestoreReq(t, validBundle(t, s, true)))

			// handleError answers a native form POST with a flash + 303 redirect
			// (post-redirect-get), so the refusal shape is the 303 - the real
			// assertions are the untouched database below.
			if rr.Code != http.StatusSeeOther {
				t.Errorf("state %s: code = %d, want the 303 refusal redirect", state, rr.Code)
			}
			var users int
			_ = s.sqlite.QueryRow("SELECT COUNT(*) FROM users").Scan(&users)
			if users != 0 {
				t.Error("the bundle's admin was installed despite the lifecycle guard")
			}
			if n := auditCount(t, s, "FACTORY_RESTORE_ATTEMPT"); n != 0 {
				t.Errorf("attempt audited before the lifecycle guard (%d rows)", n)
			}
		})
	}
}

// In FACTORY every attempt must be audited BEFORE the bundle is applied - a
// takeover leaves a trail even when the upload is garbage.
func TestFactoryRestoreAuditsEveryAttempt(t *testing.T) {
	s := authTestServer(t)

	rr := httptest.NewRecorder()
	s.handleFactoryRestore(rr, factoryRestoreReq(t, []byte("not json")))
	if rr.Code != http.StatusSeeOther {
		t.Errorf("garbage upload = %d, want the 303 refusal redirect", rr.Code)
	}
	if n := auditCount(t, s, "FACTORY_RESTORE_ATTEMPT"); n != 1 {
		t.Errorf("garbage attempt audit rows = %d, want 1 (trail before apply)", n)
	}

	// A bundle without an administrator cannot recover a factory box.
	rr = httptest.NewRecorder()
	s.handleFactoryRestore(rr, factoryRestoreReq(t, validBundle(t, s, false)))
	if rr.Code != http.StatusSeeOther {
		t.Errorf("admin-less bundle = %d, want the 303 refusal redirect", rr.Code)
	}
	var users int
	_ = s.sqlite.QueryRow("SELECT COUNT(*) FROM users").Scan(&users)
	if users != 0 {
		t.Error("an admin-less bundle wrote users")
	}
}

// The happy path: a valid bundle restores the admin and moves the lifecycle.
func TestFactoryRestoreHappyPath(t *testing.T) {
	s := authTestServer(t)

	rr := httptest.NewRecorder()
	s.handleFactoryRestore(rr, factoryRestoreReq(t, validBundle(t, s, true)))

	var users int
	_ = s.sqlite.QueryRow("SELECT COUNT(*) FROM users WHERE username = 'restored'").Scan(&users)
	if users != 1 {
		t.Fatalf("restored admin rows = %d, want 1 (code %d, body %s)", users, rr.Code, rr.Body.String())
	}
	if st, _ := s.sqlite.GetState(db.LifecycleStateKey); st != db.StateOnboarding {
		t.Errorf("lifecycle = %q, want the bundle's ONBOARDING", st)
	}
}

// The throttle must fire BEFORE credential verification: once an IP is inside
// the backoff window, even the CORRECT password is refused - otherwise the
// throttle is a brute-force speed bump only for wrong guesses.
func TestLoginThrottleBeforeCredentials(t *testing.T) {
	s := authTestServer(t)
	seedAdmin(t, s, "correct-horse-battery")

	for i := 0; i < loginFreebies+1; i++ {
		rr := httptest.NewRecorder()
		s.handleLoginSubmit(rr, loginPost("admin", "wrong"))
	}

	rr := httptest.NewRecorder()
	s.handleLoginSubmit(rr, loginPost("admin", "correct-horse-battery"))

	var sessions int
	_ = s.sqlite.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&sessions)
	if sessions != 0 {
		t.Error("a throttled IP minted a session with the correct password")
	}
	for _, c := range rr.Result().Cookies() {
		if c.Name == sessionCookieName && c.Value != "" {
			t.Error("a throttled login set a session cookie")
		}
	}
}

// Unknown-username and wrong-password must be indistinguishable in status and
// body, so an attacker cannot enumerate accounts.
func TestLoginFailureIndistinguishable(t *testing.T) {
	s := authTestServer(t)
	seedAdmin(t, s, "correct-horse-battery")

	rrUnknown := httptest.NewRecorder()
	s.handleLoginSubmit(rrUnknown, loginPost("nobody", "x"))
	rrWrong := httptest.NewRecorder()
	s.handleLoginSubmit(rrWrong, loginPost("admin", "wrong"))

	if rrUnknown.Code != rrWrong.Code {
		t.Errorf("status codes differ: unknown=%d wrong=%d", rrUnknown.Code, rrWrong.Code)
	}
	if rrUnknown.Body.String() != rrWrong.Body.String() {
		t.Error("response bodies differ between unknown-user and wrong-password")
	}
}

// A successful login mints exactly one session and sets the cookie.
func TestLoginSuccessMintsSession(t *testing.T) {
	s := authTestServer(t)
	seedAdmin(t, s, "correct-horse-battery")

	rr := httptest.NewRecorder()
	s.handleLoginSubmit(rr, loginPost("admin", "correct-horse-battery"))

	if rr.Code != http.StatusFound {
		t.Errorf("success = %d, want 302", rr.Code)
	}
	var sessions int
	_ = s.sqlite.QueryRow("SELECT COUNT(*) FROM sessions WHERE username = 'admin'").Scan(&sessions)
	if sessions != 1 {
		t.Errorf("session rows = %d, want 1", sessions)
	}
	var got string
	for _, c := range rr.Result().Cookies() {
		if c.Name == sessionCookieName {
			got = c.Value
		}
	}
	if got == "" {
		t.Error("no session cookie set on success")
	}
	if n := auditCount(t, s, "LOGIN"); n != 1 {
		t.Errorf("LOGIN audit rows = %d, want 1", n)
	}
}

// Logout must delete the session row (not just the cookie) and clear the cookie.
func TestLogoutDeletesSessionAndClearsCookie(t *testing.T) {
	s := authTestServer(t)
	seedAdmin(t, s, "pw")
	sid, err := s.createSession("admin")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "/logout", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	rr := httptest.NewRecorder()
	s.handleLogout(rr, req)

	var sessions int
	_ = s.sqlite.QueryRow("SELECT COUNT(*) FROM sessions WHERE session_id = ?", sid).Scan(&sessions)
	if sessions != 0 {
		t.Error("session row survives logout - the cookie alone was cleared")
	}
	cleared := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == sessionCookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("logout did not clear the session cookie")
	}
	if n := auditCount(t, s, "LOGOUT"); n != 1 {
		t.Errorf("LOGOUT audit rows = %d, want 1", n)
	}

	// A cookie-less logout must be safe (no panic, still clears client state).
	rr = httptest.NewRecorder()
	s.handleLogout(rr, httptest.NewRequest("POST", "/logout", nil))
}
