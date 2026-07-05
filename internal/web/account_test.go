package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// accountRequest builds a sessioned POST to /account/save for the given form
// values, returning the recorder. sessionID may be empty (no cookie).
func accountRequest(t *testing.T, s *Server, sessionID string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := postForm(form)
	if sessionID != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})
	}
	rr := httptest.NewRecorder()
	s.handleAccountSave(rr, req)
	return rr
}

func userPasswordHash(t *testing.T, s *Server, username string) string {
	t.Helper()
	var h string
	if err := s.sqlite.QueryRow("SELECT password_hash FROM users WHERE username = ?", username).Scan(&h); err != nil {
		t.Fatalf("load hash for %q: %v", username, err)
	}
	return h
}

// TestAccountSaveRequiresReauth proves neither a rename nor a password change
// lands without the correct current password.
func TestAccountSaveRequiresReauth(t *testing.T) {
	s, _ := newTestServer(t)
	seedAdmin(t, s, "correct horse battery staple")
	sid, err := s.createSession("admin")
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	for _, form := range []url.Values{
		{"username": {"stagehand"}, "current_password": {"wrong"}},
		{"username": {"stagehand"}}, // missing entirely
		{"new_password": {"a brand new passphrase"}, "confirm_password": {"a brand new passphrase"}, "current_password": {"wrong"}},
	} {
		before := userPasswordHash(t, s, "admin")
		accountRequest(t, s, sid, form)
		var n int
		if err := s.sqlite.QueryRow("SELECT COUNT(*) FROM users WHERE username = 'admin'").Scan(&n); err != nil || n != 1 {
			t.Fatalf("form %v: admin row gone (n=%d err=%v) - change applied without re-auth", form, n, err)
		}
		if userPasswordHash(t, s, "admin") != before {
			t.Fatalf("form %v: password hash changed without re-auth", form)
		}
	}
}

// TestAccountSaveMinLength proves the 12-character password floor survived the
// move out of the settings handler.
func TestAccountSaveMinLength(t *testing.T) {
	s, _ := newTestServer(t)
	seedAdmin(t, s, "correct horse battery staple")
	sid, err := s.createSession("admin")
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	before := userPasswordHash(t, s, "admin")
	accountRequest(t, s, sid, url.Values{
		"new_password":     {"elevenchars"},
		"confirm_password": {"elevenchars"},
		"current_password": {"correct horse battery staple"},
	})
	if userPasswordHash(t, s, "admin") != before {
		t.Fatal("an 11-character password was accepted")
	}
	// Mismatched confirmation is also rejected.
	accountRequest(t, s, sid, url.Values{
		"new_password":     {"a brand new passphrase"},
		"confirm_password": {"a different passphrase"},
		"current_password": {"correct horse battery staple"},
	})
	if userPasswordHash(t, s, "admin") != before {
		t.Fatal("a mismatched confirmation was accepted")
	}
}

// TestAccountSaveRenameRewritesSession proves a rename updates the users row,
// keeps the live session valid under the new name, and audits CHANGE_USERNAME.
func TestAccountSaveRenameRewritesSession(t *testing.T) {
	s, _ := newTestServer(t)
	seedAdmin(t, s, "correct horse battery staple")
	sid, err := s.createSession("admin")
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	rr := accountRequest(t, s, sid, url.Values{
		"username":         {"stagehand"},
		"current_password": {"correct horse battery staple"},
	})
	if rr.Code != http.StatusFound {
		t.Fatalf("rename response = %d, want 302 redirect", rr.Code)
	}

	var n int
	if err := s.sqlite.QueryRow("SELECT COUNT(*) FROM users WHERE username = 'stagehand'").Scan(&n); err != nil || n != 1 {
		t.Fatalf("renamed user rows = %d (err=%v), want 1", n, err)
	}
	var sessUser string
	if err := s.sqlite.QueryRow("SELECT username FROM sessions WHERE session_id = ?", sid).Scan(&sessUser); err != nil {
		t.Fatalf("session row gone after rename: %v", err)
	}
	if sessUser != "stagehand" {
		t.Fatalf("session username = %q, want rewritten to %q", sessUser, "stagehand")
	}
	if err := s.sqlite.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action = 'CHANGE_USERNAME'").Scan(&n); err != nil || n != 1 {
		t.Fatalf("CHANGE_USERNAME audit rows = %d (err=%v), want 1", n, err)
	}
}

// TestAccountSavePasswordRevokesOtherSessions proves a password change keeps the
// current session, deletes every other one, applies the new hash, and audits
// CHANGE_PASSWORD.
func TestAccountSavePasswordRevokesOtherSessions(t *testing.T) {
	s, _ := newTestServer(t)
	seedAdmin(t, s, "correct horse battery staple")
	mine, err := s.createSession("admin")
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	other, err := s.createSession("admin")
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	accountRequest(t, s, mine, url.Values{
		"new_password":     {"a brand new passphrase"},
		"confirm_password": {"a brand new passphrase"},
		"current_password": {"correct horse battery staple"},
	})

	if !verifyPassword(userPasswordHash(t, s, "admin"), "a brand new passphrase") {
		t.Fatal("new password does not verify after the change")
	}
	var n int
	if err := s.sqlite.QueryRow("SELECT COUNT(*) FROM sessions WHERE session_id = ?", mine).Scan(&n); err != nil || n != 1 {
		t.Fatalf("current session rows = %d (err=%v), want it kept", n, err)
	}
	if err := s.sqlite.QueryRow("SELECT COUNT(*) FROM sessions WHERE session_id = ?", other).Scan(&n); err != nil || n != 0 {
		t.Fatalf("other session rows = %d (err=%v), want revoked", n, err)
	}
	if err := s.sqlite.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action = 'CHANGE_PASSWORD'").Scan(&n); err != nil || n != 1 {
		t.Fatalf("CHANGE_PASSWORD audit rows = %d (err=%v), want 1", n, err)
	}
}
