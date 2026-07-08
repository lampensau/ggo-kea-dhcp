package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"ggo-kea-dhcp/internal/db"
)

// TestSessionSlideGate pins the in-process slide gate (lifecycleMiddleware): a session
// whose idle window is inside the slide zone (<50 min left) must still slide and re-issue
// the cookie, while one with plenty of time left must not. A wrong threshold (e.g. gating
// on the wrong bound) would silently stop sliding live sessions - this catches that.
func TestSessionSlideGate(t *testing.T) {
	s, _ := newTestServer(t)
	seedAdmin(t, s, "pw")
	if err := s.sqlite.SetState(db.LifecycleStateKey, db.StateActive); err != nil {
		t.Fatalf("set state: %v", err)
	}

	h := s.lifecycleMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	// slid reports whether a GET as this session re-issued the session cookie, which the
	// middleware does only when the slide UPDATE actually moved expires_at.
	slid := func(expiresExpr string) bool {
		sid, err := s.createSession("admin")
		if err != nil {
			t.Fatalf("createSession: %v", err)
		}
		if _, err := s.sqlite.Exec("UPDATE sessions SET expires_at = datetime('now', ?) WHERE session_id = ?", expiresExpr, sid); err != nil {
			t.Fatalf("set expires_at: %v", err)
		}
		req := httptest.NewRequest("GET", "/dashboard", nil)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		for _, c := range rr.Result().Cookies() {
			if c.Name == sessionCookieName {
				return true
			}
		}
		return false
	}

	if slid("+59 minutes") {
		t.Error("session with 59 min left should NOT slide (outside the 50-min slide zone)")
	}
	if !slid("+40 minutes") {
		t.Error("session with 40 min left MUST slide (inside the 50-min slide zone)")
	}
}
