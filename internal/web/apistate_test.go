package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"ggo-kea-dhcp/internal/db"
)

// TestAPIStateBypassesAuthInMiddleware proves the lifecycleMiddleware lets an
// UNAUTHENTICATED GET /api/state through to the handler (the public lifecycle probe
// the CONFIGURING page polls), while a normal authenticated path without a session
// is still redirected to /login. Guards the `path == "/api/state"` whitelist.
func TestAPIStateBypassesAuthInMiddleware(t *testing.T) {
	s, _ := newTestServer(t)
	if err := s.sqlite.SetState(db.LifecycleStateKey, db.StateActive); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	reached := false
	h := s.lifecycleMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	// /api/state must bypass auth and reach the handler.
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/api/state", nil))
	if !reached || rr.Code != http.StatusOK {
		t.Fatalf("/api/state did not bypass auth: reached=%v code=%d (want true/200)", reached, rr.Code)
	}

	// Control: a normal authed path with no session cookie must 302 to /login.
	reached = false
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, httptest.NewRequest("GET", "/dashboard", nil))
	if reached || rr2.Code != http.StatusFound {
		t.Fatalf("/dashboard should 302 to /login unauthenticated: reached=%v code=%d", reached, rr2.Code)
	}
}
