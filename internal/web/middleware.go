package web

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"ggo-kea-dhcp/internal/db"
)

// maxRequestBody bounds every authenticated mutating request's body, applied in
// lifecycleMiddleware before the CSRF check's form parse. Sized to the largest
// legitimate upload (a backup bundle / reservations CSV - see maxBackupUpload).
const maxRequestBody = maxBackupUpload

// isUnsafeMethod reports whether the HTTP method mutates state (and thus needs
// CSRF validation).
func isUnsafeMethod(m string) bool {
	switch m {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// sameOriginRequest is the pre-session CSRF defense for the FACTORY-state bootstrap
// POSTs (/factory/setup, /factory/restore), which run before any session or CSRF
// token exists. For an unsafe method it requires the Origin (else Referer) header to
// match the request Host. A cross-origin browser POST always carries a mismatched
// Origin and is rejected; a legitimate same-origin submit matches. When both headers
// are absent it fails closed: browsers always send at least one on an unsafe request
// (a fetch/@post sends Origin, a native <form> POST sends Referer), so only header-less
// scripted clients (curl) are blocked.
//
// ACCEPTED RISK (reviewed): a forged Origin defeats this CSRF check, and no in-request
// control can fix that (first-admin creation is unauthenticated by necessity). Accepted
// because FACTORY is not attacker-inducible and short-lived; do not re-file.
func sameOriginRequest(r *http.Request) bool {
	if !isUnsafeMethod(r.Method) {
		return true
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		if ref := r.Header.Get("Referer"); ref != "" {
			if u, err := url.Parse(ref); err == nil {
				origin = u.Scheme + "://" + u.Host
			}
		}
	}
	if origin == "" {
		return false // no Origin/Referer to check - fail closed (browsers always send one)
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return u.Host == r.Host
}

func (s *Server) lifecycleMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.HasPrefix(path, "/static/") || path == "/api/state" {
			// /api/state is the public lifecycle-state probe the CONFIGURING page polls
			// to reload itself once the apply finishes (no auth, reachable in any state).
			next.ServeHTTP(w, r)
			return
		}

		state, _ := s.sqlite.GetState(db.LifecycleStateKey)
		if state == "" {
			state = db.StateFactory
		}

		// State: FACTORY - only the admin-bootstrap pages are reachable, and only
		// pre-auth (there is no admin yet). /wifi/scan is no longer exposed here.
		if state == db.StateFactory {
			if path != "/factory" && path != "/factory/setup" && path != "/factory/restore" {
				http.Redirect(w, r, "/factory", http.StatusFound)
				return
			}
			// These POSTs run with no session/CSRF token (no admin exists yet), so a
			// same-origin check is the only CSRF defense available - reject a
			// cross-origin bootstrap/recovery POST before it can create an admin or
			// restore a crafted bundle.
			if !sameOriginRequest(r) {
				http.Error(w, "cross-origin request rejected", http.StatusForbidden)
				return
			}
			// Bound the body like the authenticated branch does: handleFactorySetup
			// ParseForms pre-auth, so without this a SoftAP client could spill a
			// multi-GB body into RAM before any admin exists. handleFactoryRestore also
			// self-caps; this makes the guard uniform across both bootstrap POSTs.
			if isUnsafeMethod(r.Method) {
				r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
			}
			next.ServeHTTP(w, r)
			return
		}

		// Authenticate via session cookie.
		var authenticated bool
		var csrfToken string
		if cookie, err := r.Cookie(sessionCookieName); err == nil && cookie.Value != "" {
			if _, csrf, expiresAt, ok := s.sessionUser(cookie.Value); ok {
				authenticated = true
				csrfToken = csrf

				// Slide the 1h idle window forward, but at most ~once / 10 min (the 1h
				// TTL minus a 50-min floor) to avoid a DB write on every authenticated
				// request (the SSE live stream + Datastar actions). The read above already
				// returned expires_at, so gate the write in-process: ~5/6 of requests are
				// outside the slide zone and skip the 0-row UPDATE on the pinned single
				// connection entirely. The SQL WHERE stays the authoritative guard, so a
				// boundary/clock-skew miss only costs a one-request-late slide, never a
				// wrong window. When it actually slides, re-issue the cookie so the
				// browser's 1h MaxAge tracks the server window (the 12h absolute cap lives
				// in created_at, enforced in sessionUser). Past the cap, sessionUser
				// already failed auth above.
				if time.Until(expiresAt) < 50*time.Minute {
					if res, err := s.sqlite.Exec("UPDATE sessions SET expires_at = datetime('now', '+1 hour') WHERE session_id = ? AND expires_at < datetime('now', '+50 minutes')", cookie.Value); err == nil {
						if n, _ := res.RowsAffected(); n > 0 {
							setSessionCookie(w, r, cookie.Value)
						}
					}
				}
			}
		}

		if !authenticated {
			if path != "/login" {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// CSRF: every state-changing request from an authenticated session must
		// carry the matching token (htmx sends it as a header; forms as a field).
		// SameSite=Strict on the cookie is the primary mitigation; this is the
		// defense-in-depth token check.
		if isUnsafeMethod(r.Method) {
			// Bound the body BEFORE the FormValue fallback below: FormValue parses the
			// whole (multipart) body into RAM and temp files, and this middleware runs
			// ahead of every handler - so this is the appliance's real upload cap. A
			// handler-level MaxBytesReader for a form POST would be dead code (the body
			// is already consumed and the parsed form cached by the time it runs).
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
			provided := r.Header.Get("X-CSRF-Token")
			if provided == "" {
				// Parse explicitly (FormValue swallows parse errors) so an over-cap
				// upload surfaces as 413 rather than a misleading CSRF failure.
				if err := r.ParseMultipartForm(4 << 20); err != nil && !errors.Is(err, http.ErrNotMultipart) {
					if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
						// Route the 413 through the app error path (Datastar toast, or an error
						// flash + redirect back for a native form) so an over-cap upload shows an
						// in-app notification instead of a bare error page.
						s.handleError(w, r, "That file is too large - backups and imports are limited to 8 MB.", http.StatusRequestEntityTooLarge)
						return
					}
				}
				provided = r.FormValue("csrf_token")
			}
			// An empty stored token must never match an empty submission: createSession
			// always sets one, but the sessions read COALESCEs a NULL to "", and an
			// equal-empty compare would otherwise wave a token-less request through.
			if csrfToken == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(csrfToken)) != 1 {
				http.Error(w, "invalid or missing CSRF token", http.StatusForbidden)
				return
			}
		}

		// Authenticated users trying to access login or factory pages
		if path == "/login" || path == "/factory" {
			http.Redirect(w, r, s.postAuthRedirect(), http.StatusFound)
			return
		}

		// Per-state path authorization (ONBOARDING confines to setup/settings;
		// ACTIVE blocks the setup wizard).
		if redirect := stateRedirectFor(state, path); redirect != "" {
			http.Redirect(w, r, redirect, http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// stateRedirectFor returns where an authenticated request should be redirected
// when the current lifecycle state forbids the path, or "" when it may proceed.
// Pure, so the routing rules are unit-testable without spinning up a server.
func stateRedirectFor(state, path string) string {
	switch state {
	case db.StateConfiguring:
		// An apply is in flight: keep the operator on the dashboard (and stop a
		// second apply from starting). The reconnect interstitial's /dashboard
		// navigation lands on the dashboard instead of bouncing to /setup before
		// the apply goroutine flips the state to ACTIVE.
		if path == "/setup" || path == "/setup/apply" || strings.HasPrefix(path, "/factory") {
			return "/dashboard"
		}
	case db.StateActive:
		// ACTIVE allows the setup wizard as "create a new configuration" - that is
		// how a second profile (and thus profile switching) becomes reachable. The
		// /factory bootstrap POSTs are the exception: they carry no re-auth and exist
		// only for the pre-auth FACTORY window, so they must not be reachable here.
		if strings.HasPrefix(path, "/factory") {
			return "/dashboard"
		}
	case db.StateFactory:
		// FACTORY is fully gated by lifecycleMiddleware's earlier branch, so this is
		// never reached in production; keep it permissive so this router never
		// second-guesses that gate. Only genuinely unrecognized states fail closed.
		return ""
	default:
		// ONBOARDING and, as a fail-closed catch, any unrecognized/corrupt state
		// string (a hand-edited or older/newer bundle, or an empty one). Without a
		// default an unknown state returned "" (serve every route) while the
		// reconciler tore the box down to onboarding; routing it like onboarding
		// keeps the two in step.
		switch path {
		case "/setup", "/setup/apply", "/setup/pools/edit", "/settings", "/settings/save", "/settings/backup", "/settings/restore", "/logout", "/wifi/scan", "/sse/live":
			// /sse/live is opened by the shell on every authenticated page (it keeps
			// the wizard's link-status badge live). Without it whitelisted here, the
			// middleware 302s the stream to /setup; Datastar follows the redirect,
			// receives the full /setup page (whose #scopes-container is empty), and
			// morphs it in - wiping the scope card the wizard JS just added.
			return ""
		default:
			return "/setup"
		}
	}
	return ""
}
