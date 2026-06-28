package web

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/web/views"

	"github.com/starfederation/datastar-go/datastar"
)

// pbkdf2Iter is the PBKDF2-HMAC-SHA256 work factor (OWASP-recommended floor).
const pbkdf2Iter = 600000

// dummyPasswordHash is a well-formed but unmatchable hash used to equalize login
// timing: a login for a NONEXISTENT username must run the same ~600k-iteration
// derivation as one for a real user, otherwise its sub-millisecond response time
// reveals which usernames exist. Same iteration count + output length as a real hash.
var dummyPasswordHash = fmt.Sprintf("pbkdf2$%d$%s$%s", pbkdf2Iter, strings.Repeat("00", 16), strings.Repeat("00", 32))

// sessionCookieName is the cookie carrying the opaque session id.
const sessionCookieName = "ggo_session"

// sessionUser resolves a session id to its owning user, returning the username
// and CSRF token for a live (unexpired) session. ok is false for an unknown or
// expired session.
func (s *Server) sessionUser(sessionID string) (username, csrf string, ok bool) {
	err := s.sqlite.QueryRow(
		// Live = within the sliding 1h idle window (expires_at) AND under the 12h
		// absolute cap from login (created_at). The cap kills even an actively-used
		// session, bounding a stolen-cookie window.
		"SELECT username, COALESCE(csrf_token, '') FROM sessions WHERE session_id = ? AND expires_at > datetime('now') AND created_at > datetime('now', '-12 hours')",
		sessionID).Scan(&username, &csrf)
	if err != nil || username == "" {
		return "", "", false
	}
	return username, csrf, true
}

// sessionInfo resolves the request's session cookie to its owning user. It is
// the request-level wrapper around sessionUser.
func (s *Server) sessionInfo(r *http.Request) (username, csrf string, ok bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return "", "", false
	}
	return s.sessionUser(cookie.Value)
}

// postAuthRedirect is the landing path after authentication: the setup wizard
// while onboarding, otherwise the dashboard.
func (s *Server) postAuthRedirect() string {
	if state, _ := s.sqlite.GetState(db.LifecycleStateKey); state == db.StateOnboarding {
		return "/setup"
	}
	return "/dashboard"
}

// hashPassword returns a "pbkdf2$<iter>$<saltHex>$<hashHex>" encoded hash.
func hashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk, err := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iter, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2$%d$%s$%s", pbkdf2Iter, hex.EncodeToString(salt), hex.EncodeToString(dk)), nil
}

// verifyPassword checks a candidate against a stored pbkdf2 hash in constant
// time. Non-pbkdf2 (e.g. legacy) hashes never verify - this is a hard cutover.
func verifyPassword(stored, pw string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(parts[3])
	if err != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// randomToken returns n random bytes hex-encoded.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// createSession inserts a new session (1h sliding idle window from now, 12h absolute cap
// keyed off created_at) with a CSRF token and returns the session id (the csrf token is
// stored and surfaced to templates via lookups).
func (s *Server) createSession(username string) (sessionID string, err error) {
	sessionID, err = randomToken(16)
	if err != nil {
		return "", err
	}
	csrf, err := randomToken(16)
	if err != nil {
		return "", err
	}
	_, err = s.sqlite.Exec(
		"INSERT INTO sessions (session_id, username, csrf_token, created_at, expires_at) VALUES (?, ?, ?, datetime('now'), datetime('now', '+1 hour'))",
		sessionID, username, csrf)
	return sessionID, err
}

// isHTTPS reports whether the request reached us over TLS, directly or via a
// terminating proxy (Caddy). Used to set the Secure cookie flag only when it
// won't break a plain-HTTP management session on :8080.
//
// X-Forwarded-Proto is trusted only from a loopback peer: the app binds
// 127.0.0.1, so in production only the local Caddy reverse proxy can set it, and a
// remote client cannot spoof the header to influence the Secure flag.
func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") && isLoopbackRemote(r.RemoteAddr)
}

// isLoopbackRemote reports whether the request's immediate peer is a loopback
// address (i.e. the local reverse proxy), parsing the host out of host:port.
func isLoopbackRemote(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// setSessionCookie writes the session cookie with SameSite=Strict (the primary
// CSRF mitigation) and Secure when the connection is HTTPS. MaxAge is the 1h idle
// window; the middleware re-issues this cookie when it slides the server session, so
// an active session's cookie keeps refreshing (the 12h absolute cap is server-side).
func setSessionCookie(w http.ResponseWriter, r *http.Request, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   3600,
	})
}

// clearSessionCookie expires the session cookie (logout, factory reset).
func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Already authenticated? Skip the login form.
	if _, _, ok := s.sessionInfo(r); ok {
		http.Redirect(w, r, s.postAuthRedirect(), http.StatusFound)
		return
	}
	s.renderTempl(w, r, views.Login(views.LoginView{Page: s.pageData(w, r, "Sign in")}))
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	// Per-source-IP backoff. A blocked attempt returns the SAME generic message as
	// a wrong password, so an attacker can't even distinguish "throttled" from
	// "wrong" - and it never reveals whether the username exists.
	ip := clientIP(r)
	if ok, retry := s.loginThrottle.allow(ip); !ok {
		log.Printf("[Login] throttled %s (retry in ~%s)", ip, retry.Round(time.Second))
		s.loginThrottled(w, r, retry)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	var dbHash string
	err := s.sqlite.QueryRow("SELECT password_hash FROM users WHERE username = ?", username).Scan(&dbHash)
	if err != nil {
		// Unknown username: still run the full derivation against a dummy hash so the
		// response time doesn't distinguish "no such user" from "wrong password".
		dbHash = dummyPasswordHash
	}
	if !verifyPassword(dbHash, password) {
		if n := s.loginThrottle.fail(ip); n == loginAuditAt {
			_ = s.sqlite.LogAudit(username, "LOGIN_THROTTLE", ip, "", "", "FAILURE")
		}
		s.loginFailure(w, r, "Invalid username or password")
		return
	}
	s.loginThrottle.succeed(ip)

	sessionID, err := s.createSession(username)
	if err != nil {
		log.Printf("Failed to insert session: %v", err)
		s.loginFailure(w, r, "Internal server error")
		return
	}
	// Cookie must be written before NewSSE flushes the response headers.
	setSessionCookie(w, r, sessionID)

	_ = s.sqlite.LogAudit(username, "LOGIN", username, "", "", "SUCCESS")

	redirectPath := s.postAuthRedirect()
	if isDatastar(r) {
		sse := datastar.NewSSE(w, r)
		_ = sse.Redirect(redirectPath)
		return
	}
	http.Redirect(w, r, redirectPath, http.StatusFound)
}

// loginThrottled tells the client it is inside the per-IP backoff window. A
// Datastar request gets the retry seconds as a signal - the login page renders a
// live countdown and keeps submit disabled until it elapses - plus a cleared static
// error so a prior "invalid" message doesn't linger under the countdown. A no-JS
// request re-renders the page with a static "try again in Ns" message. This reveals
// only that THIS IP is throttled (never whether the username exists), which is safe.
func (s *Server) loginThrottled(w http.ResponseWriter, r *http.Request, retry time.Duration) {
	secs := int(retry / time.Second)
	if retry%time.Second != 0 {
		secs++ // round up so the countdown never reads 0 while still blocked
	}
	if secs < 1 {
		secs = 1
	}
	if isDatastar(r) {
		sse := datastar.NewSSE(w, r)
		_ = sse.PatchSignals([]byte(fmt.Sprintf(`{"retry": %d}`, secs)))
		_ = sse.PatchElementTempl(views.LoginErrorBox("")) // clear any stale wrong-password text
		return
	}
	s.renderTempl(w, r, views.Login(views.LoginView{
		Page:  s.pageData(w, r, "Sign in"),
		Error: fmt.Sprintf("Too many attempts. Try again in %ds.", secs),
	}))
}

// loginFailure surfaces a failed sign-in: a Datastar request gets an SSE patch
// of just the #login-error region (the form stays put); a plain request re-renders
// the page with the error inline (no-JS fallback).
func (s *Server) loginFailure(w http.ResponseWriter, r *http.Request, msg string) {
	if isDatastar(r) {
		sse := datastar.NewSSE(w, r)
		_ = sse.PatchElementTempl(views.LoginErrorBox(msg))
		return
	}
	s.renderTempl(w, r, views.Login(views.LoginView{Page: s.pageData(w, r, "Sign in"), Error: msg}))
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if username, _, ok := s.sessionInfo(r); ok {
		_ = s.sqlite.LogAudit(username, "LOGOUT", username, "", "", "SUCCESS")
	}
	if cookie, err := r.Cookie(sessionCookieName); err == nil && cookie.Value != "" {
		_, _ = s.sqlite.Exec("DELETE FROM sessions WHERE session_id = ?", cookie.Value)
	}

	clearSessionCookie(w, r)
	s.redirectHTMX(w, r, "/login")
}
