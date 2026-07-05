package web

import (
	"log"
	"net/http"
	"strings"
)

// handleAccountSave changes the signed-in administrator's own credentials: an
// optional username rename and/or a new password, submitted from the header
// account dialog (this flow lived inside the Settings form before). Either
// change is sensitive and requires the current password; the username keys the
// session, so a rename also rewrites the live session rows.
func (s *Server) handleAccountSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.handleError(w, r, "invalid form data", http.StatusBadRequest)
		return
	}

	// Validate everything FIRST, so a later failure can't leave the account
	// half-changed.
	actor := s.getActor(r)
	newUsername := strings.TrimSpace(r.FormValue("username"))
	usernameChanged := newUsername != "" && newUsername != actor
	if usernameChanged {
		if len(newUsername) < 3 || len(newUsername) > 32 || strings.ContainsAny(newUsername, " \t") {
			s.handleError(w, r, "Username must be 3-32 characters with no spaces", http.StatusBadRequest)
			return
		}
		// Uniqueness is checked AFTER re-auth (below): the DB probe would otherwise
		// let an authenticated session enumerate which usernames exist without ever
		// re-entering the password.
	}

	newPass := r.FormValue("new_password")
	var newPassHash string
	if newPass != "" {
		if newPass != r.FormValue("confirm_password") {
			s.handleError(w, r, "New passwords do not match", http.StatusBadRequest)
			return
		}
		if len(newPass) < 12 {
			s.handleError(w, r, "New password must be at least 12 characters long", http.StatusBadRequest)
			return
		}
		hashed, err := hashPassword(newPass)
		if err != nil {
			s.handleError(w, r, "internal server error", http.StatusInternalServerError)
			return
		}
		newPassHash = hashed
	}

	if !usernameChanged && newPassHash == "" {
		s.setFlash(w, r, "No account changes to save.", "info")
		s.redirectHTMX(w, r, accountReturnPath(r))
		return
	}

	// Any sensitive account change (rename or new password) requires the current
	// password, verified against the still-current username.
	if ok, reason := s.reauthCurrentPassword(r); !ok {
		s.handleError(w, r, reason, http.StatusBadRequest)
		return
	}

	// Username uniqueness, now that the password is proven (see the note above).
	if usernameChanged {
		var n int
		if err := s.sqlite.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", newUsername).Scan(&n); err != nil {
			s.handleError(w, r, "Database error checking username", http.StatusInternalServerError)
			return
		} else if n > 0 {
			s.handleError(w, r, "That username is already taken", http.StatusBadRequest)
			return
		}
	}

	// Password first (keyed on the current username), then the rename, so the rename's
	// session/users rewrite doesn't strand the password update.
	if newPassHash != "" {
		if _, err := s.sqlite.Exec("UPDATE users SET password_hash = ? WHERE username = ?", newPassHash, actor); err != nil {
			s.handleError(w, r, "Failed to update password", http.StatusInternalServerError)
			return
		}
		// A password change logs out every OTHER session (a forgotten browser or a
		// suspected-compromise device), keeping only the current one. Keyed on the
		// still-current username, before any rename below.
		if c, err := r.Cookie(sessionCookieName); err == nil {
			// Security-relevant: if this fails silently a suspected-compromise session
			// survives the password change. Surface it rather than swallow.
			if _, err := s.sqlite.Exec("DELETE FROM sessions WHERE username = ? AND session_id != ?", actor, c.Value); err != nil {
				log.Printf("[account] password changed but failed to revoke other sessions for %q: %v", actor, err)
			}
		}
		_ = s.sqlite.LogAudit(actor, "CHANGE_PASSWORD", actor, "", "", "SUCCESS")
	}
	if usernameChanged {
		if _, err := s.sqlite.Exec("UPDATE users SET username = ? WHERE username = ?", newUsername, actor); err != nil {
			s.handleError(w, r, "Failed to rename administrator: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// Keep every live session for this admin valid (the session cookie maps to a
		// sessions row keyed by username), so the rename doesn't log the operator out.
		if _, err := s.sqlite.Exec("UPDATE sessions SET username = ? WHERE username = ?", newUsername, actor); err != nil {
			log.Printf("[account] renamed user but failed to update sessions: %v", err)
		}
		_ = s.sqlite.LogAudit(newUsername, "CHANGE_USERNAME", actor+" -> "+newUsername, "", "", "SUCCESS")
	}

	s.setFlash(w, r, "Account updated.", "success")
	s.redirectHTMX(w, r, accountReturnPath(r))
}

// accountReturnPath sends the operator back to the page the account dialog was
// opened on (the header menu exists on every page); the dashboard when the
// Referer is unusable.
func accountReturnPath(r *http.Request) string {
	if p := refererPath(r); isValidRedirect(p) {
		return p
	}
	return "/dashboard"
}
