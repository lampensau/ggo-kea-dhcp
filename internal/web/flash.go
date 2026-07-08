package web

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/version"
	"ggo-kea-dhcp/internal/web/views"

	"github.com/a-h/templ"
	"github.com/starfederation/datastar-go/datastar"
)

// isDatastar reports whether the request originates from the Datastar runtime
// (a backend-action fetch expecting an SSE response), the new-stack analogue of
// isHTMX. Datastar sets this header on every @get/@post/@delete action.
func isDatastar(r *http.Request) bool {
	return r.Header.Get("Datastar-Request") == "true"
}

// renderTempl renders a templ component as a full HTML response.
func (s *Server) renderTempl(w http.ResponseWriter, r *http.Request, c templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := c.Render(r.Context(), w); err != nil {
		log.Printf("templ render error: %v", err)
	}
}

// pageData assembles the shell context (lifecycle state, auth + CSRF token,
// current path, one-shot flash) every full page needs. It consumes the flash
// cookie, so call it once per response.
func (s *Server) pageData(w http.ResponseWriter, r *http.Request, title string) views.PageData {
	state, _ := s.sqlite.GetState(db.LifecycleStateKey)
	d := views.PageData{State: state, CurrentPath: r.URL.Path, Title: title, AssetVer: assetVersion, Version: version.Number, HealthPill: views.StatusPillView{State: state}}
	if username, csrf, ok := s.sessionInfo(r); ok {
		d.Authenticated = true
		d.Username = username
		d.CSRFToken = csrf
		d.SysHealth = s.buildSysHealthView(state)
		d.HealthPill = s.buildStatusPill(state)
		d.Update = s.buildUpdateView() // first paint of the footer badge + its dialogs
		if s.health != nil {
			d.BackendAlerts = s.backendAlertRows() // first paint of the #backend-alert strip (health + preflight)
		}
	}
	if f := s.getFlash(w, r); f != nil {
		d.Flash = &views.Flash{Message: f.Message, Type: f.Type}
		if f.Device != nil {
			d.Flash.Device = &views.FlashDevice{MAC: f.Device.MAC, IP: f.Device.IP, Name: f.Device.Name}
		}
	}
	return d
}

// Middleware & helper utilities

// isValidRedirect reports whether p is a root-relative path usable as a
// same-site redirect target: "/x" but not "//host" or "/\host" (browsers
// normalize the backslash into a scheme-relative URL). The name matters:
// CodeQL's open-redirect query only treats a guard as a sanitizer when the
// validation function is named like isLocalUrl/isValidRedirect.
func isValidRedirect(p string) bool {
	return strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") && !strings.HasPrefix(p, "/\\")
}

// logSafe strips CR/LF so attacker-supplied values can't forge log lines.
func logSafe(s string) string {
	return strings.NewReplacer("\n", " ", "\r", " ").Replace(s)
}

// redirect navigates the client to path: a Datastar SSE redirect for Datastar
// actions, else a plain 302 (native form posts and full page loads).
func (s *Server) redirectHTMX(w http.ResponseWriter, r *http.Request, path string) {
	if !isValidRedirect(path) {
		path = "/"
	}
	if isDatastar(r) {
		sse := datastar.NewSSE(w, r)
		_ = sse.Redirect(path)
		return
	}
	http.Redirect(w, r, path, http.StatusFound)
}

type FlashMessage struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	// Device is set only when the action targeted an online Green-GO device: the next
	// page offers to reboot it to apply the change now (see setFlashDevice).
	Device *FlashDevice `json:"device,omitempty"`
}

// FlashDevice is the reboot-to-apply target carried alongside a flash: the device's
// current address and already-sanitized name (its MAC is kept for reference).
type FlashDevice struct {
	MAC  string `json:"mac,omitempty"`
	IP   string `json:"ip"`
	Name string `json:"name"`
}

func (s *Server) setFlash(w http.ResponseWriter, r *http.Request, msg, msgType string) {
	s.writeFlash(w, r, FlashMessage{Message: msg, Type: msgType})
}

// setFlashDevice writes a flash that also carries a reboot-to-apply device context, so
// the next page load can offer to reboot that Green-GO device and apply the change now.
func (s *Server) setFlashDevice(w http.ResponseWriter, r *http.Request, msg, msgType string, dev FlashDevice) {
	s.writeFlash(w, r, FlashMessage{Message: msg, Type: msgType, Device: &dev})
}

func (s *Server) writeFlash(w http.ResponseWriter, r *http.Request, flash FlashMessage) {
	data, _ := json.Marshal(flash)
	// Server-read only (getFlash) - HttpOnly + Strict + Secure like the session
	// cookie (conditional: FACTORY/ONBOARDING runs over plain HTTP on the SoftAP).
	http.SetCookie(w, &http.Cookie{
		Name:     "ggo_flash",
		Value:    hex.EncodeToString(data),
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   60,
	})
}

func (s *Server) getFlash(w http.ResponseWriter, r *http.Request) *FlashMessage {
	cookie, err := r.Cookie("ggo_flash")
	if err != nil {
		return nil
	}

	// Delete cookie immediately
	http.SetCookie(w, &http.Cookie{
		Name:     "ggo_flash",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	data, err := hex.DecodeString(cookie.Value)
	if err != nil {
		return nil
	}

	var flash FlashMessage
	if err := json.Unmarshal(data, &flash); err != nil {
		// Tolerate a cookie that predates the JSON schema (a bare message string), so
		// an in-flight flash across a deploy still shows rather than being dropped.
		var bare string
		if json.Unmarshal(data, &bare) == nil && bare != "" {
			return &FlashMessage{Message: bare, Type: "info"}
		}
		return nil
	}

	return &flash
}

// toast appends a toast of the given kind ("success"/"error") into the open
// page's live toast region.
func toast(sse *datastar.ServerSentEventGenerator, msg, kind string) {
	_ = sse.PatchElementTempl(views.Toast(msg, kind),
		datastar.WithSelectorID("toast-container"), datastar.WithModeAppend())
}

func (s *Server) handleError(w http.ResponseWriter, r *http.Request, msg string, code int) {
	log.Printf("Error: %s (status code: %d)", logSafe(msg), code)
	if isDatastar(r) {
		// Append an error toast into the live toast region; the page stays put.
		toast(datastar.NewSSE(w, r), msg, "error")
		return
	}
	// A mutating native form post: show the message as an error flash on the page the
	// request came from (post-redirect-get) rather than a bare error page. This is what
	// makes a validation/conflict rejection on a native form (reservations, pinning,
	// settings) read as a toast instead of dumping the operator on a blank page. Falls
	// back to the dashboard when there is no usable same-site Referer.
	//
	// Only for unsafe methods: a GET handler keeps its real status - redirecting a
	// GET error would drop the status code and could loop if the failing page is
	// its own Referer.
	if isUnsafeMethod(r.Method) {
		back := refererPath(r)
		if !isValidRedirect(back) {
			back = "/"
		}
		s.setFlash(w, r, msg, "error")
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}
	http.Error(w, msg, code)
}

func (s *Server) getActor(r *http.Request) string {
	if username, _, ok := s.sessionInfo(r); ok {
		return username
	}
	return "admin"
}
