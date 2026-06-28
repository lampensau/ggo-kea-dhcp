package web

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/kea"
	"ggo-kea-dhcp/internal/web/views"
)

func (s *Server) handleFactory(w http.ResponseWriter, r *http.Request) {
	s.renderTempl(w, r, views.Factory(views.FactoryView{Page: s.pageData(w, r, "Create Administrator")}))
}

func (s *Server) handleFactorySetup(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.handleError(w, r, "invalid form data", http.StatusBadRequest)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	confirm := r.FormValue("confirm_password")

	if username == "" {
		s.handleError(w, r, "Username cannot be empty", http.StatusBadRequest)
		return
	}

	if password != confirm {
		s.handleError(w, r, "Passwords do not match", http.StatusBadRequest)
		return
	}

	// Backend password complexity check (minimum 12 characters)
	if len(password) < 12 {
		s.handleError(w, r, "Password must be at least 12 characters long", http.StatusBadRequest)
		return
	}

	// Hash with PBKDF2 (hard cutover from the old sha256 scheme).
	passwordHash, err := hashPassword(password)
	if err != nil {
		s.handleError(w, r, "internal server error", http.StatusInternalServerError)
		return
	}

	// Save admin to SQLite
	if _, err := s.sqlite.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", username, passwordHash); err != nil {
		log.Printf("Failed to create admin user: %v", err)
		s.handleError(w, r, "failed to initialize user", http.StatusInternalServerError)
		return
	}

	// Transition state to ONBOARDING
	if err := s.sqlite.SetState(db.LifecycleStateKey, db.StateOnboarding); err != nil {
		s.handleError(w, r, "Failed to update appliance state", http.StatusInternalServerError)
		return
	}
	_ = s.sqlite.LogAudit("SYSTEM", "INITIALIZE_ADMIN", username, "", "", "SUCCESS")

	// Establish an authenticated session.
	sessionID, err := s.createSession(username)
	if err != nil {
		s.handleError(w, r, "failed to create session", http.StatusInternalServerError)
		return
	}
	setSessionCookie(w, r, sessionID)

	s.setFlash(w, "Administrator credentials initialized successfully!", "success")

	s.redirectHTMX(w, r, "/setup")
}

// linkTrunkState upgrades the config-derived link state with the onboarding trunk probe's
// observation: when the box has no VLAN sub-interfaces of its own (state "Flat") but the
// probe has seen tagged frames on the wire, report "Trunk" and list the VLAN ids in the
// detail. This is what makes the wizard badge reflect the SWITCH PORT (tagged VLANs present
// on the link) rather than just the box's own configuration.
func (s *Server) linkTrunkState(configState string) (state, detail string) {
	state = configState
	if state == "Flat" && s.trunkProbe != nil {
		if vids := s.trunkProbe.VLANs(); len(vids) > 0 {
			state = "Trunk"
			detail = "tagged VLANs seen: " + joinInts(vids)
		}
	}
	return
}

// joinInts renders an int slice as "1, 200".
func joinInts(xs []int) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = strconv.Itoa(x)
	}
	return strings.Join(parts, ", ")
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	shield := s.net.GetLinkStatus("eth0")
	state, detail := s.linkTrunkState(shield.LinkState)
	upEn, upSSID, upPass := s.uplinkSettings()
	v := views.SetupView{
		Page:           s.pageData(w, r, "Setup Wizard"),
		ShieldState:    shield.ShieldState,
		LinkState:      state,
		Interface:      shield.Interface,
		LinkDetail:     detail,
		UplinkEnabled:  upEn,
		UplinkSSID:     upSSID,
		UplinkPassword: upPass,
	}
	// /setup?edit=1 reopens the wizard prefilled with the active profile, so the
	// same authoring UI serves in-place edits (apply replaces the same-named
	// profile and reconciles). Without it, the wizard starts blank ("new").
	if r.URL.Query().Get("edit") == "1" {
		if prefill, ok := s.activeProfilePrefill(); ok {
			v.Editing = true
			v.PrefillJSON = prefill
			v.Page.Title = "Edit configuration"
		}
	}
	s.renderTempl(w, r, views.Setup(v))
}

// activeProfilePrefill returns the active profile serialized as the wizard's
// import JSON (the ProfileExport shape ggoApplyImported consumes), or ok=false
// when there is no active profile to edit. json.Marshal HTML-escapes <,>,& so the
// payload is safe to embed in a <script type="application/json"> block.
func (s *Server) activeProfilePrefill() (string, bool) {
	var profileID int
	var name string
	if err := s.sqlite.QueryRow("SELECT id, name FROM profiles WHERE active = 1 LIMIT 1").Scan(&profileID, &name); err != nil {
		return "", false
	}
	scopes, err := s.loadScopeConfigs(profileID)
	if err != nil || len(scopes) == 0 {
		return "", false
	}
	b, err := json.Marshal(ProfileExport{Name: name, Scopes: scopes})
	if err != nil {
		return "", false
	}
	return string(b), true
}

// maxScopes bounds the scopes[i] form array so a malformed or malicious POST
// can't drive an unbounded parse loop. A real appliance config is far smaller.
const maxScopes = 64

// parseSetupScopes reads the scopes[i][...] form array, enforcing the count cap
// and the wizard's invariants (at least one scope; at most one untagged scope
// on eth0). It is pure over the request form, so it is unit-testable.
// scopeIndexFromKey extracts the scope index N from a form key "scopes[N][preset]",
// used to find every present scope regardless of gaps in the indices.
func scopeIndexFromKey(key string) (int, bool) {
	const pre, suf = "scopes[", "][preset]"
	if !strings.HasPrefix(key, pre) || !strings.HasSuffix(key, suf) {
		return 0, false
	}
	n, err := strconv.Atoi(key[len(pre) : len(key)-len(suf)])
	if err != nil {
		return 0, false
	}
	return n, true
}

func parseSetupScopes(r *http.Request) ([]ScopeConfig, error) {
	_ = r.ParseForm() // ensure r.Form is populated before scanning its keys
	field := func(name string, i int) string {
		return r.FormValue(fmt.Sprintf("scopes[%d][%s]", i, name))
	}
	atoi := func(name string, i int) int {
		n, _ := strconv.Atoi(field(name, i))
		return n
	}

	// The wizard does NOT renumber scope indices when a card is removed (or after a
	// duplicate), so the scopes[i] keys can be sparse (e.g. 0,2,3). Collect the indices
	// actually present in the form by their preset key and parse them in order. Scanning
	// 0..N and stopping at the first gap would silently drop every scope after a removal -
	// the "only the first scope is created" bug.
	var indices []int
	for key := range r.Form {
		if i, ok := scopeIndexFromKey(key); ok {
			indices = append(indices, i)
		}
	}
	sort.Ints(indices)
	if len(indices) > maxScopes {
		return nil, fmt.Errorf("too many scopes (max %d)", maxScopes)
	}

	var scopes []ScopeConfig
	for _, i := range indices {
		preset := field("preset", i)
		if preset == "" {
			continue // present-but-blank card; skip rather than abort the whole apply
		}
		vlan := atoi("vlan", i)
		if !validVLANID(vlan) {
			return nil, fmt.Errorf("scope %d: VLAN ID must be between 0 and 4094", i+1)
		}
		sc := ScopeConfig{
			Name:   strings.TrimSpace(field("name", i)),
			Preset: preset,
			VlanID: vlan,
			CIDR:   field("cidr", i),
			// Per-scope uplink is now ONLY the toggle (route this scope through the
			// box-level wlan0); the SSID/password are box-level (parseUplinkForm).
			Uplink:         UplinkConfig{Enabled: field("uplink", i) == "true"},
			MulticastSniff: field("multicast_sniff", i) == "true",
		}
		// Per-scope DHCP network services (explicit gateway/DNS, lease override, extra
		// options). Shared with the /pools editor via parseScopeServices. Option rows
		// arrive as repeated scopes[i][opt_name][]/[opt_data][] fields.
		svc, serr := parseScopeServices(
			field("gateway", i), field("dns", i), field("lease", i),
			r.Form[fmt.Sprintf("scopes[%d][opt_name][]", i)],
			r.Form[fmt.Sprintf("scopes[%d][opt_data][]", i)],
		)
		if serr != nil {
			return nil, fmt.Errorf("scope %d: %w", i+1, serr)
		}
		sc.Services = svc
		// The Datastar editor posts the plan as scopes[i][pool][n][...] fields; parse
		// them into the authoritative plan. A seed fallback covers an untouched scope
		// (no JS / editor never ran): it uses the configured default size rather than
		// an empty plan, so a fresh greengo scope still gets device-class pools.
		sc.Plan = parsePoolFields(r, fmt.Sprintf("scopes[%d][pool]", i), sc.CIDR)
		if len(sc.Plan) == 0 {
			sc.Plan = seedDefaultPlan(sc)
		}
		// Heal an imported Green-GO plan that lost its catch-alls: re-add them so
		// unmatched devices always get an address. The import has no Advanced toggle,
		// so rather than reject (which would misclassify a deliberate, range-pin-free
		// Advanced plan as Simple), we auto-restore; the operator can still remove the
		// catch-all afterward in the live Advanced editor.
		sc = ensureGreengoCatchAll(sc)
		// Auto-grow the subnet to fit the plan (matches the live editor's auto-sizing).
		// Idempotent: an already-fitting CIDR is returned unchanged, so a CIDR the
		// editor already widened stays put.
		sc.CIDR = kea.FitCIDR(sc.CIDR, sc.Plan.ToSpecs())
		scopes = append(scopes, sc)
	}

	if len(scopes) == 0 {
		return nil, fmt.Errorf("at least one scope is required")
	}
	untagged := 0
	for _, sc := range scopes {
		if sc.VlanID == 0 {
			untagged++
		}
	}
	if untagged > 1 {
		return nil, fmt.Errorf("Only one untagged network scope is allowed on eth0. All other scopes must specify a VLAN ID.")
	}
	return scopes, nil
}

// parseUplinkForm reads the box-level WiFi uplink fields (uplink_enabled / uplink_ssid
// / uplink_pass) shared by the setup wizard and the settings page. When enabled it
// requires an SSID and runs the standard credential check.
func parseUplinkForm(r *http.Request) (UplinkConfig, error) {
	cfg := UplinkConfig{
		Enabled:  r.FormValue("uplink_enabled") == "on" || r.FormValue("uplink_enabled") == "true",
		SSID:     strings.TrimSpace(r.FormValue("uplink_ssid")),
		Password: r.FormValue("uplink_pass"),
	}
	if cfg.Enabled {
		if cfg.SSID == "" {
			return cfg, fmt.Errorf("Select a WiFi network (Scan) to enable the uplink, or disable it")
		}
		if msg := validateUplink(cfg.SSID, cfg.Password); msg != "" {
			return cfg, fmt.Errorf("%s", msg)
		}
	}
	return cfg, nil
}

// buildRenderScopes maps parsed scopes to renderer inputs and picks the gateway
// the operator's browser will reconnect to (the untagged eth0 scope if present,
// else the first scope). boxUplink is the box-level master enable - a scope only
// advertises the uplink gateway when its own toggle AND the master are on. Pure, so
// it is unit-testable.
func buildRenderScopes(scopes []ScopeConfig, boxUplink bool) (renderScopes []kea.ScopeInput, gatewayIP string) {
	for _, sc := range scopes {
		ri := sc.ToRenderInput()
		ri.Uplink = ri.Uplink && boxUplink
		renderScopes = append(renderScopes, ri)
		if _, ipnet, err := net.ParseCIDR(sc.CIDR); err == nil {
			gw := kea.IncIP(ipnet.IP, 1).String()
			if gatewayIP == "" || sc.VlanID == 0 {
				gatewayIP = gw
			}
		}
	}
	return renderScopes, gatewayIP
}

// handleSetupApply is the thin HTTP entry point for a profile apply: it parses
// the wizard form, then hands off to the (synchronous) beginApply and
// (asynchronous) finishApply orchestration in profile_apply.go. The interstitial
// is flushed between the two halves, while the old IP still works.
func (s *Server) handleSetupApply(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.handleError(w, r, "invalid form data", http.StatusBadRequest)
		return
	}

	profileName := r.FormValue("profile_name")
	log.Printf("[Wizard] Applying setup: ProfileName='%s'", profileName)

	scopes, err := parseSetupScopes(r)
	if err != nil {
		s.handleError(w, r, err.Error(), http.StatusBadRequest)
		return
	}

	// Box-level WiFi uplink (one wlan0): the master enable + credentials, parsed from
	// the top-level form fields (the Profile card), not per-scope.
	uplink, err := parseUplinkForm(r)
	if err != nil {
		s.handleError(w, r, err.Error(), http.StatusBadRequest)
		return
	}

	plan, err := s.beginApply(profileName, scopes, uplink)
	if err != nil {
		s.handleError(w, r, err.Error(), http.StatusBadRequest)
		return
	}

	actor := s.getActor(r)

	// Flush the reconnect interstitial NOW, while the old IP still works - the
	// imminent eth0/VLAN re-IP will drop this very connection.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, interstitialHTML(plan.gatewayIP))
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	go s.finishApply(plan, profileName, actor)
}

func (s *Server) handleWifiScan(w http.ResponseWriter, r *http.Request) {
	aps, err := s.net.ScanWifi()
	if err != nil {
		log.Printf("WiFi scanning failed: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	sort.Slice(aps, func(i, j int) bool {
		return aps[i].Signal > aps[j].Signal
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(aps)
}
