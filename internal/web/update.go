package web

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/version"
	"ggo-kea-dhcp/internal/web/views"
)

// The self-update checker: while ACTIVE and the WiFi uplink is up, the box asks
// GitHub for the latest release, notifies the operator (footer badge + Settings
// card), and never installs anything on its own. The HTTPS request itself is
// the internet probe - a failed check is silent by design (an isolated show
// network is the normal state, not an error).
const (
	updateRepo          = "lampensau/ggo-kea-dhcp"
	updateDebAsset      = "ggo-kea-dhcp_arm64.deb"
	updateManifestAsset = "release.json"

	updateCheckInterval = 30 * time.Minute
	// updateKickDelay defers the post-uplink-connect check a moment so NAT/routing
	// have settled before the first outbound HTTPS attempt.
	updateKickDelay = 5 * time.Second
	// updateBackoffOn403 pauses checks after a rate-limit response (venue NAT
	// sharing one public IP can exhaust GitHub's unauthenticated quota).
	updateBackoffOn403 = time.Hour
	// updateNotesMax caps the stored release body - app_state is not a blob store.
	updateNotesMax = 16 * 1024
	// updateAPITimeout mirrors the dedicated outbound client's budget.
	updateAPITimeout = 20 * time.Second
)

// app_state keys for the persisted check result. update_latest_* describe the
// newest known release; the two latches keep the audit row and the badge
// dismissal one-per-version across restarts.
const (
	stateUpdateLastCheck    = "update_last_check"
	stateUpdateVersion      = "update_latest_version"
	stateUpdateScope        = "update_latest_scope"
	stateUpdateNotes        = "update_latest_notes"
	stateUpdateDebURL       = "update_latest_deb_url"
	stateUpdateSHA256       = "update_latest_deb_sha256"
	stateUpdateNotified     = "update_notified_version"
	stateUpdateDismissed    = "update_dismissed_version"
	stateUpdateBackoffUntil = "update_backoff_until"
	stateUpdateNeedsSystem  = "update_needs_system"
)

// updateCurrentVersion is the running product version every comparison uses. A
// var (not the const directly) so tests can pin it.
var updateCurrentVersion = version.Number

// newUpdateHTTPClient is the dedicated outbound client for release checks and
// the .deb download - mirroring the Kea client's construction (a plain
// http.Client with an overall timeout), separate from it so a wedged GitHub
// can never contend with control-socket traffic.
func newUpdateHTTPClient() *http.Client {
	return &http.Client{Timeout: updateAPITimeout}
}

// parseSemver parses a strict X.Y.Z version (an optional leading "v" is
// stripped). ok is false for anything else - malformed is treated as "not
// newer" everywhere.
func parseSemver(s string) (maj, min, pat int, ok bool) {
	s = strings.TrimPrefix(s, "v")
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return 0, 0, 0, false
	}
	n := [3]int{}
	for i, p := range parts {
		if p == "" || len(p) > 9 {
			return 0, 0, 0, false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return 0, 0, 0, false
			}
		}
		v, err := strconv.Atoi(p)
		if err != nil {
			return 0, 0, 0, false
		}
		n[i] = v
	}
	return n[0], n[1], n[2], true
}

// semverLess reports a < b. Either side malformed = false.
func semverLess(a, b string) bool {
	a1, a2, a3, ok := parseSemver(a)
	if !ok {
		return false
	}
	b1, b2, b3, ok := parseSemver(b)
	if !ok {
		return false
	}
	if a1 != b1 {
		return a1 < b1
	}
	if a2 != b2 {
		return a2 < b2
	}
	return a3 < b3
}

// semverNewer reports whether candidate is strictly newer than current.
// Downgrades and equal versions are never offered (this also sidesteps the
// Pi's possibly-behind clock - no date comparison anywhere).
func semverNewer(candidate, current string) bool {
	return semverLess(current, candidate)
}

// ghAsset / ghRelease are the slices of GitHub's releases/latest payload the
// checker consumes. Digest is the API-published checksum ("sha256:<hex>") -
// the same field install.sh verifies against, so the trust model is identical.
type ghAsset struct {
	Name        string `json:"name"`
	Digest      string `json:"digest"`
	DownloadURL string `json:"browser_download_url"`
}

type ghRelease struct {
	TagName string    `json:"tag_name"`
	Body    string    `json:"body"`
	Assets  []ghAsset `json:"assets"`
}

// releaseManifest is the release.json asset the release workflow publishes:
// the release's app-vs-system scope. A missing or malformed manifest means
// scope "app" (the conservative frozen-dependency install path).
type releaseManifest struct {
	Schema  int    `json:"schema"`
	Version string `json:"version"`
	Scope   string `json:"scope"`
}

// startUpdateCheckLoop launches the 30-minute release-check ticker (modeled on
// startBackendHealthProbe). No immediate check on start: the boot-time uplink
// connect kicks one via kickUpdateCheck when there is an uplink at all.
func (s *Server) startUpdateCheckLoop() {
	go func() {
		t := time.NewTicker(updateCheckInterval)
		defer t.Stop()
		for range t.C {
			s.updateCheckSafe(false)
		}
	}()
}

// kickUpdateCheck schedules one near-immediate check; called from the uplink
// connect success path (the only moment the box knowably just gained internet).
func (s *Server) kickUpdateCheck() {
	go func() {
		time.Sleep(updateKickDelay)
		s.updateCheckSafe(false)
	}()
}

// updateCheckSafe wraps one check in a recover (the sampleOnceSafe pattern) so
// a panic degrades that one check instead of killing the ticker goroutine.
func (s *Server) updateCheckSafe(manual bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[update] check recovered from panic: %v", r)
		}
	}()
	if _, err := s.checkForUpdate(manual); err != nil {
		// Silent by design for the background paths: no uplink means every check
		// fails, and that is the normal state of a show network.
		log.Printf("[update] check: %v", err)
	}
}

// checkForUpdate performs one release check. It returns whether a newer
// release is known after the check. Background checks run only in ACTIVE and
// honor the rate-limit backoff; a manual Check Now (manual=true) skips both
// gates but still records a fresh backoff on a 403/429.
func (s *Server) checkForUpdate(manual bool) (newer bool, err error) {
	if !manual {
		if state, _ := s.sqlite.GetState(db.LifecycleStateKey); state != db.StateActive {
			return false, nil
		}
		if until, _ := s.sqlite.GetState(stateUpdateBackoffUntil); until != "" {
			if t, perr := time.Parse(time.RFC3339, until); perr == nil && time.Now().Before(t) {
				return false, nil
			}
		}
	}

	rel, status, err := s.fetchLatestRelease()
	if err != nil {
		if status == http.StatusForbidden || status == http.StatusTooManyRequests {
			_ = s.sqlite.SetState(stateUpdateBackoffUntil, time.Now().Add(updateBackoffOn403).Format(time.RFC3339))
			return false, fmt.Errorf("rate-limited (%d) - backing off", status)
		}
		return false, err
	}

	now := time.Now().UTC().Format(time.RFC3339)
	latest := strings.TrimPrefix(rel.TagName, "v")
	if !semverNewer(latest, updateCurrentVersion) {
		// Current (or a malformed/older tag): clear any previously stored release so
		// the badge and card go quiet, e.g. after the operator updated by re-running
		// the installer.
		_ = s.sqlite.SetStates(map[string]string{
			stateUpdateLastCheck: now,
			stateUpdateVersion:   "", stateUpdateScope: "", stateUpdateNotes: "",
			stateUpdateDebURL: "", stateUpdateSHA256: "", stateUpdateNeedsSystem: "",
		})
		s.publishUpdateBadge()
		return false, nil
	}

	var debURL, debSHA string
	for _, a := range rel.Assets {
		if a.Name == updateDebAsset {
			debURL = a.DownloadURL
			// Fail closed on the digest: no published sha256 means notify-only, the
			// install button never appears (stateUpdateSHA256 stays empty).
			if strings.HasPrefix(a.Digest, "sha256:") {
				debSHA = strings.TrimPrefix(a.Digest, "sha256:")
			}
		}
	}
	scope := s.fetchReleaseScope(rel)
	notes := rel.Body
	if len(notes) > updateNotesMax {
		notes = notes[:updateNotesMax]
	}

	kv := map[string]string{
		stateUpdateLastCheck: now,
		stateUpdateVersion:   latest,
		stateUpdateScope:     scope,
		stateUpdateNotes:     notes,
		stateUpdateDebURL:    debURL,
		stateUpdateSHA256:    debSHA,
	}
	if prev, _ := s.sqlite.GetState(stateUpdateVersion); prev != latest {
		// A different release than last seen: the needs-system latch belonged to the
		// old one, and a dismissed badge must resurface for a new version.
		kv[stateUpdateNeedsSystem] = ""
	}
	if err := s.sqlite.SetStates(kv); err != nil {
		return true, fmt.Errorf("persist check result: %w", err)
	}

	// Audit once per newly seen version (persisted latch), not once per check.
	if notified, _ := s.sqlite.GetState(stateUpdateNotified); notified != latest {
		_ = s.sqlite.LogAudit("SYSTEM", "UPDATE_AVAILABLE", "v"+latest, "", "scope="+scope, "INFO")
		_ = s.sqlite.SetState(stateUpdateNotified, latest)
	}
	s.publishUpdateBadge()
	return true, nil
}

// fetchLatestRelease GETs /releases/latest from the (test-overridable) API
// base. status carries the HTTP status for the caller's 403/429 backoff.
func (s *Server) fetchLatestRelease() (*ghRelease, int, error) {
	req, err := http.NewRequest("GET", s.updateAPIBase+"/repos/"+updateRepo+"/releases/latest", nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := s.updateHTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("releases/latest returned %d", resp.StatusCode)
	}
	var rel ghRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("decode releases/latest: %w", err)
	}
	return &rel, resp.StatusCode, nil
}

// fetchReleaseScope downloads the release.json manifest asset when the release
// carries one and returns its scope. Anything missing or malformed is "app" -
// the conservative default that installs with frozen dependencies.
func (s *Server) fetchReleaseScope(rel *ghRelease) string {
	var url string
	for _, a := range rel.Assets {
		if a.Name == updateManifestAsset {
			url = a.DownloadURL
		}
	}
	if url == "" {
		return "app"
	}
	resp, err := s.updateHTTP.Get(url)
	if err != nil {
		return "app"
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "app"
	}
	var m releaseManifest
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&m); err != nil {
		return "app"
	}
	if m.Scope == "system" {
		return "system"
	}
	return "app"
}

// publishUpdateBadge pushes the footer badge live region (shell region: every
// authenticated page has the footer).
func (s *Server) publishUpdateBadge() {
	if s.live == nil {
		return
	}
	s.live.publishIfChanged("update-badge", renderFragment(views.UpdateBadge(s.updateBadgeView())))
}

// updateBadgeView derives the footer badge state: shown only when a strictly
// newer release is known and the operator has not dismissed that exact version.
func (s *Server) updateBadgeView() views.UpdateBadgeView {
	latest, _ := s.sqlite.GetState(stateUpdateVersion)
	if latest == "" || !semverNewer(latest, updateCurrentVersion) {
		return views.UpdateBadgeView{}
	}
	if dismissed, _ := s.sqlite.GetState(stateUpdateDismissed); dismissed == latest {
		return views.UpdateBadgeView{}
	}
	return views.UpdateBadgeView{Show: true, Version: latest}
}

// buildUpdateView assembles the Settings card's state from app_state.
func (s *Server) buildUpdateView(csrf string) views.UpdateView {
	latest, _ := s.sqlite.GetState(stateUpdateVersion)
	v := views.UpdateView{Current: updateCurrentVersion, CSRF: csrf}
	v.LastCheck, _ = s.sqlite.GetState(stateUpdateLastCheck)
	if latest == "" || !semverNewer(latest, updateCurrentVersion) {
		return v
	}
	v.Available = true
	v.Version = latest
	v.Scope, _ = s.sqlite.GetState(stateUpdateScope)
	if v.Scope == "" {
		v.Scope = "app"
	}
	v.Notes, _ = s.sqlite.GetState(stateUpdateNotes)
	sha, _ := s.sqlite.GetState(stateUpdateSHA256)
	v.CanInstall = sha != ""
	ns, _ := s.sqlite.GetState(stateUpdateNeedsSystem)
	v.NeedsSystem = ns == "1"
	dismissed, _ := s.sqlite.GetState(stateUpdateDismissed)
	v.Dismissed = dismissed == latest
	return v
}

// handleUpdateCheck is the Settings card's Check Now: one synchronous manual
// check, result surfaced as a flash toast.
func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	newer, err := s.checkForUpdate(true)
	switch {
	case err != nil:
		s.setFlash(w, r, "Update check failed - is the WiFi uplink connected?", "error")
	case newer:
		latest, _ := s.sqlite.GetState(stateUpdateVersion)
		s.setFlash(w, r, "Update v"+latest+" is available.", "success")
	default:
		s.setFlash(w, r, "You are running the latest version.", "success")
	}
	s.redirectHTMX(w, r, "/settings")
}

// handleUpdateDismiss hides the footer badge for the currently known version
// (the Settings card keeps showing it; a NEWER release resurfaces the badge).
func (s *Server) handleUpdateDismiss(w http.ResponseWriter, r *http.Request) {
	latest, _ := s.sqlite.GetState(stateUpdateVersion)
	if latest != "" {
		if err := s.sqlite.SetState(stateUpdateDismissed, latest); err != nil {
			s.handleError(w, r, "Failed to save the dismissal", http.StatusInternalServerError)
			return
		}
		s.publishUpdateBadge()
	}
	s.redirectHTMX(w, r, "/settings")
}
