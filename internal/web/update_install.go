package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"ggo-kea-dhcp/internal/db"
)

// The privileged half of the self-update: the control plane stages the .deb
// into the StateDirectory (streamed through sha256 against the release's
// published digest), then triggers a root oneshot unit that installs it. The
// running process is restarted in place by the package's own postinstall; the
// updater reports its outcome to result.json, which this process (app-scope
// failures) or the next boot (successful restarts) reconciles into the audit
// log.
const (
	updateStagedDeb    = "ggo-kea-dhcp_arm64.deb"
	updateManifestFile = "manifest.json"
	updateResultFile   = "result.json"
	updateAptLogFile   = "apt.log"
	// updateMaxDebSize bounds the download so a misbehaving remote can't fill the
	// SD card (real packages are ~15 MB).
	updateMaxDebSize = 256 << 20
	// updateStageHeadroom is the free space required beyond the package itself.
	updateStageHeadroom = 64 << 20
)

// Result-poll cadence after triggering the oneshot. On success this process is
// restarted long before the deadline; the poll exists for the failure paths,
// which never restart the service. Vars so tests can shrink them.
var (
	updateResultPollInterval = 10 * time.Second
	updateResultWaitApp      = 5 * time.Minute
	// System scope runs a full apt upgrade of the pinned dependencies - allow the
	// update unit's whole TimeoutStartSec plus a margin.
	updateResultWaitSystem = 21 * time.Minute
)

// updateStageManifest is what the app writes for the root updater: everything
// the oneshot needs, re-verifiable (sha256) and self-describing (scope).
// Compact JSON with string values - updater.sh parses it with sed, no jq.
type updateStageManifest struct {
	Schema      int    `json:"schema"`
	Version     string `json:"version"`
	Scope       string `json:"scope"`
	SHA256      string `json:"sha256"`
	Deb         string `json:"deb"`
	RequestedBy string `json:"requested_by"`
}

// updateRunResult is updater.sh's outcome report.
type updateRunResult struct {
	Version string `json:"version"`
	Status  string `json:"status"` // "ok" | "failed" | "needs_system"
	Detail  string `json:"detail"`
}

// stageUpdate downloads the release .deb into the staging directory, streaming
// through sha256 and verifying against the GitHub-published digest before the
// file gets its final name (.partial until proven). Also writes the manifest
// the root updater consumes. Synchronous - the install POST's data-busy covers
// the download and the server has no WriteTimeout.
func (s *Server) stageUpdate(version, scope, debURL, wantSHA, requestedBy string) error {
	dir := s.updateDir
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create staging dir: %w", err)
	}

	resp, err := s.updateHTTP.Get(debURL)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: server returned %d", resp.StatusCode)
	}
	if resp.ContentLength > updateMaxDebSize {
		return fmt.Errorf("download: package is implausibly large (%d bytes)", resp.ContentLength)
	}
	if err := checkStageSpace(dir, resp.ContentLength); err != nil {
		return err
	}

	partial := filepath.Join(dir, updateStagedDeb+".partial")
	f, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create staging file: %w", err)
	}
	sum := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, sum), io.LimitReader(resp.Body, updateMaxDebSize+1))
	if err == nil && n > updateMaxDebSize {
		err = fmt.Errorf("package exceeds the %d byte staging cap", int64(updateMaxDebSize))
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		if got := hex.EncodeToString(sum.Sum(nil)); !strings.EqualFold(got, wantSHA) {
			err = fmt.Errorf("checksum mismatch: got sha256:%s, expected sha256:%s - refusing to stage", got, wantSHA)
		}
	}
	if err != nil {
		_ = os.Remove(partial)
		return err
	}

	staged := filepath.Join(dir, updateStagedDeb)
	if err := os.Rename(partial, staged); err != nil {
		_ = os.Remove(partial)
		return fmt.Errorf("finalize staged package: %w", err)
	}

	man, _ := json.Marshal(updateStageManifest{
		Schema: 1, Version: version, Scope: scope,
		SHA256: strings.ToLower(wantSHA), Deb: staged, RequestedBy: requestedBy,
	})
	tmp := filepath.Join(dir, updateManifestFile+".partial")
	if err := os.WriteFile(tmp, append(man, '\n'), 0o644); err != nil {
		return fmt.Errorf("write staging manifest: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, updateManifestFile)); err != nil {
		return fmt.Errorf("finalize staging manifest: %w", err)
	}
	// A previous run's result must not be mistaken for this run's.
	_ = os.Remove(filepath.Join(dir, updateResultFile))
	return nil
}

// checkStageSpace refuses to download when the staging filesystem lacks the
// package size plus headroom (apt needs room of its own during the install).
func checkStageSpace(dir string, contentLength int64) error {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return nil // can't tell - let the write itself fail if space runs out
	}
	need := uint64(updateStageHeadroom)
	if contentLength > 0 {
		need += uint64(contentLength)
	}
	if avail := st.Bavail * uint64(st.Bsize); avail < need {
		return fmt.Errorf("not enough free space to stage the update (%d MB available)", avail>>20)
	}
	return nil
}

// handleUpdateInstall is the one-click privileged install. Guard chain, in
// order: password re-auth, lifecycle ACTIVE, the requested version must still
// be the known latest with a published digest, then the updating CAS and the
// shared apply guard - so an install can never race a profile apply (or a
// second install) against the box. Staging runs synchronously; the response is
// the same-IP polling interstitial; the root oneshot is triggered after the
// response has flushed.
func (s *Server) handleUpdateInstall(w http.ResponseWriter, r *http.Request) {
	actor := s.getActor(r)
	refuse := func(code int, reason string) {
		_ = s.sqlite.LogAudit(actor, "UPDATE_INSTALL", "", "", reason, "WARNING")
		s.handleError(w, r, reason, code)
	}

	if ok, reason := s.reauthCurrentPassword(r); !ok {
		refuse(http.StatusBadRequest, reason)
		return
	}
	if state, _ := s.sqlite.GetState(db.LifecycleStateKey); state != db.StateActive {
		refuse(http.StatusConflict, "Updates can only be installed while the appliance is active.")
		return
	}

	latest, _ := s.sqlite.GetState(stateUpdateVersion)
	if latest == "" || r.FormValue("version") != latest || !semverNewer(latest, updateCurrentVersion) {
		refuse(http.StatusConflict, "That release is no longer the latest known version - check again and retry.")
		return
	}
	sha, _ := s.sqlite.GetState(stateUpdateSHA256)
	debURL, _ := s.sqlite.GetState(stateUpdateDebURL)
	if sha == "" || debURL == "" {
		refuse(http.StatusConflict, "This release publishes no verification digest and cannot be installed from here.")
		return
	}
	scope, _ := s.sqlite.GetState(stateUpdateScope)
	if scope != "system" {
		scope = "app"
	}
	if r.FormValue("scope") == "system" && scope != "system" {
		// The broader path is offered only after a frozen-dependency install
		// reported unsatisfiable deps - it is never the silent default.
		if ns, _ := s.sqlite.GetState(stateUpdateNeedsSystem); ns != "1" {
			refuse(http.StatusBadRequest, "A system-scope install is not applicable to this release.")
			return
		}
		scope = "system"
	}

	if !s.updating.CompareAndSwap(false, true) {
		refuse(http.StatusConflict, "A software update is already in progress.")
		return
	}
	if !s.beginReconcile() {
		s.updating.Store(false)
		refuse(http.StatusConflict, reconcileBusyMsg)
		return
	}
	// Both guards are held from here until the updater reports a result (poll
	// below) or the control plane is restarted onto the new binary.

	if err := s.stageUpdate(latest, scope, debURL, sha, actor); err != nil {
		s.releaseUpdateGuards()
		_ = s.sqlite.LogAudit(actor, "UPDATE_INSTALL", "v"+latest, "", err.Error(), "FAILURE")
		s.handleError(w, r, "Could not stage the update: "+err.Error(), http.StatusBadGateway)
		return
	}
	_ = s.sqlite.LogAudit(actor, "UPDATE_INSTALL", "v"+latest, "", "scope="+scope+" staged, installer triggered", "SUCCESS")

	s.respondSystemInterstitial(w,
		"Installing update…",
		"The verified package is staged and the appliance's update service is installing it. The control plane restarts in place - this page reconnects on its own (a system-scope update can take several minutes).",
		true)
	deferAfterResponse("update-install", func() error {
		if err := s.net.TriggerUpdate(); err != nil {
			_ = s.sqlite.LogAudit("SYSTEM", "UPDATE_FAILED", "v"+latest, "", "could not start the update service: "+err.Error(), "ERROR")
			s.releaseUpdateGuards()
			return err
		}
		s.watchUpdateResult(scope)
		return nil
	})
}

// releaseUpdateGuards frees both mutual-exclusion guards the install path holds.
func (s *Server) releaseUpdateGuards() {
	s.endReconcile()
	s.updating.Store(false)
}

// watchUpdateResult polls result.json after the oneshot was triggered. On a
// successful update this process is replaced long before the deadline (the
// postinstall restarts it), so reaching a result here means the install did
// NOT restart the service: an app-scope failure or needs_system - process it
// and free the guards. A silent timeout is audited so a wedged updater isn't
// an invisible stuck state.
func (s *Server) watchUpdateResult(scope string) {
	// Join the shutdown wait like the other background loops (bg.go's bgRunner
	// comment lists this watcher among them). deferAfterResponse spawns us in a bare
	// goroutine that the shutdown join does not cover, so without this the loop
	// could be mid-processUpdateResult - a DB write - when sqlite.Close runs, losing
	// a failed/needs_system outcome. A refused registration means shutdown is under
	// way: skip and let the boot-path reconcileUpdateResult fold the result instead.
	// Mirrors kickUpdateCheck.
	done, ok := s.bg.add()
	if !ok {
		return
	}
	defer done()
	wait := updateResultWaitApp
	if scope == "system" {
		wait = updateResultWaitSystem
	}
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		select {
		case <-time.After(updateResultPollInterval):
		case <-s.bg.doneCh():
			return // shutting down (usually the update restarting us) - no audit, no DB writes
		}
		if res := s.readUpdateResult(); res != nil {
			s.processUpdateResult(*res)
			s.releaseUpdateGuards()
			return
		}
	}
	_ = s.sqlite.LogAudit("SYSTEM", "UPDATE_FAILED", "", "", fmt.Sprintf("the update service reported no result within %s", wait), "WARNING")
	s.releaseUpdateGuards()
}

// readUpdateResult parses the staging directory's result.json, nil when absent
// or malformed.
func (s *Server) readUpdateResult() *updateRunResult {
	data, err := os.ReadFile(filepath.Join(s.updateDir, updateResultFile))
	if err != nil {
		return nil
	}
	var res updateRunResult
	if err := json.Unmarshal(data, &res); err != nil {
		log.Printf("[update] malformed result.json: %v", err)
		return nil
	}
	return &res
}

// readUpdateManifest parses the staging manifest, nil when absent or malformed.
func (s *Server) readUpdateManifest() *updateStageManifest {
	data, err := os.ReadFile(filepath.Join(s.updateDir, updateManifestFile))
	if err != nil {
		return nil
	}
	var man updateStageManifest
	if err := json.Unmarshal(data, &man); err != nil {
		return nil
	}
	return &man
}

// processUpdateResult turns one updater outcome into audit rows + state. It
// does NOT touch the install guards (the boot path never held them); the
// in-process poller releases them after calling this.
func (s *Server) processUpdateResult(res updateRunResult) {
	switch res.Status {
	case "ok":
		if res.Version == updateCurrentVersion {
			s.auditUpdateApplied(res.Version)
			s.clearUpdateState()
			s.removeStaged(updateStagedDeb, updateManifestFile, updateResultFile, updateAptLogFile)
			return
		}
		// The updater reported success but this process still runs another version:
		// the restart onto the new binary did not land.
		_ = s.sqlite.LogAudit("SYSTEM", "UPDATE_FAILED", "v"+res.Version, "",
			"updater reported success but the running version is v"+updateCurrentVersion, "ERROR")
		s.removeStaged(updateResultFile)
	case "needs_system":
		// Frozen-dependency install hit unsatisfiable deps. Keep the staged .deb -
		// the Settings card now offers the system-scope path as a second explicit
		// click (which re-stages anyway, but the artifact documents what happened).
		_ = s.sqlite.SetState(stateUpdateNeedsSystem, "1")
		_ = s.sqlite.LogAudit("SYSTEM", "UPDATE_FAILED", "v"+res.Version, "",
			"dependencies changed - a system-scope update is required ("+res.Detail+")", "WARNING")
		s.removeStaged(updateResultFile)
		s.publishUpdateBadge()
	default: // "failed" or anything unrecognized
		_ = s.sqlite.LogAudit("SYSTEM", "UPDATE_FAILED", "v"+res.Version, "", res.Detail, "ERROR")
		s.removeStaged(updateStagedDeb, updateManifestFile, updateResultFile, updateAptLogFile)
	}
}

// auditUpdateApplied writes the one UPDATE_APPLIED row per landed version. The
// persisted latch makes it idempotent across the boot path and a late-arriving
// result.json (the updater writes its result AFTER apt returns, i.e. after the
// new binary already booted).
func (s *Server) auditUpdateApplied(ver string) {
	if applied, _ := s.sqlite.GetState("update_applied_version"); applied == ver {
		return
	}
	_ = s.sqlite.LogAudit("SYSTEM", "UPDATE_APPLIED", "v"+ver, "", "running version confirmed", "OK")
	_ = s.sqlite.SetState("update_applied_version", ver)
}

// clearUpdateState drops the stored "newer release" record (badge + card go
// quiet immediately; the next check re-derives everything).
func (s *Server) clearUpdateState() {
	_ = s.sqlite.SetStates(map[string]string{
		stateUpdateVersion: "", stateUpdateScope: "", stateUpdateNotes: "",
		stateUpdateDebURL: "", stateUpdateSHA256: "", stateUpdateNeedsSystem: "",
	})
	s.publishUpdateBadge()
}

// removeStaged deletes the named staging files, best-effort.
func (s *Server) removeStaged(names ...string) {
	for _, n := range names {
		_ = os.Remove(filepath.Join(s.updateDir, n))
	}
}

// clearStagedUpdate empties the whole staging directory, best-effort. Called on
// reset so a staged .deb/manifest (and the badge/anchor its state drives) never
// outlives the wipe. Safe against a racing install: both reset handlers and the
// install path hold the reconcile guard.
func (s *Server) clearStagedUpdate() {
	entries, err := os.ReadDir(s.updateDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		_ = os.Remove(filepath.Join(s.updateDir, e.Name()))
	}
}

// reconcileUpdateResult runs once at boot: it clears stale partials, folds a
// pending updater result into the audit log, and recognizes the
// successful-update race - on success the postinstall restarts this process
// while apt is still running, so the new binary boots BEFORE result.json
// exists; the staged manifest matching the running version is the proof the
// update landed.
func (s *Server) reconcileUpdateResult() {
	entries, err := os.ReadDir(s.updateDir)
	if err != nil {
		return // no staging dir - nothing ever staged
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".partial") {
			_ = os.Remove(filepath.Join(s.updateDir, e.Name()))
		}
	}
	if res := s.readUpdateResult(); res != nil {
		s.processUpdateResult(*res)
		return
	}
	man := s.readUpdateManifest()
	if man == nil {
		return
	}
	if man.Version == updateCurrentVersion {
		// Reaching here means the running binary already IS the manifest's version, so
		// the oneshot ran and restarted us mid-flight and its exit-trap result.json write
		// is imminent (readUpdateResult above returned nil because that file is not there
		// yet, or is a malformed partial). Fold via the manifest now; removeStaged clears
		// a malformed leftover, and the sweep below removes the valid result.json the
		// oneshot writes just after - which would otherwise sit orphaned in the staging
		// dir until the next restart.
		s.auditUpdateApplied(man.Version)
		s.clearUpdateState()
		s.removeStaged(updateStagedDeb, updateManifestFile, updateResultFile, updateAptLogFile)
		s.sweepLateUpdateResult()
		return
	}
	// A staged package for some other version with no result: a crash between
	// staging and the oneshot's report. Drop it - the operator can simply retry
	// from the Settings card.
	log.Printf("[update] discarding stale staged update v%s (no result recorded)", man.Version)
	s.removeStaged(updateStagedDeb, updateManifestFile, updateResultFile, updateAptLogFile)
}

// sweepLateUpdateResult removes the result.json that updater.sh writes from its exit
// trap just AFTER a clean apply was already folded via reconcileUpdateResult's manifest
// branch (the .deb postinstall restarts the service mid-oneshot, so the boot reconcile
// can beat the result write). Without this, that late file is orphaned in the staging
// dir until the next restart. Polls on a short cadence and stops the instant it removes
// the file; joined to the shutdown wait and bailing on bg.doneCh, mirroring watchUpdateResult.
func (s *Server) sweepLateUpdateResult() {
	done, ok := s.bg.add()
	if !ok {
		return
	}
	go func() {
		defer done()
		deadline := time.Now().Add(updateResultWaitApp)
		for time.Now().Before(deadline) {
			select {
			case <-time.After(updateResultPollInterval):
			case <-s.bg.doneCh():
				return
			}
			if _, err := os.Stat(filepath.Join(s.updateDir, updateResultFile)); err == nil {
				s.removeStaged(updateResultFile)
				return
			}
		}
	}()
}
