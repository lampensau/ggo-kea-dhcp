package web

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/version"
)

// b2i is the SQLite 1/0 encoding of a bool.
func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// backupFormat is the bundle format version. Bump it on an incompatible change so
// restore can refuse a bundle it can't safely apply.
const backupFormat = 1

// maxBackupUpload bounds an uploaded backup so a malformed/huge file can't exhaust
// memory. A real appliance backup is a few KB to low MB.
const maxBackupUpload = 8 << 20 // 8 MiB

// Backup is the complete portable state of an appliance: the control-plane SQLite
// data (users, profiles+scopes, port labels, lifecycle) AND the MariaDB host
// reservations / port pins. It is the disaster-recovery superset of the
// profile-only ProfileExport, and the safety net behind the SQLite self-heal.
//
// SECURITY: this bundle contains the admin password hashes - treat it as a
// credential and store it securely.
type Backup struct {
	Format     int               `json:"format"`     // bundle format (backupFormat)
	AppSchema  int               `json:"app_schema"` // SQLite user_version at export
	AppVersion string            `json:"app_version"`
	ExportedAt string            `json:"exported_at"`
	Lifecycle  string            `json:"lifecycle"`
	Users      []BackupUser      `json:"users"`
	Profiles   []BackupProfile   `json:"profiles"`
	PortLabels []BackupPortLabel `json:"port_labels"`
	// ReservationsIncluded is true when MariaDB was reachable at export, so the
	// hosts table was captured (even if it had zero rows). It lets restore tell
	// "no reservations because there were none" (overwrite the live table) from "no
	// reservations because MariaDB was down" (leave the live table alone). Absent in
	// pre-existing bundles (defaults false).
	ReservationsIncluded bool `json:"reservations_included"`
	// Reservations are the MariaDB hosts rows (type 0 = MAC reservation, type 4 =
	// flex-id port pin). Empty when MariaDB was unavailable at export.
	Reservations []BackupHost `json:"reservations"`
}

// BackupUser is one admin account (PBKDF2 hash carried verbatim so restore is complete).
type BackupUser struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

// BackupProfile is a stored profile and its scopes (round-tripped via ScopeConfig).
type BackupProfile struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Active      bool          `json:"active"`
	Scopes      []ScopeConfig `json:"scopes"`
}

// BackupPortLabel is one operator port annotation.
type BackupPortLabel struct {
	FlexIDHex string `json:"flex_id_hex"`
	Label     string `json:"label"`
	Location  string `json:"location"`
	Notes     string `json:"notes"`
}

// BackupHost is one Kea hosts-table row. Identifier is raw bytes (JSON base64).
type BackupHost struct {
	Identifier     []byte `json:"identifier"`
	IdentifierType int    `json:"identifier_type"`
	SubnetID       int    `json:"subnet_id"`
	IPv4Address    uint32 `json:"ipv4_address"`
	Hostname       string `json:"hostname"`
}

// buildBackup assembles the full backup bundle from SQLite + MariaDB.
func (s *Server) buildBackup() (*Backup, error) {
	b := &Backup{
		Format:     backupFormat,
		AppVersion: version.Number,
		ExportedAt: time.Now().UTC().Format(time.RFC3339),
	}
	_ = s.sqlite.QueryRow("PRAGMA user_version;").Scan(&b.AppSchema)
	b.Lifecycle, _ = s.sqlite.GetState(db.LifecycleStateKey)

	// Users. A backup that silently dropped an admin would lock the operator out on
	// restore, so any read error fails the export rather than reporting success.
	urows, err := s.sqlite.Query("SELECT username, password_hash FROM users ORDER BY id")
	if err != nil {
		return nil, fmt.Errorf("read users: %w", err)
	}
	for urows.Next() {
		var u BackupUser
		if err := urows.Scan(&u.Username, &u.PasswordHash); err != nil {
			urows.Close()
			return nil, fmt.Errorf("scan user: %w", err)
		}
		b.Users = append(b.Users, u)
	}
	if err := urows.Err(); err != nil {
		urows.Close()
		return nil, fmt.Errorf("iterate users: %w", err)
	}
	urows.Close()

	// Profiles + scopes (scopes via the same ScopeConfig path the rest of the app uses).
	prows, err := s.sqlite.Query("SELECT id, name, COALESCE(description,''), active FROM profiles ORDER BY id")
	if err != nil {
		return nil, fmt.Errorf("read profiles: %w", err)
	}
	type profRow struct {
		id     int
		name   string
		desc   string
		active bool
	}
	var profs []profRow
	for prows.Next() {
		var p profRow
		if err := prows.Scan(&p.id, &p.name, &p.desc, &p.active); err != nil {
			prows.Close()
			return nil, fmt.Errorf("scan profile: %w", err)
		}
		profs = append(profs, p)
	}
	if err := prows.Err(); err != nil {
		prows.Close()
		return nil, fmt.Errorf("read profiles: %w", err)
	}
	prows.Close()
	for _, p := range profs {
		scopes, err := s.loadScopeConfigs(p.id)
		if err != nil {
			return nil, fmt.Errorf("load scopes for profile %q: %w", p.name, err)
		}
		b.Profiles = append(b.Profiles, BackupProfile{Name: p.name, Description: p.desc, Active: p.active, Scopes: scopes})
	}

	// Port labels.
	lrows, err := s.sqlite.Query("SELECT flex_id_hex, label, COALESCE(location,''), COALESCE(notes,'') FROM port_labels")
	if err != nil {
		return nil, fmt.Errorf("read port labels: %w", err)
	}
	for lrows.Next() {
		var l BackupPortLabel
		if err := lrows.Scan(&l.FlexIDHex, &l.Label, &l.Location, &l.Notes); err != nil {
			lrows.Close()
			return nil, fmt.Errorf("scan port label: %w", err)
		}
		b.PortLabels = append(b.PortLabels, l)
	}
	if err := lrows.Err(); err != nil {
		lrows.Close()
		return nil, fmt.Errorf("iterate port labels: %w", err)
	}
	lrows.Close()

	// MariaDB host reservations + pins. Captured only when MariaDB is reachable; the
	// flag records that so restore knows whether an empty list means "none" or
	// "uncaptured" (see Backup.ReservationsIncluded).
	if s.mariadb != nil {
		if hosts, err := s.mariadb.AllReservations(); err == nil {
			b.ReservationsIncluded = true
			for _, h := range hosts {
				b.Reservations = append(b.Reservations, BackupHost{
					Identifier:     h.Identifier,
					IdentifierType: h.IdentifierType,
					SubnetID:       h.SubnetID,
					IPv4Address:    h.IPv4Address,
					Hostname:       h.Hostname,
				})
			}
		}
	}

	return b, nil
}

// restoreSections is the set of backup sections selected for a partial restore. An empty
// set (caller sent no "sections" field) is treated as "all" by selectedSections, so the
// default and any legacy/factory caller still does a full restore.
var allSections = []string{"users", "profiles", "port_labels", "reservations"}

// selectedSections reads the restore-form "sections" checkboxes. No field at all (legacy
// client, or the factory picker that omits the checkboxes) means a full restore.
func selectedSections(r *http.Request) map[string]bool {
	vals := r.Form["sections"]
	sel := map[string]bool{}
	if len(vals) == 0 {
		for _, s := range allSections {
			sel[s] = true
		}
		return sel
	}
	for _, s := range vals {
		sel[s] = true
	}
	return sel
}

// restore overwrites the selected appliance sections from a bundle: the chosen SQLite
// sections (users, profiles+scopes, port labels) are rewritten in one transaction, then
// the MariaDB hosts table is replaced (best effort) when reservations are selected.
// Unselected sections are left untouched. Lifecycle is applied only with profiles (it
// reflects whether a profile is active); otherwise the current state is kept and returned.
// It returns the lifecycle to converge to ("" signals a hard SQLite failure).
func (s *Server) restore(b *Backup, sel map[string]bool) (string, error) {
	if b.Format != backupFormat {
		return "", fmt.Errorf("unsupported backup format %d (this build supports %d)", b.Format, backupFormat)
	}
	var current int
	_ = s.sqlite.QueryRow("PRAGMA user_version;").Scan(&current)
	if b.AppSchema > current {
		return "", fmt.Errorf("backup was made by a newer version (schema %d > %d); upgrade this appliance before restoring", b.AppSchema, current)
	}

	// Read the pre-restore lifecycle BEFORE opening the transaction: the SQLite pool is
	// pinned to one connection, so a query through s.sqlite while the tx holds that
	// connection would deadlock. Used as the return value when profiles aren't restored.
	currentLifecycle, _ := s.sqlite.GetState(db.LifecycleStateKey)

	tx, err := s.sqlite.Begin()
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }() // no-op after a successful Commit

	// Each selected section clears then re-inserts its own tables. Unselected sections
	// are left alone, so a profiles-only restore keeps the current admins, and vice versa.
	if sel["users"] {
		// Clear sessions alongside users: the restored admin set may not include the
		// currently-logged-in username, and a stale ggo_session must not outlive it.
		for _, stmt := range []string{"DELETE FROM users", "DELETE FROM sessions"} {
			if _, err := tx.Exec(stmt); err != nil {
				return "", fmt.Errorf("clear users: %w", err)
			}
		}
		for _, u := range b.Users {
			if _, err := tx.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", u.Username, u.PasswordHash); err != nil {
				return "", fmt.Errorf("restore user %q: %w", u.Username, err)
			}
		}
	}

	if sel["profiles"] {
		for _, stmt := range []string{"DELETE FROM scopes", "DELETE FROM profiles"} {
			if _, err := tx.Exec(stmt); err != nil {
				return "", fmt.Errorf("clear profiles: %w", err)
			}
		}
		for _, p := range b.Profiles {
			res, err := tx.Exec("INSERT INTO profiles (name, description, active) VALUES (?, ?, ?)", p.Name, p.Description, b2i(p.Active))
			if err != nil {
				return "", fmt.Errorf("restore profile %q: %w", p.Name, err)
			}
			pid64, _ := res.LastInsertId()
			for _, sc := range p.Scopes {
				ifaceMode := "physical"
				if sc.VlanID > 0 {
					ifaceMode = "trunk"
				}
				poolSpec, _ := sc.poolSpecJSON()
				uplinkSpec, _ := sc.uplinkJSON()
				planJSON, _ := sc.planJSON()
				servicesSpec, _ := sc.servicesJSON()
				if _, err := tx.Exec(`
					INSERT INTO scopes (profile_id, iface_mode, vlan_id, cidr, preset, pool_spec, uplink_json, pool_plan, multicast_sniff, services_json, name)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
					int(pid64), ifaceMode, sc.VlanID, sc.CIDR, sc.Preset, poolSpec, uplinkSpec, planJSON, b2i(sc.MulticastSniff), servicesSpec, sc.Name); err != nil {
					return "", fmt.Errorf("restore scope in profile %q: %w", p.Name, err)
				}
			}
		}
	}

	if sel["port_labels"] {
		if _, err := tx.Exec("DELETE FROM port_labels"); err != nil {
			return "", fmt.Errorf("clear port labels: %w", err)
		}
		for _, l := range b.PortLabels {
			if _, err := tx.Exec("INSERT INTO port_labels (flex_id_hex, label, location, notes) VALUES (?, ?, ?, ?)",
				l.FlexIDHex, l.Label, l.Location, l.Notes); err != nil {
				return "", fmt.Errorf("restore port label: %w", err)
			}
		}
	}

	// Lifecycle follows the profiles section (a restored profile may be active). Without
	// it, keep - and return - the current state so the box doesn't lurch on a labels-only
	// or admins-only restore.
	lifecycle := currentLifecycle
	if sel["profiles"] {
		lifecycle = b.Lifecycle
		if lifecycle == "" {
			lifecycle = db.StateOnboarding
		}
		if _, err := tx.Exec(
			"INSERT INTO app_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
			db.LifecycleStateKey, lifecycle); err != nil {
			return "", fmt.Errorf("restore lifecycle: %w", err)
		}
	}
	if lifecycle == "" {
		lifecycle = db.StateOnboarding
	}

	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit restore: %w", err)
	}

	// MariaDB: replace the hosts table when the bundle actually captured it (so the
	// "overwrite everything" promise holds even for a bundle whose hosts table was
	// empty). A bundle taken while MariaDB was down (not captured) leaves the live
	// reservations alone rather than wiping data the backup never held. The len>0
	// clause also covers pre-existing bundles that predate the ReservationsIncluded
	// flag.
	//
	// This runs AFTER the SQLite commit (two engines, no shared transaction). A
	// failure here therefore leaves the box half-restored: control plane in, hosts
	// table not. We return that error (rather than swallow it) so the caller stops
	// reporting unqualified success and tells the operator the reservations did not
	// fully restore. lifecycle is still returned non-empty, so the caller knows the
	// SQLite restore itself succeeded and can still reconcile.
	if sel["reservations"] && s.mariadb != nil && (b.ReservationsIncluded || len(b.Reservations) > 0) {
		if err := s.mariadb.DeleteAllReservations(); err != nil {
			log.Printf("[restore] clearing MariaDB hosts failed: %v", err)
			return lifecycle, fmt.Errorf("the reservation table did not fully restore: %w", err)
		}
		hosts := make([]db.HostReservation, 0, len(b.Reservations))
		for _, h := range b.Reservations {
			hosts = append(hosts, db.HostReservation{
				Identifier:     h.Identifier,
				IdentifierType: h.IdentifierType,
				SubnetID:       h.SubnetID,
				IPv4Address:    h.IPv4Address,
				Hostname:       h.Hostname,
			})
		}
		if err := s.mariadb.InsertReservations(hosts); err != nil {
			log.Printf("[restore] inserting reservations failed: %v", err)
			return lifecycle, fmt.Errorf("the reservation table did not fully restore: %w", err)
		}
	}

	return lifecycle, nil
}

// handleBackupExport serves the full appliance backup as a downloadable JSON file.
func (s *Server) handleBackupExport(w http.ResponseWriter, r *http.Request) {
	b, err := s.buildBackup()
	if err != nil {
		s.handleError(w, r, "Failed to build backup: "+err.Error(), http.StatusInternalServerError)
		return
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		s.handleError(w, r, "Failed to encode backup: "+err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.sqlite.LogAudit(s.getActor(r), "BACKUP_EXPORT", "appliance", "", "", "SUCCESS")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", backupFilename(b)))
	_, _ = w.Write(data)
}

// backupFilename names the download after the app, the active configuration, and
// the export date, e.g. "ggo-kea-dhcp-green-go-school-2026-06-28.json". Falls back
// to the bare app name + date when no profile is active (factory/onboarding box).
func backupFilename(b *Backup) string {
	date := time.Now().Format("2006-01-02")
	for _, p := range b.Profiles {
		if p.Active {
			if slug := slugify(p.Name); slug != "" {
				return version.Name + "-" + slug + "-" + date + ".json"
			}
		}
	}
	return version.Name + "-" + date + ".json"
}

// slugify turns a profile name into a filename-safe token: lowercase, with every
// run of non-alphanumeric characters collapsed to a single hyphen.
func slugify(s string) string {
	var b strings.Builder
	lastDash := true // leading: suppress a leading hyphen
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.TrimRight(b.String(), "-")
}

// parseUploadedBackup reads and decodes the uploaded backup file from a multipart form.
func parseUploadedBackup(r *http.Request) (*Backup, error) {
	if err := r.ParseMultipartForm(maxBackupUpload); err != nil {
		return nil, fmt.Errorf("could not read upload: %w", err)
	}
	file, _, err := r.FormFile("backup")
	if err != nil {
		return nil, fmt.Errorf("no backup file provided")
	}
	defer file.Close()
	var b Backup
	dec := json.NewDecoder(io.LimitReader(file, maxBackupUpload))
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("invalid backup file: %w", err)
	}
	return &b, nil
}

// handleFactoryRestore restores from an uploaded backup on a factory-fresh box -
// the recovery path that lets a self-healed or reset appliance regain its users,
// profiles, and reservations without re-onboarding. Reachable only in FACTORY,
// pre-auth (there is no admin yet); it must carry one in the bundle.
func (s *Server) handleFactoryRestore(w http.ResponseWriter, r *http.Request) {
	// This route is pre-auth (FACTORY has no admin yet) and installs the admin hash
	// from the uploaded bundle verbatim - so it is also a takeover primitive for
	// anyone who can reach the box during the FACTORY window. True auth is impossible
	// here without an out-of-band recovery secret; we reduce the exposure by
	// rate-limiting (a global "factory-restore" bucket - behind the loopback proxy
	// every attempt shares it, which still throttles a brute force) and by auditing
	// every ATTEMPT before applying, so a takeover leaves a trail.
	r.Body = http.MaxBytesReader(w, r.Body, maxBackupUpload) // bound the pre-auth upload before any temp-file spill
	const throttleKey = "factory-restore"
	if ok, retry := s.loginThrottle.allow(throttleKey); !ok {
		s.loginThrottled(w, r, retry)
		return
	}
	_ = s.sqlite.LogAudit("SYSTEM", "FACTORY_RESTORE_ATTEMPT", "appliance", "", clientIP(r), "WARNING")

	b, err := parseUploadedBackup(r)
	if err != nil {
		s.loginThrottle.fail(throttleKey)
		s.handleError(w, r, err.Error(), http.StatusBadRequest)
		return
	}
	if len(b.Users) == 0 {
		s.loginThrottle.fail(throttleKey)
		s.handleError(w, r, "This backup has no administrator account; it cannot recover a factory-fresh appliance.", http.StatusBadRequest)
		return
	}
	// The factory picker now exposes per-section checkboxes, so honor the operator's
	// selection - but force users on regardless so the box can never be left admin-less.
	sel := selectedSections(r)
	sel["users"] = true
	lifecycle, rerr := s.restore(b, sel)
	if lifecycle == "" {
		s.loginThrottle.fail(throttleKey)
		_ = s.sqlite.LogAudit("SYSTEM", "BACKUP_RESTORE", "appliance", "", rerr.Error(), "ERROR")
		s.handleError(w, r, "Restore failed: "+rerr.Error(), http.StatusInternalServerError)
		return
	}
	s.loginThrottle.succeed(throttleKey) // a completed restore clears the backoff
	s.finishRestore(w, "SYSTEM", lifecycle, rerr,
		"Backup restored. Sign in with your restored administrator account.")
	http.Redirect(w, r, "/login", http.StatusFound)
}

// handleSettingsRestore restores from an uploaded backup (authenticated path) and
// reconciles runtime state to the restored profile.
func (s *Server) handleSettingsRestore(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBackupUpload)
	b, err := parseUploadedBackup(r)
	if err != nil {
		s.handleError(w, r, err.Error(), http.StatusBadRequest)
		return
	}
	lifecycle, rerr := s.restore(b, selectedSections(r))
	if lifecycle == "" {
		// Hard failure: the SQLite restore itself did not happen (nothing changed).
		_ = s.sqlite.LogAudit(s.getActor(r), "BACKUP_RESTORE", "appliance", "", rerr.Error(), "ERROR")
		s.handleError(w, r, "Restore failed: "+rerr.Error(), http.StatusInternalServerError)
		return
	}
	s.finishRestore(w, s.getActor(r), lifecycle, rerr,
		"Backup restored. The appliance is re-applying the restored configuration.")
	http.Redirect(w, r, "/settings", http.StatusFound)
}

// finishRestore runs the post-SQLite-commit steps shared by both restore paths:
// reconcile to the restored config (serialized by the guard), then audit + flash
// according to whether the MariaDB hosts table also fully restored. A non-nil rerr
// here means the control plane restored but reservations did not - reported as a
// warning, not unqualified success, so the operator knows the box is half-restored.
func (s *Server) finishRestore(w http.ResponseWriter, actor, lifecycle string, rerr error, okMsg string) {
	if s.beginReconcile() {
		s.scheduleReconcileHeld("restore", 0, ModeConverge, 0)
	} else {
		log.Printf("[restore] post-restore reconcile deferred - a configuration change is in progress")
	}
	if rerr != nil {
		_ = s.sqlite.LogAudit(actor, "BACKUP_RESTORE", "appliance", "", "lifecycle="+lifecycle+"; "+rerr.Error(), "WARNING")
		s.setFlash(w, "Control plane restored, but "+rerr.Error()+" - re-run the restore or re-add the reservations.", "info")
		return
	}
	_ = s.sqlite.LogAudit(actor, "BACKUP_RESTORE", "appliance", "", "lifecycle="+lifecycle, "SUCCESS")
	s.setFlash(w, okMsg, "success")
}
