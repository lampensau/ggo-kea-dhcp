package web

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"ggo-kea-dhcp/internal/db"
)

// allSel is the full-restore section set (every section selected), matching the default
// the handlers use when the form carries no "sections" field.
func allSel() map[string]bool {
	m := map[string]bool{}
	for _, s := range allSections {
		m[s] = true
	}
	return m
}

// TestBackupRestoreRoundTrip seeds control-plane data, exports a backup, mutates
// the database, then restores the (JSON-round-tripped) bundle and asserts the
// original state came back. MariaDB is nil here, so only the SQLite half is
// exercised - the reservation path is best-effort and guarded by s.mariadb != nil.
func TestBackupRestoreRoundTrip(t *testing.T) {
	s, _ := newTestServer(t)

	// Seed: an admin, an active profile + scope, a port label, ACTIVE lifecycle.
	if _, err := s.sqlite.Exec("INSERT INTO users (username, password_hash) VALUES ('admin','hash-123')"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	res, err := s.sqlite.Exec("INSERT INTO profiles (name, description, active) VALUES ('Show A','main',1)")
	if err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	pid, _ := res.LastInsertId()
	if _, err := s.sqlite.Exec(
		"INSERT INTO scopes (profile_id, iface_mode, vlan_id, cidr, preset) VALUES (?,?,?,?,?)",
		pid, "physical", 0, "10.0.0.0/24", "greengo"); err != nil {
		t.Fatalf("seed scope: %v", err)
	}
	if _, err := s.sqlite.Exec("INSERT INTO port_labels (flex_id_hex, label, location, notes) VALUES ('41561f','Stage L','FOH','note')"); err != nil {
		t.Fatalf("seed label: %v", err)
	}
	if err := s.sqlite.SetState(db.LifecycleStateKey, db.StateActive); err != nil {
		t.Fatalf("seed lifecycle: %v", err)
	}

	// Export.
	b, err := s.buildBackup(t.Context())
	if err != nil {
		t.Fatalf("buildBackup: %v", err)
	}
	if len(b.Users) != 1 || b.Users[0].Username != "admin" || b.Users[0].PasswordHash != "hash-123" {
		t.Fatalf("backup users wrong: %+v", b.Users)
	}
	if len(b.Profiles) != 1 || b.Profiles[0].Name != "Show A" || !b.Profiles[0].Active || len(b.Profiles[0].Scopes) != 1 {
		t.Fatalf("backup profiles wrong: %+v", b.Profiles)
	}
	if len(b.PortLabels) != 1 || b.PortLabels[0].Label != "Stage L" {
		t.Fatalf("backup labels wrong: %+v", b.PortLabels)
	}
	if b.Lifecycle != db.StateActive {
		t.Fatalf("backup lifecycle = %q, want ACTIVE", b.Lifecycle)
	}

	// Simulate the file round-trip (download -> upload).
	raw, _ := json.Marshal(b)
	var restored Backup
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatalf("json round-trip: %v", err)
	}

	// Mutate the DB so the restore has something to undo.
	if _, err := s.sqlite.Exec("DELETE FROM users"); err != nil {
		t.Fatalf("wipe users: %v", err)
	}
	if err := s.sqlite.SetState(db.LifecycleStateKey, db.StateFactory); err != nil {
		t.Fatalf("mutate lifecycle: %v", err)
	}

	// Restore.
	lifecycle, err := s.restore(&restored, allSel())
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if lifecycle != db.StateActive {
		t.Fatalf("restore returned lifecycle %q, want ACTIVE", lifecycle)
	}

	// Verify the original state came back.
	var uname, phash string
	if err := s.sqlite.QueryRow("SELECT username, password_hash FROM users").Scan(&uname, &phash); err != nil {
		t.Fatalf("read restored user: %v", err)
	}
	if uname != "admin" || phash != "hash-123" {
		t.Errorf("restored user = %s/%s, want admin/hash-123", uname, phash)
	}
	var pname string
	var active int
	if err := s.sqlite.QueryRow("SELECT name, active FROM profiles").Scan(&pname, &active); err != nil {
		t.Fatalf("read restored profile: %v", err)
	}
	if pname != "Show A" || active != 1 {
		t.Errorf("restored profile = %s active=%d, want Show A active=1", pname, active)
	}
	var nScopes, nLabels int
	_ = s.sqlite.QueryRow("SELECT COUNT(*) FROM scopes").Scan(&nScopes)
	_ = s.sqlite.QueryRow("SELECT COUNT(*) FROM port_labels").Scan(&nLabels)
	if nScopes != 1 || nLabels != 1 {
		t.Errorf("restored counts: scopes=%d labels=%d, want 1/1", nScopes, nLabels)
	}
	if st, _ := s.sqlite.GetState(db.LifecycleStateKey); st != db.StateActive {
		t.Errorf("restored lifecycle = %q, want ACTIVE", st)
	}
}

// TestSettingsRestoreRefusedWhileBusy proves the authenticated restore claims the
// mutation guard BEFORE rewriting profiles/scopes/lifecycle: while an apply holds
// the guard, the restore is refused and nothing in the database changes (it would
// otherwise rewrite the very rows the in-flight apply is reconciling).
func TestSettingsRestoreRefusedWhileBusy(t *testing.T) {
	s, _ := newTestServer(t)
	seedAdmin(t, s, "pw")
	if _, err := s.sqlite.Exec("INSERT INTO profiles (name, description, active) VALUES ('Current','live',1)"); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	if err := s.sqlite.SetState(db.LifecycleStateKey, db.StateConfiguring); err != nil {
		t.Fatalf("seed lifecycle: %v", err)
	}

	// A valid bundle that would replace the profile set if the restore ran.
	var schema int
	_ = s.sqlite.QueryRow("PRAGMA user_version;").Scan(&schema)
	raw, _ := json.Marshal(&Backup{
		Format: backupFormat, AppSchema: schema, Lifecycle: db.StateActive,
		Users:    []BackupUser{{Username: "restored", PasswordHash: "hash"}},
		Profiles: []BackupProfile{{Name: "Restored", Active: true}},
	})
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("current_password", "pw")
	fw, _ := mw.CreateFormFile("backup", "b.json")
	_, _ = fw.Write(raw)
	_ = mw.Close()
	req := httptest.NewRequest("POST", "/settings/restore", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())

	// An apply is in flight.
	if !s.beginReconcile() {
		t.Fatal("beginReconcile should succeed")
	}
	defer s.endReconcile()

	rr := httptest.NewRecorder()
	s.handleSettingsRestore(rr, req)

	if rr.Code == http.StatusOK {
		t.Errorf("busy restore returned 200 - it should have been refused")
	}
	var name string
	if err := s.sqlite.QueryRow("SELECT name FROM profiles WHERE active = 1").Scan(&name); err != nil || name != "Current" {
		t.Errorf("active profile = %q (err=%v), want the untouched 'Current'", name, err)
	}
	if st, _ := s.sqlite.GetState(db.LifecycleStateKey); st != db.StateConfiguring {
		t.Errorf("lifecycle = %q, want the untouched CONFIGURING", st)
	}
	var users int
	_ = s.sqlite.QueryRow("SELECT COUNT(*) FROM users WHERE username = 'restored'").Scan(&users)
	if users != 0 {
		t.Error("the bundle's users were written despite the busy refusal")
	}
}

// TestRestoreRejectsNewerSchema verifies a bundle from a newer schema is refused.
func TestRestoreRejectsNewerSchema(t *testing.T) {
	s, _ := newTestServer(t)
	b := &Backup{Format: backupFormat, AppSchema: 99999, Lifecycle: db.StateActive}
	if _, err := s.restore(b, allSel()); err == nil {
		t.Fatal("expected restore to reject a newer-schema bundle")
	}
}

// TestPartialRestoreLeavesUnselectedSections verifies a profiles-only restore rewrites
// profiles + lifecycle but leaves the current admins and port labels untouched.
func TestPartialRestoreLeavesUnselectedSections(t *testing.T) {
	s, _ := newTestServer(t)

	// Current box: an admin and a port label we must NOT lose, FACTORY lifecycle.
	if _, err := s.sqlite.Exec("INSERT INTO users (username, password_hash) VALUES ('keep','keep-hash')"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := s.sqlite.Exec("INSERT INTO port_labels (flex_id_hex, label) VALUES ('aa','Keep me')"); err != nil {
		t.Fatalf("seed label: %v", err)
	}
	_ = s.sqlite.SetState(db.LifecycleStateKey, db.StateFactory)

	// Bundle carries a different admin, a profile, a different label, ACTIVE.
	b := &Backup{
		Format: backupFormat, Lifecycle: db.StateActive,
		Users:      []BackupUser{{Username: "from-backup", PasswordHash: "x"}},
		Profiles:   []BackupProfile{{Name: "Show B", Active: true, Scopes: []ScopeConfig{{Preset: "greengo", CIDR: "10.0.0.0/24"}}}},
		PortLabels: []BackupPortLabel{{FlexIDHex: "bb", Label: "From backup"}},
	}

	// Restore only profiles.
	lifecycle, err := s.restore(b, map[string]bool{"profiles": true})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if lifecycle != db.StateActive {
		t.Errorf("lifecycle = %q, want ACTIVE (follows profiles)", lifecycle)
	}

	// Profiles came in.
	var pname string
	if err := s.sqlite.QueryRow("SELECT name FROM profiles").Scan(&pname); err != nil || pname != "Show B" {
		t.Errorf("profile = %q err=%v, want Show B", pname, err)
	}
	// Admins untouched: the original 'keep' admin remains, the backup's admin did NOT land.
	var uname string
	if err := s.sqlite.QueryRow("SELECT username FROM users").Scan(&uname); err != nil || uname != "keep" {
		t.Errorf("user = %q err=%v, want keep (admins not selected)", uname, err)
	}
	// Port labels untouched.
	var label string
	if err := s.sqlite.QueryRow("SELECT label FROM port_labels").Scan(&label); err != nil || label != "Keep me" {
		t.Errorf("label = %q err=%v, want 'Keep me' (labels not selected)", label, err)
	}
}

// TestSelectedSectionsDefaultsToAll: an empty form (no checkboxes) means full restore.
func TestSelectedSectionsDefaultsToAll(t *testing.T) {
	r := httptest.NewRequest("POST", "/settings/restore", nil)
	_ = r.ParseForm()
	sel := selectedSections(r)
	for _, s := range allSections {
		if !sel[s] {
			t.Errorf("empty form should select %q", s)
		}
	}
}

// TestBackupExportRequiresReauth proves the backup download re-proves the operator's
// password before handing out the bundle (it carries every admin hash plus the WiFi
// and SoftAP passphrases): a wrong or missing password is refused and audited, the
// correct one returns the attachment.
func TestBackupExportRequiresReauth(t *testing.T) {
	s, _ := newTestServer(t)
	seedAdmin(t, s, "correct horse battery staple")
	sid, err := s.createSession("admin")
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	export := func(form url.Values) *httptest.ResponseRecorder {
		req := postForm(form)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
		rr := httptest.NewRecorder()
		s.handleBackupExport(rr, req)
		return rr
	}

	for _, form := range []url.Values{
		{"current_password": {"wrong"}},
		{}, // missing entirely
	} {
		if cd := export(form).Header().Get("Content-Disposition"); cd != "" {
			t.Fatalf("form %v: export served an attachment without re-auth", form)
		}
	}
	var refused int
	if err := s.sqlite.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action = 'BACKUP_EXPORT' AND result = 'WARNING'").Scan(&refused); err != nil || refused != 2 {
		t.Fatalf("refused exports audited %d times (err=%v), want 2", refused, err)
	}

	rr := export(url.Values{"current_password": {"correct horse battery staple"}})
	if rr.Code != http.StatusOK || !strings.Contains(rr.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("correct password: code=%d disposition=%q, want an attachment", rr.Code, rr.Header().Get("Content-Disposition"))
	}
	var b Backup
	if err := json.Unmarshal(rr.Body.Bytes(), &b); err != nil {
		t.Fatalf("export body is not a backup bundle: %v", err)
	}
	if len(b.Users) != 1 || b.Users[0].Username != "admin" {
		t.Fatalf("bundle users = %+v, want the seeded admin", b.Users)
	}
}
