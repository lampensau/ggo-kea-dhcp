package web

import (
	"testing"

	"ggo-kea-dhcp/internal/db"
)

// TestBackupSettingKeysCoverCredentials guards the whitelist: the day someone adds a
// new box-level app_state setting (e.g. uplink_priority) and forgets to add it to
// backupSettingKeys, that setting would silently drop on every restore. This fails
// loudly instead. Deliberately asserts a subset (the credential + service keys that
// cause real damage if lost), not the exact list, so adding a key doesn't require
// touching this test.
func TestBackupSettingKeysCoverCredentials(t *testing.T) {
	must := []string{
		"uplink_enabled", "uplink_ssid", "uplink_pass",
		"softap_ssid", "softap_pass",
		"global_dhcp_options", "lease_lifetime",
	}
	have := map[string]bool{}
	for _, k := range backupSettingKeys {
		have[k] = true
	}
	for _, k := range must {
		if !have[k] {
			t.Errorf("backupSettingKeys is missing %q - a box setting the tree reads/writes but the backup does not carry silently drops on restore", k)
		}
	}
}

// TestRestoreNilSettingsLeavesLiveValues exercises the back-compat promise the PR
// leads with: a pre-existing bundle (no settings map -> Settings decodes as nil) must
// leave the live box settings untouched, not wipe them. This is the exact regression a
// future refactor of the restore gate would break.
func TestRestoreNilSettingsLeavesLiveValues(t *testing.T) {
	s, _ := newTestServer(t)

	// A live box setting that the old-format bundle never captured.
	if err := s.sqlite.SetState("uplink_ssid", "LiveNet"); err != nil {
		t.Fatalf("seed live setting: %v", err)
	}

	var schema int
	_ = s.sqlite.QueryRow("PRAGMA user_version;").Scan(&schema)
	// Old-style bundle: profiles section present (so the settings gate is reached),
	// but Settings is nil - the shape a pre-settings bundle decodes to.
	b := &Backup{
		Format: backupFormat, AppSchema: schema, Lifecycle: db.StateActive,
		Profiles: []BackupProfile{{Name: "P", Active: true}},
		Settings: nil,
	}
	if _, err := s.restore(b, map[string]bool{"profiles": true}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if v, _ := s.sqlite.GetState("uplink_ssid"); v != "LiveNet" {
		t.Errorf("nil-Settings restore wiped a live value: uplink_ssid=%q, want LiveNet (unchanged)", v)
	}
}
