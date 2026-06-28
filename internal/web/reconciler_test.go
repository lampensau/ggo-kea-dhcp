package web

import (
	"path/filepath"
	"testing"
	"time"

	"ggo-kea-dhcp/internal/config"
	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/kea"
	"ggo-kea-dhcp/internal/network"
)

// withResumeBackoff temporarily overrides the resume-apply backoff so a test that
// drives the (permanent-failure) fallback path doesn't sleep the production schedule.
func withResumeBackoff(d time.Duration) func() {
	prev := resumeApplyBackoff
	resumeApplyBackoff = d
	return func() { resumeApplyBackoff = prev }
}

// TestReconcileGuardSerializes proves the shared mutation guard admits one holder at
// a time and re-opens after release - the fence that serializes apply/switch against
// settings/reset/pools/restore reconciles.
func TestReconcileGuardSerializes(t *testing.T) {
	s, _ := newTestServer(t)
	if !s.beginReconcile() {
		t.Fatal("first beginReconcile should succeed")
	}
	if s.beginReconcile() {
		t.Fatal("second beginReconcile must fail while the guard is held")
	}
	s.endReconcile()
	if !s.beginReconcile() {
		t.Fatal("beginReconcile should succeed again after endReconcile")
	}
	s.endReconcile()
}

// newTestServer builds a Server backed by a temp SQLite DB, a fake Commander, and
// a Kea client pointed at an unreachable endpoint - enough to exercise the
// reconciler's state machine without touching the host or a real Kea.
func newTestServer(t *testing.T) (*Server, *network.RecordingCommander) {
	t.Helper()
	dir := t.TempDir()
	sqlite, err := db.OpenSQLite(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = sqlite.Close() })

	rec := &network.RecordingCommander{}
	s := &Server{
		cfg: &config.Config{
			KeaConfDir:    dir,
			KeaSecretPath: filepath.Join(dir, "secret"),
			MariaDBDSN:    "kea_user:vertas@tcp(localhost:3306)/kea",
			KeaAPIURL:     "http://127.0.0.1:1/",
			BindAddr:      "127.0.0.1:8080",
		},
		sqlite: sqlite,
		kea:    kea.NewClient("http://127.0.0.1:1/", "gui", "x"),
		dns:    network.NewDNSManager(),
		net:    network.NewManagerWithCommander(rec),
	}
	return s, rec
}

// TestApplyNATDrivesFirewall proves the reconciler drives the network layer
// through the injectable Commander seam (no real nft / root needed). applyNAT
// touches only s.net, so a Server with just that field is sufficient.
func TestApplyNATDrivesFirewall(t *testing.T) {
	rec := &network.RecordingCommander{}
	s := &Server{net: network.NewManagerWithCommander(rec)}

	if err := s.applyNAT(true); err != nil {
		t.Fatalf("applyNAT(true): %v", err)
	}
	if !rec.Ran("sysctl") {
		t.Error("expected ip_forward to be set via sysctl")
	}
	if !rec.Ran("nft") {
		t.Error("expected nft masquerade rules")
	}

	rec2 := &network.RecordingCommander{}
	s2 := &Server{net: network.NewManagerWithCommander(rec2)}
	if err := s2.applyNAT(false); err != nil {
		t.Fatalf("applyNAT(false): %v", err)
	}
	if !rec2.Ran("sysctl") || !rec2.Ran("nft") {
		t.Error("teardown path should still touch sysctl + nft")
	}
}

func TestInterruptedMidApply(t *testing.T) {
	if !interruptedMidApply(db.StateConfiguring, ModeConverge) {
		t.Error("CONFIGURING at converge (boot) should be treated as an interrupted apply")
	}
	if interruptedMidApply(db.StateConfiguring, ModeApply) {
		t.Error("CONFIGURING during a live apply (ModeApply) is not interrupted")
	}
	if interruptedMidApply(db.StateActive, ModeConverge) {
		t.Error("ACTIVE is never an interrupted apply")
	}
	if interruptedMidApply(db.StateOnboarding, ModeConverge) {
		t.Error("ONBOARDING is never an interrupted apply")
	}
}

// TestResumeInterruptedApplyFallsBackToOnboarding verifies that when an
// interrupted apply CANNOT be completed (here: no active profile to bring up),
// the box falls back to ONBOARDING rather than getting stuck in CONFIGURING. The
// success path (reconcile completes → ACTIVE) needs a reachable Kea and is
// verified on the Pi.
func TestResumeInterruptedApplyFallsBackToOnboarding(t *testing.T) {
	s, _ := newTestServer(t)
	// Shrink the resume backoff so the (permanent) failure here doesn't sleep through
	// the full production schedule before falling back.
	defer withResumeBackoff(0)()
	if err := s.sqlite.SetState(db.LifecycleStateKey, db.StateConfiguring); err != nil {
		t.Fatalf("seed CONFIGURING: %v", err)
	}

	// No active profile exists, so reconcileActive fails fast and resume reverts.
	_ = s.ReconcileApplianceState(ModeConverge, 0)

	if got, _ := s.sqlite.GetState(db.LifecycleStateKey); got != db.StateOnboarding {
		t.Errorf("uncompletable interrupted apply = %q want %q", got, db.StateOnboarding)
	}
}
