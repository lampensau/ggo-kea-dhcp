package web

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ggo-kea-dhcp/internal/config"
	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/dns"
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
func newTestServer(t testing.TB) (*Server, *network.RecordingCommander) {
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
		dns:    dns.New(""),
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

// TestWriteFileSync covers the durable in-place conf writer: create, overwrite
// with truncation (a shorter config must not leave a tail of the old one), and
// the error path (every step's error must surface, not vanish in a defer).
func TestWriteFileSync(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kea-dhcp4.conf")

	if err := writeFileSync(path, []byte("first-longer-content"), 0660); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := writeFileSync(path, []byte("short"), 0660); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "short" {
		t.Errorf("content = %q, want %q (stale tail not truncated?)", got, "short")
	}

	if err := writeFileSync(dir, []byte("x"), 0660); err == nil {
		t.Error("writing to a directory path should error")
	}
	if err := writeFileSync(filepath.Join(dir, "missing", "sub.conf"), []byte("x"), 0660); err == nil {
		t.Error("writing into a missing directory should error")
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

// TestActiveZeroScopesRescuesToOnboarding verifies the survivability fallback:
// a box persisted ACTIVE whose active profile has no scopes (or no active
// profile at all - a corrupted or hand-edited DB) must not fail its converge
// before any interface is up and sit unreachable. It demotes itself to
// ONBOARDING (SoftAP + onboarding IP) and leaves an audit trail.
func TestActiveZeroScopesRescuesToOnboarding(t *testing.T) {
	seed := func(t *testing.T, withProfile bool) *Server {
		s, _ := newTestServer(t)
		if err := s.sqlite.SetState(db.LifecycleStateKey, db.StateActive); err != nil {
			t.Fatalf("seed ACTIVE: %v", err)
		}
		if withProfile {
			if _, err := s.sqlite.Exec("INSERT INTO profiles (name, active) VALUES ('empty', 1)"); err != nil {
				t.Fatalf("seed profile: %v", err)
			}
		}
		return s
	}

	for _, tc := range []struct {
		name        string
		withProfile bool
	}{
		{"active profile with zero scopes", true},
		{"no active profile at all", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := seed(t, tc.withProfile)
			s.rescueArmed.Store(true) // NewServer arms it; newTestServer builds the struct bare
			_ = s.ReconcileApplianceState(ModeConverge, 0)

			if got, _ := s.sqlite.GetState(db.LifecycleStateKey); got != db.StateOnboarding {
				t.Errorf("state after converge = %q want %q", got, db.StateOnboarding)
			}
			var n int
			if err := s.sqlite.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action = 'RESCUE_ONBOARDING'").Scan(&n); err != nil || n != 1 {
				t.Errorf("RESCUE_ONBOARDING audit rows = %d (err %v), want 1", n, err)
			}
		})
	}
}

// TestActiveZeroScopesApplyDoesNotRescue pins the guard: the apply/switch paths
// (ModeApply) have their own rollback and must see the zero-scopes error - a
// silent demotion here would make finishApply declare the apply successful and
// stamp ACTIVE over a box actually sitting in onboarding.
func TestActiveZeroScopesApplyDoesNotRescue(t *testing.T) {
	s, _ := newTestServer(t)
	if err := s.sqlite.SetState(db.LifecycleStateKey, db.StateActive); err != nil {
		t.Fatalf("seed ACTIVE: %v", err)
	}

	err := s.ReconcileApplianceState(ModeApply, 0)
	if !errors.Is(err, errNoScopes) {
		t.Errorf("ModeApply with zero scopes = %v, want errNoScopes", err)
	}
	if got, _ := s.sqlite.GetState(db.LifecycleStateKey); got != db.StateActive {
		t.Errorf("state after failed apply = %q, want %q (no demotion)", got, db.StateActive)
	}
}

// TestZeroScopesRescueOnlyOnFirstConverge pins the rescue window: the flag is
// consumed by the FIRST ACTIVE converge, so a later zero-scopes converge (a
// mid-show settings save on a box whose rows were lost while its runtime still
// serves) surfaces the error instead of demoting a serving box to the SoftAP.
func TestZeroScopesRescueOnlyOnFirstConverge(t *testing.T) {
	s, _ := newTestServer(t)
	if err := s.sqlite.SetState(db.LifecycleStateKey, db.StateActive); err != nil {
		t.Fatal(err)
	}
	// The boot converge already ran (and consumed the window) on a healthy box.
	s.rescueArmed.Store(false)

	err := s.ReconcileApplianceState(ModeConverge, 0)
	if !errors.Is(err, errNoScopes) {
		t.Errorf("post-boot converge with zero scopes = %v, want errNoScopes surfaced", err)
	}
	if got, _ := s.sqlite.GetState(db.LifecycleStateKey); got != db.StateActive {
		t.Errorf("state = %q, want ACTIVE untouched (no mid-show demotion)", got)
	}
	var n int
	_ = s.sqlite.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action = 'RESCUE_ONBOARDING'").Scan(&n)
	if n != 0 {
		t.Errorf("RESCUE_ONBOARDING fired outside the boot window (%d rows)", n)
	}
}

// TestZeroScopesRescueConsumedByAnyBoot pins the window to the BOOT reconcile
// regardless of state: a box that boots into ONBOARDING consumes the window on
// that first reconcile, so after a later apply a settings converge that finds
// zero scopes (rows lost post-boot) surfaces the error instead of demoting a
// serving box - the gap the ACTIVE-only consume left open.
func TestZeroScopesRescueConsumedByAnyBoot(t *testing.T) {
	s, _ := newTestServer(t)
	s.rescueArmed.Store(true)
	if err := s.sqlite.SetState(db.LifecycleStateKey, db.StateOnboarding); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	_ = s.ReconcileApplianceState(ModeConverge, 0) // the boot reconcile, in ONBOARDING

	// Later: ACTIVE with zero scopes (no active profile row at all).
	if err := s.sqlite.SetState(db.LifecycleStateKey, db.StateActive); err != nil {
		t.Fatalf("flip state: %v", err)
	}
	err := s.ReconcileApplianceState(ModeConverge, 0)
	if !errors.Is(err, errNoScopes) {
		t.Fatalf("want errNoScopes surfaced, got %v", err)
	}
	if st, _ := s.sqlite.GetState(db.LifecycleStateKey); st != db.StateActive {
		t.Fatalf("post-boot converge must not rescue: state = %q, want ACTIVE", st)
	}
}
