package web

import (
	"strings"
	"testing"
	"time"

	"ggo-kea-dhcp/internal/db"
)

// A panic inside a detached reconcile goroutine must not kill the process: the
// wrapper absorbs it, writes a SYSTEM audit row (Diagnostics is the operator's
// only view without SSH), and - because fn's own defers run during unwinding,
// before the recover - the mutation guard is released so the next apply is not
// locked out forever.
func TestRunRecoveredAuditedAbsorbsPanicAndReleasesGuard(t *testing.T) {
	s, _ := newTestServer(t)

	if !s.beginReconcile() {
		t.Fatal("beginReconcile should succeed")
	}
	s.runRecoveredAudited("test-panic", func() {
		defer s.endReconcile()
		panic("boom in reconcile")
	})

	if !s.beginReconcile() {
		t.Fatal("mutation guard still held after a recovered panic - endReconcile did not run")
	}
	s.endReconcile()

	rows, err := s.sqlite.Query("SELECT action, target, after_json, result FROM audit_log WHERE action = 'PANIC_RECOVERED'")
	if err != nil {
		t.Fatalf("query audit_log: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatal("no PANIC_RECOVERED audit row written")
	}
	var action, target, detail, result string
	if err := rows.Scan(&action, &target, &detail, &result); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if target != "test-panic" || result != "ERROR" || !strings.Contains(detail, "boom in reconcile") {
		t.Fatalf("audit row = %q %q %q %q, want target/detail/result to carry the panic", action, target, detail, result)
	}
}

// The non-panicking path must run fn exactly once and write no audit row.
func TestRunRecoveredAuditedCleanRun(t *testing.T) {
	s, _ := newTestServer(t)

	ran := 0
	s.runRecoveredAudited("clean", func() { ran++ })
	if ran != 1 {
		t.Fatalf("fn ran %d times, want 1", ran)
	}

	rows, err := s.sqlite.Query("SELECT COUNT(*) FROM audit_log WHERE action = 'PANIC_RECOVERED'")
	if err != nil {
		t.Fatalf("query audit_log: %v", err)
	}
	defer rows.Close()
	var n int
	if rows.Next() {
		_ = rows.Scan(&n)
	}
	if n != 0 {
		t.Fatalf("clean run wrote %d PANIC_RECOVERED rows, want 0", n)
	}
}

// A recovered panic in a transition-owning goroutine must kick one converge:
// the box is stranded in persisted CONFIGURING, and the converge dispatches
// into resumeInterruptedApply, which (with nothing to complete here) reverts
// to ONBOARDING - the self-healing a process crash used to get from systemd.
func TestRunRecoveredReconcileKicksConverge(t *testing.T) {
	s, _ := newTestServer(t)
	defer withResumeBackoff(0)()
	if err := s.sqlite.SetState(db.LifecycleStateKey, db.StateConfiguring); err != nil {
		t.Fatal(err)
	}

	s.runRecoveredReconcile("finish-apply", func() {
		defer s.endReconcile() // finishApply's own defer shape
		panic("boom mid-apply")
	})

	deadline := time.Now().Add(3 * time.Second)
	for {
		if st, _ := s.sqlite.GetState(db.LifecycleStateKey); st == db.StateOnboarding {
			break
		}
		if time.Now().After(deadline) {
			st, _ := s.sqlite.GetState(db.LifecycleStateKey)
			t.Fatalf("state = %q after recovery kick, want ONBOARDING via resumeInterruptedApply", st)
		}
		time.Sleep(10 * time.Millisecond)
	}
	var n int
	_ = s.sqlite.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action = 'PANIC_RECOVERED'").Scan(&n)
	if n != 1 {
		t.Errorf("PANIC_RECOVERED rows = %d, want 1", n)
	}
}
