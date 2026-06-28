package netmon

import "testing"

func testGovConfig() govConfig {
	return govConfig{
		dropHigh: 0, chanDropHigh: 0, ppsHigh: 10000,
		stepDownAfter: 2, stepUpAfter: 3, cooldownTicks: 2,
	}
}

func TestGovernor_NoFlapOnTransientSpike(t *testing.T) {
	g := newGovernor(testGovConfig())
	// A single breach tick must not shed (stepDownAfter = 2).
	if lv := g.observe(govInputs{tpDrops: 5}); lv != LevelFull {
		t.Fatalf("shed on a single spike: level=%v", lv)
	}
	// Calm again - no step.
	if lv := g.observe(govInputs{}); lv != LevelFull {
		t.Fatalf("level after calm = %v, want full", lv)
	}
	// Two sustained breaches → step down to L1.
	g.observe(govInputs{tpDrops: 5})
	if lv := g.observe(govInputs{tpDrops: 5}); lv != LevelNoPromisc {
		t.Fatalf("level after sustained breach = %v, want no-promiscuous", lv)
	}
}

func TestGovernor_StepsDownThroughLevels(t *testing.T) {
	g := newGovernor(testGovConfig())
	want := []Level{LevelNoPromisc, LevelCountersOnly, LevelPaused, LevelPaused}
	for _, w := range want {
		g.observe(govInputs{tpDrops: 1})
		lv := g.observe(govInputs{tpDrops: 1}) // two breaches per step
		if lv != w {
			t.Fatalf("step down: got %v, want %v", lv, w)
		}
	}
}

func TestGovernor_StepsUpOnlyAfterCooldownAndCalm(t *testing.T) {
	g := newGovernor(testGovConfig())
	// Shed to L1.
	g.observe(govInputs{tpDrops: 1})
	g.observe(govInputs{tpDrops: 1})
	if g.currentLevel() != LevelNoPromisc {
		t.Fatalf("setup: level=%v", g.currentLevel())
	}
	// Calm ticks: cooldown (2) must elapse AND calm reach stepUpAfter (3).
	g.observe(govInputs{}) // calm 1, cooldown 2→1
	g.observe(govInputs{}) // calm 2, cooldown 1→0
	if g.currentLevel() != LevelNoPromisc {
		t.Fatalf("stepped up too early: %v", g.currentLevel())
	}
	if lv := g.observe(govInputs{}); lv != LevelFull { // calm 3 + cooldown elapsed → recover
		t.Fatalf("did not recover: %v", lv)
	}
}

// TestGovernor_DualSignal proves the governor is not blind to either bottleneck:
// it sheds on channel-drops alone (tp_drops≈0) and on tp_drops alone.
func TestGovernor_DualSignal(t *testing.T) {
	// Channel-drop only (parse pipeline behind; socket buffer fine).
	g := newGovernor(testGovConfig())
	g.observe(govInputs{tpDrops: 0, chanDrops: 7})
	if lv := g.observe(govInputs{tpDrops: 0, chanDrops: 7}); lv != LevelNoPromisc {
		t.Fatalf("did not shed on channel-drops alone: %v", lv)
	}

	// tp_drops only (socket buffer overflow; pipeline fine).
	g2 := newGovernor(testGovConfig())
	g2.observe(govInputs{tpDrops: 3, chanDrops: 0})
	if lv := g2.observe(govInputs{tpDrops: 3, chanDrops: 0}); lv != LevelNoPromisc {
		t.Fatalf("did not shed on tp_drops alone: %v", lv)
	}
}

// TestGovernor_HighPPSDoesNotShed proves the H3 fix: a busy-but-healthy wire
// (zero overflow, huge pps) must NOT escalate the level - otherwise monitoring
// blacks out on exactly the networks it targets. pps gates only the sampling
// window (tested at the monitor level), never the governor level.
func TestGovernor_HighPPSDoesNotShed(t *testing.T) {
	g := newGovernor(testGovConfig())
	for range 20 {
		if lv := g.observe(govInputs{tpDrops: 0, chanDrops: 0}); lv != LevelFull {
			t.Fatalf("governor shed with no overflow signals: %v", lv)
		}
	}
}
