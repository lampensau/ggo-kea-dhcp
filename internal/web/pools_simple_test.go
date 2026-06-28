package web

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// seedScopePreset inserts an active profile with one scope of the given preset and
// returns its scope-row id. Distinct from seedActiveProfile (greengo-only) so the
// advanced/range tests can avoid the Green-GO catch-all requirement.
func seedScopePreset(t *testing.T, s *Server, preset string) int {
	t.Helper()
	res, err := s.sqlite.Exec("INSERT INTO profiles (name, active) VALUES ('PresetTest', 1)")
	if err != nil {
		t.Fatalf("insert profile: %v", err)
	}
	pid, _ := res.LastInsertId()
	sr, err := s.sqlite.Exec(
		`INSERT INTO scopes (profile_id, iface_mode, vlan_id, cidr, preset, pool_spec, uplink_json)
		 VALUES (?, 'physical', 0, '10.0.0.0/24', ?, '{}', '{}')`, pid, preset)
	if err != nil {
		t.Fatalf("insert scope: %v", err)
	}
	sid, _ := sr.LastInsertId()
	return int(sid)
}

// TestNilIfEmpty proves the NULL-sentinel helper: empty string -> nil (SQL
// NULL), any non-empty -> the same string.
func TestNilIfEmpty(t *testing.T) {
	if got := nilIfEmpty(""); got != nil {
		t.Errorf("nilIfEmpty(\"\") = %v want nil", got)
	}
	if got := nilIfEmpty("x"); got != "x" {
		t.Errorf("nilIfEmpty(\"x\") = %v want \"x\"", got)
	}
	if got := nilIfEmpty(" "); got != " " {
		t.Errorf("nilIfEmpty(\" \") = %v want \" \" (only the empty string is NULL)", got)
	}
}

// TestActiveProfileScopes covers the active-profile scope loader: a seeded
// active profile yields its id + one scope, and a box with no active profile
// returns ok=false.
func TestActiveProfileScopes(t *testing.T) {
	s, _ := newTestServer(t)

	// No active profile yet.
	if _, _, _, ok := s.activeProfileScopes(); ok {
		t.Fatal("activeProfileScopes should report ok=false with no active profile")
	}

	sid := seedScopePreset(t, s, "greengo")
	pid, ids, scopes, ok := s.activeProfileScopes()
	if !ok {
		t.Fatal("activeProfileScopes should succeed after seeding an active profile")
	}
	if pid <= 0 {
		t.Errorf("profileID = %d, want > 0", pid)
	}
	if len(ids) != 1 || ids[0] != sid {
		t.Errorf("ids = %v, want [%d]", ids, sid)
	}
	if len(scopes) != 1 || scopes[0].CIDR != "10.0.0.0/24" || scopes[0].Preset != "greengo" {
		t.Errorf("scopes = %+v, want one greengo 10.0.0.0/24 scope", scopes)
	}
}

// TestPoolsPlanSave_SimpleStripsRange proves the Simple-mode save strips any
// posted Advanced range pin, so the persisted plan re-opens as Simple (planMode).
func TestPoolsPlanSave_SimpleStripsRange(t *testing.T) {
	s, _ := newTestServer(t)
	sid := seedScopePreset(t, s, "generic")

	// A plan carrying an explicit (Advanced) range pin on the Fixed pool.
	plan := PoolPlan{
		{Kind: PoolKindReserve, Name: "Static reserve", Count: 18},
		{Kind: PoolKindFixed, Class: "GGO-BPX", Name: "Beltpacks", Sizing: "explicit", Count: 80, Range: "10.0.0.20 - 10.0.0.200", Icon: "bpx"},
	}
	form := poolFormValues(plan, "scopes[0][pool]")
	req := httptest.NewRequest("POST", "/pools/save?s=0&mode=simple", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handlePoolsPlanSave(w, req)

	stored := readStoredPlan(t, s, sid)
	for i, e := range stored {
		if e.Range != "" {
			t.Errorf("Simple-mode save must strip ranges; entry %d kept Range=%q", i, e.Range)
		}
	}
	if m := planMode(stored); m != "simple" {
		t.Errorf("stored plan reopens as %q, want simple", m)
	}
}

// TestPoolsPlanSave_AdvancedKeepsRange proves the Advanced-mode save retains
// the explicit range pin, so the scope re-opens in Advanced mode.
func TestPoolsPlanSave_AdvancedKeepsRange(t *testing.T) {
	s, _ := newTestServer(t)
	sid := seedScopePreset(t, s, "generic")

	plan := PoolPlan{
		{Kind: PoolKindReserve, Name: "Static reserve", Count: 18},
		{Kind: PoolKindFixed, Class: "GGO-BPX", Name: "Beltpacks", Sizing: "explicit", Count: 80, Range: "10.0.0.20 - 10.0.0.200", Icon: "bpx"},
	}
	form := poolFormValues(plan, "scopes[0][pool]")
	req := httptest.NewRequest("POST", "/pools/save?s=0&mode=advanced", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handlePoolsPlanSave(w, req)

	stored := readStoredPlan(t, s, sid)
	var foundRange bool
	for _, e := range stored {
		if e.Range != "" {
			foundRange = true
		}
	}
	if !foundRange {
		t.Errorf("Advanced-mode save must keep the explicit range; stored plan: %+v", stored)
	}
	if m := planMode(stored); m != "advanced" {
		t.Errorf("stored plan reopens as %q, want advanced", m)
	}
}

// TestPoolsPlanOp_SimpleStripsThenRederives proves the op endpoint applies the
// Simple-mode strip in-flight: posting a plan with a hand-set range in simple mode
// still produces a wired, range-bearing morph (ranges are auto-derived, not pinned).
func TestPoolsPlanOp_SimpleStripsThenRederives(t *testing.T) {
	s, _ := newTestServer(t)
	seedScopePreset(t, s, "generic")

	plan := PoolPlan{
		{Kind: PoolKindReserve, Name: "Static reserve", Count: 18},
		{Kind: PoolKindFixed, Class: "GGO-BPX", Name: "Beltpacks", Sizing: "explicit", Count: 80, Range: "10.0.0.20 - 10.0.0.200", Icon: "bpx"},
	}
	form := poolFormValues(plan, "scopes[0][pool]")
	req := httptest.NewRequest("POST", "/pools/edit?s=0&op=recompute&mode=simple", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handlePoolsPlanOp(w, req)

	body := w.Body.String()
	if !strings.Contains(body, `id="poolplan-0"`) {
		t.Errorf("op response missing morph region; got:\n%s", body[:min(len(body), 300)])
	}
	if strings.Contains(body, `data-on:click=""`) {
		t.Errorf("op emitted an empty data-on:click")
	}
}

// TestPoolsPlanOp_NoActiveProfile asserts the op endpoint toasts an error
// (instead of panicking) when there is no active profile to edit.
func TestPoolsPlanOp_NoActiveProfile(t *testing.T) {
	s, _ := newTestServer(t)
	req := httptest.NewRequest("POST", "/pools/edit?s=0&op=recompute&mode=simple", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handlePoolsPlanOp(w, req)
	if !strings.Contains(w.Body.String(), "No active profile") {
		t.Errorf("expected a no-active-profile toast, got:\n%s", w.Body.String())
	}
}

// readStoredPlan loads and decodes the persisted pool_plan for a scope row.
func readStoredPlan(t *testing.T, s *Server, sid int) PoolPlan {
	t.Helper()
	var stored string
	if err := s.sqlite.QueryRow("SELECT pool_plan FROM scopes WHERE id = ?", sid).Scan(&stored); err != nil {
		t.Fatalf("read pool_plan: %v", err)
	}
	if stored == "" {
		t.Fatal("pool_plan was not persisted")
	}
	var got PoolPlan
	if err := json.Unmarshal([]byte(stored), &got); err != nil {
		t.Fatalf("stored pool_plan is not valid JSON: %v", err)
	}
	return got
}
