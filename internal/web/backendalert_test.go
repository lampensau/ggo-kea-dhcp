package web

import (
	"strings"
	"testing"

	"ggo-kea-dhcp/internal/web/views"
)

// TestBackendAlertStripAndPillSeparation proves the backend-health split: a Kea-down
// state renders an error row in the #backend-alert strip, and the SAME state does NOT
// leak into the header status pill (which now carries netmon signals only).
func TestBackendAlertStripAndPillSeparation(t *testing.T) {
	s, _ := newTestServer(t)
	s.health = newBackendHealth()
	// Trip Kea down (debounced: needs backendDownThreshold consecutive failed samples).
	for i := 0; i < backendDownThreshold; i++ {
		s.health.observeKea(false, "control socket refused")
	}

	rows := s.health.alertRows()
	if len(rows) != 1 || rows[0].Severity != "err" {
		t.Fatalf("alertRows = %+v, want one err row for Kea down", rows)
	}

	// The strip renders the row inside the live region.
	strip := renderFragment(views.BackendAlert(rows))
	if !strings.Contains(strip, `id="backend-alert"`) || !strings.Contains(strip, rows[0].Title) {
		t.Errorf("strip missing region id or alert title:\n%s", strip)
	}

	// The header pill stays clean (netmon-only): a clean netmon view yields a zero pill
	// even while Kea is down.
	pill := s.statusPillView("ACTIVE", views.NetHealthView{})
	if pill.ErrCount != 0 || pill.WarnCount != 0 || len(pill.Details) != 0 {
		t.Errorf("backend health leaked into the header pill: %+v", pill)
	}
}

// TestBackendAlertEmptyWhenHealthy proves a healthy box renders an empty strip wrapper
// (the #backend-alert:empty CSS rule then collapses it).
func TestBackendAlertEmptyWhenHealthy(t *testing.T) {
	s, _ := newTestServer(t)
	s.health = newBackendHealth() // both backends start healthy
	strip := renderFragment(views.BackendAlert(s.health.alertRows()))
	if strings.Contains(strip, "alert-err") || strings.Contains(strip, "alert-warn") {
		t.Errorf("healthy box should render no alert rows, got:\n%s", strip)
	}
	if !strings.Contains(strip, `id="backend-alert"`) {
		t.Errorf("strip wrapper must always be present as a morph target:\n%s", strip)
	}
}

// drainHub non-blockingly collects every fragment currently buffered on a subscriber.
func drainHub(ch chan string) []string {
	var out []string
	for {
		select {
		case f := <-ch:
			out = append(out, f)
		default:
			return out
		}
	}
}

// TestOnBackendChangeKeaPushesStripAndToast drives the live-push path: a Kea down
// transition broadcasts both the persistent #backend-alert strip (error row) and the
// one-shot #kea-toast-slot nudge; the subsequent up transition clears the toast slot.
func TestOnBackendChangeKeaPushesStripAndToast(t *testing.T) {
	s, _ := newTestServer(t)
	s.health = newBackendHealth()
	s.live = newLiveHub()
	ch := s.live.subscribe("/dashboard") // shell regions reach every page
	defer s.live.unsubscribe(ch)

	// Down edge: trip the tracker, then signal the transition.
	for i := 0; i < backendDownThreshold; i++ {
		s.health.observeKea(false, "control socket refused")
	}
	s.onBackendChange("KEA", false, "control socket refused")

	frags := drainHub(ch)
	var sawStrip, sawToast bool
	for _, f := range frags {
		if strings.Contains(f, `id="backend-alert"`) && strings.Contains(f, "alert-err") {
			sawStrip = true
		}
		if strings.Contains(f, `id="kea-toast-slot"`) && strings.Contains(f, "toast-error") {
			sawToast = true
		}
	}
	if !sawStrip {
		t.Errorf("Kea-down did not broadcast the backend-alert strip; got %d frags: %v", len(frags), frags)
	}
	if !sawToast {
		t.Errorf("Kea-down did not broadcast the kea-toast nudge; got %d frags: %v", len(frags), frags)
	}

	// Up edge: the toast slot must clear (empty wrapper, no error toast).
	s.health.observeKea(true, "connected")
	s.onBackendChange("KEA", true, "connected")
	for _, f := range drainHub(ch) {
		if strings.Contains(f, `id="kea-toast-slot"`) && strings.Contains(f, "toast-error") {
			t.Errorf("Kea-up should clear the toast slot, but re-pushed a toast: %s", f)
		}
	}
}

// TestKeaToastSlot covers the one-shot toast slot the live hub patches on a Kea
// up/down edge: show=true renders a self-dismissing error toast; show=false is an
// empty (but present) morph target.
func TestKeaToastSlot(t *testing.T) {
	show := renderFragment(views.KeaToastSlot(true))
	if !strings.Contains(show, `id="kea-toast-slot"`) || !strings.Contains(show, "toast-error") || !strings.Contains(show, "el.remove()") {
		t.Errorf("active toast slot wrong (want region + error toast + self-dismiss):\n%s", show)
	}
	empty := renderFragment(views.KeaToastSlot(false))
	if !strings.Contains(empty, `id="kea-toast-slot"`) || strings.Contains(empty, "toast-error") {
		t.Errorf("inactive toast slot should be an empty wrapper:\n%s", empty)
	}
}
