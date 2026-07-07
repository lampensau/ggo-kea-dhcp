package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/kea"
)

// TestReconcileActiveHappyPath covers the core converge sequence that every apply,
// switch, restore, and boot flows through but no existing test exercised: render ->
// write kea-dhcp4.conf -> config-reload -> configure the served interface. It fakes
// Kea with an httptest control endpoint (returning result:0) and the network layer
// with the RecordingCommander, so nothing touches the host or a real Kea. The monitor
// starts (netmon/arp/ggoscan) are nil in a bare test server and each nil-guards, and
// remap/rebalance nil-guard the absent MariaDB, so the pass runs clean. It asserts each
// of the three effects happened (conf written, reload sent, interface set), not their
// ordering.
func TestReconcileActiveHappyPath(t *testing.T) {
	s, rec := newTestServer(t)

	// Fake Kea control socket: every command succeeds, and we capture the last one so
	// the test can prove config-reload was actually sent.
	var lastCmd string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		// The command name is the "command" field; a cheap contains check avoids
		// pulling in the kea.Request type here.
		if b := string(body); strings.Contains(b, "config-reload") {
			lastCmd = "config-reload"
		}
		// arguments{} keeps GetLeases (rebalance) parsing a clean empty lease set.
		_, _ = io.WriteString(w, `[{"result":0,"arguments":{}}]`)
	}))
	t.Cleanup(srv.Close)
	s.kea = kea.NewClient(srv.URL, "gui", "x")

	// Seed one active profile with a single untagged scope.
	res, err := s.sqlite.Exec("INSERT INTO profiles (name, description, active) VALUES ('Live','',1)")
	if err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	pid, _ := res.LastInsertId()
	if _, err := s.sqlite.Exec(
		"INSERT INTO scopes (profile_id, iface_mode, vlan_id, cidr, preset) VALUES (?,?,?,?,?)",
		pid, "physical", 0, "10.0.0.0/24", "greengo"); err != nil {
		t.Fatalf("seed scope: %v", err)
	}
	if err := s.sqlite.SetState(db.LifecycleStateKey, db.StateActive); err != nil {
		t.Fatalf("seed lifecycle: %v", err)
	}

	if err := s.reconcileActive(ModeApply, int(pid)); err != nil {
		t.Fatalf("reconcileActive returned error: %v", err)
	}

	// 1) kea-dhcp4.conf was rendered to disk with the scope's subnet.
	confPath := filepath.Join(s.cfg.KeaConfDir, "kea-dhcp4.conf")
	conf, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("kea conf not written: %v", err)
	}
	if !strings.Contains(string(conf), "10.0.0.0/24") {
		t.Errorf("kea conf missing the scope subnet; got:\n%s", conf)
	}

	// 2) config-reload was actually sent to the control socket.
	if lastCmd != "config-reload" {
		t.Errorf("expected a config-reload command, last was %q", lastCmd)
	}

	// 3) the served interface was configured with the scope gateway (.1). The manager
	// runs this through the commander, so the recorded calls must mention 10.0.0.1/24.
	if !rec.Mentions("10.0.0.1/24") {
		t.Errorf("expected the served interface to be set to 10.0.0.1/24; calls=%v", rec.Calls)
	}
}
