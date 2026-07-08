package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
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
		"INSERT INTO scopes (profile_id, vlan_id, cidr, preset) VALUES (?,?,?,?)",
		pid, 0, "10.0.0.0/24", "greengo"); err != nil {
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

// TestReconcileActiveRestartRecovery covers writeAndReloadKea's socket-unreachable
// recovery branch: when config-reload fails at the transport level (Kea running without
// the :8004 control socket, which a reload can never fix), the reconciler restarts the
// service so it re-reads the on-disk config, then re-probes. This is the rarely-hit
// failure path the happy-path test can't reach. The branch is gated by kea.Installed(),
// which is false on a box with no kea-dhcp4 binary (all CI), so we seam it true; the
// fake Kea transport-fails the reload (hijack + close) to flip Reachable() false, then
// answers version-get so the post-restart re-probe succeeds, and RestartService is
// recorded through the fake commander.
func TestReconcileActiveRestartRecovery(t *testing.T) {
	s, rec := newTestServer(t)

	origInstalled := kea.Installed
	kea.Installed = func() bool { return true }
	t.Cleanup(func() { kea.Installed = origInstalled })

	// Fake Kea: config-reload is transport-failed by hijacking the connection and closing
	// it with no response, so the client's request errors and marks the socket unreachable
	// (the branch's !Reachable() condition). Only one config-reload ever arrives - recovery
	// re-probes with version-get, not a second reload - so the failure is unconditional; no
	// need to read shared state (which would race the reconciler's RecordingCommander write
	// from this handler goroutine). version-get answers result:0 so the post-restart re-probe
	// succeeds without waiting out a retry delay. reprobed is atomic: written here, read on
	// the test goroutine.
	var reprobed atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		b := string(body)
		if strings.Contains(b, "config-reload") {
			if hj, ok := w.(http.Hijacker); ok {
				conn, _, _ := hj.Hijack()
				_ = conn.Close()
				return
			}
		}
		if strings.Contains(b, "version-get") {
			reprobed.Store(true)
		}
		_, _ = io.WriteString(w, `[{"result":0,"arguments":{}}]`)
	}))
	t.Cleanup(srv.Close)
	s.kea = kea.NewClient(srv.URL, "gui", "x")

	res, err := s.sqlite.Exec("INSERT INTO profiles (name, description, active) VALUES ('Live','',1)")
	if err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	pid, _ := res.LastInsertId()
	if _, err := s.sqlite.Exec(
		"INSERT INTO scopes (profile_id, vlan_id, cidr, preset) VALUES (?,?,?,?)",
		pid, 0, "10.0.0.0/24", "greengo"); err != nil {
		t.Fatalf("seed scope: %v", err)
	}
	if err := s.sqlite.SetState(db.LifecycleStateKey, db.StateActive); err != nil {
		t.Fatalf("seed lifecycle: %v", err)
	}

	if err := s.reconcileActive(ModeApply, int(pid)); err != nil {
		t.Fatalf("reconcileActive should recover via restart, got error: %v", err)
	}
	if !rec.Mentions("isc-kea-dhcp4-server") {
		t.Errorf("expected a restart of isc-kea-dhcp4-server on the recovery path; calls=%v", rec.Calls)
	}
	if !reprobed.Load() {
		t.Error("expected a version-get re-probe after the restart")
	}
}
