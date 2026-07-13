package web

import (
	"ggo-kea-dhcp/internal/appliance"
	"path/filepath"
	"testing"

	"ggo-kea-dhcp/internal/config"
	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/dns"
	"ggo-kea-dhcp/internal/kea"
	"ggo-kea-dhcp/internal/network"
)

// testHooks keeps the monitor starts (they no-op on their own when the monitors are
// absent, and several tests drive the paths that call them) but silences the three
// notification edges, so a converge in a unit test reaches no SSE hub, no DNS zone,
// and no update path. The embedded serverHooks implements any hook added later, live -
// a new notification hook must be re-silenced here by hand.
type testHooks struct{ serverHooks }

func (testHooks) AnnounceUplink(bool, string) {}
func (testHooks) PrimeZone()                  {}
func (testHooks) KickUpdate()                 {}

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
		sqlite:   sqlite,
		kea:      kea.NewClient("http://127.0.0.1:1/", "gui", "x"),
		dns:      dns.New(""),
		net:      network.NewManagerWithCommander(rec),
		bg:       newBgRunner(),
		lastSeen: newLastSeenTracker(),
		ggoFw:    newFwCensus(),
	}
	// The reconciler shares the Server's handles, and gets the silenced test hooks.
	s.recon = appliance.New(s.cfg, s.sqlite, s.mariadb, s.kea, s.dns, s.net, &s.mon, testHooks{serverHooks{s}})
	return s, rec
}

// TestNewServerBuildsReconciler covers the constructor's ordering: appliance.New panics
// on a nil required handle, so a NewServer that built the reconciler before it had set
// one of them fails here. The hooks need no assertion - they are a required parameter,
// so the compiler already proves they are wired.
func TestNewServerBuildsReconciler(t *testing.T) {
	dir := t.TempDir()
	sqlite, err := db.OpenSQLite(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = sqlite.Close() })

	// A non-nil MariaDB sentinel: NewServer only stores the handle, and asserting
	// identity against nil would be vacuous. Passing nil here is what let the
	// reconciler's mariadb go unchecked - and a nil recon.mariadb beside a live
	// s.mariadb degrades silently (fixedLeaseIPs treats every lease as movable,
	// RemapReservationSubnets returns early), it never errors.
	mariadb := &db.MariaDB{}
	s := NewServer(&config.Config{
		KeaConfDir:    dir,
		KeaSecretPath: filepath.Join(dir, "secret"),
		DBPath:        filepath.Join(dir, "test.db"),
		KeaAPIURL:     "http://127.0.0.1:1/",
	}, sqlite, mariadb)

	// Handle identity is proven inside the appliance package (TestNewSharesHandles).
	if s.recon == nil {
		t.Fatal("NewServer left the reconciler nil")
	}
}
