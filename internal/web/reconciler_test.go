package web

import (
	"ggo-kea-dhcp/internal/appliance"
	"path/filepath"
	"reflect"
	"testing"

	"ggo-kea-dhcp/internal/config"
	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/dns"
	"ggo-kea-dhcp/internal/kea"
	"ggo-kea-dhcp/internal/network"
)

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
	// The reconciler shares the Server's handles; its web-side edges stay nil so a
	// converge in a unit test never reaches the SSE hub, DNS zone, or update path.
	s.recon = appliance.New(s.cfg, s.sqlite, s.mariadb, s.kea, s.dns, s.net, &s.mon,
		s.startNetmon, s.startArpProber, s.startGgoScan)
	return s, rec
}

// TestNewServerWiresReconcilerEdges guards the nil-tolerant reconciler edges. A
// forgotten wire is silent - the edge just no-ops - so this reflects over every
// func-typed field on the reconciler and fails if NewServer left one nil. It
// covers new edges automatically, so a later edge added without wiring is caught.
func TestNewServerWiresReconcilerEdges(t *testing.T) {
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
	// remapReservationSubnets returns early), it never errors.
	mariadb := &db.MariaDB{}
	s := NewServer(&config.Config{
		KeaConfDir:    dir,
		KeaSecretPath: filepath.Join(dir, "secret"),
		DBPath:        filepath.Join(dir, "test.db"),
		KeaAPIURL:     "http://127.0.0.1:1/",
	}, sqlite, mariadb)

	rv := reflect.ValueOf(s.recon).Elem()
	rt := rv.Type()
	wired := 0
	for i := range rt.NumField() {
		if rt.Field(i).Type.Kind() != reflect.Func {
			continue
		}
		wired++
		if rv.Field(i).IsNil() {
			t.Errorf("NewServer left reconciler edge %q unwired (nil func)", rt.Field(i).Name)
		}
	}
	if wired == 0 {
		t.Fatal("no func-typed edges found on reconciler - test can no longer guard wiring")
	}

	// Handle identity is proven inside the appliance package (TestNewSharesHandles); here
	// the constructor itself is the guard - appliance.New panics on a nil required handle,
	// so a NewServer that built the reconciler too early would fail this test by panicking.
	if s.recon == nil {
		t.Fatal("NewServer left the reconciler nil")
	}
}
