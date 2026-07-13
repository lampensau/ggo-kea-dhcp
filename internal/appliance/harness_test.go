package appliance

import (
	"path/filepath"
	"testing"

	"ggo-kea-dhcp/internal/config"
	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/dns"
	"ggo-kea-dhcp/internal/kea"
	"ggo-kea-dhcp/internal/network"
)

// nopHooks is the deliberate no-op caller. Every converge in this package runs through
// it, so none of them reaches an SSE hub, a DNS zone, an updater, or a monitor - and
// that is stated here rather than implied by six nil fields.
type nopHooks struct{}

func (nopHooks) AnnounceUplink(bool, string)  {}
func (nopHooks) PrimeZone()                   {}
func (nopHooks) KickUpdate()                  {}
func (nopHooks) StartNetmon([]ScopeConfig)    {}
func (nopHooks) StartArpProber([]ScopeConfig) {}
func (nopHooks) StartGgoScan([]ScopeConfig)   {}

// newTestReconciler builds a Reconciler backed by a temp SQLite DB, a fake Commander,
// and a Kea client pointed at an unreachable endpoint - enough to exercise the state
// machine without touching the host or a real Kea. This is the payoff of the package
// split: no HTTP server is needed to test the lifecycle.
func newTestReconciler(t testing.TB) (*Reconciler, *network.RecordingCommander) {
	t.Helper()
	dir := t.TempDir()
	sqlite, err := db.OpenSQLite(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = sqlite.Close() })

	rec := &network.RecordingCommander{}
	r := New(
		&config.Config{
			KeaConfDir:    dir,
			KeaSecretPath: filepath.Join(dir, "secret"),
			MariaDBDSN:    "kea_user:vertas@tcp(localhost:3306)/kea",
			KeaAPIURL:     "http://127.0.0.1:1/",
			BindAddr:      "127.0.0.1:8080",
		},
		sqlite, nil,
		kea.NewClient("http://127.0.0.1:1/", "gui", "x"),
		dns.New(""),
		network.NewManagerWithCommander(rec),
		&MonitorSet{},
		nopHooks{},
	)
	return r, rec
}

// TestNewRejectsNilHandles pins the fail-fast contract. A caller that builds the
// Reconciler before it has set one of these handles would otherwise drive a different
// appliance than the one it renders from, and nothing would error - the reconcile would
// just reconfigure a Kea nobody reads. mariadb is the one legitimate nil.
func TestNewRejectsNilHandles(t *testing.T) {
	dir := t.TempDir()
	sqlite, err := db.OpenSQLite(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = sqlite.Close() })

	cfg := &config.Config{KeaConfDir: dir}
	keaCli := kea.NewClient("http://127.0.0.1:1/", "gui", "x")
	dnsSrv := dns.New("")
	netMgr := network.NewManagerWithCommander(&network.RecordingCommander{})
	mon := &MonitorSet{}
	hooks := nopHooks{}

	cases := map[string]func(){
		"nil config":          func() { New(nil, sqlite, nil, keaCli, dnsSrv, netMgr, mon, hooks) },
		"nil sqlite":          func() { New(cfg, nil, nil, keaCli, dnsSrv, netMgr, mon, hooks) },
		"nil kea client":      func() { New(cfg, sqlite, nil, nil, dnsSrv, netMgr, mon, hooks) },
		"nil dns server":      func() { New(cfg, sqlite, nil, keaCli, nil, netMgr, mon, hooks) },
		"nil network manager": func() { New(cfg, sqlite, nil, keaCli, dnsSrv, nil, mon, hooks) },
		"nil monitor set":     func() { New(cfg, sqlite, nil, keaCli, dnsSrv, netMgr, nil, hooks) },
		// reconcileActive and connectUplink call through hooks unguarded, on the
		// strength of this check. Only a literal nil is caught here (a typed-nil
		// implementation panics at the first call instead).
		"nil hooks": func() { New(cfg, sqlite, nil, keaCli, dnsSrv, netMgr, mon, nil) },
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("New accepted a %s; it must fail fast, not degrade silently", name)
				}
			}()
			build()
		})
	}

	// MariaDB absent is a supported degraded mode, not a programming error.
	r := New(cfg, sqlite, nil, keaCli, dnsSrv, netMgr, mon, hooks)
	if r == nil {
		t.Fatal("New must accept a nil MariaDB (documented degraded mode)")
	}
}

// TestNewSharesHandles proves the Reconciler stores exactly the handles it was given.
// The web layer renders from the same pointers; if New copied or replaced one, the two
// halves would drive different appliances.
func TestNewSharesHandles(t *testing.T) {
	dir := t.TempDir()
	sqlite, err := db.OpenSQLite(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = sqlite.Close() })

	cfg := &config.Config{KeaConfDir: dir}
	keaCli := kea.NewClient("http://127.0.0.1:1/", "gui", "x")
	dnsSrv := dns.New("")
	netMgr := network.NewManagerWithCommander(&network.RecordingCommander{})
	mon := &MonitorSet{}
	hooks := nopHooks{}

	r := New(cfg, sqlite, nil, keaCli, dnsSrv, netMgr, mon, hooks)
	if r.cfg != cfg || r.sqlite != sqlite || r.kea != keaCli || r.dns != dnsSrv || r.net != netMgr || r.mon != mon {
		t.Error("New did not store the handles it was given")
	}
	if r.hooks != Hooks(hooks) {
		t.Error("New did not store the hooks it was given")
	}
}
