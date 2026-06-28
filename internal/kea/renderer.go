package kea

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// --- Kea config JSON shape (marshalled, not string-templated) ---
//
// These private structs mirror the `Dhcp4` configuration object. Building the
// config as typed values and letting encoding/json emit it means commas,
// nesting, and value escaping are the encoder's job - a MariaDB password or an
// SSID containing a quote or backslash can no longer produce invalid JSON, and
// adding an optional field never reopens hand-managed comma logic.

type keaConfig struct {
	Dhcp4 dhcp4Config `json:"Dhcp4"`
}

type dhcp4Config struct {
	InterfacesConfig interfacesConfig `json:"interfaces-config"`
	Authoritative    bool             `json:"authoritative"`
	// Lease timers (seconds). Zero → omitted → Kea defaults (used by the transient
	// onboarding config). The active profile sets them SHORT on purpose: a device
	// re-DHCPs at renew-timer (T1), and that renewal is when it adopts a new host
	// reservation or migrates into its correct device-class pool after a class/pool
	// change - not at the full lifetime. See RenderProfile.
	ValidLifetime              int             `json:"valid-lifetime,omitempty"`
	RenewTimer                 int             `json:"renew-timer,omitempty"`
	RebindTimer                int             `json:"rebind-timer,omitempty"`
	HostReservationIdentifiers []string        `json:"host-reservation-identifiers"`
	ControlSockets             []controlSocket `json:"control-sockets"`
	LeaseDatabase              leaseDatabase   `json:"lease-database"`
	// HostsDatabase is a pointer so it is omitted entirely when no MariaDB host is
	// configured: the onboarding config serves only dynamic leases and must NOT
	// depend on MariaDB (a down/uninitialized backend would otherwise make Kea fail
	// to (re)load and stop serving DHCP on eth0 - bricking onboarding reachability).
	HostsDatabase  *hostsDatabase `json:"hosts-database,omitempty"`
	HooksLibraries []hookLibrary  `json:"hooks-libraries"`
	ClientClasses  []clientClass  `json:"client-classes,omitempty"`
	Subnet4        []subnet4      `json:"subnet4"`
	Loggers        []logger       `json:"loggers"`
}

type interfacesConfig struct {
	Interfaces []string `json:"interfaces"`
	ReDetect   bool     `json:"re-detect"`
}

// controlSocket covers both the unix and http socket shapes via omitempty; the
// fields a given socket doesn't use stay zero and are dropped from the output.
type controlSocket struct {
	SocketType     string      `json:"socket-type"`
	SocketName     string      `json:"socket-name,omitempty"`
	SocketAddress  string      `json:"socket-address,omitempty"`
	SocketPort     int         `json:"socket-port,omitempty"`
	Authentication *socketAuth `json:"authentication,omitempty"`
}

type socketAuth struct {
	Type    string         `json:"type"`
	Realm   string         `json:"realm"`
	Clients []socketClient `json:"clients"`
}

type socketClient struct {
	User         string `json:"user"`
	PasswordFile string `json:"password-file"`
}

type leaseDatabase struct {
	Type        string `json:"type"`
	LfcInterval int    `json:"lfc-interval"`
}

type hostsDatabase struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	User     string `json:"user"`
	Password string `json:"password"`
	Host     string `json:"host"`
	// RetryOnStartup + OnFail keep a slow or down MariaDB from killing DHCP. Kea's
	// defaults are retry-on-startup=false and on-fail=stop-retry-exit, i.e. a backend
	// connection failure at startup is FATAL (the daemon exits / crash-loops). With
	// these set, Kea instead starts, serves dynamic leases, and retries the backend -
	// matching the "MariaDB down = warn, dynamic leases keep serving" design.
	RetryOnStartup bool   `json:"retry-on-startup"`
	OnFail         string `json:"on-fail"`
}

type hookLibrary struct {
	Library    string         `json:"library"`
	Parameters map[string]any `json:"parameters,omitempty"`
}

type clientClass struct {
	Name string `json:"name"`
	Test string `json:"test"`
}

type subnet4 struct {
	ID     int         `json:"id"`
	Subnet string      `json:"subnet"`
	Pools  []poolEntry `json:"pools"`
	// Per-subnet lease timers (seconds); zero → omitted → the subnet inherits the
	// global Dhcp4 timers. Set only when a scope carries a lease-lifetime override.
	ValidLifetime int           `json:"valid-lifetime,omitempty"`
	RenewTimer    int           `json:"renew-timer,omitempty"`
	RebindTimer   int           `json:"rebind-timer,omitempty"`
	OptionData    []optionDatum `json:"option-data"`
}

type poolEntry struct {
	Pool          string   `json:"pool"`
	ClientClasses []string `json:"client-classes,omitempty"`
}

type optionDatum struct {
	Name string `json:"name"`
	Data string `json:"data"`
}

type logger struct {
	Name          string         `json:"name"`
	OutputOptions []outputOption `json:"output_options"`
	Severity      string         `json:"severity"`
	DebugLevel    int            `json:"debuglevel"`
}

type outputOption struct {
	Output string `json:"output"`
}

type ClientClassConfig struct {
	Name string
	Test string
}

type PoolConfig struct {
	Range       string
	ClientClass string
}

// OptionKV is one extra DHCP option (Kea option name + data), carried per-scope
// straight into a subnet's option-data. The option name is not validated here -
// kea-dhcp4 -t (TestConfig) is the gate, so any valid Kea option works (ntp-servers,
// domain-name, domain-search, interface-mtu, ...).
type OptionKV struct {
	Name string
	Data string
}

type SubnetConfig struct {
	ID      int
	Subnet  string
	Pools   []PoolConfig
	Gateway string
	DNS     string
	// LeaseLifetime, when >0, overrides the global lease timers for THIS subnet
	// (renew/rebind derived via leaseTimers). Zero inherits the global Dhcp4 timers.
	LeaseLifetime int
	// Options are extra DHCP options appended after routers/domain-name-servers.
	Options []OptionKV
}

type TemplateData struct {
	Interfaces    []string
	MariaDBHost   string
	MariaDBUser   string
	MariaDBPass   string
	MariaDBName   string
	HooksDir      string
	PortPinning   bool
	KeaSecretPath string
	ClientClasses []ClientClassConfig
	Subnets       []SubnetConfig
	// Lease timers (seconds); zero leaves them unset (Kea defaults). RenderProfile
	// sets short values for the active profile so reservation adoption / pool
	// migration takes effect within minutes; onboarding leaves them zero.
	ValidLifetime int
	RenewTimer    int
	RebindTimer   int
	// Debug raises Kea logging to DEBUG/debuglevel 99. Default (false) renders
	// INFO so production boxes don't hammer the SD card / fill the disk.
	Debug bool
}

// RenderConfig generates the Kea configuration string by marshalling typed
// structs to JSON.
func RenderConfig(data TemplateData) (string, error) {
	// Auto-detect hooks directory if empty
	if data.HooksDir == "" {
		data.HooksDir = detectHooksDir()
	}

	// Default to INFO logging; only raise to DEBUG when explicitly requested.
	severity, debugLevel := "INFO", 0
	if data.Debug {
		severity, debugLevel = "DEBUG", 99
	}

	cfg := keaConfig{Dhcp4: dhcp4Config{
		InterfacesConfig: interfacesConfig{
			Interfaces: data.Interfaces,
			ReDetect:   true,
		},
		Authoritative:              true,
		ValidLifetime:              data.ValidLifetime,
		RenewTimer:                 data.RenewTimer,
		RebindTimer:                data.RebindTimer,
		HostReservationIdentifiers: []string{"flex-id", "hw-address"},
		ControlSockets: []controlSocket{
			{SocketType: "unix", SocketName: "/var/run/kea/kea-dhcp4-ctrl.sock"},
			{
				SocketType:    "http",
				SocketAddress: "127.0.0.1",
				SocketPort:    8004,
				Authentication: &socketAuth{
					Type:  "basic",
					Realm: "kea-api",
					Clients: []socketClient{
						{User: "gui", PasswordFile: data.KeaSecretPath},
					},
				},
			},
		},
		LeaseDatabase:  leaseDatabase{Type: "memfile", LfcInterval: 3600},
		HostsDatabase:  hostsDB(data),
		HooksLibraries: buildHooks(data.HooksDir, data.PortPinning, data.MariaDBHost != ""),
		ClientClasses:  buildClientClasses(data.ClientClasses),
		Subnet4:        buildSubnets(data.Subnets),
		Loggers: []logger{
			{
				Name:          "kea-dhcp4",
				OutputOptions: []outputOption{{Output: "/var/log/kea/kea.log"}},
				Severity:      severity,
				DebugLevel:    debugLevel,
			},
		},
	}}

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal Kea config: %w", err)
	}
	return string(out), nil
}

// hostsDB returns the MySQL hosts-database backend, or nil when no DB host is
// configured. Onboarding renders with an empty host so its config is memfile-only
// and never blocks on MariaDB; the active profile passes a real host. See the
// HostsDatabase field comment for why decoupling matters.
func hostsDB(data TemplateData) *hostsDatabase {
	if data.MariaDBHost == "" {
		return nil
	}
	return &hostsDatabase{
		Type:           "mysql",
		Name:           data.MariaDBName,
		User:           data.MariaDBUser,
		Password:       data.MariaDBPass,
		Host:           data.MariaDBHost,
		RetryOnStartup: true,
		OnFail:         "serve-retry-continue",
	}
}

// buildHooks lists the hooks libraries. flex_id (port-pinning identifier
// expression) is prepended only when port pinning is enabled; the MySQL host
// backend hooks (host_cmds + the mysql connector) are appended only when a DB is
// configured (hasDB) so the onboarding config loads without MariaDB present. The
// memfile-only lease_cmds/stat_cmds are always loaded.
func buildHooks(hooksDir string, portPinning, hasDB bool) []hookLibrary {
	var hooks []hookLibrary
	if portPinning {
		hooks = append(hooks, hookLibrary{
			Library: hooksDir + "libdhcp_flex_id.so",
			Parameters: map[string]any{
				// Build the flex-id from the Option-82 sub-options: remote-id
				// (relay4[2]) and circuit-id (relay4[1]), joined by a 0x1f (unit
				// separator) byte so the UI can split the two halves back apart for
				// display regardless of their content (Netgear uses ASCII with a
				// slash, Mikrotik uses "ether7"-style names with none - a raw concat
				// can't be separated). Kea matches the whole opaque identifier, so a
				// delimiter that happens to occur inside a sub-option only affects the
				// cosmetic split, never the reservation match.
				//
				// The ifelse(... , '') guard is load-bearing: relay4[N].hex is empty
				// for a direct (non-relayed) client, and an unconditional concat would
				// still yield the lone 0x1f delimiter - a non-empty value that
				// replace-client-id would then stamp onto every direct client as a
				// phantom flex-id. Emitting '' when neither sub-option exists keeps
				// flex_id from replacing the client-id for non-Option-82 clients.
				"identifier-expression": "ifelse(relay4[1].exists or relay4[2].exists, relay4[2].hex + 0x1f + relay4[1].hex, '')",
				"replace-client-id":     true,
			},
		})
	}
	// Lease + stat commands operate on the memfile lease DB; always available.
	for _, lib := range []string{
		"libdhcp_lease_cmds.so",
		"libdhcp_stat_cmds.so",
	} {
		hooks = append(hooks, hookLibrary{Library: hooksDir + lib})
	}
	// Host reservations need the MySQL backend; only load when a DB is configured.
	if hasDB {
		for _, lib := range []string{
			"libdhcp_host_cmds.so",
			"libdhcp_mysql.so",
		} {
			hooks = append(hooks, hookLibrary{Library: hooksDir + lib})
		}
	}
	return hooks
}

func buildClientClasses(in []ClientClassConfig) []clientClass {
	if len(in) == 0 {
		return nil // omitempty drops the whole block
	}
	out := make([]clientClass, len(in))
	for i, c := range in {
		out[i] = clientClass(c)
	}
	return out
}

func buildSubnets(in []SubnetConfig) []subnet4 {
	out := make([]subnet4, 0, len(in))
	for _, s := range in {
		pools := make([]poolEntry, 0, len(s.Pools))
		for _, p := range s.Pools {
			pe := poolEntry{Pool: p.Range}
			if p.ClientClass != "" {
				// Guard the pool by its device class OR the built-in KNOWN class, so a
				// client with a host reservation (KNOWN) can take its reserved address
				// from ANY pool regardless of device class - operator reservations are
				// highest-order and override the per-class guards. This is LOAD-BEARING
				// for cross-pool reservations (a reserved in-pool address belonging to a
				// different device class) and works INDEPENDENTLY of class exclusivity.
				// Unreserved clients (UNKNOWN) match only the pools whose class they
				// belong to - and with the scope-relative GGO-OTHERS guard (profile.go), a
				// device with its own pool is no longer a member of the catch-all, so it
				// can't sit there. KNOWN is evaluated after the reservation lookup, so it
				// is valid in a pool guard.
				pe.ClientClasses = []string{p.ClientClass, "KNOWN"}
			}
			pools = append(pools, pe)
		}
		// option-data must always serialize as an array (possibly empty), never
		// null - isolated scopes legitimately have zero options.
		opts := []optionDatum{}
		if s.Gateway != "" {
			opts = append(opts, optionDatum{Name: "routers", Data: s.Gateway})
		}
		if s.DNS != "" {
			opts = append(opts, optionDatum{Name: "domain-name-servers", Data: s.DNS})
		}
		// Extra per-scope options (NTP, domain-name, etc.) appended after the
		// gateway/DNS defaults. A blank name/data row is skipped; kea -t validates.
		for _, o := range s.Options {
			if o.Name == "" || o.Data == "" {
				continue
			}
			opts = append(opts, optionDatum(o))
		}
		sn := subnet4{ID: s.ID, Subnet: s.Subnet, Pools: pools, OptionData: opts}
		if s.LeaseLifetime > 0 {
			sn.ValidLifetime, sn.RenewTimer, sn.RebindTimer = leaseTimers(s.LeaseLifetime)
		}
		out = append(out, sn)
	}
	return out
}

func detectHooksDir() string {
	// Try standard Raspberry Pi OS (Debian arm64) path first
	paths := []string{
		"/usr/lib/aarch64-linux-gnu/kea/hooks/",
		"/usr/lib/x86_64-linux-gnu/kea/hooks/",
		"/usr/lib/kea/hooks/",
		"./test-kea-gui/", // testing path
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// No candidate exists: fall back to the architecture-NEUTRAL multiarch-free path
	// rather than guessing arm64, which on an x86_64 / non-standard box would emit hook
	// paths Kea can't dlopen (config-reload then fails). kea-dhcp4 -t still catches a
	// genuinely wrong path before apply.
	return "/usr/lib/kea/hooks/"
}

// keaValidationTimeout bounds `kea-dhcp4 -t` so a wedged validation can't hang
// the apply request goroutine that calls TestConfig synchronously.
const keaValidationTimeout = 30 * time.Second

// keaInstalled reports whether kea-dhcp4 is present. It delegates to keaBinaryPath
// (detect.go) so the PATH+sbin lookup lives in exactly one place.
func keaInstalled() bool {
	return keaBinaryPath() != ""
}

// TestConfig runs Kea's config validation command (kea-dhcp4 -t) on the provided
// configuration. In a development sandbox without kea-dhcp4 it skips validation
// (the presence check happens BEFORE invoking sudo, so it never blocks on a sudo
// auth delay), and the real run is bounded by a context timeout.
func TestConfig(configContent string) error {
	if !keaInstalled() {
		return nil // offline development sandbox - nothing to validate against
	}

	tmpFile, err := os.CreateTemp("", "kea-test-*.conf")
	if err != nil {
		return fmt.Errorf("failed to create temp file for validation: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := tmpFile.WriteString(configContent); err != nil {
		return fmt.Errorf("failed to write config to temp file: %w", err)
	}

	// `sudo kea-dhcp4 -t <tempfile>`. Kea's -t takes the config file as its direct
	// argument (NOT `-t -c file`, which makes Kea print usage and exit non-zero).
	// The service user runs this via passwordless sudo.
	ctx, cancel := context.WithTimeout(context.Background(), keaValidationTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sudo", "kea-dhcp4", "-t", tmpFile.Name())
	// Capture stdout AND stderr: Kea's logger writes the actual parse/validation
	// error to stdout by default, so reading stderr alone left the surfaced message
	// empty ("exit status 1") and the operator never saw what was wrong.
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("kea-dhcp4 config test timed out after %s", keaValidationTimeout)
		}
		msg := strings.TrimSpace(out.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("kea-dhcp4 config test failed: %s", msg)
	}
	return nil
}

// IncIP increments an IP address by a given offset.
func IncIP(ip net.IP, num int) net.IP {
	ret := make(net.IP, len(ip))
	copy(ret, ip)
	for i := len(ret) - 1; i >= 0; i-- {
		sum := int(ret[i]) + num
		ret[i] = byte(sum)
		num = sum >> 8
		if num == 0 {
			break
		}
	}
	return ret
}
