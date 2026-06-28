// Package preflight probes the host for the prerequisites the appliance needs to
// function: the Kea binary and hooks, the control socket, the privileged tools,
// the reservation database, Linux capabilities, and a writable config dir. It is
// read-only and never panics on a missing tool - a missing prerequisite is a
// reported Check, not a crash. It runs at startup (logged + audited, never aborts
// boot) and via `--check` (the installer uses the exit code).
package preflight

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"ggo-kea-dhcp/internal/config"
	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/kea"
	"ggo-kea-dhcp/internal/network"
)

// Status is the outcome of a single check.
type Status string

const (
	OK   Status = "OK"   // prerequisite satisfied
	Warn Status = "WARN" // degraded - the box runs, but a feature is unavailable
	Fail Status = "FAIL" // a hard prerequisite for core DHCP function is missing
)

// Check is one prerequisite probe result.
type Check struct {
	Name   string `json:"name"`
	Status Status `json:"status"`
	Detail string `json:"detail"`
}

// Result is an ordered set of checks.
type Result []Check

// HasFailure reports whether any check is Fail (the `--check` non-zero condition).
func (r Result) HasFailure() bool {
	for _, c := range r {
		if c.Status == Fail {
			return true
		}
	}
	return false
}

// Worst returns the most severe status in the result (OK if empty).
func (r Result) Worst() Status {
	worst := OK
	for _, c := range r {
		switch c.Status {
		case Fail:
			return Fail
		case Warn:
			worst = Warn
		}
	}
	return worst
}

// Run executes every probe and returns the results in a stable order.
func Run(cfg *config.Config) Result {
	r := Result{
		checkKeaBinary(),
		checkHooks(),
		checkKeaSocket(cfg),
	}
	r = append(r, checkTools()...)
	r = append(r, checkMariaDB(cfg), checkKeaConfDir(cfg))
	r = append(r, checkCaps()...)
	return r
}

// checkKeaBinary verifies kea-dhcp4 is installed and is the supported 3.0.x series
// (2.x and 3.2+ differ in config/flex-id behavior this appliance depends on).
func checkKeaBinary() Check {
	const name = "Kea binary"
	if !kea.Installed() {
		return Check{name, Fail, "kea-dhcp4 not found in PATH or sbin - install isc-kea-dhcp4-server"}
	}
	v, err := kea.Version()
	if err != nil {
		return Check{name, Warn, fmt.Sprintf("present but version unreadable: %v", err)}
	}
	if !strings.HasPrefix(v, "3.0.") {
		return Check{name, Fail, fmt.Sprintf("found Kea %s but this appliance requires the 3.0.x series", v)}
	}
	return Check{name, OK, "Kea " + v}
}

// checkHooks verifies the required hook libraries exist in the detected hooks dir.
func checkHooks() Check {
	const name = "Kea hooks"
	dir := kea.HooksDir()
	var missing []string
	for _, lib := range kea.RequiredHooks {
		if _, err := os.Stat(filepath.Join(dir, lib)); err != nil {
			missing = append(missing, lib)
		}
	}
	if len(missing) > 0 {
		return Check{name, Fail, fmt.Sprintf("missing in %s: %s", dir, strings.Join(missing, ", "))}
	}
	return Check{name, OK, "all present in " + dir}
}

// checkKeaSocket verifies the Kea control socket answers. Warn (not Fail): Kea may
// simply not be started yet at boot; the runtime health monitor tracks it ongoing.
func checkKeaSocket(cfg *config.Config) Check {
	const name = "Kea control socket"
	secret, err := cfg.GetKeaSecret()
	if err != nil {
		return Check{name, Warn, fmt.Sprintf("cannot read API secret: %v", err)}
	}
	if err := kea.NewClient(cfg.KeaAPIURL, "gui", secret).Ping(); err != nil {
		return Check{name, Warn, fmt.Sprintf("%s unreachable: %v", cfg.KeaAPIURL, err)}
	}
	return Check{name, OK, "reachable at " + cfg.KeaAPIURL}
}

// checkTools verifies the privileged binaries the network layer shells out to.
func checkTools() []Check {
	// ip/nmcli/nft drive active networking; hostapd/iw drive the onboarding SoftAP;
	// systemctl manages services. All are needed for full appliance function.
	tools := []string{"nmcli", "nft", "ip", "hostapd", "iw", "systemctl"}
	var checks []Check
	for _, t := range tools {
		if network.ToolPresent(t) {
			checks = append(checks, Check{"Tool: " + t, OK, "installed"})
		} else {
			checks = append(checks, Check{"Tool: " + t, Fail, "not found in PATH or sbin"})
		}
	}
	return checks
}

// checkMariaDB verifies the reservation database is reachable and initialized.
// Warn (not Fail): Kea still serves dynamic leases without it; only reservations
// and port pinning are unavailable.
func checkMariaDB(cfg *config.Config) Check {
	const name = "Reservation database (MariaDB)"
	m, err := db.ConnectMariaDB(cfg.MariaDBDSN)
	if err != nil {
		return Check{name, Warn, fmt.Sprintf("connect failed: %v", err)}
	}
	defer m.Close()
	if err := m.VerifySchema(); err != nil {
		return Check{name, Warn, fmt.Sprintf("schema not ready: %v", err)}
	}
	return Check{name, OK, "connected, hosts table present (" + config.RedactedMariaDSN(cfg.MariaDBDSN) + ")"}
}

// checkKeaConfDir verifies the app can write kea-dhcp4.conf - a hard requirement for
// applying any profile. The app OVERWRITES that file in place (it owns it, mode 0660); it
// never creates new files in /etc/kea, which the package deliberately keeps 0750 root:_kea.
// So when the conf already exists we probe THAT file's writability (open for write, no
// truncate) rather than creating a temp file in the dir - the old dir-create probe was a
// false negative on a correctly-installed box. Only when the conf doesn't exist yet (so the
// app would have to create it) do we fall back to the dir-create probe.
func checkKeaConfDir(cfg *config.Config) Check {
	const name = "Kea config dir writable"
	dir := cfg.KeaConfDir
	conf := filepath.Join(dir, "kea-dhcp4.conf")
	if _, err := os.Stat(conf); err == nil {
		f, err := os.OpenFile(conf, os.O_WRONLY, 0) // no O_TRUNC: opening + closing leaves it untouched
		if err != nil {
			return Check{name, Fail, fmt.Sprintf("%s not writable: %v", conf, err)}
		}
		_ = f.Close()
		return Check{name, OK, conf + " is writable"}
	}
	probe := filepath.Join(dir, ".ggo-write-test")
	if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
		return Check{name, Fail, fmt.Sprintf("%s not writable: %v", dir, err)}
	}
	_ = os.Remove(probe)
	return Check{name, OK, dir + " is writable"}
}

// Linux capability bit numbers (see capabilities(7)).
const (
	capNetBindService = 10 // bind to ports < 1024 (onboarding DNS on :53)
	capNetRaw         = 13 // AF_PACKET raw sockets (passive network monitor)
)

// checkCaps reports whether the process holds the capabilities needed for the
// onboarding DNS bind and the passive monitor. Warn (not Fail): both are degraded
// features, not core DHCP - and a process running as root holds them implicitly.
func checkCaps() []Check {
	eff, err := readCapEff()
	if err != nil {
		return []Check{{"Linux capabilities", Warn, fmt.Sprintf("cannot read /proc/self/status: %v", err)}}
	}
	return []Check{
		capCheck("CAP_NET_RAW (network monitor)", eff, capNetRaw),
		capCheck("CAP_NET_BIND_SERVICE (onboarding DNS)", eff, capNetBindService),
	}
}

func capCheck(name string, eff uint64, bit uint) Check {
	if eff&(1<<bit) != 0 {
		return Check{name, OK, "held"}
	}
	return Check{name, Warn, "not held - feature disabled (granted via systemd AmbientCapabilities)"}
}

// readCapEff parses the effective capability bitmask from /proc/self/status.
func readCapEff() (uint64, error) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "CapEff:"); ok {
			return strconv.ParseUint(strings.TrimSpace(v), 16, 64)
		}
	}
	return 0, fmt.Errorf("CapEff not found")
}
