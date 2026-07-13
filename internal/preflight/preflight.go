// Package preflight probes the host for the prerequisites the appliance needs to
// function: the Kea binary and hooks, the control socket, the privileged tools,
// the reservation database, Linux capabilities, and a writable config dir. It is
// read-only and never panics on a missing tool - a missing prerequisite is a
// reported Check, not a crash. It runs at startup (logged + audited, never aborts
// boot) and via `--check` (the installer uses the exit code).
package preflight

import (
	"context"
	"errors"
	"fmt"
	"net"
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

// Run executes every probe and returns the results grouped by subsystem, in a
// stable order: the Kea DHCP engine first (its binary, hooks, writable config, then
// live control socket), then the privileged tools, the reservation database, the
// Linux capabilities, port 53 for the local DNS server, and finally the host
// clock. Grouping keeps related checks adjacent (the config-dir check belongs
// with the other Kea checks, not stranded after the database).
func Run(cfg *config.Config) Result {
	r := Result{
		checkKeaBinary(),
		checkHooks(),
		checkKeaConfDir(cfg),
		checkKeaSocket(cfg),
	}
	r = append(r, checkTools()...)
	r = append(r, checkMariaDB(cfg))
	r = append(r, checkCaps()...)
	r = append(r, checkPort53())
	r = append(r, checkPort53TCP())
	r = append(r, checkClock())
	return r
}

// checkKeaBinary verifies kea-dhcp4 is installed and is the supported 3.0.x series
// (2.x and 3.2+ differ in config/flex-id behavior this appliance depends on).
func checkKeaBinary() Check {
	if !kea.Installed() {
		return keaBinaryStatus(false, "", nil)
	}
	v, err := kea.Version()
	return keaBinaryStatus(true, v, err)
}

// keaBinaryStatus is the pure decision (clockStatus pattern): installed at all,
// version readable, and inside the supported series.
func keaBinaryStatus(installed bool, version string, verr error) Check {
	const name = "Kea binary"
	if !installed {
		return Check{name, Fail, "kea-dhcp4 not found in PATH or sbin - install isc-kea-dhcp4-server"}
	}
	if verr != nil {
		return Check{name, Warn, fmt.Sprintf("present but version unreadable: %v", verr)}
	}
	if !strings.HasPrefix(version, "3.0.") {
		return Check{name, Fail, fmt.Sprintf("found Kea %s but this appliance requires the 3.0.x series", version)}
	}
	return Check{name, OK, "version " + version}
}

// checkHooks verifies the required hook libraries exist in the detected hooks dir.
func checkHooks() Check {
	dir := kea.HooksDir()
	var missing []string
	for _, lib := range kea.RequiredHooks {
		if _, err := os.Stat(filepath.Join(dir, lib)); err != nil {
			missing = append(missing, lib)
		}
	}
	return hooksStatus(dir, missing)
}

// hooksStatus is the pure decision over the probed missing-library list.
func hooksStatus(dir string, missing []string) Check {
	const name = "Kea hooks"
	dir = strings.TrimRight(dir, "/")
	if len(missing) > 0 {
		return Check{name, Fail, fmt.Sprintf("missing in %s: %s", dir, strings.Join(missing, ", "))}
	}
	return Check{name, OK, "all present in " + dir}
}

// checkKeaSocket verifies the Kea control socket answers. Warn (not Fail): Kea may
// simply not be started yet at boot; the runtime health monitor tracks it ongoing.
func checkKeaSocket(cfg *config.Config) Check {
	secret, err := cfg.GetKeaSecret()
	if err != nil {
		return keaSocketStatus(cfg.KeaAPIURL, err, nil)
	}
	return keaSocketStatus(cfg.KeaAPIURL, nil, kea.NewClient(cfg.KeaAPIURL, "gui", secret).Ping(context.Background()))
}

// keaSocketStatus is the pure decision: Warn (not Fail) throughout, because Kea
// may simply not be started yet at boot and the runtime health monitor tracks it.
func keaSocketStatus(url string, secretErr, pingErr error) Check {
	const name = "Kea control socket"
	if secretErr != nil {
		return Check{name, Warn, fmt.Sprintf("cannot read API secret: %v", secretErr)}
	}
	if pingErr != nil {
		return Check{name, Warn, fmt.Sprintf("%s unreachable: %v", url, pingErr)}
	}
	return Check{name, OK, "reachable at " + url}
}

// checkTools verifies the privileged binaries the network layer shells out to.
func checkTools() []Check {
	// ip/nmcli/nft drive active networking; hostapd/iw drive the onboarding SoftAP;
	// systemctl manages services. All are needed for full appliance function.
	tools := []string{"nmcli", "nft", "ip", "hostapd", "iw", "systemctl"}
	var checks []Check
	for _, t := range tools {
		checks = append(checks, toolStatus(t, network.ToolPresent(t)))
	}
	return checks
}

// toolStatus is the pure decision for one privileged tool's presence.
func toolStatus(tool string, present bool) Check {
	if present {
		return Check{"Tool: " + tool, OK, "installed"}
	}
	return Check{"Tool: " + tool, Fail, "not found in PATH or sbin"}
}

// checkMariaDB verifies the reservation database is reachable and initialized.
// Warn (not Fail): Kea still serves dynamic leases without it; only reservations
// and port pinning are unavailable.
func checkMariaDB(cfg *config.Config) Check {
	m, err := db.ConnectMariaDB(cfg.MariaDBDSN)
	if err != nil {
		return mariadbStatus(cfg.MariaDBDSN, err, nil)
	}
	defer m.Close()
	return mariadbStatus(cfg.MariaDBDSN, nil, m.VerifySchema(context.Background()))
}

// mariadbStatus is the pure decision: Warn (not Fail) throughout, because Kea
// still serves dynamic leases without the reservation database.
func mariadbStatus(dsn string, connectErr, schemaErr error) Check {
	const name = "Reservation database (MariaDB)"
	if connectErr != nil {
		return Check{name, Warn, fmt.Sprintf("connect failed: %v", connectErr)}
	}
	if schemaErr != nil {
		return Check{name, Warn, fmt.Sprintf("schema not ready: %v", schemaErr)}
	}
	return Check{name, OK, "connected, hosts table present (" + config.RedactedMariaDSN(dsn) + ")"}
}

// checkKeaConfDir verifies the app can write kea-dhcp4.conf, a hard requirement for
// applying any profile. The app OVERWRITES that file in place (it owns it, mode 0660)
// and never creates files in /etc/kea, which the package deliberately keeps 0750
// root:_kea. So an existing conf is probed for writability directly (open for write, no
// truncate); a dir-create probe there is a false negative on a correctly-installed box.
// Only when the conf is absent, so the app would have to create it, does that apply.
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
		return Check{name, OK, conf + " writable"}
	}
	probe := filepath.Join(dir, ".ggo-write-test")
	if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
		return Check{name, Fail, fmt.Sprintf("%s not writable: %v", dir, err)}
	}
	_ = os.Remove(probe)
	return Check{name, OK, dir + " writable"}
}

// Linux capability bit numbers (see capabilities(7)).
const (
	capNetBindService = 10 // bind to ports < 1024 (the local DNS server on :53)
	capNetRaw         = 13 // AF_PACKET raw sockets (passive network monitor)
)

// checkCaps reports whether the process holds the capabilities needed for the
// port-53 DNS bind and the passive monitor. Warn (not Fail): both are degraded
// features, not core DHCP - and a process running as root holds them implicitly.
func checkCaps() []Check {
	eff, err := readCapEff()
	return capsStatus(eff, err)
}

// capsStatus is the pure decision over the probed effective-capability mask.
func capsStatus(eff uint64, err error) []Check {
	if err != nil {
		return []Check{{"Linux capabilities", Warn, fmt.Sprintf("cannot read /proc/self/status: %v", err)}}
	}
	return []Check{
		capCheck("CAP_NET_RAW (network monitor)", eff, capNetRaw),
		capCheck("CAP_NET_BIND_SERVICE (local DNS)", eff, capNetBindService),
	}
}

func capCheck(name string, eff uint64, bit uint) Check {
	if eff&(1<<bit) != 0 {
		return Check{name, OK, "held"}
	}
	return Check{name, Warn, "not held - feature disabled (granted via systemd AmbientCapabilities)"}
}

// checkPort53 probes whether UDP port 53 is available for the local DNS server. The
// appliance's own listeners bind per-scope addresses, never loopback, so a loopback
// bind succeeding means no wildcard binder (systemd-resolved, dnsmasq) is squatting the
// port; failing means one is, and device-name resolution will not come up. Warn, not
// Fail: DNS is a feature and DHCP serves without it. A permission error is folded into
// the CAP_NET_BIND_SERVICE story rather than blamed on a conflicting service.
func checkPort53() Check {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53})
	if err == nil {
		_ = conn.Close()
	}
	return port53Status("UDP", err)
}

// checkPort53TCP probes TCP port 53, the RFC 7766 fallback the DNS server serves
// alongside UDP for answers over the UDP size. It binds best-effort per listener,
// so a TCP-only squatter (or a missing capability) can leave the box serving UDP
// while silently unable to return oversize answers; this surfaces that gap on
// Diagnostics instead of a single startup log line. Same loopback-proxy logic as
// the UDP probe.
func checkPort53TCP() Check {
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53})
	if err == nil {
		_ = ln.Close()
	}
	return port53Status("TCP", err)
}

// port53Status is the pure decision over a loopback bind outcome: a permission
// error is the missing-capability story, any other error means a binder
// (systemd-resolved, dnsmasq, a squatter) is holding the port.
func port53Status(proto string, err error) Check {
	name := proto + " port 53 (local DNS)"
	if err == nil {
		return Check{name, OK, "available"}
	}
	if errors.Is(err, os.ErrPermission) {
		return Check{name, Warn, "bind denied - CAP_NET_BIND_SERVICE missing (granted via systemd AmbientCapabilities)"}
	}
	return Check{name, Warn, fmt.Sprintf("port taken by another service - local DNS cannot bind %s/53: %v", proto, err)}
}

// checkClock reports the reliability of the time source lease expiry depends on. The
// failure it guards against: an RTC-less box boots with a stale clock, devices lease
// under that wrong time, and a later FORWARD step (NTP syncs, or a late correction)
// lands every lease's expiry in the past at once, so Kea reclaims them all and the
// whole active-lease table vanishes.
//
// A hardware RTC removes the risk entirely, the kernel restoring a correct time before
// userspace so nothing steps forward later, hence RTC-present is OK regardless of NTP.
// Without one we rely on fake-hwclock (restores the last-known time at boot, and only
// ever forward) plus NTP. The one genuinely risky state is no RTC AND an undisciplined
// clock, where the wall-clock may be wrong and a later sync could trip the wipe.
func checkClock() Check {
	return clockStatus(hasRTC(), clockSynced())
}

// clockStatus is the pure tri-state decision, split out so it is unit-testable
// without touching the host.
func clockStatus(rtc, synced bool) Check {
	const name = "System clock / RTC"
	switch {
	case rtc:
		return Check{name, OK, "hardware RTC present - survives reboot without NTP"}
	case synced:
		return Check{name, OK, "time-synced, fake-hwclock persists it (no RTC)"}
	default:
		return Check{name, Warn, "no RTC and not time-synced - leases run on last-known time"}
	}
}

// hasRTC reports whether the kernel exposes a real-time clock device. Pi 4 and
// earlier have none (empty /sys/class/rtc); Pi 5 exposes rtc0 - present whether or
// not a coin cell is fitted, and the battery can't be probed at runtime, so device
// presence is the best available signal (and still strictly better than no RTC).
func hasRTC() bool {
	entries, err := os.ReadDir("/sys/class/rtc")
	return err == nil && len(entries) > 0
}

// clockSynced reports whether systemd-timesyncd has disciplined the clock. It drops
// the /run/systemd/timesync/synchronized stamp file on first sync - the same signal
// systemd-time-wait-sync waits on. A plain file read: seccomp-safe under the unit's
// ProtectClock (which would block a live adjtimex query), and needs no privilege.
func clockSynced() bool {
	_, err := os.Stat("/run/systemd/timesync/synchronized")
	return err == nil
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
