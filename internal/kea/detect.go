package kea

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Installed reports whether the kea-dhcp4 binary is present (PATH + sbin).
func Installed() bool { return keaInstalled() }

// HooksDir returns the detected Kea hooks library directory.
func HooksDir() string { return detectHooksDir() }

// RequiredHooks are the hook libraries the rendered kea-dhcp4.conf always
// references. flex_id is only used when port pinning is enabled, but it is part of
// the standard Kea hooks package and the wizard can turn pinning on at any time, so
// preflight treats it as required.
var RequiredHooks = []string{
	"libdhcp_host_cmds.so",
	"libdhcp_lease_cmds.so",
	"libdhcp_stat_cmds.so",
	"libdhcp_mysql.so",
	"libdhcp_flex_id.so",
}

// keaBinaryPath resolves the kea-dhcp4 binary, checking PATH then the common sbin
// locations an interactive user's PATH often omits. Returns "" when not found.
// This is the single resolver for the binary's location (keaInstalled and Version
// both use it - no duplicated path list).
func keaBinaryPath() string {
	if p, err := exec.LookPath("kea-dhcp4"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/sbin/kea-dhcp4", "/usr/local/sbin/kea-dhcp4", "/sbin/kea-dhcp4"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// keaVersionTimeout bounds `kea-dhcp4 -v` so a wedged binary can't hang the caller
// (preflight, --check, the Diagnostics handler) indefinitely.
const keaVersionTimeout = 5 * time.Second

// Version returns the kea-dhcp4 version string (e.g. "3.0.3") via `kea-dhcp4 -v`,
// which prints just the version number and needs no privileges.
func Version() (string, error) {
	bin := keaBinaryPath()
	if bin == "" {
		return "", fmt.Errorf("kea-dhcp4 not found")
	}
	ctx, cancel := context.WithTimeout(context.Background(), keaVersionTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "-v").Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("kea-dhcp4 -v timed out after %s", keaVersionTimeout)
		}
		return "", fmt.Errorf("kea-dhcp4 -v failed: %w", err)
	}
	// -v prints the bare version on the first line.
	v := strings.TrimSpace(string(out))
	if nl := strings.IndexByte(v, '\n'); nl != -1 {
		v = strings.TrimSpace(v[:nl])
	}
	return v, nil
}
