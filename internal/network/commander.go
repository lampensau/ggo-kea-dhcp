package network

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Commander runs a single privileged system command (via sudo) and returns its
// stdout. It is the one seam through which the network layer touches the host,
// which (a) centralizes the dev-sandbox bypass when a tool is absent and (b)
// lets the reconciler and the network manager be unit-tested against a fake.
type Commander interface {
	Run(name string, args ...string) (string, error)
}

// commandTimeout bounds a single privileged command so a wedged nmcli/iw/hostapd
// can't hang a reconcile goroutine indefinitely (previously there was none). It
// is generous (60s) because a legitimate `nmcli device wifi connect` association
// can take well over the time a quick `nft`/`sysctl` call needs.
const commandTimeout = 60 * time.Second

// SudoCommander is the production Commander: it shells out to `sudo <name> args`.
type SudoCommander struct {
	timeout time.Duration
}

// NewSudoCommander returns a Commander that runs real privileged commands.
func NewSudoCommander() *SudoCommander {
	return &SudoCommander{timeout: commandTimeout}
}

// redactSecretArgs returns a copy of args with the value following any
// password/psk token replaced, so a dev-mode bypass log can't leak a WiFi
// passphrase (nmcli ... wifi-sec.psk <secret>, ... password <secret>).
func redactSecretArgs(args []string) []string {
	out := make([]string, len(args))
	copy(out, args)
	for i := 0; i < len(out)-1; i++ {
		k := strings.ToLower(out[i])
		if strings.Contains(k, "password") || strings.Contains(k, "psk") {
			out[i+1] = "<redacted>"
		}
	}
	return out
}

func (c *SudoCommander) Run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sudo", append([]string{name}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// In a development sandbox the privileged tool is simply absent - bypass rather
		// than fail, so the app runs without the full appliance stack. But ONLY when the
		// command genuinely could not be found (sudo missing -> ErrNotFound, or sudo
		// exits 127 "command not found") AND it isn't on any known path. A tool that ran
		// and returned a non-zero exit was found and executed - its failure must surface,
		// even if it lives outside the path scan, so a real misconfiguration on the Pi is
		// never silently swallowed as success.
		if commandNotFound(err) && !toolPresent(name) {
			log.Printf("[Dev Mode] Bypassing command: %s %s", name, strings.Join(redactSecretArgs(args), " "))
			return "", nil
		}
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("command %q timed out after %s", name, c.timeout)
		}
		return "", fmt.Errorf("command %q failed: %s: %w", name, strings.TrimSpace(stderr.String()), err)
	}
	return stdout.String(), nil
}

// commandNotFound reports whether err means "the command does not exist" - sudo itself
// missing (exec.ErrNotFound) or sudo running the target and exiting 127 - as opposed to
// the target running and returning a non-zero exit (which must not be bypassed).
func commandNotFound(err error) bool {
	if errors.Is(err, exec.ErrNotFound) {
		return true
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode() == 127
	}
	return false
}

// toolPresent reports whether a privileged binary is installed, checking PATH and
// the common sbin locations that aren't always on an interactive user's PATH
// (this generalizes the per-call hostapd/nmcli/nft presence checks that used to
// be scattered across the network files).
func toolPresent(name string) bool {
	if _, err := exec.LookPath(name); err == nil {
		return true
	}
	for _, dir := range []string{"/usr/sbin", "/usr/local/sbin", "/sbin", "/bin", "/usr/bin"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return true
		}
	}
	return false
}

// ToolPresent reports whether a privileged binary is installed (PATH + the common
// sbin locations). Exported for the preflight checks; the network layer's own
// presence handling stays internal in Run.
func ToolPresent(name string) bool { return toolPresent(name) }

// RecordingCommander is a Commander test double: it records every invocation and
// returns canned output (keyed by command name) or a canned error. It lets tests
// in any package drive the network layer without touching the host.
type RecordingCommander struct {
	Calls   [][]string        // every Run invocation, as [name, args...]
	Outputs map[string]string // optional stdout per command name
	Err     error             // if set, every Run returns it
}

func (r *RecordingCommander) Run(name string, args ...string) (string, error) {
	r.Calls = append(r.Calls, append([]string{name}, args...))
	if r.Err != nil {
		return "", r.Err
	}
	if r.Outputs != nil {
		return r.Outputs[name], nil
	}
	return "", nil
}

// Ran reports whether a command with the given name was invoked.
func (r *RecordingCommander) Ran(name string) bool {
	for _, c := range r.Calls {
		if len(c) > 0 && c[0] == name {
			return true
		}
	}
	return false
}
