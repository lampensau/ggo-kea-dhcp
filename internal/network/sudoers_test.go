package network

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// sudoersPath is the packaged sudoers drop-in this package's privileged argvs
// must be covered by.
const sudoersPath = "../../packaging/sudoers/ggo-kea-dhcp"

// TestSudoersCoversPrivilegedInvocations cross-checks every Commander invocation
// in this package against packaging/sudoers/ggo-kea-dhcp, so a new privileged
// command - or a new argv for an exact-argument-tier command like systemctl -
// fails here in CI instead of only on the Pi (where sudo refuses it at runtime).
//
// Two tiers mirror the sudoers file: a command whose sudoers entry carries no
// arguments is allowed with any argv; a command that appears only WITH arguments
// (systemctl, pkill, sysctl - broad escalation paths) must be invoked with an
// all-literal argv exactly matching one of its sudoers lines. An invocation of an
// exact-tier command with a non-literal argument fails too: the test cannot prove
// sudo will accept it, so spell the argv out (see SetIPForwarding).
func TestSudoersCoversPrivilegedInvocations(t *testing.T) {
	bare, exact := parseSudoers(t)
	for _, inv := range scanInvocations(t) {
		if bare[inv.name] {
			continue
		}
		argv := inv.name + " " + strings.Join(inv.args, " ")
		if !inv.allLiteral {
			t.Errorf("%s: %s is on the sudoers exact-argument tier but is invoked with a non-literal argv %q - use literal arguments so this test can verify the matching sudoers line", inv.site, inv.name, argv)
			continue
		}
		if !exact[strings.TrimSpace(argv)] {
			t.Errorf("%s: no sudoers rule matches %q - add the exact line to packaging/sudoers/ggo-kea-dhcp", inv.site, argv)
		}
	}
}

// parseSudoers reads the packaged drop-in and returns the bare-name tier (any
// argv allowed) and the exact-argv tier ("name arg arg" strings) of the NOPASSWD
// command list.
func parseSudoers(t *testing.T) (bare map[string]bool, exact map[string]bool) {
	t.Helper()
	data, err := os.ReadFile(sudoersPath)
	if err != nil {
		t.Fatalf("read sudoers drop-in: %v", err)
	}
	// Join the backslash-continued spec into one logical line, then take the
	// comma-separated command list after every NOPASSWD: (a future split of the
	// drop-in into several specs keeps working).
	spec := strings.ReplaceAll(string(data), "\\\n", " ")
	var cmdList string
	for _, line := range strings.Split(spec, "\n") {
		if _, after, found := strings.Cut(line, "NOPASSWD:"); found {
			cmdList += "," + after
		}
	}
	if cmdList == "" {
		t.Fatalf("no NOPASSWD command list found in %s", sudoersPath)
	}

	bare = map[string]bool{}
	exact = map[string]bool{}
	for _, entry := range strings.Split(cmdList, ",") {
		fields := strings.Fields(entry)
		if len(fields) == 0 {
			continue
		}
		name := filepath.Base(fields[0])
		if len(fields) == 1 {
			bare[name] = true
			continue
		}
		exact[name+" "+strings.Join(fields[1:], " ")] = true
	}
	return bare, exact
}

// invocation is one cmd.Run(...) call found in this package's source: the literal
// command name, its arguments (literal text, or the raw expression for a
// non-literal), and whether every argument was a string literal.
type invocation struct {
	site       string // file:line
	name       string
	args       []string
	allLiteral bool
}

// runCallRe matches a Commander call - including multi-line ones - and captures
// the argument-list source text up to the first closing paren. That paren is a
// safe terminator because none of the fixed argvs put ')' inside a string
// literal; the fail-closed count check below catches a call the regex misses.
var runCallRe = regexp.MustCompile(`(?s)\.Run\(([^)]*)\)`)

// scanInvocations regex-scans every non-test .go file in this package for
// cmd.Run calls whose command (first argument) is a string literal. It FAILS
// CLOSED: every textual ".Run(" occurrence must be matched and parsed to a
// literal command name - an un-scannable call would otherwise silently bypass
// the sudoers cross-check and fail only on the Pi, the exact gap this test
// exists to close.
// constRe matches a single-line package const bound to a string literal
// (`const NAME = "value"`). Only true `const` declarations are resolved (never
// vars, which can be reassigned), and const-block entries are deliberately left
// out - an unresolved const stays non-literal, i.e. fail-closed.
var constRe = regexp.MustCompile(`(?m)^\s*const\s+([A-Za-z_]\w*)\s*=\s*("(?:[^"\\]|\\.)*")`)

// packageStringConsts maps this package's single-line string consts to their
// value, so an exact-tier argv built from such a const (e.g. hostapd.go's wlan0
// SoftAP CIDR) is still statically verifiable against the sudoers file.
func packageStringConsts(t *testing.T) map[string]string {
	t.Helper()
	consts := map[string]string{}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		data, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, m := range constRe.FindAllStringSubmatch(string(data), -1) {
			if v, err := strconv.Unquote(m[2]); err == nil {
				consts[m[1]] = v
			}
		}
	}
	return consts
}

func scanInvocations(t *testing.T) []invocation {
	t.Helper()
	consts := packageStringConsts(t)
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var out []invocation
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		data, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		src := string(data)
		matches := runCallRe.FindAllStringSubmatchIndex(src, -1)
		if raw := strings.Count(src, ".Run("); raw != len(matches) {
			t.Errorf("%s: %d .Run( occurrences but only %d scannable - extend the scanner or reshape the call", e.Name(), raw, len(matches))
		}
		for _, m := range matches {
			argSrc := src[m[2]:m[3]]
			if strings.TrimSpace(argSrc) == "" {
				continue // zero-arg .Run() is exec.Cmd's own method, never a Commander call
			}
			inv := parseArgs(argSrc, consts)
			if inv.name == "" {
				t.Errorf("%s:%d: .Run call with a non-literal command name - the sudoers cross-check cannot verify it", e.Name(), 1+strings.Count(src[:m[0]], "\n"))
				continue
			}
			inv.site = e.Name() + ":" + strconv.Itoa(1+strings.Count(src[:m[0]], "\n"))
			out = append(out, inv)
		}
	}
	if len(out) == 0 {
		t.Fatal("no Commander invocations found - the scanner regex no longer matches the code")
	}
	return out
}

// parseArgs splits a Run(...) argument-list source string into the command name
// and argument tokens, tracking whether every argument is a plain string literal.
// A comma-split is sufficient: none of the fixed privileged argvs carry a comma
// inside a string literal, and a non-literal expression containing one merely
// splits into two non-literal tokens (still correctly flagged non-literal).
func parseArgs(src string, consts map[string]string) invocation {
	var inv invocation
	inv.allLiteral = true
	for i, tok := range strings.Split(src, ",") {
		tok = strings.TrimSpace(tok)
		lit, err := strconv.Unquote(tok)
		isLiteral := err == nil && strings.HasPrefix(tok, `"`)
		// A same-package `const NAME = "literal"` is as statically verifiable as the
		// literal itself: resolve it so an exact-tier argv naming one still matches.
		if !isLiteral {
			if v, ok := consts[tok]; ok {
				lit, isLiteral = v, true
			}
		}
		switch {
		case i == 0:
			if !isLiteral {
				return invocation{} // dynamic command name - out of scope
			}
			inv.name = lit
		case isLiteral:
			inv.args = append(inv.args, lit)
		default:
			inv.args = append(inv.args, tok)
			inv.allLiteral = false
		}
	}
	return inv
}
