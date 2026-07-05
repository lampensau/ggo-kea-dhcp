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
	// comma-separated command list after NOPASSWD:.
	spec := strings.ReplaceAll(string(data), "\\\n", " ")
	var cmdList string
	for _, line := range strings.Split(spec, "\n") {
		if _, after, found := strings.Cut(line, "NOPASSWD:"); found {
			cmdList = after
			break
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

// runCallRe matches a Commander call and captures its argument list source text.
// All privileged invocations in this package are single-line cmd.Run(...) calls;
// a future multi-line one simply won't match and its command will surface as an
// uncovered name if it is new (and the reviewer extends this scanner).
var runCallRe = regexp.MustCompile(`\.Run\(([^)]*)\)`)

// scanInvocations regex-scans every non-test .go file in this package for
// cmd.Run calls whose command (first argument) is a string literal.
func scanInvocations(t *testing.T) []invocation {
	t.Helper()
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
		for lineNo, line := range strings.Split(string(data), "\n") {
			for _, m := range runCallRe.FindAllStringSubmatch(line, -1) {
				inv := parseArgs(m[1])
				if inv.name == "" {
					continue // first argument not a literal (no such call today)
				}
				inv.site = e.Name() + ":" + strconv.Itoa(lineNo+1)
				out = append(out, inv)
			}
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
func parseArgs(src string) invocation {
	var inv invocation
	inv.allLiteral = true
	for i, tok := range strings.Split(src, ",") {
		tok = strings.TrimSpace(tok)
		lit, err := strconv.Unquote(tok)
		isLiteral := err == nil && strings.HasPrefix(tok, `"`)
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
