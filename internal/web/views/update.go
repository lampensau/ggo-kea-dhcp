package views

import "strings"

// UpdateBadgeView is the footer's #update-badge live region: empty when the box
// is current (or the operator dismissed this version), a link to the Settings
// update card when a newer release is known.
type UpdateBadgeView struct {
	Show    bool
	Version string
}

// UpdateView is the Settings "Software Update" card. Available means a newer
// release than the running version is known; CanInstall additionally requires
// the release's published SHA-256 digest (no digest = notify only, never
// install). NeedsSystem latches after a frozen-dependency install failed on
// unsatisfiable deps, offering the broader system-scope path as a second
// explicit click.
type UpdateView struct {
	Current     string
	Available   bool
	Version     string
	Scope       string // "app" | "system"
	Notes       string
	CanInstall  bool
	NeedsSystem bool
	Dismissed   bool
	LastCheck   string
	CSRF        string
}

// noteBlock is one rendered block of the escaped-plaintext release-notes
// renderer: a heading ("## ..."), a bullet list, or a paragraph. All text is
// emitted through templ's normal escaping - release notes are remote content
// and must never reach the DOM as markup.
type noteBlock struct {
	Kind  string // "h" | "list" | "p"
	Text  string
	Items []string
}

// parseReleaseNotes turns a raw markdown-ish release body into flat blocks for
// the dialog: `#`-prefixed lines become headings, `-`/`*` lines group into
// bullet lists, everything else is a paragraph. No inline markup is
// interpreted - this is deliberately not a markdown engine (vendored deps only,
// and the body is untrusted).
func parseReleaseNotes(body string) []noteBlock {
	var blocks []noteBlock
	var list []string
	flushList := func() {
		if len(list) > 0 {
			blocks = append(blocks, noteBlock{Kind: "list", Items: list})
			list = nil
		}
	}
	for _, line := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
			flushList()
		case strings.HasPrefix(line, "#"):
			flushList()
			blocks = append(blocks, noteBlock{Kind: "h", Text: strings.TrimSpace(strings.TrimLeft(line, "#"))})
		case strings.HasPrefix(line, "- ") || strings.HasPrefix(line, "* "):
			list = append(list, strings.TrimSpace(line[2:]))
		default:
			flushList()
			blocks = append(blocks, noteBlock{Kind: "p", Text: line})
		}
	}
	flushList()
	return blocks
}

// installDlgID names the two install-confirm dialogs (normal / system-escalation).
func installDlgID(system bool) string {
	if system {
		return "update-install-sys-dlg"
	}
	return "update-install-dlg"
}

// updateScopeHint is the honest one-liner for what installing this release does
// to the running show, keyed by the release manifest's scope.
func updateScopeHint(scope string) string {
	if scope == "system" {
		return "This release also updates system packages the appliance depends on. Expect a brief DHCP interruption while they upgrade; the page reconnects on its own."
	}
	return "Updates the appliance software only - DHCP keeps serving and the page reconnects on its own once the control plane restarts."
}
