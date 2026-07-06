package views

// THROWAWAY preview harness (see zz_preview_test.go). Renders the self-update
// UI states - footer badge, Settings card variants, release-notes dialog - to
// a static HTML file for screenshotting without running the appliance. DELETE
// static/_preview_*.html before any `make pi`. Gated: normal `go test` skips it.

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestZZPreviewUpdate(t *testing.T) {
	if os.Getenv("GGO_PREVIEW") != "1" {
		t.Skip("preview-only")
	}
	ctx := context.Background()
	notes := "## Highlights\n- Faster pool rebalancing after a reservation\n- Port pinning labels survive a routine reset\n\n## Fixes\n- Dashboard sparkline freeze after a sampler panic\n- Wizard trunk badge on tagged-only links\n\nSee the full changelog on GitHub."

	upToDate := UpdateView{Current: "1.1.2"}
	appAvail := UpdateView{Current: "1.1.2", Available: true, Version: "1.2.0", Scope: "app", Notes: notes, CanInstall: true}
	sysAvail := UpdateView{Current: "1.1.2", Available: true, Version: "2.0.0", Scope: "system", Notes: notes, CanInstall: true}
	needsSys := UpdateView{Current: "1.1.2", Available: true, Version: "1.2.0", Scope: "app", Notes: notes, CanInstall: true, NeedsSystem: true}
	noDigest := UpdateView{Current: "1.1.2", Available: true, Version: "1.2.0", Scope: "app", Notes: notes, CanInstall: false}

	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en" data-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><link rel="stylesheet" href="style.css"><title>Update UI preview</title></head><body><main class="container">`)

	// Footer badge in its real footer context (shown + hidden).
	b.WriteString(`<h3 class="section-heading">Footer badge (visible state)</h3><footer class="app-footer" style="position:static"><div class="app-footer-inner"><span class="settings-version">Green-GO Kea DHCP v1.1.2</span>`)
	_ = UpdateBadge(UpdateView{Available: true, Version: "1.2.0"}).Render(ctx, &b)
	b.WriteString(`<div class="btn-row"></div></div></footer>`)

	section := func(title string, v UpdateView) {
		b.WriteString(`<h3 class="section-heading">` + title + `</h3>`)
		_ = UpdateDialogs(v).Render(ctx, &b)
	}
	section("Up to date", upToDate)
	section("App-scope release available", appAvail)
	section("System-scope release available", sysAvail)
	section("needs_system escalation", needsSys)
	section("No published digest (notify only)", noDigest)

	b.WriteString(`</main></body></html>`)
	// Preview-only: force the release-notes + install dialogs open so the static
	// page shows them (dialogs render closed by default; ids collide across the
	// repeated cards but only the first of each is opened, which is enough).
	html := b.String()
	html = strings.Replace(html, `<dialog id="update-dialog"`, `<dialog open id="update-dialog"`, 1)
	html = strings.Replace(html, `<dialog id="update-notes-dlg"`, `<dialog open id="update-notes-dlg"`, 1)
	html = strings.Replace(html, `<dialog id="update-install-dlg"`, `<dialog open id="update-install-dlg"`, 1)
	if err := os.WriteFile("../static/_preview_update.html", []byte(html), 0o644); err != nil {
		t.Fatal(err)
	}
}
