package views

import (
	"context"
	"strings"
	"testing"
)

// renderBase renders the Base shell wrapping trivial content for assertions.
func renderBase(t *testing.T, d PageData) string {
	t.Helper()
	var sb strings.Builder
	body := Base(d) // children optional; Base renders header/shell regardless
	if err := body.Render(context.Background(), &sb); err != nil {
		t.Fatalf("render: %v", err)
	}
	return sb.String()
}

func TestShellActiveNavAndLiveChannel(t *testing.T) {
	html := renderBase(t, PageData{State: "ACTIVE", Authenticated: true, CurrentPath: "/leases", CSRFToken: "tok"})

	for _, want := range []string{
		`id="state-badge"`, `status-pill`, `is-ok`, // live status pill, ACTIVE = ok
		`Leases`,                                                 // nav label text actually renders (templ children-swallow guard)
		`href="/dashboard"`, `href="/leases"`, `href="/pinning"`, // nav links present
		`@get('/sse/live?page=' + encodeURIComponent(location.pathname), {openWhenHidden: true})`, // live channel opens on load (authenticated), passing its page so the hub scopes patches
		`__ggoCycleTheme()`,       // theme toggle wired
		`lucide-layout-dashboard`, // genuine Lucide nav icon inlined
	} {
		if !strings.Contains(html, want) {
			t.Errorf("active shell missing %q", want)
		}
	}
	// aria-current marks exactly the current path.
	if !strings.Contains(html, `href="/leases" aria-current="page"`) {
		t.Error("current nav link should carry aria-current=page")
	}
	if strings.Contains(html, `href="/dashboard" aria-current="page"`) {
		t.Error("non-current nav link must not carry aria-current")
	}
}

func TestShellUnauthHasNoNavOrLiveChannel(t *testing.T) {
	html := renderBase(t, PageData{State: "ONBOARDING", Authenticated: false})
	if strings.Contains(html, "/sse/live") {
		t.Error("unauthenticated shell must not open the live channel")
	}
	if strings.Contains(html, `aria-label="Primary"`) {
		t.Error("unauthenticated shell must not render primary nav")
	}
	// The theme toggle is always available, even pre-auth.
	if !strings.Contains(html, "__ggoCycleTheme()") {
		t.Error("theme toggle should render pre-auth")
	}
}
