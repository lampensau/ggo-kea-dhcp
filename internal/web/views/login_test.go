package views

import (
	"context"
	"regexp"
	"strings"
	"testing"
)

// renderToString renders a templ component for assertions.
func renderLogin(t *testing.T, v LoginView) string {
	t.Helper()
	var sb strings.Builder
	if err := Login(v).Render(context.Background(), &sb); err != nil {
		t.Fatalf("render: %v", err)
	}
	return sb.String()
}

func TestLoginRendersStackPrimitives(t *testing.T) {
	html := renderLogin(t, LoginView{Page: PageData{State: "ONBOARDING", CSRFToken: "tok"}})

	for _, want := range []string{
		`src="/static/datastar.js?v=`,              // Datastar runtime, self-hosted + cache-busted
		`method="post" action="/login"`,            // NATIVE submit (works over a self-signed cert where a fetch would abort)
		`data-busy`,                                // busy/spinner on submit (busySubmitScript)
		`data-signals="{showpw: false, retry: 0}"`, // client-side signals (password reveal + backoff)
		`pw-reveal`,                                // in-field show/hide eye toggle (no checkbox)
		`id="login-error"`,                         // error message region
		`data-theme`,                               // no-FOUC theme script
	} {
		if !strings.Contains(html, want) {
			t.Errorf("login HTML missing %q", want)
		}
	}
}

func TestLoginErrorBoxFilledOnlyWhenSet(t *testing.T) {
	// The backoff countdown alert is always present but hidden (style="display:none"
	// + data-show), so assert on the static error MESSAGE rather than the shared
	// alert-err class. A clean page carries no static message.
	empty := renderLogin(t, LoginView{})
	if strings.Contains(empty, "Invalid username or password") {
		t.Error("clean login should not contain a static error message")
	}
	if !strings.Contains(empty, `style="display:none"`) || !strings.Contains(empty, `data-show="$retry > 0"`) {
		t.Error("backoff countdown alert should be present-but-hidden on a clean page")
	}
	withErr := renderLogin(t, LoginView{Error: "Invalid username or password"})
	if !strings.Contains(withErr, "alert-err") || !strings.Contains(withErr, "Invalid username or password") {
		t.Error("error login should render the alert and message")
	}
}

// TestLoginNoRemoteAssets is the output-level offline gate: the markup we emit
// must reference no remote origin (everything is embedded and served same-origin).
// W3C namespace URIs (xmlns on SVG/MathML) are identifiers, never fetched, so
// they are excluded.
func TestLoginNoRemoteAssets(t *testing.T) {
	html := renderLogin(t, LoginView{Page: PageData{State: "ONBOARDING"}})
	remote := regexp.MustCompile(`(?i)(https?:)?//[a-z0-9.-]+|@import|cdn\.|googleapis|fonts\.g`)
	for _, m := range remote.FindAllString(html, -1) {
		if strings.Contains(m, "w3.org") {
			continue // SVG/MathML namespace identifier, not a fetched asset
		}
		t.Errorf("login HTML references a remote asset: %q", m)
	}
}
