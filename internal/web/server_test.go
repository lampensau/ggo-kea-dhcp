package web

import (
	"testing"

	"ggo-kea-dhcp/internal/db"
)

func TestStateRedirectFor(t *testing.T) {
	cases := []struct {
		state, path, want string
	}{
		{db.StateOnboarding, "/setup", ""},
		{db.StateOnboarding, "/setup/apply", ""},
		{db.StateOnboarding, "/settings/save", ""},
		{db.StateOnboarding, "/logout", ""},
		// The shell opens /sse/live on every authenticated page (live link-status
		// badge in the wizard). It must NOT 302 here: a redirect makes Datastar
		// follow it to the full /setup page and morph it in, wiping the JS-added
		// scope card.
		{db.StateOnboarding, "/sse/live", ""},
		{db.StateOnboarding, "/dashboard", "/setup"},
		{db.StateOnboarding, "/pinning", "/setup"},
		{db.StateActive, "/setup", ""},       // wizard allowed in ACTIVE = create a new configuration
		{db.StateActive, "/setup/apply", ""}, // and apply it
		{db.StateActive, "/dashboard", ""},
		{db.StateActive, "/pinning", ""},
		{db.StateConfiguring, "/setup", "/dashboard"}, // but not while an apply is mid-flight
		{db.StateConfiguring, "/dashboard", ""},
		{db.StateFactory, "/anything", ""},
	}
	for _, c := range cases {
		if got := stateRedirectFor(c.state, c.path); got != c.want {
			t.Errorf("stateRedirectFor(%q,%q)=%q want %q", c.state, c.path, got, c.want)
		}
	}
}
