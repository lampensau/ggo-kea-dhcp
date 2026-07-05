package views

import (
	"strings"
	"testing"
)

// TestNoNativeConfirmAnywhere renders every page that used to gate a destructive
// action behind the browser's native confirm() and asserts none survives: the
// styled in-app dialogs replaced all five sites (lease release, remove
// reservation, unpin port, activate profile, delete profile).
func TestNoNativeConfirmAnywhere(t *testing.T) {
	active := PageData{State: "ACTIVE", Authenticated: true, CSRFToken: "tok", CurrentPath: "/dashboard"}
	pages := map[string]string{
		"leases": render(t, Leases(LeasesView{Page: active, CanReserve: true, Leases: []LeaseRow{
			{IPAddress: "10.0.0.50", HWAddress: "00:1f:80:aa:bb:cc", Class: "GGO-BPX", ExpiresIn: "30m"},
			{IPAddress: "10.0.0.9", HWAddress: "00:1f:80:11:22:33", Class: "GGO-WP-X", Reserved: true, SubnetID: 1},
		}})),
		"pinning": render(t, Pinning(PinningView{Page: active,
			Pinned:    []PortRow{{PortIdentity: "1/2", IPAddress: "10.0.0.9", HWAddress: "00:1f:80:20:aa:bb", SubnetID: 1, Pinned: true}},
			Learnable: []PortRow{{PortIdentity: "1/3", IPAddress: "10.0.0.12"}}})),
		"dashboard": render(t, Dashboard(DashboardView{Page: active, ProfileName: "Show", Profiles: []ProfileOption{
			{ID: 1, Name: "Show", Active: true, ScopeCount: 2},
			{ID: 2, Name: "Tour B", ScopeCount: 1},
		}})),
	}
	for name, html := range pages {
		if strings.Contains(html, "confirm(") {
			t.Errorf("%s still renders a native confirm()", name)
		}
	}
}

// TestReleaseDialogWiring: the release row button only stashes its IP and opens
// the shared dialog (mounted outside the live #leases-body region); the dialog's
// confirm button fires the Datastar @delete, reading the CSRF token from the
// page <meta> at click time so a live re-broadcast can't strand it.
func TestReleaseDialogWiring(t *testing.T) {
	active := PageData{State: "ACTIVE", Authenticated: true, CSRFToken: "tok", CurrentPath: "/leases"}
	page := render(t, Leases(LeasesView{Page: active, Leases: []LeaseRow{
		{IPAddress: "10.0.0.50", HWAddress: "00:1f:80:aa:bb:cc", Class: "GGO-BPX", ExpiresIn: "30m"},
	}}))
	for _, want := range []string{
		`id="release-dialog"`,
		"ggoReleaseOpen",
		"@delete(&#39;/leases/release?ip=&#39; + el.closest(&#39;dialog&#39;).dataset.ip",
		"csrf-token",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("leases page missing release-dialog wiring %q", want)
		}
	}
	// The dialog must live OUTSIDE the live region: the body fragment alone
	// (what the SSE ticker re-broadcasts) must not contain it.
	body := render(t, LeasesBody([]LeaseRow{{IPAddress: "10.0.0.50", HWAddress: "00:1f:80:aa:bb:cc", ExpiresIn: "30m"}}, true))
	if strings.Contains(body, "release-dialog") {
		t.Error("release dialog must not be rendered inside #leases-body")
	}
	if !strings.Contains(body, `data-ip="10.0.0.50"`) {
		t.Error("release row button should carry its IP in a data attribute")
	}
}

// TestResvDeleteDialogWiring: the remove-reservation dialog posts the same form
// the per-row version did (action, return target, mac + subnet_id fields) and
// still sets the CSRF token from the page <meta> at submit time.
func TestResvDeleteDialogWiring(t *testing.T) {
	dlg := render(t, resvDeleteDialog("tok"))
	for _, want := range []string{
		`action="/reservations/delete"`,
		`name="return" value="/leases"`,
		`name="mac"`,
		`name="subnet_id"`,
		"meta[name=csrf-token]",
	} {
		if !strings.Contains(dlg, want) {
			t.Errorf("resvDeleteDialog missing %q", want)
		}
	}
	body := render(t, LeasesBody([]LeaseRow{{IPAddress: "10.0.0.9", HWAddress: "00:1f:80:11:22:33", Reserved: true, SubnetID: 1}}, true))
	if strings.Contains(body, "resv-del-dialog") {
		t.Error("remove-reservation dialog must not be rendered inside #leases-body")
	}
}

// TestUnpinDialogWiring: the unpin dialog posts the same form the per-row
// version did; the row button (inside the live #pinned-body region) only
// carries its target in data attributes.
func TestUnpinDialogWiring(t *testing.T) {
	dlg := render(t, unpinDialog("tok"))
	for _, want := range []string{
		`action="/pinning/unpin"`,
		`name="csrf_token" value="tok"`,
		`name="port_identity"`,
		`name="subnet_id"`,
	} {
		if !strings.Contains(dlg, want) {
			t.Errorf("unpinDialog missing %q", want)
		}
	}
	body := render(t, PinnedBody([]PortRow{{PortIdentity: "1/2", IPAddress: "10.0.0.9", SubnetID: 1, Pinned: true}}, "tok"))
	if !strings.Contains(body, "ggoUnpinOpen") || !strings.Contains(body, `data-port="1/2"`) {
		t.Error("pinned row should render the unpin dialog opener with its port identity")
	}
	if strings.Contains(body, "unpin-dialog") {
		t.Error("unpin dialog must not be rendered inside #pinned-body")
	}
}

// TestProfileConfirmDialogs: the Manage menu's per-profile actions open the two
// shared dialogs (rendered only when another profile exists) instead of
// per-row confirm forms.
func TestProfileConfirmDialogs(t *testing.T) {
	withOther := render(t, configMenu([]ProfileOption{
		{ID: 1, Name: "Show", Active: true, ScopeCount: 2},
		{ID: 2, Name: "Tour B", ScopeCount: 1},
	}, "tok", true))
	for _, want := range []string{
		`id="profile-activate-dialog"`,
		`id="profile-delete-dialog"`,
		`action="/profile/activate"`,
		`action="/profile/delete"`,
		"ggoProfileOpen",
		`data-profile="2"`,
	} {
		if !strings.Contains(withOther, want) {
			t.Errorf("configMenu with a second profile missing %q", want)
		}
	}
	// Only the active profile: no rows, so no dialogs either.
	activeOnly := render(t, configMenu([]ProfileOption{{ID: 1, Name: "Show", Active: true}}, "tok", true))
	if strings.Contains(activeOnly, "profile-activate-dialog") {
		t.Error("configMenu without other profiles should not mount the profile dialogs")
	}
}
