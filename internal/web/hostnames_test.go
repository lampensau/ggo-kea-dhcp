package web

import (
	"strings"
	"testing"

	"ggo-kea-dhcp/internal/kea"
	"ggo-kea-dhcp/internal/web/views"
)

// TestHostnameSlugsDedupe: two devices sharing a name get distinct MAC-tagged
// labels, and the result is stable across repeated calls (the SSE change-only
// broadcast hashes fragments, so the same input set must always render the same
// bytes).
func TestHostnameSlugsDedupe(t *testing.T) {
	names := map[string]string{
		"001f80aa0001": "BPX 19666",
		"001f80bb0002": "BPX 19666",
		"001f80cc0003": "Stage Rack",
	}
	got := HostnameSlugs(names)
	if got["001f80aa0001"] != "bpx-19666-0001" || got["001f80bb0002"] != "bpx-19666-0002" {
		t.Errorf("colliding names not MAC-tagged: %v", got)
	}
	if got["001f80cc0003"] != "stage-rack" {
		t.Errorf("unique name should keep its bare slug, got %q", got["001f80cc0003"])
	}
	for range 20 {
		if again := HostnameSlugs(names); len(again) != len(got) {
			t.Fatalf("unstable result size")
		} else {
			for mac, s := range got {
				if again[mac] != s {
					t.Fatalf("unstable slug for %s: %q vs %q", mac, s, again[mac])
				}
			}
		}
	}
}

// TestHostnameSlugsTailCollision: colliding devices whose MACs share the same
// trailing hex escalate to the full MAC, which cannot collide.
func TestHostnameSlugsTailCollision(t *testing.T) {
	got := HostnameSlugs(map[string]string{
		"aabbcc112233": "bpx",
		"ffeedd112233": "bpx",
	})
	if got["aabbcc112233"] != "bpx-aabbcc112233" || got["ffeedd112233"] != "bpx-ffeedd112233" {
		t.Errorf("shared-tail collision not escalated to full MAC: %v", got)
	}
}

// TestHostnameSlugsBareVsTaggedCollision: one device's bare slug ("foo-0001")
// must not collide with another device's tagged label ("foo" + "-0001"). The
// tagged label escalates to the full MAC so every output stays unique.
func TestHostnameSlugsBareVsTaggedCollision(t *testing.T) {
	got := HostnameSlugs(map[string]string{
		"001f80aa0001": "foo-0001", // slugifies to bare "foo-0001"
		"001f80bb0001": "foo",      // shares "foo" -> tagged, tail "0001"
		"001f80cc0003": "foo",      // shares "foo" -> forces tagging
	})
	seen := map[string]string{}
	for mac, label := range got {
		if label == "" {
			t.Errorf("%s got empty label", mac)
		}
		if other, dup := seen[label]; dup {
			t.Fatalf("duplicate label %q for %s and %s: %v", label, other, mac, got)
		}
		seen[label] = mac
	}
	if got["001f80aa0001"] != "foo-0001" {
		t.Errorf("bare-slug device should keep its name, got %q", got["001f80aa0001"])
	}
	if got["001f80bb0001"] != "foo-001f80bb0001" {
		t.Errorf("tagged label colliding with a bare slug should escalate to the full MAC, got %q", got["001f80bb0001"])
	}
}

// TestHostnameSlugsPermutationInvariant: the same MAC->name set produces the same
// labels regardless of insertion/iteration order (the map is walked in a
// randomized order, so this exercises real shuffles). #14's DNS zone builder
// relies on stable output.
func TestHostnameSlugsPermutationInvariant(t *testing.T) {
	base := map[string]string{
		"001f80aa0001": "foo-0001",
		"001f80bb0001": "foo",
		"001f80cc0003": "foo",
		"aabbcc112233": "bar",
		"ffeedd112233": "bar", // shared tail with the previous -> full-MAC escalation
		"001f80dd0009": "Stage Rack",
		"001f80ee000a": "", // slugifies to empty
	}
	want := HostnameSlugs(base)
	for range 50 {
		// Rebuild the map fresh each time so Go re-randomizes iteration order.
		shuffled := make(map[string]string, len(base))
		for k, v := range base {
			shuffled[k] = v
		}
		got := HostnameSlugs(shuffled)
		if len(got) != len(want) {
			t.Fatalf("size drift: %d vs %d", len(got), len(want))
		}
		for mac, label := range want {
			if got[mac] != label {
				t.Fatalf("order-dependent label for %s: %q vs %q", mac, label, got[mac])
			}
		}
	}
}

// TestTagSlugCapsLength: tagging an already-63-char slug trims the base so the
// result stays a valid DNS label.
func TestTagSlugCapsLength(t *testing.T) {
	long := strings.Repeat("a", 63)
	got := tagSlug(long, "001f80aa0001", hostnameTagLen)
	if len(got) > 63 {
		t.Errorf("tagged slug is %d chars, want <= 63", len(got))
	}
	if !strings.HasSuffix(got, "-0001") {
		t.Errorf("tag lost while capping: %q", got)
	}
}

// TestSanitizeLeaseHostnames covers the display funnel end-to-end on lease rows:
// raw names slugified, cross-device collisions tagged, same-device rows (one
// lease per VLAN) sharing one untagged label, and the MAC-less placeholder row
// slugified without a tag.
func TestSanitizeLeaseHostnames(t *testing.T) {
	rows := []views.LeaseRow{
		{HWAddress: "00:1f:80:aa:00:01", Hostname: "BPX 19666"},
		{HWAddress: "00:1f:80:bb:00:02", Hostname: "BPX 19666"},
		{HWAddress: "00:1f:80:cc:00:03", Hostname: "workstation."},
		{HWAddress: "00:1f:80:dd:00:04", Hostname: "Trunked Unit"},
		{HWAddress: "00:1f:80:dd:00:04", Hostname: "Trunked Unit"},
		{HWAddress: "-", Hostname: "Pinned Offline"},
		{HWAddress: "00:1f:80:ee:00:05", Hostname: ""},
	}
	sanitizeLeaseHostnames(rows)
	want := []string{"bpx-19666-0001", "bpx-19666-0002", "workstation", "trunked-unit", "trunked-unit", "pinned-offline", ""}
	for i, w := range want {
		if rows[i].Hostname != w {
			t.Errorf("row %d hostname = %q, want %q", i, rows[i].Hostname, w)
		}
	}
}

// TestMergePortRowsSanitizesHostnames proves the pinning rows go through the
// funnel: a raw pin hostname renders slugified, and two ports whose devices share
// a name stay distinguishable.
func TestMergePortRowsSanitizesHostnames(t *testing.T) {
	// Client-ids are 0x00 + a printable flex-id ("p1"/"p2"), the Option-82 form
	// decodePortIdentity accepts (see TestFlexIDRoundTrip).
	leases := []kea.ActiveLease{
		{ClientID: "007031", HWAddress: "00:1f:80:aa:00:01", IPAddress: "10.0.0.21", Hostname: "BPX 19666"},
		{ClientID: "007032", HWAddress: "00:1f:80:bb:00:02", IPAddress: "10.0.0.22", Hostname: "BPX 19666"},
	}
	rows := mergePortRows(nil, nil, leases, nil, 0, nil)
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	got := map[string]bool{rows[0].Hostname: true, rows[1].Hostname: true}
	if !got["bpx-19666-0001"] || !got["bpx-19666-0002"] {
		t.Errorf("port hostnames not funneled: %q / %q", rows[0].Hostname, rows[1].Hostname)
	}
}

// TestRestoreHostsSanitizes: a backup bundle exported before sanitization carries
// raw reservation hostnames; the restore insert slugifies them.
func TestRestoreHostsSanitizes(t *testing.T) {
	hosts := restoreHosts([]BackupHost{
		{Identifier: []byte{0, 0x1f, 0x80, 0xaa, 0, 1}, Hostname: "BPX 19666"},
		{Identifier: []byte{0, 0x1f, 0x80, 0xbb, 0, 2}, Hostname: "workstation."},
		{Identifier: []byte{0, 0x1f, 0x80, 0xcc, 0, 3}, Hostname: "already-clean"},
	})
	want := []string{"bpx-19666", "workstation", "already-clean"}
	for i, w := range want {
		if hosts[i].Hostname != w {
			t.Errorf("restored hostname %d = %q, want %q", i, hosts[i].Hostname, w)
		}
	}
}
