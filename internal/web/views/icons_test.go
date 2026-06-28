package views

import (
	"context"
	"strings"
	"testing"
)

// TestIconSetCoversShell asserts every icon the shell references is present in
// the embedded curated set (so no nav/theme icon silently renders empty).
func TestIconSetCoversShell(t *testing.T) {
	needed := []string{"log-out", "monitor", "sun", "moon"}
	for _, st := range []string{"ACTIVE", "ONBOARDING"} {
		for _, l := range navLinksFor(st) {
			needed = append(needed, l.Icon)
		}
	}
	for _, name := range needed {
		if !hasIcon(name) {
			t.Errorf("required icon %q missing from views/icons/", name)
		}
	}
}

// TestIconPickerGlyphsExist asserts every glyph offered in the custom-pool icon
// picker resolves to a real embedded SVG (so the picker never shows a blank).
func TestIconPickerGlyphsExist(t *testing.T) {
	for _, ic := range deviceIcons() {
		var sb strings.Builder
		if err := DeviceIcon(ic.Key).Render(context.Background(), &sb); err != nil {
			t.Fatalf("DeviceIcon(%q): %v", ic.Key, err)
		}
		if !strings.Contains(sb.String(), "<svg") {
			t.Errorf("icon-picker glyph %q (%s) renders empty - missing from views/icons/", ic.Key, ic.Label)
		}
	}
}

// TestIconRendersGenuineLucide verifies Icon emits a real Lucide SVG (lucide
// class marker) and strips the license comment.
func TestIconRendersGenuineLucide(t *testing.T) {
	var sb strings.Builder
	if err := Icon("server").Render(context.Background(), &sb); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	if !strings.HasPrefix(strings.TrimSpace(out), "<svg") {
		t.Errorf("icon should start at <svg, got: %.40q", out)
	}
	if !strings.Contains(out, "lucide-server") {
		t.Error("icon should carry the genuine Lucide class (lucide-server)")
	}
	if strings.Contains(out, "@license") {
		t.Error("license comment should be stripped")
	}
}

// TestDeviceIcons renders every device icon the setup grid references and checks
// the SVG is structurally intact (has a viewBox and shapes) - a guard against a
// transform collapsing/mangling them. Device classes without a dedicated icon
// fall back to a Lucide icon of the given name.
func TestDeviceIcons(t *testing.T) {
	device := []string{"bpx", "mcx", "wpx", "interface", "bridge", "beacon", "mcd"}
	for _, name := range device {
		var sb strings.Builder
		if err := DeviceIcon(name).Render(context.Background(), &sb); err != nil {
			t.Fatalf("DeviceIcon(%q): %v", name, err)
		}
		out := sb.String()
		if !strings.Contains(out, "<svg") || !strings.Contains(out, "viewBox") {
			t.Errorf("device icon %q is not a valid svg: %.60q", name, out)
		}
		if !strings.Contains(out, `fill="currentColor"`) {
			t.Errorf("device icon %q must use currentColor to theme", name)
		}
		if strings.Contains(out, "<style") || strings.Contains(out, `class="st`) {
			t.Errorf("device icon %q has leftover style/class that breaks currentColor", name)
		}
	}
	// Lucide fallbacks the grid uses for classes without a device icon.
	for _, name := range []string{"radio-tower", "wifi", "cpu"} {
		var sb strings.Builder
		_ = DeviceIcon(name).Render(context.Background(), &sb)
		if !strings.Contains(sb.String(), "lucide-"+name) {
			t.Errorf("device-icon fallback %q did not resolve to the Lucide icon", name)
		}
	}
}

// TestUnknownIconRendersNothing keeps a typo from emitting broken markup.
func TestUnknownIconRendersNothing(t *testing.T) {
	var sb strings.Builder
	if err := Icon("definitely-not-an-icon").Render(context.Background(), &sb); err != nil {
		t.Fatal(err)
	}
	if sb.Len() != 0 {
		t.Errorf("unknown icon should render nothing, got %q", sb.String())
	}
}
