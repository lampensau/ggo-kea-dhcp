package views

import (
	"ggo-kea-dhcp/internal/kea"
)

// ClassMeta is the operator-facing presentation of a Kea client-class: the human
// label and the device-icon key (a Green-GO silhouette in icons/devices/, or a
// Lucide fallback resolved by DeviceIcon).
type ClassMeta struct {
	Label string
	Icon  string
}

// IconChoice is one option in the custom-pool icon picker.
type IconChoice struct {
	Key   string // icon name (resolved by DeviceIcon)
	Label string // accessible name / tooltip
}

// deviceIcons is the curated glyph set offered for a custom (non-Green-GO) pool -
// the pro-AV device categories, drawn from the embedded Lucide set. Green-GO pools
// keep their hardware silhouette and aren't editable.
func deviceIcons() []IconChoice {
	return []IconChoice{
		// Intercom / comms
		{"headset", "Intercom / headset"},
		{"mic", "Microphone"},
		// Audio
		{"sliders-vertical", "Console / desk"}, // vertical faders
		{"audio-waveform", "Audio device"},
		{"speaker", "Speaker"},
		// Lighting (no open lucide-style "moving head" glyph exists - drop a real
		// SVG into views/icons/ and add a row here if one is sourced later)
		{"lamp-ceiling", "Light / fixture"},
		// Video / RF
		{"video", "Camera / video"},
		{"radio-tower", "Antenna / RF"},
		// Network
		{"network", "Network switch"},
		{"router", "Router / AP"},
		{"route", "Gateway"},
		{"brick-wall", "Firewall"},
		// Control / compute
		{"joystick", "Controller"},
		{"server", "Server"},
		{"monitor", "PC / display"},
		{"smartphone", "Phone / tablet"},
		{"box", "Device"},
		{"cpu", "Generic"},
		{"circle-help", "Unknown"},
	}
}

// ClassMenuItem is one Green-GO device class offered in the greengo Add-pool menu.
type ClassMenuItem struct {
	Class string // Kea client-class name, e.g. "GGO-BPX"
	Label string // operator-facing name, e.g. "Beltpacks"
	Icon  string // device-silhouette key
	Codes string // hardware codes, e.g. "BPX / BP2"
}

// DeviceClassMenu lists the known Green-GO device classes (canonical order) for the
// Add-pool menu. Catch-alls (GGO-OTHERS/OTHERS) are intentionally excluded - they
// are auto-maintained and never added by hand.
func DeviceClassMenu() []ClassMenuItem {
	out := make([]ClassMenuItem, 0, len(kea.DeviceClasses))
	for _, dc := range kea.DeviceClasses {
		out = append(out, ClassMenuItem{Class: dc.Name, Label: dc.Label, Icon: dc.Icon, Codes: dc.Codes})
	}
	return out
}

// ClassDisplay maps a Kea client-class name (as produced by kea.ClassifyMAC and
// the elastic-pool generator) to its label + icon. These mirror the setup
// wizard's device grid (setup.templ) so the same hardware reads the same name
// in setup, the dashboard breakdown, the pool table, and the lease list. An
// unrecognized class falls back to its raw name with a generic chip icon.
func ClassDisplay(class string) ClassMeta {
	label, icon, _ := kea.ClassMetadata(class)
	return ClassMeta{Label: label, Icon: icon}
}
