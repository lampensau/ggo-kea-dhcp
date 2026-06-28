package views

import (
	"bytes"
	"context"
	"embed"
	"io"

	"github.com/a-h/templ"
)

// iconFS embeds the curated set of genuine Lucide icons (lucide-static v1.18.0,
// ISC). They are chosen for the Console UI's needs - not inherited from the
// retired front-end - and rendered inline so they work natively inside SSE
// fragments (no client-side icon hydration). Size and color come from CSS via
// the .lucide class (each Lucide SVG carries class="lucide lucide-<name>").
//
//go:embed icons/*.svg
var iconFS embed.FS

// deviceIconFS holds the Green-GO device-profile silhouettes (extracted from the
// control software, normalized to currentColor). Rendered in the setup device
// grid so each class is recognizable at a glance.
//
//go:embed icons/devices/*.svg
var deviceIconFS embed.FS

// DeviceIcon renders a Green-GO device silhouette by class key (e.g. "bpx"),
// falling back to a Lucide icon of the same name for classes without a dedicated
// device icon (e.g. "radio-tower" for antennas). Renders nothing if neither exists.
func DeviceIcon(name string) templ.Component {
	return templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		b, err := deviceIconFS.ReadFile("icons/devices/" + name + ".svg")
		if err != nil {
			if b, err = iconFS.ReadFile("icons/" + name + ".svg"); err != nil {
				return nil
			}
		}
		return writeInlineSVG(w, b)
	})
}

// Icon renders a Lucide icon inline by name (e.g. Icon("server")). The SVG is a
// trusted embedded asset, so it is written verbatim from the <svg> tag onward
// (dropping the leading license comment). An unknown name renders nothing;
// TestIconSetComplete guards every name the UI references.
func Icon(name string) templ.Component {
	return templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		b, err := iconFS.ReadFile("icons/" + name + ".svg")
		if err != nil {
			return nil
		}
		return writeInlineSVG(w, b)
	})
}

// writeInlineSVG writes an embedded SVG from its <svg> tag onward, marking it
// decorative (aria-hidden / not focusable) - every interactive element that
// carries an icon has its own text or aria-label, so the glyph is never the
// accessible name. This keeps screen readers from announcing icon noise.
func writeInlineSVG(w io.Writer, b []byte) error {
	if i := bytes.Index(b, []byte("<svg")); i >= 0 {
		b = b[i:]
	}
	b = bytes.Replace(b, []byte("<svg"), []byte(`<svg aria-hidden="true" focusable="false"`), 1)
	_, err := w.Write(b)
	return err
}

// hasIcon reports whether an icon name is in the embedded set (used by tests).
func hasIcon(name string) bool {
	_, err := iconFS.ReadFile("icons/" + name + ".svg")
	return err == nil
}
