package web

import (
	"embed"
	"encoding/hex"
	"hash/fnv"
	"io/fs"
	"net/http"
	"strings"
)

// staticFS holds the offline-first client assets: the Datastar runtime, the
// Console style.css, and the self-hosted subset fonts. Everything is embedded at
// build time so the appliance never fetches anything from the network at runtime
// (offline-honest, per DESIGN.md §1). Genuine Lucide icon SVGs are embedded
// separately in the views package (see views/icons.go). favicon.svg (the Kea app
// icon) uses a parrot-head glyph by Lorc, game-icons.net, CC BY 3.0, recolored to
// brand green - attribution is retained in the SVG's leading comment.
//
//go:embed static/*
var staticFS embed.FS

// assetVersion is a short content hash of the embedded UI assets. It is appended
// to asset URLs (?v=) so a binary upgrade busts stale browser caches even though
// the URLs are otherwise stable and immutably cached - without it, a long
// immutable cache would pin an old style.css across upgrades.
var assetVersion = computeAssetVersion()

func computeAssetVersion() string {
	h := fnv.New64a()
	for _, f := range []string{"static/style.css", "static/datastar.js"} {
		if b, err := staticFS.ReadFile(f); err == nil {
			_, _ = h.Write(b)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// contentTypeFor returns the MIME type for a static asset by extension. Kept
// explicit (not mime.TypeByExtension) so the set is auditable and stable across
// platforms where the system MIME database may be absent (a bare Pi).
func contentTypeFor(path string) string {
	switch {
	case strings.HasSuffix(path, ".js"):
		return "application/javascript; charset=utf-8"
	case strings.HasSuffix(path, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(path, ".woff2"):
		return "font/woff2"
	case strings.HasSuffix(path, ".svg"):
		return "image/svg+xml"
	default:
		return "application/octet-stream"
	}
}

// handleStatic serves an embedded asset under static/. The path value {file...}
// captures the remainder after /static/ (including a fonts/ subpath). It rejects
// traversal and missing files with 404. Assets only change on a binary upgrade,
// so they carry a long cache lifetime.
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	rel := r.PathValue("file")
	// Defense in depth: fs.ValidPath rejects "", absolute, and ".." segments.
	if rel == "" || !fs.ValidPath(rel) {
		http.NotFound(w, r)
		return
	}
	data, err := staticFS.ReadFile("static/" + rel)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", contentTypeFor(rel))
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	_, _ = w.Write(data)
}
