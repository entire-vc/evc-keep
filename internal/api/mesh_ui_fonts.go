package api

import (
	"embed"
	"net/http"
	"path"
	"strings"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/reqid"
)

// The screen's fonts (Inter 400-700, JetBrains Mono 400; latin, latin-ext,
// cyrillic; OFL-1.1, see NOTICE) are built into the binary and served from
// the screen's own origin: the policy allows font-src 'self' and nothing else,
// so the screen never loads a font from Mesh or a CDN.
//
//go:embed meshui_fonts/*.woff2
var meshUIFontFiles embed.FS

// meshUIFonts maps a served name (inter-latin-400-normal.woff2) to its bytes.
// The set is closed: it is exactly the embedded files.
var meshUIFonts = func() map[string][]byte {
	entries, err := meshUIFontFiles.ReadDir("meshui_fonts")
	if err != nil {
		panic("api: embedded fonts: " + err.Error())
	}
	out := make(map[string][]byte, len(entries))
	for _, e := range entries {
		b, err := meshUIFontFiles.ReadFile(path.Join("meshui_fonts", e.Name()))
		if err != nil {
			panic("api: embedded font " + e.Name() + ": " + err.Error())
		}
		out[e.Name()] = b
	}
	return out
}()

// font serves GET /mesh/ui/fonts/{name}: no session (a font is public), only a
// built-in name; any other name is the same 404.
func (u *meshUI) font(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	b, ok := meshUIFonts[name]
	if !ok || !strings.HasSuffix(name, ".woff2") {
		writeError(w, http.StatusNotFound, apperr.ClassNotFound, "not found", reqid.FromContext(r.Context()))
		return
	}
	h := w.Header()
	h.Set("Content-Type", "font/woff2")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Cache-Control", "public, max-age=604800")
	_, _ = w.Write(b)
}
