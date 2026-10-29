// Package intakeweb serves immutable, embedded input-page assets.
package intakeweb

import (
	"crypto/sha512"
	_ "embed"
	"encoding/base64"
	"html/template"
	"io"
	"strings"
)

//go:embed hpke.js
var hpke string

//go:embed app.js
var app string

//go:embed style.css
var style string

//go:embed page.html
var page string

var script = "(async()=>{\n" + strings.ReplaceAll(hpke, "export ", "") + "\n" + app + "\n})();"
var integrity = assetHash(script)
var policy = "default-src 'none'; script-src '" + integrity + "'; style-src '" + assetHash(style) + "'; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'"
var tmpl = template.Must(template.New("input").Funcs(template.FuncMap{"metadataText": metadataText}).Parse(page))

// Escape first, then preserve CR through HTML parser newline conversion.
// Only character references are added; metadata can never introduce markup.
func metadataText(text string) template.HTML {
	return template.HTML(strings.ReplaceAll(template.HTMLEscapeString(text), "\r", "&#13;")) // #nosec G203 -- text is fully HTML-escaped before adding a fixed character reference
}

func assetHash(asset string) string {
	sum := sha512.Sum384([]byte(asset))
	return "sha384-" + base64.StdEncoding.EncodeToString(sum[:])
}

// Script returns the exact bytes covered by SRI and CSP.
func Script() string { return script }

// CSP allows only the embedded assets and same-origin ciphertext delivery.
func CSP() string { return policy }

// Page is the closed set of metadata shown to the capability holder.
// It has no value, provider locator, token, or private key field.
type Page struct {
	RequestID, SecretName, Scope, StoreName, Class, RequestedBy, Sponsor string
	PublicKey, SigningKey, Signature                                     string
}

func Render(w io.Writer, p Page) error {
	return tmpl.Execute(w, struct {
		Page
		Integrity string
		Style     template.CSS
	}{p, integrity, template.CSS(style)}) // #nosec G203 -- immutable embedded stylesheet, never request data
}
