package intakeweb

import (
	"bytes"
	"html"
	"strings"
	"testing"
)

func TestRenderMetadataPreservesCRAndEscapesMarkup(t *testing.T) {
	text := "name<&\r\nnext"
	var output bytes.Buffer
	if err := Render(&output, Page{SecretName: text, Scope: text, StoreName: text, Class: text, RequestedBy: text, Sponsor: text}); err != nil {
		t.Fatal("render metadata")
	}
	escaped := strings.ReplaceAll(html.EscapeString(text), "\r", "&#13;")
	if strings.Contains(output.String(), "\r") || strings.Count(output.String(), ">"+escaped+"<") != 6 {
		t.Fatal("visible metadata did not preserve CR through escaped text")
	}
}
