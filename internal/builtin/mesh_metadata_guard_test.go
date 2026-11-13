package builtin

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// The metadata reader is narrow by construction: its SQL names two scalar
// expressions and no key material, and its body reaches no resolve, decrypt,
// fingerprint or write path. Each test below has a mutant in
// scripts/check-mesh-metadata-mutations.sh that must turn it red.

func TestMeshMetadataSQLIsScalarOnly(t *testing.T) {
	sql := strings.ToLower(meshMetadataSQL)
	for _, banned := range []string{"*", "wrapped_dek", "kek_id", "name,", " name ", "insert", "update", "delete", "for update"} {
		if strings.Contains(sql, banned) {
			t.Fatalf("metadata SQL names %q", banned)
		}
	}
	// ciphertext appears once, only inside octet_length().
	if strings.Count(sql, "ciphertext") != 1 || !strings.Contains(sql, "octet_length(ciphertext) - 28") {
		t.Fatal("metadata SQL must read ciphertext only as octet_length(ciphertext) - 28")
	}
	if !strings.HasPrefix(sql, "select version::text, octet_length(ciphertext) - 28 as length\nfrom keep_envelope") {
		t.Fatal("metadata SQL selects something other than version and length")
	}
	if !strings.Contains(sql, "status = 'active'") || !strings.Contains(sql, "order by version desc limit 1") {
		t.Fatal("metadata SQL is not the newest active version")
	}
	if gcmNonceAndTag != 28 {
		t.Fatal("the 28 in the metadata SQL is no longer the AES-GCM overhead")
	}
}

func TestMeshMetadataReaderReachesNoValuePath(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "mesh_metadata.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if x, ok := d.(*ast.FuncDecl); ok && x.Name.Name == "MetadataSecret" {
			fn = x
		}
	}
	if fn == nil {
		t.Fatal("MetadataSecret not found")
	}
	allowed := map[string]bool{"meshSecretPath": true, "QueryRow": true, "Scan": true, "Is": true, "meshVersionValid": true}
	calls := 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var name string
		switch fun := c.Fun.(type) {
		case *ast.Ident:
			name = fun.Name
		case *ast.SelectorExpr:
			name = fun.Sel.Name
		}
		calls++
		if !allowed[name] {
			t.Errorf("MetadataSecret calls %s: not on the metadata allow-list", name)
		}
		return true
	})
	if calls == 0 {
		t.Fatal("the allow-list walk saw no call; the check proves nothing")
	}
	for _, id := range collectIdents(fn.Body) {
		switch id {
		case "Provider", "Resolve", "Open", "Write", "FingerprintKey", "lookup", "latestActive", "Exec", "Query", "Begin", "Expose":
			t.Errorf("MetadataSecret mentions %s", id)
		}
	}
}

// The helpers of mesh_metadata.go may not touch storage either: the allow-list
// above lets MetadataSecret call them, so a query hidden in one would pass it.
func TestMeshMetadataHelpersTouchNoStorage(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "mesh_metadata.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name == "MetadataSecret" {
			continue
		}
		seen++
		for _, id := range collectIdents(fn) {
			switch id {
			case "pool", "local", "QueryRow", "Query", "Exec", "Begin", "Provider", "Resolve", "Open", "FingerprintKey", "Expose":
				t.Errorf("%s mentions %s", fn.Name.Name, id)
			}
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			if l, ok := n.(*ast.BasicLit); ok && l.Kind == token.STRING && strings.Contains(strings.ToLower(l.Value), "select") {
				t.Errorf("%s holds SQL text", fn.Name.Name)
			}
			return true
		})
	}
	if seen == 0 {
		t.Fatal("no helper found; the check proves nothing")
	}
}

func collectIdents(n ast.Node) []string {
	var out []string
	ast.Inspect(n, func(x ast.Node) bool {
		if id, ok := x.(*ast.Ident); ok {
			out = append(out, id.Name)
		}
		return true
	})
	return out
}

func TestMeshVersionValid(t *testing.T) {
	for v, want := range map[string]bool{"1": true, "9223372036854775807": true, "0": false, "01": false, "-1": false, "9223372036854775808": false, "": false, "1.0": false, "1e3": false} {
		if meshVersionValid(v) != want {
			t.Errorf("meshVersionValid(%q) != %v", v, want)
		}
	}
}
