package apperr

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestClassesListsEveryClassConstant: a Class constant added to apperr.go
// but not to Classes() would make clients print it as "(unexpected value)".
func TestClassesListsEveryClassConstant(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "apperr.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	declared := 0
	listed := map[string]bool{}
	for _, c := range Classes() {
		listed[string(c)] = true
	}
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || len(vs.Names) != 1 || vs.Type == nil || len(vs.Values) != 1 {
			return true
		}
		if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != "Class" {
			return true
		}
		lit := vs.Values[0].(*ast.BasicLit)
		declared++
		if !listed[lit.Value[1:len(lit.Value)-1]] {
			t.Errorf("%s = %s is not in Classes()", vs.Names[0].Name, lit.Value)
		}
		return true
	})
	if declared != len(Classes()) {
		t.Fatalf("declared %d Class constants, Classes() lists %d", declared, len(Classes()))
	}
}
