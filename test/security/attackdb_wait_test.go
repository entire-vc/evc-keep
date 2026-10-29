package security

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// callOf reports whether stmt is a bare statement calling pkg.name.
func callOf(stmt ast.Stmt, pkg, name string) bool {
	es, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := es.X.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg
}

// opensPool reports whether stmt assigns the result of pgxpool.New.
func opensPool(stmt ast.Stmt) bool {
	as, ok := stmt.(*ast.AssignStmt)
	if !ok || len(as.Rhs) != 1 {
		return false
	}
	call, ok := as.Rhs[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "New" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "pgxpool"
}

// attackDB must wait for the test database before it opens a pool: a service
// that answers late otherwise fails the first attack test with a deadline. The
// wait must be a direct statement of the function body (not behind a branch)
// and come before the pool is opened.
func TestAttackDBWaitsForTheDatabase(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "identity_attack_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "attackDB" {
			continue
		}
		wait, open := -1, -1
		for i, stmt := range fn.Body.List {
			if wait < 0 && callOf(stmt, "pgscratch", "WaitReady") {
				wait = i
			}
			if open < 0 && opensPool(stmt) {
				open = i
			}
		}
		switch {
		case wait < 0:
			t.Fatal("attackDB does not call pgscratch.WaitReady as a direct statement")
		case open < 0:
			t.Fatal("attackDB does not open its pool with pgxpool.New directly")
		case wait > open:
			t.Fatal("attackDB opens the pool before it waits for the database")
		}
		return
	}
	t.Fatal("attackDB not found")
}
