package fsm

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"strings"

	"golang.org/x/xerrors"
)

type fsmStateFunc struct {
	Name      string
	NextState map[string]struct{}
}

type dotOutput struct {
	Struct     *ast.StructType
	FSMState   map[string]*fsmStateFunc
	FirstState string
	EndState   string
	Funcs      map[string]*ast.FuncDecl
}

func NewDotOutput(w io.Writer, dir string) error {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, nil, 0)
	if err != nil {
		return err
	}
	d := &dotOutput{
		FSMState: make(map[string]*fsmStateFunc),
		Funcs:    make(map[string]*ast.FuncDecl),
	}
	for _, pkg := range pkgs {
		for _, f := range pkg.Files {
			if err := d.walk(f); err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}
	}
	d.Output(w)

	return nil
}

func (d *dotOutput) walk(n ast.Node) error {
	ast.Inspect(n, d.walkFunc)

	d.analyzeFSMFunc()

	return nil
}

func (d *dotOutput) walkFunc(n ast.Node) bool {
	if n == nil {
		return true
	}

	switch node := n.(type) {
	case *ast.StructType:
		for _, v := range node.Fields.List {
			f, ok := v.Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			sel, ok := f.X.(*ast.SelectorExpr)
			if !ok {
				continue
			}
			if sel.X.(*ast.Ident).Name == "fsm" && sel.Sel.Name == "FSM" {
				d.Struct = node
			}
		}
	case *ast.FuncDecl:
		recv := ""
		if node.Recv != nil {
			if v, ok := node.Recv.List[0].Type.(*ast.StarExpr); ok {
				recv = v.X.(*ast.Ident).Name + "."
			}
			if v, ok := node.Recv.List[0].Type.(*ast.Ident); ok {
				recv = v.Name + "."
			}
		}
		d.Funcs[recv+node.Name.Name] = node
	case *ast.CallExpr:
		sel, ok := node.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name == "NewFSM" {
			d.listStates(node)
		}
	}

	return true
}

func (d *dotOutput) listStates(node *ast.CallExpr) {
	comp := node.Args[0].(*ast.CompositeLit)
	for _, v := range comp.Elts {
		kv := v.(*ast.KeyValueExpr)
		sel := kv.Value.(*ast.SelectorExpr)
		d.FSMState[kv.Key.(*ast.Ident).Name] = &fsmStateFunc{
			Name:      sel.Sel.Name,
			NextState: make(map[string]struct{}),
		}
	}

	d.FirstState = node.Args[1].(*ast.Ident).Name
	d.EndState = node.Args[2].(*ast.Ident).Name
}

func (d *dotOutput) analyzeFSMFunc() {
	for _, f := range d.FSMState {
		var funcBody *ast.FuncDecl
		for funcName, v := range d.Funcs {
			if strings.HasSuffix(funcName, f.Name) {
				funcBody = v
				break
			}
		}
		if funcBody == nil {
			continue
		}

		ast.Inspect(funcBody, func(n ast.Node) bool {
			if n == nil {
				return false
			}

			switch node := n.(type) {
			case *ast.ReturnStmt:
				if len(node.Results) == 2 {
					switch v := node.Results[0].(type) {
					case *ast.SelectorExpr:
						recv := ""
						if v, ok := v.X.(*ast.Ident); ok {
							recv = v.Name
						}
						f.NextState[recv+"."+v.Sel.Name] = struct{}{}
					case *ast.Ident:
						f.NextState[v.Name] = struct{}{}
					}
				}
			}
			return true
		})
	}
}

func (d *dotOutput) Output(w io.Writer) {
	fmt.Fprintln(w, "digraph dot {")
	fmt.Fprintf(w, "\t%q [shape = box];\n", "fsm.WaitState")
	fmt.Fprintf(w, "\t%q [shape = box];\n", "fsm.UnknownState")
	fmt.Fprintf(w, "\t%q [shape = box];\n", "fsm.CloseState")
	fmt.Fprintln(w, "")
	for state, f := range d.FSMState {
		for n, _ := range f.NextState {
			fmt.Fprintf(w, "\t%q -> %q;\n", state, n)
		}
	}
	fmt.Fprintf(w, "\t%q -> %q;\n", "fsm.UnknownState", d.EndState)
	fmt.Fprintf(w, "\t%q -> %q;\n", "fsm.WaitState", d.EndState)
	fmt.Fprintln(w, "}")
}
