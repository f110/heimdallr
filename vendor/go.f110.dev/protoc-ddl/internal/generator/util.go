package generator

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/pingcap/tidb/pkg/parser/ast"
	"github.com/pingcap/tidb/pkg/parser/opcode"
	"github.com/pingcap/tidb/pkg/parser/test_driver"
	"github.com/pingcap/tidb/pkg/parser/types"

	"go.f110.dev/protoc-ddl/internal/schema"
)

type ctxState int

const (
	binaryOperationState ctxState = iota + 1
	binaryOperationRightState
	fieldListState
	fieldListSubsequentState
	fromCauseState
	whereCauseState
)

type formatContext struct {
	state  ctxState
	opCode opcode.Op
}

type QueryFormatter struct {
	message *schema.Message

	node  ast.StmtNode
	text  *bytes.Buffer
	ctx   *formatContext
	debug bool
}

func NewQueryFormatter(m *schema.Message, s ast.StmtNode) *QueryFormatter {
	return &QueryFormatter{
		message: m,
		node:    s,
	}
}

func (f *QueryFormatter) Format(w io.Writer) {
	switch v := f.node.(type) {
	case *ast.SelectStmt:
		f.selectFormat(w, v)
	}
}

func (f *QueryFormatter) selectFormat(w io.Writer, stmt *ast.SelectStmt) {
	io.WriteString(w, "SELECT")
	if stmt.Distinct {
		w.Write([]byte(" DISTINCT"))
	}
	if stmt.Fields != nil {
		w.Write([]byte(" "))
		vis := newVisitor(fieldListState, f.message, w, f.debug)
		stmt.Fields.Accept(vis)
	}
	if stmt.From != nil {
		w.Write([]byte(" FROM "))
		vis := newVisitor(fromCauseState, f.message, w, f.debug)
		stmt.From.Accept(vis)
	}
	if stmt.Where != nil {
		w.Write([]byte(" WHERE "))
		vis := newVisitor(whereCauseState, f.message, w, f.debug)
		stmt.Where.Accept(vis)
	}
}

type queryFormatVisitor struct {
	message *schema.Message

	writer io.Writer
	ctx    *formatContext
	debug  bool
}

func newVisitor(st ctxState, m *schema.Message, w io.Writer, debug bool) *queryFormatVisitor {
	return &queryFormatVisitor{writer: w, message: m, ctx: &formatContext{state: st}, debug: debug}
}

func (a *queryFormatVisitor) Enter(in ast.Node) (node ast.Node, skipChildren bool) {
	if a.debug {
		log.Printf("IN %T", in)
	}

	switch v := in.(type) {
	case *ast.SelectField:
		if v.WildCard != nil {
			a.writer.Write([]byte("*"))
		}
	case *ast.TableName:
		if v.Name.String() == ":table_name:" && a.message != nil {
			a.writer.Write([]byte(fmt.Sprintf("`%s`", a.message.TableName)))
		} else {
			a.writer.Write([]byte(fmt.Sprintf("`%s`", v.Name.String())))
		}
	case *ast.BinaryOperationExpr:
		a.formatBinaryOperationExpr(v)
		return in, true
	case *ast.ColumnName:
		switch a.ctx.state {
		case fieldListState:
			a.writer.Write([]byte(fmt.Sprintf("`%s`", v.Name.String())))
			a.ctx.state = fieldListSubsequentState
		case fieldListSubsequentState:
			a.writer.Write([]byte(fmt.Sprintf(", `%s`", v.Name.String())))
		default:
			a.writer.Write([]byte(fmt.Sprintf("`%s`", v.Name.String())))
		}
	case *test_driver.ParamMarkerExpr:
		a.writer.Write([]byte("?"))
	case *test_driver.ValueExpr:
		switch v.Type.EvalType() {
		case types.ETInt:
			a.writer.Write([]byte(fmt.Sprintf("%d", v.GetInt64())))
		case types.ETString:
			a.writer.Write([]byte(fmt.Sprintf("%q", v.GetString())))
		}
	case *ast.FuncCallExpr:
		a.writer.Write([]byte(v.FnName.String()))
		a.writer.Write([]byte("("))
		a.writer.Write([]byte(")"))
	case *ast.IsNullExpr:
		a.formatIsNullExpr(v)
		return in, true
	case *ast.AggregateFuncExpr:
		a.writer.Write([]byte(strings.ToUpper(v.F)))
		a.writer.Write([]byte("("))
		if v.Distinct {
			a.writer.Write([]byte("distinct "))
		}
	default:
		if a.debug {
			log.Printf("Not supported: %T", v)
		}
	}

	return in, false
}

func (a *queryFormatVisitor) Leave(in ast.Node) (node ast.Node, ok bool) {
	if a.debug {
		log.Printf("OUT %T", in)
	}

	switch in.(type) {
	case *ast.BinaryOperationExpr:
		a.ctx.state = 0
	case *ast.AggregateFuncExpr:
		a.writer.Write([]byte(")"))
	}
	return in, true
}

func (a *queryFormatVisitor) formatBinaryOperationExpr(in *ast.BinaryOperationExpr) {
	switch v := in.L.(type) {
	case *ast.BinaryOperationExpr:
		a.formatBinaryOperationExpr(v)
	case *ast.ColumnNameExpr:
		v.Accept(a)
	case *test_driver.ValueExpr:
		v.Accept(a)
	default:
		log.Printf("%T", in.L)
	}

	a.writer.Write([]byte(" "))
	in.Op.Format(a.writer)
	a.writer.Write([]byte(" "))

	switch v := in.R.(type) {
	case *ast.BinaryOperationExpr:
		a.formatBinaryOperationExpr(v)
	case *test_driver.ParamMarkerExpr:
		v.Accept(a)
	case *test_driver.ValueExpr:
		v.Accept(a)
	default:
		log.Printf("%T", in.R)
	}
}

func (a *queryFormatVisitor) formatIsNullExpr(in *ast.IsNullExpr) {
	switch v := in.Expr.(type) {
	case *ast.ColumnNameExpr:
		v.Accept(a)
	}

	a.writer.Write([]byte(" IS"))
	if in.Not {
		a.writer.Write([]byte(" NOT"))
	}
	a.writer.Write([]byte(" NULL"))
}
