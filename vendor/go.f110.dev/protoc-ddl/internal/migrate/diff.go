package migrate

import (
	"bytes"
	"fmt"
	"reflect"
	"sort"

	mapset "github.com/deckarep/golang-set"
	"github.com/pkg/errors"
	"github.com/schemalex/schemalex"
	"github.com/schemalex/schemalex/format"
	"github.com/schemalex/schemalex/model"
	"golang.org/x/xerrors"
)

type Diff struct {
	fromStatement model.Stmts
	toStatement   model.Stmts

	index   int
	queries []string
}

func NewDiff(from schemalex.SchemaSource, to string) (*Diff, error) {
	buf := new(bytes.Buffer)
	if err := from.WriteSchema(buf); err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	parser := schemalex.New()
	fromStatement, err := parser.Parse(buf.Bytes())
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	toStatement, err := parser.ParseString(to)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	d := &Diff{fromStatement: fromStatement, toStatement: toStatement, index: -1}
	if err := d.parse(); err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return d, nil
}

func (d *Diff) Next() bool {
	if d.index+1 < len(d.queries) {
		d.index++
		return true
	}

	return false
}

func (d *Diff) Query() string {
	return d.queries[d.index]
}

func (d *Diff) parse() error {
	fromSet := mapset.NewSet()
	for _, stmt := range d.fromStatement {
		if cs, ok := stmt.(model.Table); ok {
			if cs.Name() == SchemaVersionTable.TableName {
				continue
			}
			fromSet.Add(cs.ID())
		}
	}
	toSet := mapset.NewSet()
	for _, stmt := range d.toStatement {
		if cs, ok := stmt.(model.Table); ok {
			toSet.Add(cs.ID())
		}
	}

	if err := d.dropTable(fromSet, toSet); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if err := d.createTable(fromSet, toSet); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if err := d.alterTable(fromSet, toSet); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (d *Diff) addQuery(query string) {
	d.queries = append(d.queries, query)
}

func (d *Diff) dropTable(fromSet, toSet mapset.Set) error {
	var buf bytes.Buffer
	ids := fromSet.Difference(toSet)
	for i, id := range ids.ToSlice() {
		if i > 0 {
			buf.WriteByte('\n')
		}

		stmt, ok := d.fromStatement.Lookup(id.(string))
		if !ok {
			return xerrors.Errorf("%s not found from source", id.(string))
		}

		table, ok := stmt.(model.Table)
		if !ok {
			return xerrors.Errorf("%s not found from target", id.(string))
		}
		d.addQuery(fmt.Sprintf("DROP TABLE `%s`", table.Name()))
	}

	return nil
}

func (d *Diff) createTable(fromSet, toSet mapset.Set) error {
	ids := toSet.Difference(fromSet)
	buf := new(bytes.Buffer)
	for _, id := range ids.ToSlice() {
		stmt, ok := d.toStatement.Lookup(id.(string))
		if !ok {
			return xerrors.Errorf("%s not found from target", id.(string))
		}

		if err := format.SQL(buf, stmt); err != nil {
			return xerrors.Errorf(": %w", err)
		}
		d.addQuery(buf.String())
		buf.Reset()
	}

	return nil
}

func (d *Diff) alterTable(fromSet, toSet mapset.Set) error {
	ids := toSet.Intersect(fromSet)
	for _, id := range ids.ToSlice() {
		var stmt model.Stmt
		var ok bool

		stmt, ok = d.fromStatement.Lookup(id.(string))
		if !ok {
			return xerrors.Errorf("%s not found from source", id.(string))
		}
		beforeStmt := stmt.(model.Table)

		stmt, ok = d.toStatement.Lookup(id.(string))
		if !ok {
			return xerrors.Errorf("%s not found from target", id.(string))
		}
		afterStmt := stmt.(model.Table)

		fromColumns := mapset.NewSet()
		for col := range beforeStmt.Columns() {
			fromColumns.Add(col.ID())
		}

		toColumns := mapset.NewSet()
		for col := range afterStmt.Columns() {
			toColumns.Add(col.ID())
		}

		fromIndexes := mapset.NewSet()
		for idx := range beforeStmt.Indexes() {
			fromIndexes.Add(idx.ID())
		}

		toIndexes := mapset.NewSet()
		for idx := range afterStmt.Indexes() {
			toIndexes.Add(idx.ID())
		}

		if err := d.dropTableIndexes(beforeStmt, afterStmt, fromIndexes, toIndexes); err != nil {
			return xerrors.Errorf(": %w", err)
		}
		if err := d.dropTableColumns(beforeStmt, fromColumns, toColumns); err != nil {
			return xerrors.Errorf(": %w", err)
		}
		if err := d.addTableColumns(beforeStmt, afterStmt, fromColumns, toColumns); err != nil {
			return xerrors.Errorf(": %w", err)
		}
		if err := d.alterTableColumns(beforeStmt, afterStmt, fromColumns, toColumns); err != nil {
			return xerrors.Errorf(": %w", err)
		}
		if err := d.addTableIndexes(beforeStmt, afterStmt, fromIndexes, toIndexes); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func (d *Diff) dropTableIndexes(before, after model.Table, fromIndexes, toIndexes mapset.Set) error {
	indexes := fromIndexes.Difference(toIndexes)
	lazy := make([]model.Index, 0, indexes.Cardinality())
	for _, index := range indexes.ToSlice() {
		indexStmt, ok := before.LookupIndex(index.(string))
		if !ok {
			return xerrors.Errorf("%s not found from source", index.(string))
		}

		if indexStmt.IsPrimaryKey() {
			d.addQuery(fmt.Sprintf("ALTER TABLE `%s` DROP PRIMARY KEY", before.Name()))
			continue
		}

		if !indexStmt.HasName() && !indexStmt.HasSymbol() {
			return xerrors.Errorf("can not drop index without name: %s", indexStmt.ID())
		}
		if !indexStmt.IsForeignKey() {
			lazy = append(lazy, indexStmt)
			continue
		}

		var name string
		if indexStmt.HasSymbol() {
			name = indexStmt.Symbol()
		} else {
			name = indexStmt.Name()
		}
		d.addQuery(fmt.Sprintf("ALTER TABLE `%s` DROP FOREIGN KEY `%s`", before.Name(), name))
	}

	for _, indexStmt := range lazy {
		var name string
		if !indexStmt.HasName() {
			name = indexStmt.Symbol()
		} else {
			name = indexStmt.Name()
		}
		d.addQuery(fmt.Sprintf("ALTER TABLE `%s` DROP INDEX `%s`", before.Name(), name))
	}

	return nil
}

func (d *Diff) dropTableColumns(before model.Table, fromColumns, toColumns mapset.Set) error {
	columnNames := fromColumns.Difference(toColumns)

	for _, columnName := range columnNames.ToSlice() {
		col, ok := before.LookupColumn(columnName.(string))
		if !ok {
			return xerrors.Errorf(`failed to lookup column %s`, columnName)
		}

		d.addQuery(fmt.Sprintf("ALTER TABLE `%s` DROP COLUMN `%s`", before.Name(), col.Name()))
	}

	return nil
}

func (d *Diff) addTableColumns(before, after model.Table, fromColumns, toColumns mapset.Set) error {
	beforeToNext := make(map[string]string)
	nextToBefore := make(map[string]string)

	var firstColumn model.TableColumn
	for _, v := range toColumns.Difference(fromColumns).ToSlice() {
		columnName := v.(string)
		col, ok := after.LookupColumn(columnName)
		if !ok {
			return xerrors.Errorf(`failed to lookup column %s`, columnName)
		}

		beforeCol, hasBeforeCol := after.LookupColumnBefore(col.ID())
		if !hasBeforeCol {
			firstColumn = col
			continue
		}

		beforeToNext[beforeCol.ID()] = columnName
		nextToBefore[columnName] = beforeCol.ID()
	}

	if firstColumn != nil {
		if err := d.writeAddColumnQuery(before, after, firstColumn.ID()); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	var columnNames []string
	for _, v := range toColumns.Intersect(fromColumns).ToSlice() {
		columnName := v.(string)
		if nextColumnName, ok := beforeToNext[columnName]; ok {
			delete(beforeToNext, columnName)
			delete(nextToBefore, nextColumnName)
			columnNames = append(columnNames, nextColumnName)
		}
	}

	if len(columnNames) > 0 {
		sort.Strings(columnNames)
		if err := d.writeAddColumnQuery(before, after, columnNames...); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	columnNames = columnNames[:0]
	for _, nextCol := range beforeToNext {
		columnNames = append(columnNames, nextCol)
	}
	if len(columnNames) > 0 {
		sort.Slice(columnNames, func(i, j int) bool {
			icol, _ := after.LookupColumnOrder(columnNames[i])
			jcol, _ := after.LookupColumnOrder(columnNames[j])
			return icol < jcol
		})
		if err := d.writeAddColumnQuery(before, after, columnNames...); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func (d *Diff) writeAddColumnQuery(before, after model.Table, columnNames ...string) error {
	buf := new(bytes.Buffer)
	for _, columnName := range columnNames {
		stmt, ok := after.LookupColumn(columnName)
		if !ok {
			return errors.Errorf(`failed to lookup column %s`, columnName)
		}

		beforeCol, hasBeforeCol := after.LookupColumnBefore(stmt.ID())
		buf.WriteString("ALTER TABLE `")
		buf.WriteString(before.Name())
		buf.WriteString("` ADD COLUMN ")
		if err := format.SQL(buf, stmt); err != nil {
			return err
		}

		if hasBeforeCol {
			buf.WriteString(" AFTER `")
			buf.WriteString(beforeCol.Name())
			buf.WriteString("`")
		} else {
			buf.WriteString(" FIRST")
		}

		d.addQuery(buf.String())
		buf.Reset()
	}
	return nil
}

func (d *Diff) alterTableColumns(before, after model.Table, fromColumns, toColumns mapset.Set) error {
	buf := new(bytes.Buffer)
	columnNames := toColumns.Intersect(fromColumns)
	for _, columnName := range columnNames.ToSlice() {
		beforeColumnStmt, ok := before.LookupColumn(columnName.(string))
		if !ok {
			return xerrors.Errorf(`column %s not found in old schema`, columnName)
		}

		afterColumnStmt, ok := after.LookupColumn(columnName.(string))
		if !ok {
			return xerrors.Errorf(`column %s not found in new schema`, columnName)
		}

		if reflect.DeepEqual(beforeColumnStmt, afterColumnStmt) {
			continue
		}
		if err := format.SQL(buf, afterColumnStmt); err != nil {
			return xerrors.Errorf(": %w", err)
		}

		d.addQuery(fmt.Sprintf("ALTER TABLE `%s` CHANGE COLUMN `%s` %s", before.Name(), afterColumnStmt.Name(), buf.String()))
		buf.Reset()
	}

	return nil
}

func (d *Diff) addTableIndexes(before, after model.Table, fromIndexes, toIndexes mapset.Set) error {
	buf := new(bytes.Buffer)
	indexes := toIndexes.Difference(fromIndexes)
	lazy := make([]model.Index, 0, indexes.Cardinality())
	for _, index := range indexes.ToSlice() {
		indexStmt, ok := after.LookupIndex(index.(string))
		if !ok {
			return xerrors.Errorf(`index '%s' not found in old schema (add index)`, index)
		}
		if indexStmt.IsForeignKey() {
			lazy = append(lazy, indexStmt)
			continue
		}

		if err := format.SQL(buf, indexStmt); err != nil {
			return xerrors.Errorf(": %w", err)
		}

		d.addQuery(fmt.Sprintf("ALTER TABLE `%s` ADD %s", before.Name(), buf.String()))
		buf.Reset()
	}

	for _, indexStmt := range lazy {
		if err := format.SQL(buf, indexStmt); err != nil {
			return xerrors.Errorf(": %w", err)
		}

		d.addQuery(fmt.Sprintf("ALTER TABGLE `%s` ADD %s", before.Name(), buf.String()))
		buf.Reset()
	}

	return nil
}
