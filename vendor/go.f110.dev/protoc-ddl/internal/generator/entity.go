package generator

import (
	"bufio"
	"bytes"
	"fmt"
	"go/format"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/golang/protobuf/protoc-gen-go/descriptor"

	"go.f110.dev/protoc-ddl/internal/schema"
)

const GoEntityGeneratorVersion = "v0.1"

type GoEntityGenerator struct{}

var (
	GoDataTypeMap = map[string]string{
		"TYPE_FLOAT":         "float32",
		"TYPE_DOUBLE":        "float64",
		"TYPE_INT32":         "int32",
		"TYPE_INT64":         "int64",
		"TYPE_UINT32":        "uint32",
		"TYPE_UINT64":        "uint64",
		"TYPE_SINT32":        "int",
		"TYPE_SINT64":        "int64",
		"TYPE_FIXED32":       "uint32",
		"TYPE_FIXED64":       "uint64",
		"TYPE_SFIXED32":      "int",
		"TYPE_SFIXED64":      "int64",
		"TYPE_BOOL":          "bool",
		"TYPE_BYTES":         "[]byte",
		"TYPE_STRING":        "string",
		schema.TimestampType: "time.Time",
	}
)

var importPackages = []string{"time", "bytes", "sync"}
var thirdPartyPackages = []string{"go.f110.dev/protoc-ddl"}

func (GoEntityGenerator) Generate(buf *bytes.Buffer, fileOpt *descriptor.FileOptions, messages *schema.Messages) {
	src := new(bytes.Buffer)

	packageName := fileOpt.GetGoPackage()
	if strings.Contains(packageName, ";") {
		s := strings.SplitN(packageName, ";", 2)
		packageName = s[1]
	} else {
		packageName = filepath.Base(packageName)
	}
	src.WriteString(fmt.Sprintf("package %s\n", packageName))
	src.WriteString("import (\n")
	for _, v := range importPackages {
		src.WriteString("\"" + v + "\"\n")
	}
	src.WriteRune('\n')
	for _, v := range thirdPartyPackages {
		src.WriteString("\"" + v + "\"\n")
	}
	src.WriteString(")\n")
	src.WriteString("var _ = time.Time{}\n")
	src.WriteString("var _ = bytes.Buffer{}\n")
	src.WriteRune('\n')
	src.WriteString("type Column struct {\n")
	src.WriteString("Name string\n")
	src.WriteString("Value interface{}\n")
	src.WriteString("}\n")
	src.WriteRune('\n')

	messages.Each(func(m *schema.Message) {
		src.WriteString(fmt.Sprintf("type %s struct {\n", m.Descriptor.GetName()))
		m.Fields.Each(func(f *schema.Field) {
			null := ""
			if f.Null {
				null = "*"
			}
			src.WriteString(fmt.Sprintf("%s %s%s\n", schema.ToCamel(f.Name), null, GoDataTypeMap[f.Type]))
		})
		src.WriteRune('\n')
		for _, v := range m.Descriptor.Field {
			if v.GetType() == descriptor.FieldDescriptorProto_TYPE_MESSAGE && v.GetTypeName() != schema.TimestampType {
				s := strings.Split(v.GetTypeName(), ".")
				src.WriteString(fmt.Sprintf("%s *%s\n", schema.ToCamel(v.GetName()), s[len(s)-1]))
			}
		}
		src.WriteString("\n")
		src.WriteString("mu sync.Mutex\n")
		src.WriteString(fmt.Sprintf("mark *%s\n", m.Descriptor.GetName()))
		src.WriteString("}\n\n")

		// ResetMark()
		src.WriteString(fmt.Sprintf("func (e *%s) ResetMark() {\n", m.Descriptor.GetName()))
		src.WriteString("e.mu.Lock()\n")
		src.WriteString("defer e.mu.Unlock()\n")
		src.WriteRune('\n')
		src.WriteString("e.mark = e.Copy()\n")
		src.WriteString("}\n\n")

		// IsChanged() bool
		src.WriteString(fmt.Sprintf("func (e *%s) IsChanged() bool {\n", m.Descriptor.GetName()))
		expr := make([]string, 0)
		m.Fields.Each(func(f *schema.Field) {
			if m.IsPrimaryKey(f) {
				return
			}

			fieldName := schema.ToCamel(f.Name)
			switch f.Type {
			case "TYPE_BYTES":
				expr = append(expr, fmt.Sprintf("!bytes.Equal(e.%s, e.mark.%s)", schema.ToCamel(f.Name), schema.ToCamel(f.Name)))
			case schema.TimestampType:
				if f.Null {
					expr = append(expr,
						fmt.Sprintf("((e.%s != nil && (e.mark.%s == nil || !e.%s.Equal(*e.mark.%s))) || (e.%s == nil && e.mark.%s != nil))",
							fieldName, fieldName, fieldName, fieldName, fieldName, fieldName),
					)
				} else {
					expr = append(expr, fmt.Sprintf("!e.%s.Equal(e.mark.%s)", fieldName, fieldName))
				}
			default:
				if f.Null {
					expr = append(expr, fmt.Sprintf("((e.%s != nil && (e.mark.%s == nil || *e.%s != *e.mark.%s)) || e.%s == nil && e.mark.%s != nil)",
						fieldName, fieldName, fieldName, fieldName, fieldName, fieldName),
					)
				} else {
					expr = append(expr, fmt.Sprintf("e.%s != e.mark.%s", fieldName, fieldName))
				}
			}
		})
		src.WriteString("e.mu.Lock()\n")
		src.WriteString("defer e.mu.Unlock()\n")
		src.WriteRune('\n')
		if len(expr) > 0 {
			src.WriteString(fmt.Sprintf("return %s\n", strings.Join(expr, " || \n")))
		} else {
			src.WriteString("return false\n")
		}
		src.WriteString("}\n\n")

		// ChangedColumn() []ddl.Column
		src.WriteString(fmt.Sprintf("func (e *%s) ChangedColumn() []ddl.Column {\n", m.Descriptor.GetName()))
		src.WriteString("e.mu.Lock()\n")
		src.WriteString("defer e.mu.Unlock()\n")
		src.WriteRune('\n')
		src.WriteString("res := make([]ddl.Column, 0)\n")
		m.Fields.Each(func(f *schema.Field) {
			if m.IsPrimaryKey(f) {
				return
			}
			fieldName := schema.ToCamel(f.Name)
			columnName := schema.ToSnake(f.Name)

			var addToRes string
			if f.Null {
				addToRes = fmt.Sprintf("if e.%s != nil {\n"+
					"res = append(res, ddl.Column{Name:\"%s\",Value:*e.%s})\n"+
					"} else {\n"+
					"res = append(res, ddl.Column{Name:\"%s\",Value:nil})\n"+
					"}\n",
					fieldName, columnName, fieldName, columnName,
				)
			} else {
				addToRes = fmt.Sprintf("res = append(res, ddl.Column{Name:\"%s\",Value:e.%s})\n", columnName, fieldName)
			}

			switch f.Type {
			case "TYPE_BYTES":
				src.WriteString(fmt.Sprintf("if !bytes.Equal(e.%s, e.mark.%s) {\n", fieldName, fieldName))
				src.WriteString(addToRes)
				src.WriteString("}\n")
			case schema.TimestampType:
				if f.Null {
					src.WriteString(fmt.Sprintf(
						"if (e.%s != nil && (e.mark.%s == nil || !e.%s.Equal(*e.mark.%s))) || (e.%s == nil && e.mark.%s != nil) {\n",
						fieldName, fieldName, fieldName, fieldName, fieldName, fieldName,
					))
					src.WriteString(addToRes)
					src.WriteString("}\n")
				} else {
					src.WriteString(fmt.Sprintf("if !e.%s.Equal(e.mark.%s) {\n", fieldName, fieldName))
					src.WriteString(addToRes)
					src.WriteString("}\n")
				}
			default:
				if f.Null {
					src.WriteString(fmt.Sprintf(
						"if (e.%s != nil && (e.mark.%s == nil || *e.%s != *e.mark.%s)) || (e.%s == nil && e.mark.%s != nil) {\n",
						fieldName, fieldName, fieldName, fieldName, fieldName, fieldName,
					))
					src.WriteString(addToRes)
					src.WriteString("}\n")
				} else {
					src.WriteString(fmt.Sprintf("if e.%s != e.mark.%s {\n", fieldName, fieldName))
					src.WriteString(addToRes)
					src.WriteString("}\n")
				}
			}
		})
		src.WriteRune('\n')
		src.WriteString("return res\n")
		src.WriteString("}\n")
		src.WriteRune('\n')

		// Copy() *Entity
		src.WriteString(fmt.Sprintf("func (e *%s) Copy() *%s {\n", m.Descriptor.GetName(), m.Descriptor.GetName()))
		src.WriteString(fmt.Sprintf("n := &%s{\n", m.Descriptor.GetName()))
		m.Fields.Each(func(f *schema.Field) {
			if f.Null {
				return
			}
			src.WriteString(fmt.Sprintf("%s: e.%s,\n", schema.ToCamel(f.Name), schema.ToCamel(f.Name)))
		})
		src.WriteString("}\n")
		m.Fields.Each(func(f *schema.Field) {
			if !f.Null {
				return
			}
			src.WriteString(fmt.Sprintf("if e.%s != nil {\n", schema.ToCamel(f.Name)))
			src.WriteString(fmt.Sprintf("v := *e.%s\n", schema.ToCamel(f.Name)))
			src.WriteString(fmt.Sprintf("n.%s = &v\n", schema.ToCamel(f.Name)))
			src.WriteString("}\n")
		})
		src.WriteRune('\n')
		rel := make([]*schema.Field, 0)
		for f := range m.Relations {
			if f.Virtual {
				continue
			}
			rel = append(rel, f)
		}
		sort.Slice(rel, func(i, j int) bool {
			return rel[i].Name < rel[j].Name
		})
		for _, f := range rel {
			src.WriteString(fmt.Sprintf("if e.%s != nil {\n", schema.ToCamel(f.Name)))
			src.WriteString(fmt.Sprintf("n.%s = e.%s.Copy()\n", schema.ToCamel(f.Name), schema.ToCamel(f.Name)))
			src.WriteString("}\n")
		}
		src.WriteRune('\n')
		src.WriteString("return n\n")
		src.WriteString("}\n")
	})

	buf.WriteString("// Generated by protoc-ddl.\n")
	buf.WriteString(fmt.Sprintf("// protoc-gen-entity: %s\n", GoEntityGeneratorVersion))
	b, err := format.Source(src.Bytes())
	if err != nil {
		r := bufio.NewScanner(strings.NewReader(src.String()))
		line := 1
		for r.Scan() {
			fmt.Fprintf(os.Stderr, "%d: %s\n", line, r.Text())
			line++
		}
		log.Print(err)
		return
	}
	buf.Write(b)
}
