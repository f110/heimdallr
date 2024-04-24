package generator

import (
	"bytes"
	"fmt"
	"go/format"
)

type Buffer struct {
	*bytes.Buffer
}

func newBuffer() *Buffer {
	return &Buffer{Buffer: new(bytes.Buffer)}
}

func (b *Buffer) Writef(format string, a ...interface{}) {
	b.Buffer.WriteString(fmt.Sprintf(format+"\n", a...))
}

func (b *Buffer) Write(s string) {
	b.Buffer.WriteString(s)
	b.LineBreak()
}

func (b *Buffer) LineBreak() {
	b.Buffer.WriteRune('\n')
}

func (b *Buffer) WriteFunc(funcs ...*goFunc) {
	for _, v := range funcs {
		if v == nil {
			continue
		}
		b.Write(v.String())
		b.LineBreak()
	}
}

func (b *Buffer) WriteInterface(funcs ...*goFunc) {
	for _, v := range funcs {
		b.Write(v.Interface())
	}
}

func (b *Buffer) GoFormat() ([]byte, error) {
	return format.Source(b.Buffer.Bytes())
}
