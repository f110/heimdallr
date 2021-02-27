package btesting

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"
)

type graphvizFormatter struct {
	child []*node
	seq   int
}

func newGraphvizFormatter(child []*node) *graphvizFormatter {
	return &graphvizFormatter{child: child}
}

func (f *graphvizFormatter) Out(name string) error {
	st := newStack()
	for i := len(f.child) - 1; i >= 0; i-- {
		st.push(f.child[i])
	}
	nodes := make(map[*node]*graphvizNode)
	edges := make([]*graphvizEdge, 0)
	for !st.isEmpty() {
		n := st.pop().(*node)
		gNode := f.newNode(n.name)
		nodes[n] = gNode
		if _, ok := nodes[n.parent]; ok {
			edges = append(edges, &graphvizEdge{Left: nodes[n.parent], Right: gNode})
		}

		for i := len(n.child) - 1; i >= 0; i-- {
			st.push(n.child[i])
		}
	}

	dir, err := os.Getwd()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	out, err := os.Create(filepath.Join(dir, strings.ToLower(name)+".dot"))
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	fmt.Fprintf(out, "digraph %s {\n", name)
	fmt.Fprintln(out, "    graph [rankdir = LR];")
	for _, v := range nodes {
		fmt.Fprintf(out, "    %s [label=%q, shape = box];\n", v.ID, v.Label)
	}
	for _, v := range edges {
		fmt.Fprintf(out, "    %s -> %s\n", v.Left.ID, v.Right.ID)
	}
	fmt.Fprintln(out, "}")
	fmt.Printf("File: %s\n", out.Name())
	return nil
}

func (f *graphvizFormatter) newNode(label string) *graphvizNode {
	f.seq++
	return &graphvizNode{ID: fmt.Sprintf("%d", f.seq), Label: label}
}

type graphvizNode struct {
	ID    string
	Label string
}

type graphvizEdge struct {
	Left  *graphvizNode
	Right *graphvizNode
}
