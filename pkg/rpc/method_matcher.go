package rpc

import (
	"strings"

	"golang.org/x/xerrors"
)

type MethodMatcher struct {
	root   *node
	freeze bool
}

type node struct {
	Id    string
	Child map[string]*node
}

func newNode(id string) *node {
	return &node{Id: id, Child: make(map[string]*node)}
}

func NewMethodMatcher() *MethodMatcher {
	return &MethodMatcher{
		root: newNode("."),
	}
}

func (m MethodMatcher) Add(method string) error {
	if m.freeze {
		return xerrors.New("rpc: can not added new method because matcher is freezing")
	}

	s := strings.Split(m.normalize(method), ".")

	n := m.root
	for _, v := range s {
		if _, ok := n.Child[v]; !ok {
			n.Child[v] = newNode(v)
		}
		n = n.Child[v]
	}

	return nil
}

func (m *MethodMatcher) Match(method string) bool {
	s := strings.Split(m.normalize(method), ".")

	n := m.root
	for _, v := range s {
		if _, ok := n.Child[v]; !ok {
			if _, ok := n.Child["*"]; ok {
				n = n.Child["*"]
				continue
			}
			return false
		}
		n = n.Child[v]
	}

	return true
}

func (m *MethodMatcher) Freeze() {
	m.freeze = true
}

func (m *MethodMatcher) normalize(method string) string {
	if strings.HasPrefix(method, "/") {
		method = method[1:]
	}
	method = strings.ReplaceAll(method, "/", ".")

	return strings.ToLower(method)
}
