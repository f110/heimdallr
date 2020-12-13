package configv2

import (
	"strings"
)

type node struct {
	children map[string]*node
	value    *HTTPBackend
}

func newNode() *node {
	return &node{children: make(map[string]*node)}
}

type HTTPBackendSelector struct {
	root           *node
	defaultBackend *HTTPBackend
}

func NewHTTPBackendSelector() *HTTPBackendSelector {
	return &HTTPBackendSelector{root: newNode()}
}

func (s *HTTPBackendSelector) Add(b *HTTPBackend) {
	if b.Default {
		s.defaultBackend = b
	}

	p := strings.Split(b.Path, "/")[1:]

	n := s.root
	for i := 0; i < len(p); i++ {
		nextNode, ok := n.children[p[i]]
		if !ok {
			n.children[p[i]] = newNode()
			nextNode = n.children[p[i]]
		}
		n = nextNode
	}
	n.value = b
}

func (s *HTTPBackendSelector) Find(path string) *HTTPBackend {
	if len(path) > 0 && path[0] != '/' {
		path = "/" + path
	}
	if path == "" {
		path = "/"
	}
	p := strings.Split(path, "/")[1:]

	n := s.root
	for i := 0; i < len(p); i++ {
		nextNode, ok := n.children[p[i]]
		if !ok {
			if v, ok := n.children[""]; ok {
				nextNode = v
			} else {
				break
			}
		}
		n = nextNode
	}

	if n.value == nil {
		return s.defaultBackend
	}
	return n.value
}
