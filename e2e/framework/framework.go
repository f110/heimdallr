package framework

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	format  *string
	verbose *bool
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	format = flag.String("e2e.format", "", "Output format. (json, doc)")
	verbose = flag.Bool("e2e.verbose", false, "Verbose output. include stdout and stderr of all child processes.")
}

type Framework struct {
	Proxy  *Proxy
	Agents *Agents

	t *testing.T

	child []*Scenario

	dryRun bool
}

func New(t *testing.T) *Framework {
	dryRun := false
	switch *format {
	case "doc":
		dryRun = true
	}

	p, err := NewProxy(t)
	if err != nil {
		t.Fatalf("Failed setup proxy: %v", err)
	}

	return &Framework{
		Proxy:  p,
		Agents: NewAgents(p.Domain, p.CA),
		t:      t,
		dryRun: dryRun,
		child:  make([]*Scenario, 0),
	}
}

func (f *Framework) Execute() {
	// 1st phase:
	// 1st phase is an analysis phase.
	// This phase will not execute each cases.
	child := make([]*node, 0)
	for _, c := range f.child {
		child = append(child, c.analyze())
	}

	switch *format {
	case "doc":
		// Output like documentation.
		w := new(bytes.Buffer)
		st := newStack()
		for i := len(child) - 1; i >= 0; i-- {
			st.push(child[i])
		}
		for !st.isEmpty() {
			n := st.pop().(*node)
			fmt.Fprintf(w, "%s%s\n", strings.Repeat("  ", n.depth), n.name)

			for i := len(n.child) - 1; i >= 0; i-- {
				st.push(n.child[i])
			}
		}
		w.WriteTo(os.Stdout)
		return
	}

	// 2nd phase:
	// 2nd phase is an execution phase.
	for _, c := range child {
		c.execute(f.t)
	}
}

func (f *Framework) Describe(name string, fn func(s *Scenario)) {
	s := NewScenario(f.t, nil, name, 0, fn, name)
	f.child = append(f.child, s)
}

type children interface {
	analyze() *node
}

type stack struct {
	sync.Mutex
	s []interface{}
}

func newStack() *stack {
	return &stack{s: make([]interface{}, 0)}
}

func (s *stack) isEmpty() bool {
	s.Lock()
	defer s.Unlock()

	return len(s.s) == 0
}

func (s *stack) push(n interface{}) {
	s.Lock()
	defer s.Unlock()

	s.s = append(s.s, n)
}

func (s *stack) pop() interface{} {
	if s.isEmpty() {
		return nil
	}

	s.Lock()
	defer s.Unlock()
	i := len(s.s) - 1
	item := s.s[i]
	s.s = s.s[:i]

	return item
}

type node struct {
	name       string
	route      string
	depth      int
	child      []*node
	fn         func(*Matcher)
	m          *Matcher
	beforeAll  *hook
	afterAll   *hook
	subject    *hook
	beforeEach func(*Matcher)
	afterEach  func(*Matcher)
	deferFunc  func()
}

func (n *node) execute(t *testing.T) {
	if n.deferFunc != nil {
		defer n.deferFunc()
	}

	if n.beforeAll != nil && !n.beforeAll.done {
		n.executeFunc(t, n.beforeAll.fn)
		n.beforeAll.done = true
	}

	if n.beforeEach != nil {
		n.executeFunc(t, n.beforeEach)
	}

	if n.subject != nil && !n.subject.done {
		n.executeFunc(t, n.subject.fn)
		n.subject.done = true
	}

	if n.fn != nil {
		n.executeFunc(t, n.fn)
	}

	if n.afterEach != nil {
		n.executeFunc(t, n.afterEach)
	}

	if n.m != nil && n.m.failed {
		if len(n.m.messages) == 0 {
			n.m.t.Error("Failed")
		}

		for _, v := range n.m.messages {
			n.m.t.Error(v)
		}
	}

	if n.m == nil || (n.m != nil && !n.m.failed) {
		for _, v := range n.child {
			v.execute(t)
		}
	}

	if n.afterAll != nil && !n.afterAll.done {
		n.executeFunc(t, n.afterAll.fn)
		n.afterAll.done = true
	}
}

type execDone struct {
	Stack string
	Err   interface{}
}

func (n *node) executeFunc(t *testing.T, fn func(*Matcher)) {
	done := make(chan *execDone)
	go func() {
		defer func() {
			err := recover()
			if err != nil {
				s := debug.Stack()
				done <- &execDone{Stack: string(s), Err: err}
			}
			done <- nil
		}()

		fn(n.m)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Log(err.Stack)
			t.Fatalf("%s: %+v", n.route, err.Err)
		}
	}
}

type hook struct {
	fn   func(*Matcher)
	done bool
}

type Scenario struct {
	Name string

	depth       int
	route       string
	fn          func(s *Scenario)
	beforeAll   *hook
	afterAll    *hook
	beforeEach  func(*Matcher)
	afterEach   func(*Matcher)
	subject     func(*Matcher)
	subjectDone bool
	deferFunc   func()

	t      *testing.T
	parent *Scenario
	child  []children
}

func NewScenario(t *testing.T, parent *Scenario, name string, depth int, fn func(s *Scenario), route string) *Scenario {
	return &Scenario{
		Name:   name,
		depth:  depth,
		route:  route,
		fn:     fn,
		t:      t,
		parent: parent,
		child:  make([]children, 0),
	}
}

func (f *Scenario) analyze() *node {
	f.fn(f)

	child := make([]*node, 0)
	for _, v := range f.child {
		child = append(child, v.analyze())
	}

	return &node{
		name:      f.Name,
		route:     f.route,
		depth:     f.depth,
		child:     child,
		beforeAll: f.beforeAll,
		afterAll:  f.afterAll,
		deferFunc: f.deferFunc,
	}
}

func (f *Scenario) newChild(t *testing.T, name string, fn func(s *Scenario)) *Scenario {
	s := NewScenario(t, f, name, f.depth+1, fn, f.route+" "+name)
	s.beforeEach = f.beforeEach
	s.afterEach = f.afterEach

	return s
}

func (f *Scenario) Context(name string, fn func(s *Scenario)) {
	s := f.newChild(f.t, name, fn)
	f.child = append(f.child, s)
}

func (f *Scenario) It(name string, fn func(m *Matcher)) {
	s := NewCase(f.t, f, name, f.depth+1, fn, f.beforeEach, f.afterEach, f.route+" "+name)
	f.child = append(f.child, s)
}

func (f *Scenario) BeforeAll(fn func(m *Matcher)) {
	f.beforeAll = &hook{fn: fn}
}

func (f *Scenario) AfterAll(fn func(m *Matcher)) {
	f.afterAll = &hook{fn: fn}
}

func (f *Scenario) BeforeEach(fn func(m *Matcher)) {
	if f.beforeEach != nil {
		b := f.beforeEach
		f.beforeEach = func(m *Matcher) {
			b(m)
			fn(m)
		}
	} else {
		f.beforeEach = fn
	}
}

func (f *Scenario) AfterEach(fn func(m *Matcher)) {
	if f.afterEach != nil {
		a := f.afterEach
		f.afterEach = func(m *Matcher) {
			a(m)
			fn(m)
		}
	} else {
		f.afterEach = fn
	}
}

func (f *Scenario) Defer(fn func()) {
	f.deferFunc = fn
}

func (f *Scenario) Subject(fn func(m *Matcher)) {
	f.subject = fn
}

type Case struct {
	Name string

	s          *Scenario
	depth      int
	route      string
	beforeAll  []*hook
	beforeEach func(*Matcher)
	afterEach  func(*Matcher)

	fn func(m *Matcher)

	t *testing.T
}

func NewCase(t *testing.T, s *Scenario, name string, depth int, fn func(m *Matcher), before, after func(*Matcher), route string) *Case {
	return &Case{
		Name:       name,
		s:          s,
		depth:      depth,
		t:          t,
		fn:         fn,
		beforeEach: before,
		afterEach:  after,
		route:      route,
	}
}

func (c *Case) analyze() *node {
	var s *hook
	if c.s.subject != nil {
		s = &hook{fn: c.s.subject}
	}
	return &node{
		name:       c.Name,
		route:      c.route,
		depth:      c.depth,
		m:          NewMatcher(c.t, c),
		subject:    s,
		beforeEach: c.beforeEach,
		afterEach:  c.afterEach,
		fn:         c.fn,
	}
}

type Matcher struct {
	t     *testing.T
	route string

	done         bool
	lastResponse *http.Response
	lastHttpErr  error

	failed   bool
	messages []string
}

func NewMatcher(t *testing.T, c *Case) *Matcher {
	return &Matcher{t: t, route: c.route}
}

func (m *Matcher) Must(err error) {
	if err != nil {
		panic(err)
	}
}

func (m *Matcher) LastResponse() *http.Response {
	if m.lastResponse == nil {
		m.Fail("want to get response but last response is nil")
	}

	return m.lastResponse
}

func (m *Matcher) ResetConnection() {
	if !m.done {
		m.Fail("not send request")
	}
	if m.lastResponse != nil || m.lastHttpErr == nil {
		m.Failf("expect connection reset: %v", m.lastHttpErr)
	}
}

func (m *Matcher) NoError(err error, msg ...string) {
	if err != nil {
		m.Fail(msg...)
	}
}

func (m *Matcher) Fail(msg ...string) {
	if len(msg) > 0 {
		m.failed = true
		m.messages = append(m.messages, fmt.Sprintf("%s: %s", m.route, msg[0]))
	} else {
		m.failed = true
		m.messages = append(m.messages, m.route)
	}
	runtime.Goexit()
}

func (m *Matcher) Failf(format string, args ...interface{}) {
	m.Fail(fmt.Sprintf(format, args...))
}

func (m *Matcher) Log(msg string) {
	m.t.Log(msg)
}

func (m *Matcher) Logf(format string, args ...interface{}) {
	m.t.Logf(format, args...)
}

func (m *Matcher) Equal(expected, actual interface{}) {
	assert.Equal(m.t, expected, actual)
}
