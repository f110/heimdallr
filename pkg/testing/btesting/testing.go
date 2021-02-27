package btesting

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fatih/color"
)

var (
	stdout = os.Stdout
)

type BehaviorDriven struct {
	t       *testing.T
	child   []*Scenario
	tracker *Tracker

	junitFile string
}

func New(t *testing.T, junitFile string) *BehaviorDriven {
	return &BehaviorDriven{
		t:         t,
		junitFile: junitFile,
		tracker:   DefaultTracker,
		child:     make([]*Scenario, 0),
	}
}

func (b *BehaviorDriven) Execute(format string) {
	if b.junitFile != "" {
		defer DefaultTracker.Save(b.junitFile)
	}

	// 1st phase:
	// 1st phase is an analysis phase.
	// This phase will not execute each cases.
	child := make([]*node, 0)
	for _, c := range b.child {
		suite := &testSuite{Name: c.Name}
		b.tracker.Suites = append(b.tracker.Suites, suite)

		child = append(child, c.analyze(suite))
	}

	switch format {
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
		c.execute(b.t)
	}
}

func (b *BehaviorDriven) Describe(name string, fn func(s *Scenario)) {
	s := NewScenario(b.t, nil, name, 0, fn, name)
	b.child = append(b.child, s)
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
	subject     *hook
	subjectDone bool
	deferFunc   func()
	m           *Matcher

	t      *testing.T
	parent *Scenario
	child  []children
}

type children interface {
	analyze(*testSuite) *node
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
		m:      NewMatcher(t, route),
	}
}

func (f *Scenario) analyze(suite *testSuite) *node {
	f.fn(f)

	child := make([]*node, 0)
	for _, v := range f.child {
		n := v.analyze(suite)

		child = append(child, n)
	}

	return &node{
		name:      f.Name,
		route:     f.route,
		depth:     f.depth,
		child:     child,
		m:         f.m,
		beforeAll: f.beforeAll,
		afterAll:  f.afterAll,
		deferFunc: f.deferFunc,
		suite:     suite,
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

func (f *Scenario) Step(name string, fn func(s *Scenario)) {
	s := f.newChild(f.t, name, fn)
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
	f.subject = &hook{fn: fn}
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

func NewCase(t *testing.T, s *Scenario, name string, depth int, fn, before, after func(*Matcher), route string) *Case {
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

func (c *Case) analyze(ancestor *testSuite) *node {
	var s *hook
	if c.s.subject != nil {
		s = c.s.subject
	}
	return &node{
		name:       c.Name,
		route:      c.route,
		depth:      c.depth,
		m:          c.s.m,
		subject:    s,
		beforeEach: c.beforeEach,
		afterEach:  c.afterEach,
		fn:         c.fn,
		suite:      ancestor,
	}
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

	suite *testSuite
}

func (n *node) execute(t *testing.T) {
	n.suite.Trigger()

	if n.deferFunc != nil {
		defer n.deferFunc()
	}

	if n.beforeAll != nil && !n.beforeAll.done {
		n.executeFunc(t, n.beforeAll.fn, nil)
		n.beforeAll.done = true
	}

	if n.beforeEach != nil {
		n.executeFunc(t, n.beforeEach, nil)
	}

	if n.subject != nil && !n.subject.done {
		n.executeFunc(t, n.subject.fn, nil)
		n.subject.done = true
	}

	if n.fn != nil {
		c := n.suite.NewCase(n.route)
		tSpy := &testingSpy{T: t}
		c.Start()
		success := n.executeFunc(t, n.fn, tSpy)
		c.Finish()

		if success {
			fmt.Fprint(stdout, color.GreenString("S: %s\n", n.route))
			c.Succeeded()
		} else {
			fmt.Fprint(stdout, color.RedString("F: %s\n", n.route))
			c.FailureMessage = tSpy.message
			c.Failed()
		}
	}

	if n.afterEach != nil {
		n.executeFunc(t, n.afterEach, nil)
	}

	if n.m != nil && n.m.failed {
		if len(n.m.messages) == 0 {
			n.m.T.Error("Failed")
		}

		for _, v := range n.m.messages {
			n.m.T.Error(v)
		}
	}

	if n.m == nil || (n.m != nil && !n.m.failed) {
		for _, v := range n.child {
			v.execute(t)
		}
	}

	if n.afterAll != nil && !n.afterAll.done {
		n.executeFunc(t, n.afterAll.fn, nil)
		n.afterAll.done = true
	}

	n.suite.Finish()
}

func (n *node) executeFunc(t *testing.T, fn func(*Matcher), spy *testingSpy) bool {
	done := make(chan *execDone)
	go func() {
		success := false
		defer func() {
			rErr := recover()
			if rErr != nil {
				s := debug.Stack()
				done <- &execDone{Stack: string(s), Err: rErr}
			} else if !success {
				done <- &execDone{Failure: true, Err: errors.New("failed execute")}
			}
			close(done)
		}()

		n.m.route = n.route
		m := n.m
		if spy != nil {
			m = n.m.wrapTesting(spy)
		}
		fn(m)
		success = !m.Failed()
	}()

	select {
	case err, ok := <-done:
		if !ok {
			return true
		}

		if err != nil && err.Err != nil {
			if err.Stack != "" {
				t.Log(err.Stack)
			}
			t.Fatalf("%s: %+v ", n.route, err.Err)
		}
		return false
	}
}

type hook struct {
	fn   func(*Matcher)
	done bool
}

type execDone struct {
	Stack   string
	Err     interface{}
	Failure bool
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

var DefaultTracker = &Tracker{}

type Tracker struct {
	Suites []*testSuite
}

func (t *Tracker) Save(path string) {
	junitTestSuites := NewJUnitTestSuites(DefaultTracker)
	buf, err := xml.MarshalIndent(junitTestSuites, "", " ")
	if err != nil {
		return
	}

	err = os.WriteFile(path, buf, 0644)
	if err != nil {
		log.Print(err)
	}
}

type testSuite struct {
	Name  string
	Cases []*testCase

	start  time.Time
	finish time.Time
}

func (s *testSuite) Trigger() {
	if s.start.IsZero() {
		s.start = time.Now()
	}
}

func (s *testSuite) Finish() {
	s.finish = time.Now()
}

func (s *testSuite) NewCase(name string) *testCase {
	c := &testCase{Name: name}
	s.Cases = append(s.Cases, c)

	return c
}

type testCase struct {
	Name           string
	Failure        bool
	FailureMessage string

	start  time.Time
	finish time.Time
}

func (c *testCase) Start() {
	if c.start.IsZero() {
		c.start = time.Now()
	}
}

func (c *testCase) Finish() {
	c.finish = time.Now()
}

func (c *testCase) Succeeded() {}

func (c *testCase) Failed() {
	c.Failure = true
}

type testingSpy struct {
	*testing.T

	message string
}

var _ testingT = &testingSpy{}

func (t *testingSpy) Errorf(format string, args ...interface{}) {
	t.message += fmt.Sprintf(format, args...)
	t.T.Errorf(format, args...)
}

type testingT interface {
	Log(...interface{})
	Logf(string, ...interface{})
	Error(...interface{})
	Errorf(string, ...interface{})
	Fatalf(string, ...interface{})
	TempDir() string
}
