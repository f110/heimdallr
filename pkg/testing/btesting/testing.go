package btesting

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fatih/color"
	"github.com/peterh/liner"
)

var (
	stdout = os.Stdout
)

type BehaviorDriven struct {
	t       *testing.T
	child   []*Scenario
	tracker *Tracker

	junitFile string
	step      bool
}

func New(t *testing.T, junitFile string, step bool) *BehaviorDriven {
	return &BehaviorDriven{
		t:         t,
		junitFile: junitFile,
		tracker:   DefaultTracker,
		child:     make([]*Scenario, 0),
		step:      step,
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
	case "dot":
		f := newGraphvizFormatter(child)
		f.Out(b.t.Name())
		return
	}

	// 2nd phase:
	// 2nd phase is an execution phase.
	r := newExecutionRuntime(child, b.step)
	r.Execute(b.t)
}

func (b *BehaviorDriven) Describe(name string, fn func(s *Scenario)) {
	s := NewScenario(b.t, nil, name, 0, fn, name)
	b.child = append(b.child, s)
}

type executionRuntime struct {
	nodes         []*node
	line          *liner.State
	ask           chan string
	do            chan struct{}
	hasBreakpoint bool
}

func newExecutionRuntime(nodes []*node, step bool) *executionRuntime {
	r := &executionRuntime{
		nodes: nodes,
	}
	if step {
		line := liner.NewLiner()
		line.SetCtrlCAborts(true)
		r.line = line
		r.ask = make(chan string)
		r.do = make(chan struct{})
	}

	return r
}

func (e *executionRuntime) Execute(t *testing.T) {
	ctx := context.Background()
	if e.line != nil {
		e.hasBreakpoint = e.findBreakpoint()
		c, cancel := context.WithCancel(context.Background())
		ctx = c
		go e.prompt(cancel)
	}

	for _, v := range e.nodes {
		e.executeNode(ctx, t, v)
	}
	if e.line != nil {
		e.line.Close()
	}
}

func (e *executionRuntime) prompt(cancel context.CancelFunc) {
	for {
		p := <-e.ask
		asn, err := e.line.Prompt(fmt.Sprintf("Next: %s) ", p))
		if err == liner.ErrPromptAborted {
			cancel()
			return
		}
		asn = strings.ToLower(asn)
		switch asn {
		case "next", "n":
			e.do <- struct{}{}
		default:
			log.Print([]byte(asn))
		}
	}
}

func (e *executionRuntime) findBreakpoint() bool {
	found := false
	e.walkNodes(func(n *node) bool {
		for _, v := range []*hook{
			n.beforeAll,
			n.beforeEach,
			n.subject,
			n.afterEach,
			n.afterAll,
		} {
			if v == nil {
				continue
			}
			if v.step {
				found = true
				return false
			}
		}

		return true
	})

	return found
}

func (e *executionRuntime) walkNodes(fn func(n *node) bool) {
	st := newStack()
	for i := len(e.nodes) - 1; i >= 0; i-- {
		st.push(e.nodes[i])
	}
	for !st.isEmpty() {
		n := st.pop().(*node)
		cont := fn(n)
		if !cont {
			return
		}

		for i := len(n.child) - 1; i >= 0; i-- {
			st.push(n.child[i])
		}
	}
}

func (e *executionRuntime) executeNode(ctx context.Context, t *testing.T, node *node) {
	t.Helper()
	node.suite.Trigger()

	if node.deferFunc != nil {
		defer node.deferFunc()
	}

	if node.beforeAll != nil && !node.beforeAll.done {
		e.executeFunc(ctx, t, node, node.beforeAll, nil, "BeforeAll")
		node.beforeAll.done = true
	}

	if node.beforeEach != nil {
		e.executeFunc(ctx, t, node, node.beforeEach, nil, "BeforeEach")
	}

	if node.subject != nil && !node.subject.done {
		e.executeFunc(ctx, t, node, node.subject, nil, "Subject")
		node.subject.done = true
	}

	if node.fn != nil {
		c := node.suite.NewCase(node.route)
		tSpy := &testingSpy{T: t}
		c.Start()
		e.executeFunc(ctx, t, node, node.fn, tSpy, "It")
		success := !node.m.Failed()
		c.Finish()

		if success {
			fmt.Fprint(stdout, color.GreenString("✔ %s\n", node.route))
			c.Succeeded()
		} else {
			fmt.Fprint(stdout, color.RedString("× %s\n", node.route))
			c.FailureMessage = tSpy.message
			c.Failed()
		}
	}

	if node.afterEach != nil {
		e.executeFunc(ctx, t, node, node.afterEach, nil, "AfterEach")
	}

	if node.m != nil && node.m.failed {
		if len(node.m.messages) == 0 {
			node.m.T.Error("Failed")
		}

		for _, v := range node.m.messages {
			node.m.T.Error(v)
		}
	}

	if node.m == nil || (node.m != nil && !node.m.failed) {
		for _, v := range node.child {
			e.executeNode(ctx, t, v)
		}
	}

	if node.afterAll != nil && !node.afterAll.done {
		e.executeFunc(ctx, t, node, node.afterAll, nil, "AfterAll")
		node.afterAll.done = true
	}

	node.suite.Finish()
}

func (e *executionRuntime) executeFunc(ctx context.Context, t *testing.T, node *node, h *hook, spy *testingSpy, step string) {
	t.Helper()
	if e.ask != nil && step != "" {
		if e.hasBreakpoint && !h.step {
			goto Continue
		}

		select {
		case e.ask <- node.route + " [" + step + "]":
		case <-ctx.Done():
			node.m.Fail("abort")
			return
		}

		select {
		case <-e.do:
		case <-ctx.Done():
			node.m.Fail("abort")
			return
		}
	}

Continue:
	done := make(chan *execDone)
	go func() {
		success := false
		defer func() {
			rErr := recover()
			s := debug.Stack()
			if rErr != nil {
				done <- &execDone{Stack: string(s), Err: rErr}
			} else if !success {
				done <- &execDone{Failure: true, Err: fmt.Errorf("failed execute: %v", node.m.messages), Stack: string(s)}
			}
			close(done)
		}()

		node.m.route = node.route
		m := node.m
		if spy != nil {
			m = node.m.wrapTesting(spy)
		}
		h.fn(m)
		success = !m.Failed()
	}()

	select {
	case err, ok := <-done:
		if !ok {
			return
		}

		if err != nil && err.Err != nil {
			if err.Stack != "" {
				t.Log(err.Stack)
			}
			t.Fatalf("%s: %+v ", node.route, err.Err)
		}
		return
	}
}

type Scenario struct {
	Name string

	depth       int
	route       string
	fn          func(s *Scenario)
	beforeAll   *hook
	afterAll    *hook
	beforeEach  *hook
	afterEach   *hook
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

	n := &node{
		name:      f.Name,
		route:     f.route,
		depth:     f.depth,
		m:         f.m,
		beforeAll: f.beforeAll,
		afterAll:  f.afterAll,
		deferFunc: f.deferFunc,
		suite:     suite,
	}

	child := make([]*node, 0)
	for _, v := range f.child {
		c := v.analyze(suite)
		c.parent = n

		child = append(child, c)
	}
	n.child = child

	return n
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
	s := NewCase(f.t, f, name, f.depth+1, &hook{fn: fn}, f.beforeEach, f.afterEach, f.route+" "+name)
	f.child = append(f.child, s)
}

func (f *Scenario) Step(name string, fn func(s *Scenario)) {
	s := f.newChild(f.t, name, fn)
	f.child = append(f.child, s)
}

func (f *Scenario) BeforeAll(fn func(m *Matcher)) {
	f.beforeAll = &hook{fn: fn}
}

func (f *Scenario) SBeforeAll(fn func(m *Matcher)) {
	f.beforeAll = &hook{step: true, fn: fn}
}

func (f *Scenario) AfterAll(fn func(m *Matcher)) {
	f.afterAll = &hook{fn: fn}
}

func (f *Scenario) SAfterAll(fn func(m *Matcher)) {
	f.afterAll = &hook{step: true, fn: fn}
}

func (f *Scenario) BeforeEach(fn func(m *Matcher)) {
	if f.beforeEach != nil {
		b := f.beforeEach
		f.beforeEach = &hook{
			fn: func(m *Matcher) {
				b.fn(m)
				fn(m)
			},
		}
	} else {
		f.beforeEach = &hook{fn: fn}
	}
}

func (f *Scenario) SBeforeEach(fn func(m *Matcher)) {
	if f.beforeEach != nil {
		b := f.beforeEach
		f.beforeEach = &hook{
			step: true,
			fn: func(m *Matcher) {
				b.fn(m)
				fn(m)
			},
		}
	} else {
		f.beforeEach = &hook{step: true, fn: fn}
	}
}

func (f *Scenario) AfterEach(fn func(m *Matcher)) {
	if f.afterEach != nil {
		a := f.afterEach
		f.afterEach = &hook{
			fn: func(m *Matcher) {
				a.fn(m)
				fn(m)
			},
		}
	} else {
		f.afterEach = &hook{fn: fn}
	}
}

func (f *Scenario) SAfterEach(fn func(m *Matcher)) {
	if f.afterEach != nil {
		a := f.afterEach
		f.afterEach = &hook{
			step: true,
			fn: func(m *Matcher) {
				a.fn(m)
				fn(m)
			},
		}
	} else {
		f.afterEach = &hook{step: true, fn: fn}
	}
}

func (f *Scenario) Defer(fn func()) {
	f.deferFunc = fn
}

func (f *Scenario) Subject(fn func(m *Matcher)) {
	f.subject = &hook{fn: fn}
}

func (f *Scenario) SSubject(fn func(m *Matcher)) {
	f.subject = &hook{step: true, fn: fn}
}

type Case struct {
	Name string

	s          *Scenario
	depth      int
	route      string
	beforeAll  []*hook
	beforeEach *hook
	afterEach  *hook

	fn *hook

	t *testing.T
}

func NewCase(t *testing.T, s *Scenario, name string, depth int, fn, before, after *hook, route string) *Case {
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
	parent     *node
	child      []*node
	fn         *hook
	m          *Matcher
	beforeAll  *hook
	afterAll   *hook
	subject    *hook
	beforeEach *hook
	afterEach  *hook
	deferFunc  func()

	suite *testSuite
}

type hook struct {
	fn   func(*Matcher)
	done bool
	step bool
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
	t.T.Helper()
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
	Helper()
}
