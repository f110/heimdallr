package framework

import (
	"bytes"
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var (
	format   *string
	junit    *string
	verbose  *bool
	e2eDebug *bool
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	format = flag.String("e2e.format", "", "Output format. (json, doc)")
	junit = flag.String("e2e.junit", "", "JUnit output file path")
	verbose = flag.Bool("e2e.verbose", false, "Verbose output. include stdout and stderr of all child processes.")
	e2eDebug = flag.Bool("e2e.debug", false, "Debug e2e framework")
}

var DefaultTracker = &Tracker{}

type Framework struct {
	Proxy  *Proxy
	Agents *Agents

	t       *testing.T
	tracker *Tracker

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
		Proxy:   p,
		Agents:  NewAgents(p.Domain, p.CA, p.sessionStore),
		t:       t,
		tracker: DefaultTracker,
		dryRun:  dryRun,
		child:   make([]*Scenario, 0),
	}
}

func (f *Framework) Execute() {
	if *junit != "" {
		defer DefaultTracker.Save(*junit)
	}

	// 1st phase:
	// 1st phase is an analysis phase.
	// This phase will not execute each cases.
	child := make([]*node, 0)
	for _, c := range f.child {
		suite := &testSuite{Name: c.Name}
		f.tracker.Suites = append(f.tracker.Suites, suite)

		child = append(child, c.analyze(suite))
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
	analyze(*testSuite) *node
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
	fn         func(*Matcher) bool
	m          *Matcher
	beforeAll  *hook
	afterAll   *hook
	subject    *hook
	beforeEach func(*Matcher) bool
	afterEach  func(*Matcher) bool
	deferFunc  func()

	suite *testSuite
}

func (n *node) execute(t *testing.T) {
	if *e2eDebug {
		log.Print(n.name)
	}
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
			c.Succeeded()
		} else {
			log.Print(n.route)
			c.FailureMessage = tSpy.message
			c.Failed()
		}
	}

	if n.afterEach != nil {
		n.executeFunc(t, n.afterEach, nil)
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
		n.executeFunc(t, n.afterAll.fn, nil)
		n.afterAll.done = true
	}

	n.suite.Finish()
}

type execDone struct {
	Stack   string
	Err     interface{}
	Failure bool
}

type testingT interface {
	Log(...interface{})
	Logf(string, ...interface{})
	Error(...interface{})
	Errorf(string, ...interface{})
	Fatalf(string, ...interface{})
}

func (n *node) executeFunc(t *testing.T, fn func(*Matcher) bool, spy *testingSpy) bool {
	done := make(chan *execDone)
	go func() {
		success := false
		defer func() {
			rErr := recover()
			if rErr != nil {
				s := debug.Stack()
				done <- &execDone{Stack: string(s), Err: rErr}
			} else if !success {
				done <- &execDone{Failure: true}
			}
			close(done)
		}()

		n.m.route = n.route
		m := n.m
		if spy != nil {
			m = n.m.wrapTesting(spy)
		}
		success = fn(m)
	}()

	select {
	case err, ok := <-done:
		if !ok {
			return true
		}

		if err != nil && err.Err != nil {
			t.Log(err.Stack)
			t.Fatalf("%s: %+v", n.route, err.Err)
		}
		return false
	}
}

type hook struct {
	fn   func(*Matcher) bool
	done bool
}

type Scenario struct {
	Name string

	depth       int
	route       string
	fn          func(s *Scenario)
	beforeAll   *hook
	afterAll    *hook
	beforeEach  func(*Matcher) bool
	afterEach   func(*Matcher) bool
	subject     *hook
	subjectDone bool
	deferFunc   func()
	m           *Matcher

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

func (f *Scenario) It(name string, fn func(m *Matcher) bool) {
	s := NewCase(f.t, f, name, f.depth+1, fn, f.beforeEach, f.afterEach, f.route+" "+name)
	f.child = append(f.child, s)
}

func (f *Scenario) Step(name string, fn func(s *Scenario)) {
	s := f.newChild(f.t, name, fn)
	f.child = append(f.child, s)
}

func (f *Scenario) BeforeAll(fn func(m *Matcher) bool) {
	f.beforeAll = &hook{fn: fn}
}

func (f *Scenario) AfterAll(fn func(m *Matcher) bool) {
	f.afterAll = &hook{fn: fn}
}

func (f *Scenario) BeforeEach(fn func(m *Matcher) bool) {
	if f.beforeEach != nil {
		b := f.beforeEach
		f.beforeEach = func(m *Matcher) bool {
			b(m)
			return fn(m)
		}
	} else {
		f.beforeEach = fn
	}
}

func (f *Scenario) AfterEach(fn func(m *Matcher) bool) {
	if f.afterEach != nil {
		a := f.afterEach
		f.afterEach = func(m *Matcher) bool {
			a(m)
			return fn(m)
		}
	} else {
		f.afterEach = fn
	}
}

func (f *Scenario) Defer(fn func()) {
	f.deferFunc = fn
}

func (f *Scenario) Subject(fn func(m *Matcher) bool) {
	f.subject = &hook{fn: fn}
}

type Case struct {
	Name string

	s          *Scenario
	depth      int
	route      string
	beforeAll  []*hook
	beforeEach func(*Matcher) bool
	afterEach  func(*Matcher) bool

	fn func(m *Matcher) bool

	t *testing.T
}

func NewCase(t *testing.T, s *Scenario, name string, depth int, fn func(m *Matcher) bool, before, after func(*Matcher) bool, route string) *Case {
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

type Matcher struct {
	t     testingT
	route string

	done         bool
	lastResponse *http.Response
	lastHttpErr  error

	mockServers map[string]*MockServer

	failed   bool
	messages []string
}

func NewMatcher(t *testing.T, route string) *Matcher {
	return &Matcher{t: t, route: route, mockServers: make(map[string]*MockServer)}
}

func (m *Matcher) wrapTesting(t *testingSpy) *Matcher {
	newM := &Matcher{}
	*newM = *m
	if v, ok := m.t.(*testing.T); ok {
		t.T = v
	}
	newM.t = t

	return newM
}

func (m *Matcher) Must(err error) bool {
	if err != nil {
		panic(err)
	}
	return true
}

type HttpResponse struct {
	*http.Response
}

func (h *HttpResponse) FindCookie(name string) *http.Cookie {
	for _, v := range h.Response.Cookies() {
		if v.Name == name {
			return v
		}
	}

	return nil
}

func (m *Matcher) LastResponse() *HttpResponse {
	if m.lastResponse == nil {
		m.Failf("want to get response but last response is nil. err: %v", m.lastHttpErr)
	}

	return &HttpResponse{Response: m.lastResponse}
}

func (m *Matcher) MockServer(name string) *MockServer {
	return m.mockServers[name]
}

func (m *Matcher) ResetConnection() bool {
	if !m.done {
		m.Fail("not send request")
	}
	if m.lastResponse != nil || m.lastHttpErr == nil {
		m.Failf("expect connection reset: %v", m.lastHttpErr)
	}
	return true
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

func (m *Matcher) Equal(expected, actual interface{}, msgAndArgs ...interface{}) bool {
	return assert.Equal(m.t, expected, actual, msgAndArgs...)
}

func (m *Matcher) Len(object interface{}, len int, msgAndArgs ...interface{}) bool {
	return assert.Len(m.t, object, len, msgAndArgs...)
}

func (m *Matcher) True(value bool, msgAndArgs ...interface{}) bool {
	return assert.True(m.t, value, msgAndArgs...)
}

func (m *Matcher) False(value bool, msgAndArgs ...interface{}) bool {
	return assert.False(m.t, value, msgAndArgs...)
}

func (m *Matcher) Contains(s, contains interface{}, msgAndArgs ...interface{}) bool {
	return assert.Contains(m.t, s, contains, msgAndArgs)
}

func (m *Matcher) StatusCode(code int, msgAndArgs ...interface{}) bool {
	return assert.Equal(m.t, code, m.LastResponse().StatusCode, msgAndArgs...)
}

func (m *Matcher) NotNil(object interface{}, msg ...string) {
	if object == nil {
		m.Fail(msg...)
	}
}

func (m *Matcher) Empty(object interface{}, msgAndArgs ...interface{}) bool {
	return assert.Empty(m.t, object, msgAndArgs...)
}

func (m *Matcher) NotEmpty(object interface{}, msgAndArgs ...interface{}) bool {
	return assert.NotEmpty(m.t, object, msgAndArgs...)
}

type Tracker struct {
	Suites []*testSuite
}

func (t *Tracker) Save(path string) {
	junitTestSuites := NewJUnitTestSuites(DefaultTracker)
	buf, err := xml.MarshalIndent(junitTestSuites, "", " ")
	if err != nil {
		return
	}

	err = ioutil.WriteFile(path, buf, 0644)
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
