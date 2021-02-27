package btesting

import (
	"fmt"
	"net/http"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

type Matcher struct {
	*HTTPMatcher

	T     testingT
	route string

	done         bool
	lastResponse *http.Response
	lastHttpErr  error

	urlFile string

	failed   bool
	messages []string
}

func NewMatcher(t *testing.T, route string) *Matcher {
	m := &Matcher{
		T:     t,
		route: route,
	}
	m.HTTPMatcher = &HTTPMatcher{m: m, t: t}
	return m
}

func (m *Matcher) wrapTesting(t *testingSpy) *Matcher {
	newM := &Matcher{}
	*newM = *m
	if v, ok := m.T.(*testing.T); ok {
		t.T = v
	}
	newM.T = t

	return newM
}

func (m *Matcher) Must(err error) bool {
	if err != nil {
		panic(err)
	}
	return true
}

func (m *Matcher) Done() {
	m.done = true
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
	m.T.Log(msg)
}

func (m *Matcher) Logf(format string, args ...interface{}) {
	m.T.Logf(format, args...)
}

func (m *Matcher) Equal(expected, actual interface{}, msgAndArgs ...interface{}) bool {
	return assert.Equal(m.T, expected, actual, msgAndArgs...)
}

func (m *Matcher) Len(object interface{}, len int, msgAndArgs ...interface{}) bool {
	return assert.Len(m.T, object, len, msgAndArgs...)
}

func (m *Matcher) True(value bool, msgAndArgs ...interface{}) bool {
	return assert.True(m.T, value, msgAndArgs...)
}

func (m *Matcher) False(value bool, msgAndArgs ...interface{}) bool {
	return assert.False(m.T, value, msgAndArgs...)
}

func (m *Matcher) Contains(s, contains interface{}, msgAndArgs ...interface{}) bool {
	return assert.Contains(m.T, s, contains, msgAndArgs)
}

func (m *Matcher) NotNil(object interface{}, msg ...string) {
	if object == nil {
		m.Fail(msg...)
	}
}

func (m *Matcher) Empty(object interface{}, msgAndArgs ...interface{}) bool {
	return assert.Empty(m.T, object, msgAndArgs...)
}

func (m *Matcher) NotEmpty(object interface{}, msgAndArgs ...interface{}) bool {
	return assert.NotEmpty(m.T, object, msgAndArgs...)
}

func (m *Matcher) FileExists(path string, msgANdArgs ...interface{}) bool {
	return assert.FileExists(m.T, path, msgANdArgs...)
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

type HTTPMatcher struct {
	m *Matcher
	t testingT

	lastResponse *http.Response
	lastHttpErr  error
}

func (m *HTTPMatcher) SetLastResponse(res *http.Response, err error) {
	m.lastResponse = res
	m.lastHttpErr = err
}

func (m *HTTPMatcher) LastResponse() *HttpResponse {
	if m.lastResponse == nil {
		m.m.Failf("want to get response but last response is nil. err: %v", m.lastHttpErr)
	}

	return &HttpResponse{Response: m.lastResponse}
}

func (m *HTTPMatcher) StatusCode(code int, msgAndArgs ...interface{}) bool {
	return assert.Equal(m.t, code, m.LastResponse().StatusCode, msgAndArgs...)
}

func (m *HTTPMatcher) ResetConnection() bool {
	if !m.m.done {
		m.m.Fail("not send request")
	}
	if m.lastResponse != nil || m.lastHttpErr == nil {
		m.m.Failf("expect connection reset: %v", m.lastHttpErr)
	}
	return true
}
