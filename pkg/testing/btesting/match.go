package btesting

import (
	"fmt"
	"net/http"
	"runtime"
	"strings"
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

func (m *Matcher) Failed() bool {
	return m.failed
}

func (m *Matcher) NoError(err error, msg ...string) {
	if err != nil {
		m.Failf("%+v: %s", err, strings.Join(msg, " "))
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

func (m *Matcher) Failf(format string, args ...any) {
	m.Fail(fmt.Sprintf(format, args...))
}

func (m *Matcher) Log(msg string) {
	m.T.Log(msg)
}

func (m *Matcher) Logf(format string, args ...any) {
	m.T.Logf(format, args...)
}

func (m *Matcher) Equal(expected, actual any, msgAndArgs ...any) {
	m.T.Helper()
	success := assert.Equal(m.T, expected, actual, msgAndArgs...)
	if !success {
		m.failed = true
	}
}

func (m *Matcher) Len(object any, len int, msgAndArgs ...any) {
	success := assert.Len(m.T, object, len, msgAndArgs...)
	if !success {
		m.failed = true
	}
}

func (m *Matcher) True(value bool, msgAndArgs ...any) {
	success := assert.True(m.T, value, msgAndArgs...)
	if !success {
		m.failed = true
	}
}

func (m *Matcher) False(value bool, msgAndArgs ...any) {
	success := assert.False(m.T, value, msgAndArgs...)
	if !success {
		m.failed = true
	}
}

func (m *Matcher) Contains(s, contains any, msgAndArgs ...any) {
	success := assert.Contains(m.T, s, contains, msgAndArgs)
	if !success {
		m.failed = true
	}
}

func (m *Matcher) NotNil(object any, msg ...string) {
	if object == nil {
		m.Fail(msg...)
	}
}

func (m *Matcher) Empty(object any, msgAndArgs ...any) {
	success := assert.Empty(m.T, object, msgAndArgs...)
	if !success {
		m.failed = true
	}
}

func (m *Matcher) NotEmpty(object any, msgAndArgs ...any) {
	success := assert.NotEmpty(m.T, object, msgAndArgs...)
	if !success {
		m.failed = true
	}
}

func (m *Matcher) FileExists(path string, msgANdArgs ...any) {
	success := assert.FileExists(m.T, path, msgANdArgs...)
	if !success {
		m.failed = true
	}
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

func (m *HTTPMatcher) StatusCode(code int, msgAndArgs ...any) {
	m.m.Equal(code, m.LastResponse().StatusCode, msgAndArgs...)
}

func (m *HTTPMatcher) ResetConnection() {
	if !m.m.done {
		m.m.Fail("not send request")
	}
	if m.lastResponse != nil || m.lastHttpErr == nil {
		m.m.Failf("expect connection reset: %v", m.lastHttpErr)
	}
}
