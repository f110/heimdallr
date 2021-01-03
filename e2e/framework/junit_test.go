package framework

import (
	"encoding/xml"
	"io/ioutil"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJUnit(t *testing.T) {
	in := &JUnitTestSuites{
		Tests: 1,
		TestSuites: []JUnitTestSuite{
			{
				Tests: 1,
				Properties: []JUnitProperty{
					{Name: "foo", Value: "bar"},
				},
				TestCases: []JUnitTestCase{
					{
						Stdout: &JUnitStdout{
							Text: "This is stdout",
						},
						Stderr: &JUnitStderr{
							Text: "This is stderr",
						},
					},
				},
			},
		},
	}
	out, err := ioutil.ReadFile("./testdata/junit.xml")
	require.NoError(t, err)

	buf, err := xml.MarshalIndent(in, "", "  ")
	require.NoError(t, err)
	assert.Equal(t, string(out), string(buf))
}

func TestTacker(t *testing.T) {
	stubT := &testing.T{}
	f := New(stubT)
	f.Describe("About Foo", func(s *Scenario) {
		s.Context("Bar", func(s *Scenario) {
			s.It("Baz", func(m *Matcher) bool {
				time.Sleep(1 * time.Second)
				return m.True(true)
			})
		})

		s.Context("Spam", func(s *Scenario) {
			s.It("Ham", func(m *Matcher) bool {
				time.Sleep(1 * time.Second)
				return m.True(true)
			})

			s.It("Eggs", func(m *Matcher) bool {
				return m.True(false)
			})
		})
	})
	f.Describe("About FooBar", func(s *Scenario) {
		s.Context("Bar", func(s *Scenario) {
			s.It("Baz", func(m *Matcher) bool {
				return m.True(true)
			})
		})
	})
	f.Execute()

	junitTestSuites := NewJUnitTestSuites(f.tracker)
	buf, err := xml.MarshalIndent(junitTestSuites, "", "  ")
	require.NoError(t, err)
	t.Log(string(buf))
}
