package framework

import "encoding/xml"

type JUnitTestSuites struct {
	XMLName    xml.Name         `xml:"testsuites"`
	TestSuites []JUnitTestSuite `xml:"testsuite"`
	Name       string           `xml:"name,attr,omitempty"`
	// Tests is total number of tests from all suites
	Tests int `xml:"tests,attr,omitempty"`
	// Errors is total number of tests with error result from all suites
	Errors int `xml:"errors,attr,omitempty"`
	// Failures is total number of failed tests from all suites
	Failures int `xml:"failures,attr,omitempty"`
	// Disabled is total number of disabled tests from all suites
	Disabled int `xml:"disabled,attr,omitempty"`
	// Time in seconds to execute all test suites
	Time int `xml:"time,attr,omitempty"`
}

type JUnitTestSuite struct {
	XMLName xml.Name `xml:"testsuite"`
	Name    string   `xml:"name,attr,omitempty"`
	// Tests is total number of tests in the suite. This value is required.
	Tests int `xml:"tests,attr"`
	// Failures is total number of failed tests in the suite
	Failures int `xml:"failures,attr,omitempty"`
	// Errors is total number of tests in the suite that is with error result
	Errors int `xml:"errors,attr,omitempty"`
	// Disabled is total number of disabled tests in the suite
	Disabled int `xml:"disabled,attr,omitempty"`
	// Time in seconds to execute in the suite
	Time int `xml:"time,attr,omitempty"`
	// Timestamp when tests were executed. The format is ISO8601 (2014-01-21T16:17:18)
	Timestamp string `xml:"timestamp,attr,omitempty"`
	// Hostname that tests were executed
	Hostname   string          `xml:"hostname,attr,omitempty"`
	Properties []JUnitProperty `xml:"properties>property,omitempty"`
	TestCases  []JUnitTestCase `xml:"testcase"`
}

type JUnitProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

type JUnitTestCase struct {
	XMLName xml.Name `xml:"testcase"`
	// Name of the test case
	Name string `xml:"name,attr"`
	// Assertions is the number of assertions in this test case
	Assertions int    `xml:"assertions,attr,omitempty"`
	ClassName  string `xml:"classname,attr"`
	Status     string `xml:"status,attr,omitempty"`
	// Time in seconds to execute the test case
	Time    int `xml:"time,attr,omitempty"`
	Skipped *JUnitMessage
	Error   *JUnitMessage
	Failure *JUnitMessage
	Stdout  *JUnitStdout
	Stderr  *JUnitStderr
}

type JUnitMessage struct {
	Message string `xml:"message,attr"`
}

type JUnitStdout struct {
	XMLName xml.Name `xml:"system-out"`
	Text    string   `xml:",chardata"`
}

type JUnitStderr struct {
	XMLName xml.Name `xml:"system-err"`
	Text    string   `xml:",chardata"`
}

func NewJUnitTestSuites(tracker *Tracker) *JUnitTestSuites {
	s := &JUnitTestSuites{}

	for _, v := range tracker.Suites {
		ts := JUnitTestSuite{Name: v.Name, Time: int(v.finish.Sub(v.start).Seconds())}

		for _, c := range v.Cases {
			ts.Tests++
			if c.Failure {
				ts.Failures++
			}

			tc := JUnitTestCase{
				Name: c.Name,
				Time: int(c.finish.Sub(c.start).Seconds()),
			}
			if c.Failure {
				tc.Failure = &JUnitMessage{Message: c.FailureMessage}
			}
			ts.TestCases = append(ts.TestCases, tc)
		}

		s.TestSuites = append(s.TestSuites, ts)
	}

	for _, v := range s.TestSuites {
		s.Tests += v.Tests
		s.Failures += v.Failures
	}

	return s
}
