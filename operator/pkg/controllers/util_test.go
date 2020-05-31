package controllers

import (
	"github.com/jarcoal/httpmock"
)

func activateMockTransport() (*httpmock.MockTransport, func()) {
	oldTransport := transport

	mockTransport := httpmock.NewMockTransport()
	transport = mockTransport

	return mockTransport, func() {
		transport = oldTransport
	}
}
