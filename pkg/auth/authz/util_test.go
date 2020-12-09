package authz

import (
	"testing"

	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/logger"
)

func TestMain(m *testing.M) {
	logger.Init(&configv2.Logger{Level: "debug"})

	m.Run()
}
