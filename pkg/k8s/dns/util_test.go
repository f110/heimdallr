package dns

import (
	"testing"

	"go.f110.dev/heimdallr/pkg/logger"
)

func TestMain(m *testing.M) {
	if err := logger.InitByFlags(); err != nil {
		panic(err)
	}

	m.Run()
}
