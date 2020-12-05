package authproxy

import (
	"fmt"
	"os"
	"testing"

	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/logger"
)

func TestMain(m *testing.M) {
	if err := logger.Init(&configv2.Logger{Level: "debug"}); err != nil {
		fmt.Fprintf(os.Stderr, "failure initialize logger: %+v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
