package controllers

import (
	"fmt"
	"os"
	"testing"

	"go.f110.dev/heimdallr/pkg/config"
	"go.f110.dev/heimdallr/pkg/logger"
)

func TestMain(m *testing.M) {
	if err := logger.Init(&config.Logger{Level: "debug"}); err != nil {
		fmt.Fprintf(os.Stderr, "failure initialize logger: %+v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
