package frontproxy

import (
	"fmt"
	"os"
	"testing"

	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/logger"
)

func TestMain(m *testing.M) {
	if err := logger.Init(&config.Logger{Level: "debug"}); err != nil {
		fmt.Fprintf(os.Stderr, "failure initialize logger: %+v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
