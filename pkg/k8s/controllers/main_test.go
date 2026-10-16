package controllers

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/cache"

	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/k8s/controllers/controllertest"
	"go.f110.dev/heimdallr/pkg/logger"
)

func TestMain(m *testing.M) {
	if err := logger.Init(&configv2.Logger{Level: "debug", Encoding: "console"}); err != nil {
		fmt.Fprintf(os.Stderr, "failure initialize logger: %+v\n", err)
		os.Exit(1)
	}
	// The fake clients don't send the bookmark event that the streaming list of the informer waits for.
	if err := os.Setenv("KUBE_FEATURE_WatchListClient", "false"); err != nil {
		fmt.Fprintf(os.Stderr, "failure disable WatchListClient: %+v\n", err)
		os.Exit(1)
	}
	m.Run()
}

func startInformers(t *testing.T, runner *controllertest.TestRunner, synced []cache.InformerSynced) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	runner.SharedInformerFactory.Run(ctx)
	runner.CoreSharedInformerFactory.Run(ctx)
	require.True(t, cache.WaitForCacheSync(ctx.Done(), synced...))
}
