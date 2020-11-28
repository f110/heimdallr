package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/pflag"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/klog/v2"

	clientset "go.f110.dev/heimdallr/operator/pkg/client/versioned"
	"go.f110.dev/heimdallr/operator/pkg/controllers"
	informers "go.f110.dev/heimdallr/operator/pkg/informers/externalversions"
	"go.f110.dev/heimdallr/operator/pkg/signals"
	"go.f110.dev/heimdallr/operator/pkg/webhook"
	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/logger"
)

func main() {
	id := ""
	metricsAddr := ""
	enableLeaderElection := false
	leaseLockName := ""
	leaseLockNamespace := ""
	clusterDomain := ""
	probeAddr := ""
	workers := 1
	disableWebhook := false
	certFile := ""
	keyFile := ""
	logLevel := "info"
	logEncoding := "console"
	dev := false
	fs := pflag.NewFlagSet("heimdallrcontroller", pflag.ExitOnError)
	fs.StringVar(&id, "id", uuid.New().String(), "the holder identity name")
	fs.StringVar(&metricsAddr, "metrics-addr", ":8080", "The address the metric endpoint binds to.")
	fs.BoolVar(&enableLeaderElection, "enable-leader-election", enableLeaderElection,
		"Enable leader election for controller manager. Enabling this will ensure there is only one active controller manager.")
	fs.StringVar(&leaseLockName, "lease-lock-name", "", "the lease lock resource name")
	fs.StringVar(&leaseLockNamespace, "lease-lock-namespace", "", "the lease lock resource namespace")
	fs.StringVar(&clusterDomain, "cluster-domain", clusterDomain, "Cluster domain")
	fs.StringVar(&probeAddr, "probe-addr", ":6000", "Listen addr that provides readiness probe")
	fs.IntVar(&workers, "workers", workers, "The number of workers on each controller")
	fs.BoolVar(&dev, "dev", dev, "development mode")
	fs.StringVar(&logLevel, "log-level", logLevel, "Log level")
	fs.StringVar(&logEncoding, "log-encoding", logEncoding, "Log encoding")
	fs.BoolVar(&disableWebhook, "disable-webhook", false, "Disable webhook server")
	fs.StringVar(&certFile, "cert", "", "Server certificate file for webhook")
	fs.StringVar(&keyFile, "key", "", "Private key for server certificate")

	goFlagSet := flag.NewFlagSet("", flag.ContinueOnError)
	klog.InitFlags(goFlagSet)
	fs.AddGoFlagSet(goFlagSet)

	if err := fs.Parse(os.Args[1:]); err != nil {
		panic(err)
	}
	if !disableWebhook && certFile == "" {
		panic("-cert is mandatory")
	}
	if !disableWebhook && keyFile == "" {
		panic("-private-key is mandatory")
	}

	if err := logger.OverrideKlog(&configv2.Logger{Level: logLevel, Encoding: logEncoding}); err != nil {
		panic(err)
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	signals.SetupSignalHandler(cancelFunc)

	kubeconfigPath := ""
	if dev {
		h, err := os.UserHomeDir()
		if err != nil {
			klog.Error(err)
			os.Exit(1)
		}
		kubeconfigPath = filepath.Join(h, ".kube", "config")
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}

	coreClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	client, err := clientset.NewForConfig(cfg)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}

	probe := controllers.NewProbe(probeAddr)
	go probe.Start()
	probe.Ready()

	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Name:      leaseLockName,
			Namespace: leaseLockNamespace,
		},
		Client: coreClient.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: id,
		},
	}
	leaderelection.RunOrDie(ctx, leaderelection.LeaderElectionConfig{
		Lock:            lock,
		ReleaseOnCancel: true,
		LeaseDuration:   30 * time.Second,
		RenewDeadline:   15 * time.Second,
		RetryPeriod:     5 * time.Second,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				coreSharedInformerFactory := kubeinformers.NewSharedInformerFactory(coreClient, 30*time.Second)
				sharedInformerFactory := informers.NewSharedInformerFactory(client, 30*time.Second)

				c, err := controllers.NewProxyController(sharedInformerFactory, coreSharedInformerFactory, coreClient, client)
				if err != nil {
					logger.Log.Error("Failed start proxy controller", zap.Error(err))
					os.Exit(1)
				}

				e, err := controllers.NewEtcdController(
					sharedInformerFactory,
					coreSharedInformerFactory,
					coreClient,
					client,
					cfg,
					clusterDomain,
					dev,
					http.DefaultTransport,
					nil,
				)
				if err != nil {
					logger.Log.Error("Failed start etcd controller", zap.Error(err))
					os.Exit(1)
				}

				g, err := controllers.NewGitHubController(sharedInformerFactory, coreSharedInformerFactory, coreClient, client, http.DefaultTransport)
				if err != nil {
					logger.Log.Error("Failed start github controller", zap.Error(err))
					os.Exit(1)
				}

				ic := controllers.NewIngressController(coreSharedInformerFactory, sharedInformerFactory, coreClient, client)

				coreSharedInformerFactory.Start(ctx.Done())
				sharedInformerFactory.Start(ctx.Done())

				var wg sync.WaitGroup
				wg.Add(1)
				go func() {
					defer wg.Done()

					e.Run(ctx, workers)
				}()

				wg.Add(1)
				go func() {
					defer wg.Done()

					c.Run(ctx, workers)
				}()

				wg.Add(1)
				go func() {
					defer wg.Done()

					g.Run(ctx, workers)
				}()

				wg.Add(1)
				go func() {
					defer wg.Done()

					ic.Run(ctx, workers)
				}()

				if !disableWebhook {
					wg.Add(1)
					go func() {
						defer wg.Done()

						ws := webhook.NewServer(":8080", certFile, keyFile)
						err := ws.Start()
						if err != nil && err != http.ErrServerClosed {
							logger.Log.Info("Failed start webhook server", zap.Error(err))
						}
					}()
				}

				wg.Wait()
			},
			OnStoppedLeading: func() {
				logger.Log.Debug("Leader lost", zap.String("id", id))
				os.Exit(0)
			},
			OnNewLeader: func(identity string) {
				if identity == id {
					return
				}
				logger.Log.Debug("New leader elected", zap.String("id", identity))
			},
		},
	})
}
