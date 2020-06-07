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

	mClientset "github.com/coreos/prometheus-operator/pkg/client/versioned"
	"github.com/google/uuid"
	cmClientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/klog"

	clientset "go.f110.dev/heimdallr/operator/pkg/client/versioned"
	"go.f110.dev/heimdallr/operator/pkg/controllers"
	informers "go.f110.dev/heimdallr/operator/pkg/informers/externalversions"
	"go.f110.dev/heimdallr/operator/pkg/signals"
)

func main() {
	id := ""
	metricsAddr := ""
	enableLeaderElection := false
	leaseLockName := ""
	leaseLockNamespace := ""
	clusterDomain := ""
	dev := false
	fs := flag.NewFlagSet("operator", flag.ExitOnError)
	fs.StringVar(&id, "id", uuid.New().String(), "the holder identity name")
	fs.StringVar(&metricsAddr, "metrics-addr", ":8080", "The address the metric endpoint binds to.")
	fs.BoolVar(&enableLeaderElection, "enable-leader-election", enableLeaderElection,
		"Enable leader election for controller manager. Enabling this will ensure there is only one active controller manager.")
	fs.StringVar(&leaseLockName, "lease-lock-name", "", "the lease lock resource name")
	fs.StringVar(&leaseLockNamespace, "lease-lock-namespace", "", "the lease lock resource namespace")
	fs.StringVar(&clusterDomain, "cluster-domain", clusterDomain, "Cluster domain")
	fs.BoolVar(&dev, "dev", dev, "development mode")
	klog.InitFlags(fs)
	if err := fs.Parse(os.Args[1:]); err != nil {
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

	kubeClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	proxyClient, err := clientset.NewForConfig(cfg)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	cmClient, err := cmClientset.NewForConfig(cfg)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	mClient, err := mClientset.NewForConfig(cfg)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}

	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Name:      leaseLockName,
			Namespace: leaseLockNamespace,
		},
		Client: kubeClient.CoordinationV1(),
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
				coreSharedInformerFactory := kubeinformers.NewSharedInformerFactory(kubeClient, 30*time.Second)
				sharedInformerFactory := informers.NewSharedInformerFactory(proxyClient, 30*time.Second)

				c, err := controllers.NewProxyController(ctx, sharedInformerFactory, coreSharedInformerFactory, kubeClient, proxyClient, cmClient, mClient)
				if err != nil {
					klog.Error(err)
					os.Exit(1)
				}

				e, err := controllers.NewEtcdController(
					sharedInformerFactory,
					coreSharedInformerFactory,
					kubeClient,
					proxyClient,
					cfg,
					clusterDomain,
					dev,
					http.DefaultTransport,
					nil,
				)
				if err != nil {
					klog.Error(err)
					os.Exit(1)
				}

				g, err := controllers.NewGitHubController(sharedInformerFactory, coreSharedInformerFactory, kubeClient, proxyClient, http.DefaultTransport)
				if err != nil {
					klog.Error(err)
					os.Exit(1)
				}

				coreSharedInformerFactory.Start(ctx.Done())
				sharedInformerFactory.Start(ctx.Done())

				var wg sync.WaitGroup
				wg.Add(1)
				go func() {
					defer wg.Done()

					e.Run(ctx, 1)
				}()

				wg.Add(1)
				go func() {
					defer wg.Done()

					c.Run(ctx, 1)
				}()

				wg.Add(1)
				go func() {
					defer wg.Done()

					g.Run(ctx, 1)
				}()

				wg.Wait()
			},
			OnStoppedLeading: func() {
				klog.Infof("leader lost: %s", id)
				os.Exit(0)
			},
			OnNewLeader: func(identity string) {
				if identity == id {
					return
				}
				klog.Infof("new leader elected: %s", identity)
			},
		},
	})
}
