package main

import (
	"context"
	"flag"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/klog"

	clientset "github.com/f110/lagrangian-proxy/operator/pkg/client/versioned"
	"github.com/f110/lagrangian-proxy/operator/pkg/controllers"
	informers "github.com/f110/lagrangian-proxy/operator/pkg/informers/externalversions"
	"github.com/f110/lagrangian-proxy/operator/pkg/signals"
)

func main() {
	clusterDomain := ""
	id := ""
	metricsAddr := ""
	enableLeaderElection := false
	leaseLockName := ""
	leaseLockNamespace := ""
	dev := false
	fs := flag.NewFlagSet("etcdcontroller", flag.ExitOnError)
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
		klog.Error(err)
		os.Exit(1)
	}

	kubeClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		os.Exit(1)
	}
	proxyClient, err := clientset.NewForConfig(cfg)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}

	lock, err := resourcelock.New(
		resourcelock.LeasesResourceLock,
		leaseLockNamespace,
		leaseLockName,
		kubeClient.CoreV1(),
		kubeClient.CoordinationV1(),
		resourcelock.ResourceLockConfig{Identity: id},
	)
	if err != nil {
		klog.Error(err)
		os.Exit(1)
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

				c, err := controllers.NewEtcdController(sharedInformerFactory, coreSharedInformerFactory, kubeClient, cfg, clusterDomain, dev)
				if err != nil {
					klog.Error(err)
					os.Exit(1)
				}

				coreSharedInformerFactory.Start(ctx.Done())
				sharedInformerFactory.Start(ctx.Done())

				c.Run(ctx, 1)
				klog.Info("Shutdown")
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
