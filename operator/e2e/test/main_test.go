package test

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"sync"
	"testing"
	"time"

	mClientset "github.com/coreos/prometheus-operator/pkg/client/versioned"
	cmClientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	_ "github.com/smartystreets/goconvey/convey"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/klog"

	"github.com/f110/lagrangian-proxy/operator/e2e/e2eutil"
	"github.com/f110/lagrangian-proxy/operator/e2e/framework"
	clientset "github.com/f110/lagrangian-proxy/operator/pkg/client/versioned"
	"github.com/f110/lagrangian-proxy/operator/pkg/controllers"
	informers "github.com/f110/lagrangian-proxy/operator/pkg/informers/externalversions"
)

func init() {
	framework.Flags(flag.CommandLine)
}

func TestMain(m *testing.M) {
	flag.Parse()

	rand.Seed(framework.Config.RandomSeed)
	id := e2eutil.MakeId()
	kubeConfig := ""

	framework.BeforeSuite(func() {
		crd, err := e2eutil.ReadCRDFiles(framework.Config.CRDDir)
		if err != nil {
			log.Fatal(err)
		}

		k, err := e2eutil.CreateCluster(id)
		if err != nil {
			log.Fatalf("Could not create a cluster: %v", err)
		}
		kubeConfig = k

		cfg, err := clientcmd.BuildConfigFromFlags("", kubeConfig)
		if err != nil {
			log.Fatalf("Could not build config: %v", err)
		}
		RESTConfig = cfg
		kubeClient, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			log.Fatalf("%v", err)
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

		if err := e2eutil.WaitForReady(context.TODO(), kubeClient); err != nil {
			log.Fatal(err)
		}

		if err := e2eutil.EnsureCertManager(cfg); err != nil {
			log.Fatalf("%+v", err)
		}

		// Create CustomResourceDefinition
		if err := e2eutil.EnsureCRD(cfg, crd, 3*time.Minute); err != nil {
			log.Fatal(err)
		}

		lock, err := resourcelock.New(
			resourcelock.LeasesResourceLock,
			"default",
			"e2e",
			kubeClient.CoreV1(),
			kubeClient.CoordinationV1(),
			resourcelock.ResourceLockConfig{Identity: id},
		)
		if err != nil {
			log.Fatal(err)
		}

		go func() {
			leaderelection.RunOrDie(context.TODO(), leaderelection.LeaderElectionConfig{
				Lock:            lock,
				ReleaseOnCancel: true,
				LeaseDuration:   30 * time.Second,
				RenewDeadline:   15 * time.Second,
				RetryPeriod:     5 * time.Second,
				Callbacks: leaderelection.LeaderCallbacks{
					OnStartedLeading: func(ctx context.Context) {
						coreSharedInformerFactory := kubeinformers.NewSharedInformerFactory(kubeClient, 30*time.Second)
						sharedInformerFactory := informers.NewSharedInformerFactory(proxyClient, 30*time.Second)

						e, err := controllers.NewEtcdController(sharedInformerFactory, coreSharedInformerFactory, kubeClient, proxyClient, cfg, "cluster.local", true, nil)
						if err != nil {
							log.Fatal(err)
						}

						c, err := controllers.New(ctx, sharedInformerFactory, coreSharedInformerFactory, kubeClient, proxyClient, cmClient, mClient)
						if err != nil {
							log.Fatal(err)
						}

						sharedInformerFactory.Start(ctx.Done())
						coreSharedInformerFactory.Start(ctx.Done())

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

						wg.Wait()
					},
					OnStoppedLeading: func() {},
					OnNewLeader: func(identity string) {
						if identity == id {
							return
						}
					},
				},
			})
		}()

		fs := flag.NewFlagSet("e2e", flag.ContinueOnError)
		klog.InitFlags(fs)
		if err := fs.Parse([]string{"-stderrthreshold=FATAL", fmt.Sprintf("-logtostderr=%v", framework.Config.Verbose)}); err != nil {
			log.Fatal(err)
		}
		klog.SetOutput(new(bytes.Buffer))
	})

	framework.AfterSuite(func() {
		if kubeConfig != "" {
			os.Remove(kubeConfig)
		}

		err := e2eutil.DeleteCluster(id)
		if err != nil {
			log.Fatalf("Could not delete a cluster: %v", err)
		}
	})

	os.Exit(framework.RunSpec(m))
}
