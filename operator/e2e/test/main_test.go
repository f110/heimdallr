package test

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	_ "github.com/smartystreets/goconvey/convey"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/klog/v2"

	"go.f110.dev/heimdallr/operator/e2e/e2eutil"
	"go.f110.dev/heimdallr/operator/e2e/framework"
	clientset "go.f110.dev/heimdallr/operator/pkg/client/versioned"
	"go.f110.dev/heimdallr/operator/pkg/controllers"
	informers "go.f110.dev/heimdallr/operator/pkg/informers/externalversions"
	"go.f110.dev/heimdallr/pkg/config"
	"go.f110.dev/heimdallr/pkg/logger"
)

func init() {
	framework.Flags(flag.CommandLine)
}

func TestMain(m *testing.M) {
	flag.Parse()

	rand.Seed(framework.Config.RandomSeed)
	id := e2eutil.MakeId()
	kubeConfig := ""

	if err := logger.OverrideKlog(&config.Logger{Level: "fatal"}); err != nil {
		panic(err)
		return
	}
	fs := flag.NewFlagSet("e2e", flag.ContinueOnError)
	klog.InitFlags(fs)
	if err := fs.Parse([]string{"-stderrthreshold=FATAL", fmt.Sprintf("-logtostderr=%v", framework.Config.Verbose)}); err != nil {
		log.Fatal(err)
	}
	klog.SetOutput(ioutil.Discard)

	framework.BeforeSuite(func() {
		crd, err := e2eutil.ReadCRDFiles(framework.Config.CRDDir)
		if err != nil {
			log.Fatal(err)
		}

		k, err := e2eutil.CreateCluster(id, framework.Config.ClusterVersion)
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

						e, err := controllers.NewEtcdController(
							sharedInformerFactory,
							coreSharedInformerFactory,
							kubeClient,
							proxyClient,
							cfg,
							"cluster.local",
							true,
							http.DefaultTransport,
							nil,
						)
						if err != nil {
							log.Fatal(err)
						}

						c, err := controllers.NewProxyController(sharedInformerFactory, coreSharedInformerFactory, kubeClient, proxyClient)
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
