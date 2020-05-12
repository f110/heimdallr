package main

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

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/klog"

	"github.com/f110/lagrangian-proxy/operator/e2e/e2eutil"
	"github.com/f110/lagrangian-proxy/operator/e2e/test"
	"github.com/f110/lagrangian-proxy/operator/pkg/controllers"
)

var (
	CRDDir  = flag.String("crd", "", "CRD files")
	Verbose = flag.Bool("verbose", false, "View controller's log")
)

func TestE2E(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)

	rand.Seed(ginkgo.GinkgoRandomSeed())
	id := e2eutil.MakeId()
	kubeConfig := ""

	crd, err := e2eutil.ReadCRDFiles(*CRDDir)
	if err != nil {
		t.Fatal(err)
	}

	ginkgo.BeforeSuite(func() {
		k, err := e2eutil.CreateCluster(id)
		if err != nil {
			log.Fatalf("Could not create a cluster: %v", err)
		}
		kubeConfig = k

		cfg, err := clientcmd.BuildConfigFromFlags("", kubeConfig)
		if err != nil {
			log.Fatalf("Could not build config: %v", err)
		}
		kubeClient, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			log.Fatalf("%v", err)
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
		test.Config = cfg

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
						e, err := controllers.NewEtcdController(ctx, kubeClient, cfg, "cluster.local", true)
						if err != nil {
							log.Fatal(err)
						}

						c, err := controllers.New(ctx, kubeClient, cfg)
						if err != nil {
							log.Fatal(err)
						}

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
	ginkgo.AfterSuite(func() {
		if kubeConfig != "" {
			os.Remove(kubeConfig)
		}

		err := e2eutil.DeleteCluster(id)
		if err != nil {
			log.Fatalf("Could not delete a cluster: %v", err)
		}
	})

	defer ginkgo.GinkgoRecover()

	fs := flag.NewFlagSet("e2e", flag.ContinueOnError)
	klog.InitFlags(fs)
	if err := fs.Parse([]string{"-stderrthreshold=FATAL", fmt.Sprintf("-logtostderr=%v", *Verbose)}); err != nil {
		log.Fatal(err)
	}
	klog.SetOutput(new(bytes.Buffer))
	ginkgo.RunSpecs(ginkgo.GinkgoT(), "Operator e2e Suite")
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
